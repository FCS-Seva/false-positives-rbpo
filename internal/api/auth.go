package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/FCS-Seva/false-positives-rbpo/internal/password"
)

type identity struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
	Role  string `json:"role"`
}
type authenticated func(http.ResponseWriter, *http.Request, identity, [32]byte)

// Dummy verification has the same Argon2 cost for an unknown account.
const dummyHash = "$argon2id$v=19$m=65536,t=3,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}
	if !decode(w, r, &in) {
		return
	}
	if len(in.Login) < 1 || len(in.Login) > 64 || len(in.Password) < 1 || len(in.Password) > 256 || strings.ContainsRune(in.Login, 0) {
		failure(w, 400, "invalid credentials format")
		return
	}
	select {
	case s.hashSlots <- struct{}{}:
		defer func() { <-s.hashSlots }()
	default:
		failure(w, 429, "try again later")
		return
	}
	if s.db == nil {
		failure(w, 503, "database unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	var id int64
	var stored string
	err := s.db.QueryRowContext(ctx, "SELECT id,password_hash FROM accounts WHERE login=$1", in.Login).Scan(&id, &stored)
	if errors.Is(err, sql.ErrNoRows) {
		stored = dummyHash
	} else if err != nil {
		failure(w, 503, "database unavailable")
		return
	}
	if !password.Verify(stored, in.Password) || errors.Is(err, sql.ErrNoRows) {
		failure(w, 401, "invalid credentials")
		return
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		failure(w, 503, "session unavailable")
		return
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(token))
	expires := time.Now().UTC().Add(8 * time.Hour)
	if _, err := s.db.ExecContext(ctx, "INSERT INTO sessions(token_hash,account_id,expires_at) VALUES($1,$2,$3)", hash[:], id, expires); err != nil {
		failure(w, 503, "database unavailable")
		return
	}
	respond(w, 200, map[string]any{"token": token, "expires_at": expires})
}

func (s *server) auth(next authenticated) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fields := strings.Fields(r.Header.Get("Authorization"))
		if len(fields) != 2 || fields[0] != "Bearer" {
			failure(w, 401, "authentication required")
			return
		}
		raw, err := base64.RawURLEncoding.Strict().DecodeString(fields[1])
		if err != nil || len(raw) != 32 || len(fields[1]) != 43 {
			failure(w, 401, "invalid session")
			return
		}
		if s.db == nil {
			failure(w, 503, "database unavailable")
			return
		}
		hash := sha256.Sum256([]byte(fields[1]))
		var user identity
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		err = s.db.QueryRowContext(ctx, `SELECT a.id,a.login,a.role FROM sessions s JOIN accounts a ON a.id=s.account_id WHERE s.token_hash=$1 AND s.expires_at>CURRENT_TIMESTAMP`, hash[:]).Scan(&user.ID, &user.Login, &user.Role)
		if errors.Is(err, sql.ErrNoRows) {
			failure(w, 401, "invalid session")
			return
		}
		if err != nil {
			failure(w, 503, "database unavailable")
			return
		}
		if user.Role != "requester" && user.Role != "specialist" {
			failure(w, 403, "role not allowed")
			return
		}
		next(w, r.WithContext(ctx), user, hash)
	}
}

func (s *server) me(w http.ResponseWriter, r *http.Request, user identity, hash [32]byte) {
	respond(w, 200, user)
}

func (s *server) logout(w http.ResponseWriter, r *http.Request, user identity, hash [32]byte) {
	if _, err := s.db.ExecContext(r.Context(), "DELETE FROM sessions WHERE token_hash=$1", hash[:]); err != nil {
		failure(w, 503, "database unavailable")
		return
	}
	respond(w, 200, map[string]string{"status": "logged out"})
}
