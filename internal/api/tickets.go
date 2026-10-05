package api

import (
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type ticket struct {
	ID          int64     `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	Version     int64     `json:"version"`
}

const fields = "id,title,description,status,created_at,version"
const visible = "(($2='requester' AND author_id=$1) OR ($2='specialist' AND assignee_id=$1))"

type scanner interface{ Scan(...any) error }

func scanTicket(row scanner) (ticket, error) {
	var t ticket
	err := row.Scan(&t.ID, &t.Title, &t.Description, &t.Status, &t.CreatedAt, &t.Version)
	return t, err
}

func validText(value string, max int) bool {
	return strings.TrimSpace(value) != "" && utf8.RuneCountInString(value) <= max && !strings.ContainsRune(value, 0)
}

func positiveID(value string) (int64, bool) {
	if value == "" {
		return 0, false
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	id, err := strconv.ParseInt(value, 10, 64)
	return id, err == nil && id > 0
}

func (s *server) createTicket(w http.ResponseWriter, r *http.Request, user identity, hash [32]byte) {
	if user.Role != "requester" {
		failure(w, 403, "requester role required")
		return
	}
	var in struct {
		Title       string `json:"title"`
		Description string `json:"description"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !validText(in.Title, 200) || !validText(in.Description, 4000) {
		failure(w, 400, "invalid title or description")
		return
	}
	t, err := scanTicket(s.db.QueryRowContext(r.Context(), "INSERT INTO tickets(author_id,title,description) VALUES($1,$2,$3) RETURNING "+fields, user.ID, in.Title, in.Description))
	if err != nil {
		failure(w, 503, "database unavailable")
		return
	}
	respond(w, 201, t)
}

func (s *server) readTicket(w http.ResponseWriter, r *http.Request, user identity, hash [32]byte) {
	id, ok := positiveID(r.PathValue("id"))
	if !ok {
		failure(w, 400, "invalid ticket id")
		return
	}
	t, err := scanTicket(s.db.QueryRowContext(r.Context(), "SELECT "+fields+" FROM tickets WHERE "+visible+" AND id=$3", user.ID, user.Role, id))
	if errors.Is(err, sql.ErrNoRows) {
		failure(w, 404, "ticket not found")
		return
	}
	if err != nil {
		failure(w, 503, "database unavailable")
		return
	}
	respond(w, 200, t)
}

func (s *server) listTickets(w http.ResponseWriter, r *http.Request, user identity, hash [32]byte) {
	rows, err := s.db.QueryContext(r.Context(), "SELECT "+fields+" FROM tickets WHERE "+visible+" ORDER BY id DESC", user.ID, user.Role)
	if err != nil {
		failure(w, 503, "database unavailable")
		return
	}
	defer rows.Close()
	out := make([]ticket, 0)
	for rows.Next() {
		t, err := scanTicket(rows)
		if err != nil {
			failure(w, 503, "database unavailable")
			return
		}
		out = append(out, t)
	}
	if rows.Err() != nil {
		failure(w, 503, "database unavailable")
		return
	}
	respond(w, 200, out)
}
