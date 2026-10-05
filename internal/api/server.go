package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"time"
)

type server struct {
	db        *sql.DB
	hashSlots chan struct{}
}

func New(db *sql.DB) http.Handler {
	s := &server{db: db, hashSlots: make(chan struct{}, 4)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) { respond(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /ready", s.ready)
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("POST /logout", s.auth(s.logout))
	mux.HandleFunc("GET /me", s.auth(s.me))
	mux.HandleFunc("POST /tickets", s.auth(s.createTicket))
	mux.HandleFunc("GET /tickets", s.auth(s.listTickets))
	mux.HandleFunc("GET /tickets/{id}", s.auth(s.readTicket))
	return mux
}

func respond(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func failure(w http.ResponseWriter, status int, message string) {
	respond(w, status, map[string]string{"error": message})
}

func (s *server) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if s.db == nil || s.db.PingContext(ctx) != nil {
		failure(w, 503, "database unavailable")
		return
	}
	respond(w, 200, map[string]string{"status": "ready"})
}
