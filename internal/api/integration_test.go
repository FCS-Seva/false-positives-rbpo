package api

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/FCS-Seva/false-positives-rbpo/internal/database"
	"github.com/FCS-Seva/false-positives-rbpo/internal/seed"
	"github.com/FCS-Seva/false-positives-rbpo/migrations"
)

const testPassword = "EK1-local-test-password"

type fixture struct {
	db *sql.DB
	h  http.Handler
}

func TestHTTPTickets(t *testing.T) {
	f := setup(t)
	a, b, s1, s2 := f.login(t, "requester_a"), f.login(t, "requester_b"), f.login(t, "specialist_1"), f.login(t, "specialist_2")
	f.request(t, "POST", "/tickets", `{"title":"hello","description":"world"}`, "", 401)
	f.request(t, "POST", "/tickets", `{"title":"hello","description":"world"}`, s1, 403)
	description := "quote ' OR 1=1; DROP TABLE accounts; --"
	body, _ := json.Marshal(map[string]string{"title": "Проблема", "description": description})
	data := f.request(t, "POST", "/tickets", string(body), a, 201)
	var ticket map[string]any
	if err := json.Unmarshal(data, &ticket); err != nil {
		t.Fatal(err)
	}
	id := int64(ticket["id"].(float64))
	path := "/tickets/" + strconv.FormatInt(id, 10)
	if ticket["description"] != description || ticket["status"] != "new" || ticket["version"] != float64(1) {
		t.Fatal("invalid created data")
	}
	for _, key := range []string{"author_id", "assignee_id", "notes", "password_hash"} {
		if _, ok := ticket[key]; ok {
			t.Fatal("unexpected field", key)
		}
	}
	f.request(t, "GET", path, "", a, 200)
	foreign := f.request(t, "GET", path, "", b, 404)
	if string(foreign) != string(f.request(t, "GET", "/tickets/999999", "", b, 404)) {
		t.Fatal("foreign and absent responses differ")
	}
	f.request(t, "GET", path, "", s1, 404)
	f.request(t, "GET", path, "", s2, 404)
	if string(f.request(t, "GET", "/tickets", "", b, 200)) != "[]\n" {
		t.Fatal("foreign ticket leaked in list")
	}
	var author int64
	var status string
	var when time.Time
	if err := f.db.QueryRow("SELECT author_id,status,created_at FROM tickets WHERE id=$1", id).Scan(&author, &status, &when); err != nil {
		t.Fatal(err)
	}
	if author != 1 || status != "new" || time.Since(when) > time.Minute {
		t.Fatal("server-owned fields incorrect")
	}
	if _, err := f.db.Exec("UPDATE tickets SET status='in_progress',assignee_id=3 WHERE id=$1", id); err != nil {
		t.Fatal(err)
	}
	f.request(t, "GET", path, "", s1, 200)
	f.request(t, "GET", path, "", s2, 404)
	if string(f.request(t, "GET", "/tickets", "", s2, 200)) != "[]\n" {
		t.Fatal("another specialist's ticket leaked")
	}
	if _, err := f.db.Exec("INSERT INTO tickets(author_id,title,description) SELECT 1,'owned','own' FROM generate_series(1,100)"); err != nil {
		t.Fatal(err)
	}
	var list []json.RawMessage
	if err := json.Unmarshal(f.request(t, "GET", "/tickets", "", a, 200), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 101 {
		t.Fatalf("list omitted owned tickets: got %d, want 101", len(list))
	}
}

func setup(t *testing.T) fixture {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set TEST_DATABASE_URL to a dedicated ek1_test_* database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	db, err := database.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	var name string
	if err := db.QueryRowContext(ctx, "SELECT current_database()").Scan(&name); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(name, "ek1_test_") {
		t.Fatal("refusing to clear a database without ek1_test_ prefix")
	}
	if err := migrations.Apply(ctx, db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "TRUNCATE sessions, tickets, accounts RESTART IDENTITY CASCADE"); err != nil {
		t.Fatal(err)
	}
	if err := seed.Apply(ctx, db, testPassword); err != nil {
		t.Fatal(err)
	}
	return fixture{db, New(db)}
}

func (f fixture) request(t *testing.T, method, path, body, token string, want int) []byte {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	if w.Code != want {
		t.Fatalf("%s %s: got %d want %d; %s", method, path, w.Code, want, w.Body.String())
	}
	return w.Body.Bytes()
}

func (f fixture) login(t *testing.T, login string) string {
	t.Helper()
	data := f.request(t, "POST", "/login", `{"login":"`+login+`","password":"`+testPassword+`"}`, "", 200)
	var response struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(data, &response); err != nil || response.Token == "" {
		t.Fatal("missing token")
	}
	return response.Token
}

func TestHTTPAuthentication(t *testing.T) {
	f := setup(t)
	f.request(t, "GET", "/ready", "", "", 200)
	f.request(t, "GET", "/me", "", "", 401)
	f.request(t, "POST", "/login", `{"login":"requester_a","password":"wrong"}`, "", 401)
	f.request(t, "POST", "/login", `{"login":"absent' OR 1=1--","password":"wrong"}`, "", 401)
	f.request(t, "POST", "/login", `{"login":"requester_a","password":"`+testPassword+`","role":"specialist"}`, "", 400)
	token := f.login(t, "requester_a")
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 {
		t.Fatal("token must contain 32 random bytes")
	}
	hash := sha256.Sum256([]byte(token))
	var stored []byte
	var expires time.Time
	if err := f.db.QueryRow("SELECT token_hash,expires_at FROM sessions WHERE token_hash=$1", hash[:]).Scan(&stored, &expires); err != nil {
		t.Fatal(err)
	}
	if string(stored) == token || time.Until(expires) < 7*time.Hour || time.Until(expires) > 8*time.Hour {
		t.Fatal("invalid session storage or expiry")
	}
	data := f.request(t, "GET", "/me", "", token, 200)
	if !strings.Contains(string(data), `"role":"requester"`) || strings.Contains(string(data), "password") {
		t.Fatal("identity or fields incorrect")
	}
	f.request(t, "POST", "/logout", "", token, 200)
	f.request(t, "GET", "/me", "", token, 401)
	token = f.login(t, "requester_b")
	hash = sha256.Sum256([]byte(token))
	if _, err := f.db.Exec("UPDATE sessions SET expires_at=CURRENT_TIMESTAMP-interval '1 second' WHERE token_hash=$1", hash[:]); err != nil {
		t.Fatal(err)
	}
	f.request(t, "GET", "/me", "", token, 401)
	f.request(t, "GET", "/me", "", strings.Repeat("A", 43), 401)
}

func TestHTTPRejectsInputWithoutWrites(t *testing.T) {
	f := setup(t)
	a := f.login(t, "requester_a")
	f.request(t, "POST", "/tickets", `{"title":"existing","description":"keep me"}`, a, 201)
	var before string
	if err := f.db.QueryRow("SELECT coalesce(json_agg(t ORDER BY id)::text,'[]') FROM tickets t").Scan(&before); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, body string
		code       int
	}{
		{"empty", `{}`, 400}, {"blank", `{"title":" ","description":"x"}`, 400},
		{"type", `{"title":12,"description":"x"}`, 400}, {"null", `{"title":"x","description":null}`, 400},
		{"author", `{"title":"x","description":"x","author_id":2}`, 400},
		{"role", `{"title":"x","description":"x","role":"specialist"}`, 400},
		{"status", `{"title":"x","description":"x","status":"closed"}`, 400},
		{"assignee", `{"title":"x","description":"x","assignee_id":3}`, 400},
		{"time", `{"title":"x","description":"x","created_at":"2020-01-01"}`, 400},
		{"version", `{"title":"x","description":"x","version":99}`, 400},
		{"trailing", `{"title":"x","description":"x"} {}`, 400},
		{"syntax", `{"title":`, 400}, {"utf8", "{\"title\":\"\xff\",\"description\":\"x\"}", 400},
		{"nul", `{"title":"x","description":"\u0000"}`, 400},
		{"long-title", `{"title":"` + strings.Repeat("я", 201) + `","description":"x"}`, 400},
		{"long-description", `{"title":"x","description":"` + strings.Repeat("я", 4001) + `"}`, 400},
		{"oversized", strings.Repeat(" ", 32*1024) + `{}`, 413},
	} {
		t.Run(tc.name, func(t *testing.T) { f.request(t, "POST", "/tickets", tc.body, a, tc.code) })
	}
	for _, id := range []string{"0", "-1", "99999999999999999999999", "1%20OR%201=1", "foo"} {
		f.request(t, "GET", "/tickets/"+id, "", a, 400)
	}
	var after string
	if err := f.db.QueryRow("SELECT coalesce(json_agg(t ORDER BY id)::text,'[]') FROM tickets t").Scan(&after); err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatal("rejected requests changed existing data")
	}
	f.request(t, "POST", "/tickets", `{"title":"`+strings.Repeat("я", 200)+`","description":"`+strings.Repeat("🙂", 4000)+`"}`, a, 201)
}

func TestSeedRevokesSessionsPreservesTickets(t *testing.T) {
	f := setup(t)
	token := f.login(t, "requester_a")
	f.request(t, "POST", "/tickets", `{"title":"keep","description":"preserved"}`, token, 201)
	if err := seed.Apply(context.Background(), f.db, "new local test password"); err != nil {
		t.Fatal(err)
	}
	f.request(t, "GET", "/me", "", token, 401)
	f.request(t, "POST", "/login", `{"login":"requester_a","password":"`+testPassword+`"}`, "", 401)
	f.request(t, "POST", "/login", `{"login":"requester_a","password":"new local test password"}`, "", 200)
	var count int
	var text string
	if err := f.db.QueryRow("SELECT count(*),min(description) FROM tickets").Scan(&count, &text); err != nil {
		t.Fatal(err)
	}
	if count != 1 || text != "preserved" {
		t.Fatal("seed damaged tickets")
	}
	var distinct int
	if err := f.db.QueryRow("SELECT count(DISTINCT password_hash) FROM accounts").Scan(&distinct); err != nil {
		t.Fatal(err)
	}
	if distinct != 4 {
		t.Fatal("seed reused salts")
	}
}

func TestHTTPDatabaseFailureDoesNotGrantAccess(t *testing.T) {
	f := setup(t)
	token := f.login(t, "requester_a")
	f.db.Close()
	for _, path := range []string{"/me", "/tickets", "/tickets/1", "/ready"} {
		body := f.request(t, "GET", path, "", token, 503)
		if strings.Contains(string(body), "sql") || strings.Contains(string(body), "password") {
			t.Fatal("internal failure details disclosed")
		}
	}
	f.request(t, "POST", "/login", `{"login":"requester_a","password":"`+testPassword+`"}`, "", 503)
}
