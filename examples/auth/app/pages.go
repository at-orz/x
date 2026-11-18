package app

import (
	"embed"
	"encoding/json"
	"html/template"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"time"

	"github.com/at-orz/x/auth"
)

//go:embed templates/*.html static/*.js
var files embed.FS

var pages = template.Must(template.ParseFS(files, "templates/*.html"))

type server struct {
	m   *auth.Manager
	log *slog.Logger
}

func (s *server) routes(mux *http.ServeMux) {
	mux.Handle("GET /{$}", s.m.Optional(http.HandlerFunc(s.home)))
	mux.Handle("GET /me", s.m.Require(http.HandlerFunc(s.me)))
	mux.Handle("GET /api/me", s.m.Require(http.HandlerFunc(s.apiMe)))
	mux.Handle("GET /live", s.m.Require(http.HandlerFunc(s.live)))
	mux.Handle("GET /static/", http.FileServerFS(files))
}

// view is what the pages show of a session.
type view struct {
	SignedIn bool
	LoginURL string
	Provider string
	Subject  string
	User     string
	Deadline string
	Claims   []claim
	Values   []claim
}

type claim struct{ Name, Value string }

func viewOf(sess auth.Session) view {
	v := view{
		SignedIn: true,
		Provider: sess.Identity.Provider,
		Subject:  sess.Identity.Subject,
		User:     sess.Values[UserKey],
	}
	if !sess.Deadline.IsZero() {
		v.Deadline = sess.Deadline.UTC().Format(time.RFC3339)
	}
	for _, k := range slices.Sorted(maps.Keys(sess.Identity.Claims)) {
		b, _ := json.Marshal(sess.Identity.Claims[k])
		v.Claims = append(v.Claims, claim{k, string(b)})
	}
	for _, k := range slices.Sorted(maps.Keys(sess.Values)) {
		v.Values = append(v.Values, claim{k, sess.Values[k]})
	}
	return v
}

func (s *server) home(w http.ResponseWriter, r *http.Request) {
	v := view{LoginURL: "/me"}
	if sess, ok := auth.SessionFrom(r.Context()); ok {
		v = viewOf(sess)
	}
	s.render(w, "home.html", v)
}

func (s *server) me(w http.ResponseWriter, r *http.Request) {
	sess, _ := auth.SessionFrom(r.Context())
	// The page runs one script, served from this site; nothing inline, nothing from elsewhere.
	w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
	s.render(w, "me.html", viewOf(sess))
}

// Me is the JSON answer of /api/me.
type Me struct {
	Provider string            `json:"provider"`
	Subject  string            `json:"subject"`
	Claims   map[string]any    `json:"claims,omitempty"`
	Deadline time.Time         `json:"deadline,omitzero"`
	Values   map[string]string `json:"values,omitempty"`
}

func (s *server) apiMe(w http.ResponseWriter, r *http.Request) {
	sess, _ := auth.SessionFrom(r.Context())
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(Me{
		Provider: sess.Identity.Provider,
		Subject:  sess.Identity.Subject,
		Claims:   sess.Identity.Claims,
		Deadline: sess.Deadline,
		Values:   sess.Values,
	})
}

func (s *server) render(w http.ResponseWriter, name string, v view) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Every page shows who is signed in, which must not be served to somebody else from a cache.
	w.Header().Set("Cache-Control", "no-store")
	if err := pages.ExecuteTemplate(w, name, v); err != nil {
		s.log.Warn("rendering a page failed", "page", name, "err", err)
	}
}
