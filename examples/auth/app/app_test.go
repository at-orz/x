package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/at-orz/x/auth"
	"github.com/at-orz/x/auth/store/memory"
)

func newTestApp(t *testing.T) http.Handler {
	t.Helper()
	store := memory.New()
	h, err := New(t.Context(), Config{
		Issuer:       "https://idp.example",
		ClientID:     "example-app",
		ClientSecret: "test-client-secret",
		AllowEmails:  []string{"alice@example.com"},
		AllowMinted:  []string{"bot-one"},
		Sessions:     store,
		Tickets:      store.Tickets(),
		Key:          []byte(strings.Repeat("k", 32)),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return h
}

func TestPages(t *testing.T) {
	h := newTestApp(t)
	for _, tc := range []struct {
		name, path, accept string
		status             int
		location           string
	}{
		{name: "home is public", path: "/", status: http.StatusOK},
		{name: "me sends to the login", path: "/me", status: http.StatusFound, location: "/auth/oidc/dex/login?ret=%2Fme"},
		{name: "api answers 401 to JSON", path: "/api/me", accept: "application/json", status: http.StatusUnauthorized},
		{name: "the page script is served", path: "/static/me.js", status: http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			if tc.accept != "" {
				req.Header.Set("Accept", tc.accept)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("status %d, want %d; body %s", rec.Code, tc.status, rec.Body)
			}
			if got := rec.Header().Get("Location"); got != tc.location {
				t.Fatalf("Location %q, want %q", got, tc.location)
			}
		})
	}
}

func TestHomeWithAForgedCookieStaysPublic(t *testing.T) {
	h := newTestApp(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "auth_session", Value: "not.signed"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Not signed in") {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
}

func TestAuthorize(t *testing.T) {
	a := Authorize([]string{"alice@example.com"}, []string{"bot-one"})
	for _, tc := range []struct {
		name  string
		id    auth.Identity
		allow bool
	}{
		{"allowed email", auth.Identity{Provider: "dex", Subject: "opaque", Claims: map[string]any{
			"email": "alice@example.com", "email_verified": true}}, true},
		{"unverified email", auth.Identity{Provider: "dex", Subject: "opaque", Claims: map[string]any{
			"email": "alice@example.com", "email_verified": false}}, false},
		{"other email", auth.Identity{Provider: "dex", Subject: "opaque", Claims: map[string]any{
			"email": "bob@example.com", "email_verified": true}}, false},
		{"no claims", auth.Identity{Provider: "dex", Subject: "alice@example.com"}, false},
		{"listed ticket subject", auth.Identity{Provider: "mint", Subject: "bot-one"}, true},
		{"other ticket subject", auth.Identity{Provider: "mint", Subject: "bot-two"}, false},
		{"email as a ticket subject", auth.Identity{Provider: "mint", Subject: "alice@example.com"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := a(context.Background(), tc.id)
			if tc.allow && err != nil {
				t.Fatalf("refused: %v", err)
			}
			if !tc.allow && !errors.Is(err, auth.ErrNotAllowed) {
				t.Fatalf("got %v, want a refusal", err)
			}
		})
	}
}

func TestIssueTicket(t *testing.T) {
	store := memory.New()
	path, err := IssueTicket(t.Context(), Config{Tickets: store.Tickets()}, "bot-one", 0)
	if err == nil {
		t.Fatalf("a zero session length was accepted: %s", path)
	}
	path, err = IssueTicket(t.Context(), Config{Tickets: store.Tickets()}, "bot-one", time.Minute)
	if err != nil {
		t.Fatalf("IssueTicket: %v", err)
	}
	if !strings.HasPrefix(path, "/auth/mint/mint?t=") {
		t.Fatalf("path %q", path)
	}
}
