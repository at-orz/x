package memory_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/at-orz/x/auth"
	"github.com/at-orz/x/auth/store/memory"
	"github.com/at-orz/x/auth/store/storetest"
)

func TestContract(t *testing.T) {
	storetest.Run(t, func(*testing.T) auth.Store { return memory.New() })
}

// A follower that stops reading is not waited on: once it is too far behind it gets Lost and a fresh
// Loaded instead of the backlog.
func TestAFollowerFallingBehindIsResynchronized(t *testing.T) {
	s := memory.New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := s.Follow(ctx)
	if ev := <-events; ev.Kind != auth.Loaded {
		t.Fatalf("first event %+v", ev)
	}
	// The pump goroutine holds one event while it waits to send it, so the backlog is a little larger
	// than what it keeps queued.
	for i := range 3000 {
		if err := s.Put(ctx, fmt.Sprintf("sid-%d", i), auth.Record{Subject: "alice"}, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	sawLost := false
	for !sawLost {
		select {
		case ev := <-events:
			if ev.Kind == auth.Lost {
				sawLost = true
			}
		case <-time.After(5 * time.Second):
			t.Fatal("no Lost after the follower fell behind")
		}
	}
	ev := <-events
	if ev.Kind != auth.Loaded {
		t.Fatalf("after Lost came %+v, want Loaded", ev)
	}
	// The Loaded and whatever followed it account for every session, as a follower in sync would see.
	ids := map[string]bool{}
	for _, id := range ev.IDs {
		ids[id] = true
	}
	for len(ids) < 3000 {
		select {
		case ev := <-events:
			if ev.Kind != auth.Added {
				t.Fatalf("after the resync came %+v", ev)
			}
			ids[ev.ID] = true
		case <-time.After(5 * time.Second):
			t.Fatalf("after the resync the follower knows %d sessions, want 3000", len(ids))
		}
	}
}

// method is a sign-in method that never needs its authority: enough to issue sessions on two managers.
type method struct{}

func (method) Name() string                                                       { return "corp" }
func (method) LoginURL(string) string                                             { return "/login" }
func (method) Revalidate(_ context.Context, rec auth.Record) (auth.Record, error) { return rec, nil }

var key = []byte("0123456789abcdef0123456789abcdef")

func newManager(t *testing.T, s *memory.Store) *auth.Manager {
	t.Helper()
	m, err := auth.New(auth.Options{
		Store:     s,
		Key:       key,
		Authorize: auth.AllowSubjects("corp", func() []string { return []string{"alice"} }),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Register(method{}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	m.FollowSessions(ctx, s.Follow(ctx))
	return m
}

// Two instances on one store and its feed, as a host running two processes over a shared store would be:
// what one writes, the other sees on the next request.
func TestTwoManagersSeeEachOthersWrites(t *testing.T) {
	s := memory.New()
	one, two := newManager(t, s), newManager(t, s)

	w := httptest.NewRecorder()
	if err := one.Issue(w, httptest.NewRequest(http.MethodGet, "/", nil),
		auth.Grant{Identity: auth.Identity{Provider: "corp", Subject: "alice"}}); err != nil {
		t.Fatal(err)
	}
	cookie := w.Result().Cookies()[0]

	ask := func(m *auth.Manager) (int, auth.Session) {
		var got auth.Session
		h := m.Require(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			got, _ = auth.SessionFrom(r.Context())
		}))
		r := httptest.NewRequest(http.MethodGet, "/api", nil)
		r.Header.Set("Accept", "application/json")
		r.AddCookie(cookie)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code, got
	}
	eventually := func(what string, ok func() bool) {
		t.Helper()
		for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
			if ok() {
				return
			}
		}
		t.Fatalf("%s did not happen", what)
	}

	code, sess := ask(two)
	if code != http.StatusOK {
		t.Fatalf("the other instance refused the session: %d", code)
	}
	if err := one.SetValue(context.Background(), sess.ID, "user", "42"); err != nil {
		t.Fatal(err)
	}
	eventually("the other instance seeing the value", func() bool {
		_, s := ask(two)
		return s.Values["user"] == "42"
	})

	logout := httptest.NewRequest(http.MethodPost, auth.LogoutPath, nil)
	logout.AddCookie(cookie)
	mux := http.NewServeMux()
	one.Routes(mux)
	mux.ServeHTTP(httptest.NewRecorder(), logout)
	eventually("the other instance refusing the logged-out session", func() bool {
		code, _ := ask(two)
		return code == http.StatusUnauthorized
	})
}
