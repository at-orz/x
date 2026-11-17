package etcd

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/at-orz/x/auth"
	"github.com/at-orz/x/auth/mint"
	"github.com/at-orz/x/auth/store/storetest"
)

func TestContract(t *testing.T) {
	c := dial(t, startEtcd(t))
	storetest.Run(t, func(*testing.T) auth.Store { return New(c, freshPrefix()) })
}

func TestTicketsContract(t *testing.T) {
	c := dial(t, startEtcd(t))
	storetest.RunTickets(t, func(*testing.T) mint.Tickets { return New(c, freshPrefix()).Tickets() })
}

func TestNewRefusesAPrefixWithoutASlash(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("New accepted a prefix not ending in /")
		}
	}()
	New(nil, "app")
}

func record() auth.Record {
	now := time.Now()
	return auth.Record{Provider: "corp", Subject: "alice", CreatedAt: now, VerifiedAt: now,
		State: json.RawMessage(`{"refresh_token":"r-1"}`)}
}

// Two instances on two clients reach the refresh window of one session at once: exactly one gets the
// claim.
func TestTheClaimRaceBetweenTwoClientsHasOneWinner(t *testing.T) {
	url := startEtcd(t)
	prefix := freshPrefix()
	one, two := New(dial(t, url), prefix), New(dial(t, url), prefix)
	ctx := context.Background()
	if err := one.Put(ctx, "sid", record(), time.Hour); err != nil {
		t.Fatal(err)
	}
	a, err := one.Get(ctx, "sid")
	if err != nil {
		t.Fatal(err)
	}
	b, err := two.Get(ctx, "sid")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var okA, okB bool
	var errA, errB error
	wg.Go(func() { _, okA, errA = one.Claim(ctx, "sid", a) })
	wg.Go(func() { _, okB, errB = two.Claim(ctx, "sid", b) })
	wg.Wait()
	if errA != nil || errB != nil {
		t.Fatal(errA, errB)
	}
	if okA == okB {
		t.Errorf("claims: %v and %v, want exactly one winner", okA, okB)
	}
}

// A write by another client since the read is reported, not overwritten: SetValue retries on it, and a
// revalidation keeps the newer write.
func TestTouchAfterAnotherWriteIsAConflict(t *testing.T) {
	url := startEtcd(t)
	prefix := freshPrefix()
	one, two := New(dial(t, url), prefix), New(dial(t, url), prefix)
	ctx := context.Background()
	if err := one.Put(ctx, "sid", record(), time.Hour); err != nil {
		t.Fatal(err)
	}
	mine, err := one.Get(ctx, "sid")
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := two.Get(ctx, "sid")
	if err != nil {
		t.Fatal(err)
	}
	theirs.Values = map[string]string{"user": "42"}
	if err := two.Touch(ctx, "sid", theirs); err != nil {
		t.Fatal(err)
	}
	if err := one.Touch(ctx, "sid", mine); !errors.Is(err, auth.ErrConflict) {
		t.Errorf("Touch of a stale read = %v, want ErrConflict", err)
	}
	if got, err := one.Get(ctx, "sid"); err != nil || got.Values["user"] != "42" {
		t.Errorf("the other write did not survive: %v, %v", got.Values, err)
	}
}

func TestTouchAfterTheLeaseExpiredIsNotFound(t *testing.T) {
	s := New(dial(t, startEtcd(t)), freshPrefix())
	ctx := context.Background()
	if err := s.Put(ctx, "sid", record(), time.Second); err != nil {
		t.Fatal(err)
	}
	rec, err := s.Get(ctx, "sid")
	if err != nil {
		t.Fatal(err)
	}
	for end := time.Now().Add(15 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		if _, err := s.Get(ctx, "sid"); errors.Is(err, auth.ErrNotFound) {
			break
		}
		if time.Now().After(end) {
			t.Fatal("the lease did not expire")
		}
	}
	if err := s.Touch(ctx, "sid", rec); !errors.Is(err, auth.ErrNotFound) {
		t.Errorf("Touch after the lease expired = %v, want ErrNotFound", err)
	}
}

// A record etcd refuses to store must not leave behind the lease granted for it, which would otherwise
// outlive the failed sign-in by its whole ttl.
func TestAPutThatFailsRevokesItsLease(t *testing.T) {
	c := dial(t, startEtcd(t))
	s := New(c, freshPrefix())
	ctx := context.Background()
	rec := record()
	// Larger than etcd's request limit, so the Grant succeeds and the Put after it does not.
	rec.State = json.RawMessage(`"` + strings.Repeat("x", 3<<20) + `"`)
	if err := s.Put(ctx, "big", rec, time.Hour); err == nil {
		t.Fatal("Put of an oversized record succeeded")
	}
	if err := s.Tickets().Put(ctx, "big", mint.Ticket{Subject: strings.Repeat("x", 3<<20)}, time.Hour); err == nil {
		t.Fatal("Put of an oversized ticket succeeded")
	}
	leases, err := c.Leases(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(leases.Leases) != 0 {
		t.Fatalf("leases after the failed puts = %v, want none", leases.Leases)
	}
}

func TestRedeemFromTwoClientsHasOneWinner(t *testing.T) {
	url := startEtcd(t)
	prefix := freshPrefix()
	one, two := New(dial(t, url), prefix).Tickets(), New(dial(t, url), prefix).Tickets()
	ctx := context.Background()
	if err := one.Put(ctx, "nonce", mint.Ticket{Subject: "agent", SessionTTL: time.Hour}, time.Minute); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, ts := range []*Tickets{one, two} {
		wg.Go(func() { _, errs[i] = ts.Redeem(ctx, "nonce") })
	}
	wg.Wait()
	if (errs[0] == nil) == (errs[1] == nil) {
		t.Errorf("redemptions: %v and %v, want exactly one winner", errs[0], errs[1])
	}
	for _, err := range errs {
		if err != nil && !errors.Is(err, auth.ErrNotFound) {
			t.Errorf("the loser got %v, want ErrNotFound", err)
		}
	}
}

func TestListAndRemove(t *testing.T) {
	s := New(dial(t, startEtcd(t)), freshPrefix())
	ctx := context.Background()
	older := record()
	older.CreatedAt = older.CreatedAt.Add(-time.Hour)
	if err := s.Put(ctx, "older", older, time.Hour); err != nil {
		t.Fatal(err)
	}
	newer := record()
	newer.Deadline = newer.CreatedAt.Add(time.Hour)
	if err := s.Put(ctx, "newer", newer, time.Hour); err != nil {
		t.Fatal(err)
	}
	list, err := s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].ID != "newer" || list[1].ID != "older" {
		t.Fatalf("List = %+v, want newer then older", list)
	}
	if list[0].Provider != "corp" || list[0].Subject != "alice" || !list[0].Deadline.Equal(newer.Deadline) {
		t.Errorf("the entry is %+v", list[0])
	}
	if err := s.Remove(ctx, "older"); err != nil {
		t.Fatal(err)
	}
	// A revocation that quietly did nothing must not read as success.
	if err := s.Remove(ctx, "older"); !errors.Is(err, auth.ErrNotFound) {
		t.Errorf("a second Remove = %v, want ErrNotFound", err)
	}
}

// method is a sign-in method whose revalidation holds until released, counting how often it is asked and
// writing new claims when it answers.
type method struct {
	mu      sync.Mutex
	calls   int
	entered chan struct{}
	release chan struct{}
}

func (*method) Name() string           { return "corp" }
func (*method) LoginURL(string) string { return "/login" }

func (m *method) Revalidate(_ context.Context, rec auth.Record) (auth.Record, error) {
	m.mu.Lock()
	m.calls++
	m.mu.Unlock()
	m.entered <- struct{}{}
	<-m.release
	rec.Claims = json.RawMessage(`{"groups":["revalidated"]}`)
	return rec, nil
}

func (m *method) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

var testKey = []byte("0123456789abcdef0123456789abcdef")

// Two instances of a host on two clients of one etcd, serving one session: a revalidation on one is seen
// by the other, and the claim keeps them from revalidating together.
func TestTwoManagersShareASession(t *testing.T) {
	url := startEtcd(t)
	prefix := freshPrefix()
	shared := &method{entered: make(chan struct{}, 2), release: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	newManager := func() (*auth.Manager, *Store) {
		s := New(dial(t, url), prefix)
		m, err := auth.New(auth.Options{Store: s, Key: testKey,
			Authorize: auth.AllowSubjects("corp", func() []string { return []string{"alice"} })})
		if err != nil {
			t.Fatal(err)
		}
		if err := m.Register(shared); err != nil {
			t.Fatal(err)
		}
		m.FollowSessions(ctx, s.Follow(ctx))
		return m, s
	}
	one, store := newManager()
	two, _ := newManager()

	w := httptest.NewRecorder()
	if err := one.Issue(w, httptest.NewRequest(http.MethodGet, "/", nil),
		auth.Grant{Identity: auth.Identity{Provider: "corp", Subject: "alice"}}); err != nil {
		t.Fatal(err)
	}
	var state struct {
		SID string `json:"sid"`
	}
	if err := one.Open(w.Result().Cookies()[0].Value, &state); err != nil {
		t.Fatal(err)
	}
	rec, err := store.Get(ctx, state.SID)
	if err != nil {
		t.Fatal(err)
	}
	rec.VerifiedAt = rec.VerifiedAt.Add(-time.Hour)
	if err := store.Touch(ctx, state.SID, rec); err != nil {
		t.Fatal(err)
	}
	// A cookie inside the refresh window, as both instances would receive from tabs of one browser.
	value, err := one.Seal(map[string]any{"sid": state.SID, "exp": time.Now().Add(5 * time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	inWindow := &http.Cookie{Name: "auth_session", Value: value}
	ask := func(m *auth.Manager, c *http.Cookie) (int, auth.Session) {
		var got auth.Session
		h := m.Require(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			got, _ = auth.SessionFrom(r.Context())
		}))
		r := httptest.NewRequest(http.MethodGet, "/api", nil)
		r.Header.Set("Accept", "application/json")
		r.AddCookie(c)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code, got
	}

	first := make(chan int, 1)
	go func() {
		code, _ := ask(one, inWindow)
		first <- code
	}()
	<-shared.entered
	// The first instance holds the claim and is asking; the second lets its request through without asking.
	if code, _ := ask(two, inWindow); code != http.StatusOK {
		t.Errorf("the second instance gave %d while the first revalidated, want 200", code)
	}
	close(shared.release)
	if code := <-first; code != http.StatusOK {
		t.Errorf("the revalidating instance gave %d", code)
	}
	if n := shared.count(); n != 1 {
		t.Errorf("the authority was asked %d times, want once", n)
	}

	// The second instance sees the revalidation's claims, through the feed, with a cookie outside the
	// window as its next request would carry.
	value, err = one.Seal(map[string]any{"sid": state.SID, "exp": time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	fresh := &http.Cookie{Name: "auth_session", Value: value}
	for end := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		code, s := ask(two, fresh)
		if g, _ := s.Identity.Claims["groups"].([]any); code == http.StatusOK && len(g) == 1 && g[0] == "revalidated" {
			break
		}
		if time.Now().After(end) {
			t.Fatalf("the second instance never saw the revalidation: %d %v", code, s.Identity.Claims)
		}
	}
	if n := shared.count(); n != 1 {
		t.Errorf("the authority was asked %d times in all, want once", n)
	}
}
