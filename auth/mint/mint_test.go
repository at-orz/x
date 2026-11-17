package mint_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/at-orz/x/auth"
	"github.com/at-orz/x/auth/mint"
	"github.com/at-orz/x/auth/store/memory"
)

var key = []byte("0123456789abcdef0123456789abcdef")

// brokenTickets stands for a ticket store that cannot be reached, which the handler has to tell apart
// from a ticket that is not there.
type brokenTickets struct{ mint.Tickets }

func (brokenTickets) Redeem(context.Context, string) (mint.Ticket, error) {
	return mint.Ticket{}, errors.New("store: no endpoints available")
}

type logBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

type env struct {
	m     *auth.Manager
	mt    *mint.Method
	store *memory.Store
	mux   *http.ServeMux
	logs  *logBuf

	mu      sync.Mutex
	allowed []string
}

func newEnv(t *testing.T, tickets func(*memory.Store) mint.Tickets) *env {
	t.Helper()
	e := &env{store: memory.New(), mux: http.NewServeMux(), logs: &logBuf{}, allowed: []string{"agent"}}
	m, err := auth.New(auth.Options{
		Store: e.store,
		Key:   key,
		Authorize: auth.AllowSubjects("mint", func() []string {
			e.mu.Lock()
			defer e.mu.Unlock()
			return slices.Clone(e.allowed)
		}),
		Log: slog.New(slog.NewTextHandler(e.logs, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	var ts mint.Tickets = e.store.Tickets()
	if tickets != nil {
		ts = tickets(e.store)
	}
	mt, err := mint.New(m, mint.Options{Tickets: ts})
	if err != nil {
		t.Fatal(err)
	}
	m.Routes(e.mux)
	mt.Routes(e.mux)
	e.m, e.mt = m, mt
	return e
}

func (e *env) allow(subjects ...string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.allowed = subjects
}

func (e *env) issue(t *testing.T, ttl time.Duration) string {
	t.Helper()
	path, err := e.mt.Issue(context.Background(), "agent", ttl)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

// redeem opens a sign-in link the way a browser would, optionally carrying the session cookie that
// browser already held.
func (e *env) redeem(path string, held *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	if held != nil {
		r.AddCookie(held)
	}
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, r)
	return w
}

// mintOne issues and redeems a ticket, returning the session cookie and its id.
func (e *env) mintOne(t *testing.T, ttl time.Duration) (*http.Cookie, string) {
	t.Helper()
	w := e.redeem(e.issue(t, ttl), nil)
	if w.Code != http.StatusFound {
		t.Fatalf("the redemption gave status = %d, body = %s", w.Code, w.Body)
	}
	c := sessionCookieOf(w)
	if c == nil {
		t.Fatal("the redemption set no cookie")
	}
	return c, e.sidOf(t, c)
}

func (e *env) sidOf(t *testing.T, c *http.Cookie) string {
	t.Helper()
	var s struct {
		SID string `json:"sid"`
	}
	if err := e.m.Open(c.Value, &s); err != nil {
		t.Fatal(err)
	}
	return s.SID
}

// cookieAt signs a session cookie, in the wire format of the session cookie, with its exp and deadline
// at chosen distances: those two decide separate things.
func (e *env) cookieAt(t *testing.T, sid string, until time.Duration, deadline time.Time) *http.Cookie {
	t.Helper()
	value, err := e.m.Seal(map[string]any{"sid": sid, "exp": time.Now().Add(until).Unix(), "dl": deadline.Unix()})
	if err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: "auth_session", Value: value}
}

func (e *env) ask(cookie *http.Cookie) *httptest.ResponseRecorder {
	protected := e.m.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, _ := auth.SessionFrom(r.Context())
		_, _ = w.Write([]byte(sess.Identity.Provider + "/" + sess.Identity.Subject))
	}))
	r := httptest.NewRequest(http.MethodGet, "/api/things", nil)
	r.Header.Set("Accept", "application/json")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	protected.ServeHTTP(w, r)
	return w
}

func (e *env) age(t *testing.T, sid string, by time.Duration) {
	t.Helper()
	ctx := context.Background()
	rec, err := e.store.Get(ctx, sid)
	if err != nil {
		t.Fatal(err)
	}
	rec.VerifiedAt = rec.VerifiedAt.Add(-by)
	if err := e.store.Touch(ctx, sid, rec); err != nil {
		t.Fatal(err)
	}
}

func sessionCookieOf(w *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == "auth_session" && c.Value != "" {
			return c
		}
	}
	return nil
}

func TestIssueWritesATicket(t *testing.T) {
	e := newEnv(t, nil)
	path := e.issue(t, time.Hour)
	u, err := url.Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	if u.Path != "/auth/mint/mint" || len(u.Query().Get("t")) != 32 {
		t.Errorf("Issue returned %q", path)
	}
	ticket, err := e.store.Tickets().Redeem(context.Background(), u.Query().Get("t"))
	if err != nil || ticket.Subject != "agent" || ticket.SessionTTL != time.Hour || ticket.CreatedAt.IsZero() {
		t.Errorf("the ticket written is %+v (%v)", ticket, err)
	}
	for _, bad := range []struct {
		sub string
		ttl time.Duration
	}{{"", time.Hour}, {"agent", 0}, {"agent", -time.Hour}} {
		if _, err := e.mt.Issue(context.Background(), bad.sub, bad.ttl); err == nil {
			t.Errorf("Issue(%q, %s) succeeded", bad.sub, bad.ttl)
		}
	}
}

// From the browser on, a redeemed ticket is an ordinary session. What it does not carry is anything to
// revalidate, and the deadline is there instead.
func TestMintRedeemsATicketIntoASession(t *testing.T) {
	e := newEnv(t, nil)
	w := e.redeem(e.issue(t, 24*time.Hour), nil)
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body)
	}
	// No ret parameter is accepted, so there is one place to land.
	if got := w.Header().Get("Location"); got != "/" {
		t.Errorf("it redirected to %q, want /", got)
	}
	session := sessionCookieOf(w)
	if session == nil {
		t.Fatal("no session cookie was set")
	}
	if !session.HttpOnly || session.SameSite != http.SameSiteLaxMode || session.Path != "/" {
		t.Errorf("the cookie of a minted session was built differently: %+v", session)
	}
	rec, err := e.store.Get(context.Background(), e.sidOf(t, session))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Provider != "mint" || rec.Subject != "agent" {
		t.Errorf("the record is for %q/%q", rec.Provider, rec.Subject)
	}
	if rec.Deadline.IsZero() || len(rec.State) != 0 {
		t.Errorf("the record has deadline %s and state %s", rec.Deadline, rec.State)
	}
	// VerifiedAt is the moment of minting rather than zero, or every comparison of it against the current
	// time would read as a confirmation in the distant past.
	if rec.VerifiedAt.IsZero() {
		t.Error("VerifiedAt was left zero")
	}
	if got := e.ask(session); got.Code != http.StatusOK || got.Body.String() != "mint/agent" {
		t.Errorf("the minted session was not let through: %d %s", got.Code, got.Body)
	}
}

// A link is good once. Whoever opened it first has the session, and a copy of the URL left in a
// terminal transcript buys nothing afterwards.
func TestMintSpendsATicketOnce(t *testing.T) {
	e := newEnv(t, nil)
	path := e.issue(t, time.Hour)
	if w := e.redeem(path, nil); w.Code != http.StatusFound {
		t.Fatalf("the first redemption gave status = %d", w.Code)
	}
	w := e.redeem(path, nil)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "mint_ticket_stale") {
		t.Errorf("the second redemption gave %d %s, want 400 mint_ticket_stale", w.Code, w.Body)
	}
	if sessionCookieOf(w) != nil {
		t.Error("the refused redemption handed out a session cookie anyway")
	}
}

// A link with no ticket and one never issued are one answer, and it is not a redirect into a login:
// trying again is what fixes a lost flow cookie, and it fixes neither of these.
func TestMintRefusesALinkItCannotSpend(t *testing.T) {
	for name, path := range map[string]string{
		"no ticket in the link":      "/auth/mint/mint",
		"a nonce nobody ever issued": "/auth/mint/mint?t=not-a-ticket",
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, nil)
			w := e.redeem(path, nil)
			if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "mint_ticket_stale") {
				t.Errorf("%d %s, want 400 mint_ticket_stale", w.Code, w.Body)
			}
			if sessionCookieOf(w) != nil {
				t.Error("a session was created anyway")
			}
		})
	}
}

// Minutes may pass between issuing and opening the link, and the policy is asked on every request, so a
// subject that would be refused at the next request is not given a session here.
func TestMintRefusesASubjectThatLeftThePolicy(t *testing.T) {
	e := newEnv(t, nil)
	path := e.issue(t, time.Hour)
	e.allow("someone-else")
	w := e.redeem(path, nil)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "subject_not_allowed") {
		t.Errorf("%d %s, want 403 subject_not_allowed", w.Code, w.Body)
	}
	if sessionCookieOf(w) != nil {
		t.Error("a session was created for a subject the policy refuses")
	}
}

// A ticket that cannot be read is not a ticket that is gone. Reporting a dead link over a store that is
// merely unreachable would send somebody to the host to issue another one for nothing.
func TestMintTellsAnUnreachableStoreFromASpentTicket(t *testing.T) {
	e := newEnv(t, func(s *memory.Store) mint.Tickets { return brokenTickets{s.Tickets()} })
	w := e.redeem("/auth/mint/mint?t=the-nonce", nil)
	if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "mint_ticket_stale") {
		t.Errorf("%d %s, want 503 and not a dead link", w.Code, w.Body)
	}
	if sessionCookieOf(w) != nil {
		t.Error("a session was created anyway")
	}
}

// The most important test of this package: a minted session has nothing to revalidate, and reaching the
// method's Revalidate would end it on the spot. Both halves of reaching the refresh are set up — a cookie
// inside the window, and a record not confirmed for an hour.
func TestAMintedSessionIsNeverRevalidated(t *testing.T) {
	e := newEnv(t, nil)
	_, sid := e.mintOne(t, 24*time.Hour)
	e.age(t, sid, time.Hour)
	rec, err := e.store.Get(context.Background(), sid)
	if err != nil {
		t.Fatal(err)
	}
	got := e.ask(e.cookieAt(t, sid, 5*time.Minute, rec.Deadline))
	if got.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", got.Code, got.Body)
	}
	after, err := e.store.Get(context.Background(), sid)
	if err != nil {
		t.Fatalf("the record is gone: %v", err)
	}
	if after.Version != rec.Version {
		t.Error("the record of a minted session was written back")
	}
}

// The deadline is decided from the cookie on every request, before anything reads the store.
func TestAMintedSessionEndsAtItsDeadline(t *testing.T) {
	e := newEnv(t, nil)
	_, sid := e.mintOne(t, time.Hour)
	w := e.ask(e.cookieAt(t, sid, time.Hour, time.Now().Add(-time.Minute)))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
	cleared := false
	for _, c := range w.Result().Cookies() {
		cleared = cleared || (c.Name == "auth_session" && c.MaxAge < 0)
	}
	if !cleared {
		t.Error("the browser was left holding the cookie of a session that has ended")
	}
}

// Deleting the record — a host command revoking the session — ends it on its next request, on either
// side of the refresh window.
func TestADeletedRecordEndsAMintedSession(t *testing.T) {
	e := newEnv(t, nil)
	_, sid := e.mintOne(t, 24*time.Hour)
	rec, err := e.store.Get(context.Background(), sid)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.store.Delete(context.Background(), sid); err != nil {
		t.Fatal(err)
	}
	if got := e.ask(e.cookieAt(t, sid, time.Hour, rec.Deadline)); got.Code != http.StatusUnauthorized {
		t.Errorf("status outside the refresh window = %d, want 401", got.Code)
	}
	if got := e.ask(e.cookieAt(t, sid, 5*time.Minute, rec.Deadline)); got.Code != http.StatusUnauthorized {
		t.Errorf("status inside the refresh window = %d, want 401", got.Code)
	}
}

// MaxAge follows the deadline: at a day, a week-long session would lose its cookie after a day idle, and
// a two-hour one would keep it a day after it stopped being worth anything.
func TestAMintedCookieExpiresWithItsSession(t *testing.T) {
	e := newEnv(t, nil)
	session, _ := e.mintOne(t, 3*time.Hour)
	want := int((3 * time.Hour).Seconds())
	// A second of slack, since MaxAge is computed from the moment the cookie was signed.
	if session.MaxAge < want-1 || session.MaxAge > want {
		t.Errorf("MaxAge = %d, want %d", session.MaxAge, want)
	}
}

// Redeeming ends the session the browser was already holding, as a sign-in does.
func TestRedeemingATicketEndsTheSessionItReplaces(t *testing.T) {
	e := newEnv(t, nil)
	held, oldSID := e.mintOne(t, time.Hour)
	w := e.redeem(e.issue(t, time.Hour), held)
	if w.Code != http.StatusFound {
		t.Fatalf("the redemption gave status = %d, body = %s", w.Code, w.Body)
	}
	if _, err := e.store.Get(context.Background(), oldSID); !errors.Is(err, auth.ErrNotFound) {
		t.Errorf("the replaced record is still there: %v", err)
	}
	if got := e.ask(held); got.Code != http.StatusUnauthorized {
		t.Errorf("the replaced cookie gave status = %d, want 401", got.Code)
	}
}

// Until it is spent, the nonce is a credential: it is in no log line, whatever happens to it.
func TestTheNonceIsInNoLogLine(t *testing.T) {
	e := newEnv(t, nil)
	path := e.issue(t, time.Hour)
	nonce := path[strings.Index(path, "t=")+2:]
	e.redeem(path, nil)
	e.redeem(path, nil)
	e.allow()
	e.redeem(e.issue(t, time.Hour), nil)
	if strings.Contains(e.logs.String(), nonce) {
		t.Errorf("the log carries the nonce: %s", e.logs)
	}
	if !strings.Contains(e.logs.String(), "already spent") {
		t.Errorf("the spent link left no trace: %s", e.logs)
	}
}

func TestNewAndMethod(t *testing.T) {
	e := newEnv(t, nil)
	if e.mt.Name() != "mint" || e.mt.LoginURL("/x") != "" {
		t.Errorf("Name = %q, LoginURL = %q", e.mt.Name(), e.mt.LoginURL("/x"))
	}
	if _, err := e.mt.Revalidate(context.Background(), auth.Record{}); !errors.Is(err, auth.ErrEnded) {
		t.Errorf("Revalidate = %v, want ErrEnded", err)
	}
	if _, err := mint.New(e.m, mint.Options{Name: "other"}); err == nil {
		t.Error("New accepted no Tickets")
	}
	if _, err := mint.New(e.m, mint.Options{Name: "Bad", Tickets: e.store.Tickets()}); err == nil {
		t.Error("New accepted a malformed name")
	}
	if _, err := mint.New(e.m, mint.Options{Tickets: e.store.Tickets()}); err == nil {
		t.Error("a second method named mint was registered")
	}
	ops, err := mint.New(e.m, mint.Options{Name: "ops", Tickets: e.store.Tickets()})
	if err != nil {
		t.Fatal(err)
	}
	path, err := ops.Issue(context.Background(), "agent", time.Hour)
	if err != nil || !strings.HasPrefix(path, "/auth/mint/ops?t=") {
		t.Errorf("a second mint method issued %q (%v)", path, err)
	}
}
