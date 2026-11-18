package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

// fakeStore is the session records in a map, which lets the whole request path run without a real store.
// It does compare-and-swap on Version like a shared store, and counts calls, which is how a test shows
// that a request settled something without reaching the store at all.
type fakeStore struct {
	mu      sync.Mutex
	recs    map[string]Record
	ttls    map[string]time.Duration
	version int64
	// broken stands for a store that cannot be reached, which is a third answer next to "the record is
	// there" and "it is gone".
	broken error
	// conflicts makes that many coming Touch calls lose to a concurrent write.
	conflicts int

	gets, touches int
}

func newFakeStore() *fakeStore {
	return &fakeStore{recs: map[string]Record{}, ttls: map[string]time.Duration{}}
}

func (s *fakeStore) Put(_ context.Context, sid string, rec Record, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.broken != nil {
		return s.broken
	}
	s.version++
	rec.Version = s.version
	s.recs[sid] = rec
	s.ttls[sid] = ttl
	return nil
}

func (s *fakeStore) Get(_ context.Context, sid string) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gets++
	if s.broken != nil {
		return Record{}, s.broken
	}
	rec, ok := s.recs[sid]
	if !ok {
		return Record{}, fmt.Errorf("session %q: %w", sid, ErrNotFound)
	}
	return rec, nil
}

func (s *fakeStore) Touch(_ context.Context, sid string, rec Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.touches++
	if s.broken != nil {
		return s.broken
	}
	cur, ok := s.recs[sid]
	if !ok {
		return fmt.Errorf("session %q: %w", sid, ErrNotFound)
	}
	if s.conflicts > 0 {
		s.conflicts--
		s.version++
		cur.Version = s.version
		s.recs[sid] = cur
		return ErrConflict
	}
	if cur.Version != rec.Version {
		return ErrConflict
	}
	s.version++
	rec.Version = s.version
	s.recs[sid] = rec
	return nil
}

func (s *fakeStore) Delete(_ context.Context, sid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.broken != nil {
		return s.broken
	}
	delete(s.recs, sid)
	return nil
}

func (s *fakeStore) setBroken(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.broken = err
}

func (s *fakeStore) only(t *testing.T) (string, Record) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.recs) != 1 {
		t.Fatalf("there are %d session records, expected exactly one", len(s.recs))
	}
	for sid, rec := range s.recs {
		return sid, rec
	}
	return "", Record{}
}

func (s *fakeStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.recs)
}

func (s *fakeStore) getCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gets
}

// edit rewrites a record in place, as another instance would, and moves its version.
func (s *fakeStore) edit(t *testing.T, sid string, f func(*Record)) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.recs[sid]
	if !ok {
		t.Fatalf("no record %q", sid)
	}
	f(&rec)
	s.version++
	rec.Version = s.version
	s.recs[sid] = rec
}

// claimingStore is a fakeStore shared by several instances: it implements Claimer.
type claimingStore struct {
	*fakeStore
	// claimTaken makes Claim report a lost race, which is what a shared store does when another instance
	// took the claim in the same moment.
	claimTaken bool
}

func (s *claimingStore) Claim(_ context.Context, sid string, rec Record) (Record, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.broken != nil {
		return Record{}, false, s.broken
	}
	cur, ok := s.recs[sid]
	if !ok {
		return Record{}, false, fmt.Errorf("session %q: %w", sid, ErrNotFound)
	}
	if s.claimTaken || cur.Version != rec.Version {
		return Record{}, false, nil
	}
	rec.RefreshingAt = time.Now()
	s.version++
	rec.Version = s.version
	s.recs[sid] = rec
	return rec, true, nil
}

// fakeMethod is a sign-in method whose authority answers as a test scripts it. By default it rotates a
// token in State on every revalidation, as an authority that rotates refresh tokens does.
type fakeMethod struct {
	name  string
	login string

	mu    sync.Mutex
	calls int
	// answer replaces the default revalidation when set.
	answer func(rec Record) (Record, error)
}

func (f *fakeMethod) Name() string { return f.name }

func (f *fakeMethod) LoginURL(ret string) string {
	if f.login == "" {
		return ""
	}
	return f.login + "?ret=" + ret
}

func (f *fakeMethod) Revalidate(_ context.Context, rec Record) (Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.answer != nil {
		return f.answer(rec)
	}
	rec.State = json.RawMessage(fmt.Sprintf(`{"token":"t%d"}`, f.calls))
	return rec, nil
}

func (f *fakeMethod) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeMethod) setAnswer(a func(rec Record) (Record, error)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answer = a
}

// logBuf collects what a Manager logged. The mutex is not decoration: several tests drive requests at
// once, and each of them may write a line.
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

// harness is a Manager on a fakeStore with one interactive fakeMethod "corp", admitting the subjects in
// allowed.
type harness struct {
	m      *Manager
	store  *fakeStore
	method *fakeMethod
	logs   *logBuf

	mu      sync.Mutex
	allowed []string
}

func newHarness(t *testing.T, opts ...func(*Options)) *harness {
	t.Helper()
	return newHarnessOn(t, newFakeStore(), nil, opts...)
}

// newHarnessOn builds the harness on a given store; st, when set, is what the Manager sees instead of
// the bare fakeStore (a claimingStore around it, say).
func newHarnessOn(t *testing.T, fs *fakeStore, st Store, opts ...func(*Options)) *harness {
	t.Helper()
	if st == nil {
		st = fs
	}
	h := &harness{store: fs, logs: &logBuf{}, allowed: []string{"alice"},
		method: &fakeMethod{name: "corp", login: "/login/corp"}}
	o := Options{
		Store: st,
		Key:   testKey,
		Authorize: AllowSubjects("corp", func() []string {
			h.mu.Lock()
			defer h.mu.Unlock()
			return slices.Clone(h.allowed)
		}),
		Log: slog.New(slog.NewTextHandler(h.logs, nil)),
	}
	for _, f := range opts {
		f(&o)
	}
	m, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Register(h.method); err != nil {
		t.Fatal(err)
	}
	h.m = m
	return h
}

func (h *harness) allow(subjects ...string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.allowed = subjects
}

// issue hands a grant to Issue the way a method's handler would, optionally from a browser already
// holding a session cookie.
func (h *harness) issue(g Grant, held *http.Cookie) (*httptest.ResponseRecorder, error) {
	r := httptest.NewRequest(http.MethodGet, "/signed-in", nil)
	if held != nil {
		r.AddCookie(held)
	}
	w := httptest.NewRecorder()
	return w, h.m.Issue(w, r, g)
}

// signIn issues a session for alice at corp and returns its cookie and id.
func (h *harness) signIn(t *testing.T) (*http.Cookie, string) {
	t.Helper()
	return h.signInAs(t, Grant{
		Identity: Identity{Provider: "corp", Subject: "alice", Claims: map[string]any{"groups": []any{"admins"}}},
		State:    json.RawMessage(`{"token":"t0"}`),
	})
}

func (h *harness) signInAs(t *testing.T, g Grant) (*http.Cookie, string) {
	t.Helper()
	w, err := h.issue(g, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := sessionCookieOf(h.m, w)
	if c == nil {
		t.Fatal("Issue set no session cookie")
	}
	var s sessionState
	if err := h.m.Open(c.Value, &s); err != nil {
		t.Fatal(err)
	}
	return c, s.SID
}

// ask sends one request through Require, asking for JSON, and reports what happened to it. The body of a
// 200 is the subject the handler saw.
func (h *harness) ask(t *testing.T, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/things", nil)
	r.Header.Set("Accept", "application/json")
	return h.serve(r, cookie)
}

func (h *harness) serve(r *http.Request, cookie *http.Cookie) *httptest.ResponseRecorder {
	protected := h.m.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, _ := SessionFrom(r.Context())
		_, _ = io.WriteString(w, sess.Identity.Subject)
	}))
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	protected.ServeHTTP(w, r)
	return w
}

// optional sends one request through Optional and reports the response and the session the handler saw,
// ok false when it saw none. The handler always answers 200, so any other status is Optional's own.
func (h *harness) optional(r *http.Request, cookie *http.Cookie) (*httptest.ResponseRecorder, Session, bool) {
	var (
		got Session
		ok  bool
	)
	public := h.m.Optional(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, ok = SessionFrom(r.Context())
	}))
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	public.ServeHTTP(w, r)
	return w, got, ok
}

// sessionOfRequest runs one request and returns the Session the handler saw.
func (h *harness) sessionOfRequest(t *testing.T, cookie *http.Cookie) Session {
	t.Helper()
	var got Session
	protected := h.m.Require(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, _ = SessionFrom(r.Context())
	}))
	r := httptest.NewRequest(http.MethodGet, "/api/things", nil)
	r.Header.Set("Accept", "application/json")
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	protected.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body)
	}
	return got
}

// cookieAt signs a session cookie whose exp is a chosen distance away, which is how a test reaches the
// refresh window without waiting most of an hour for it.
func (h *harness) cookieAt(t *testing.T, sid string, until time.Duration) *http.Cookie {
	t.Helper()
	return h.cookieWith(t, sessionState{SID: sid, Exp: time.Now().Add(until).Unix()})
}

func (h *harness) cookieWith(t *testing.T, s sessionState) *http.Cookie {
	t.Helper()
	value, err := h.m.Seal(s)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: h.m.sessionCookie, Value: value}
}

// age moves the last verification of a session back, which is the other half of reaching a revalidation:
// it only happens for a session the authority has not confirmed for a while.
func (h *harness) age(t *testing.T, sid string, by time.Duration) {
	t.Helper()
	h.store.edit(t, sid, func(r *Record) { r.VerifiedAt = r.VerifiedAt.Add(-by) })
}

// synced applies a Loaded holding ids, which is the state a Manager fed by a healthy feed is in.
func (h *harness) synced(ids ...string) {
	h.m.live.apply(Event{Kind: Loaded, IDs: ids})
}

func sessionCookieOf(m *Manager, w *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == m.sessionCookie && c.Value != "" {
			return c
		}
	}
	return nil
}

// cookieCleared says whether the response tells the browser to drop the session cookie.
func cookieCleared(m *Manager, w *httptest.ResponseRecorder) bool {
	for _, c := range w.Result().Cookies() {
		if c.Name == m.sessionCookie && c.Value == "" && c.MaxAge < 0 {
			return true
		}
	}
	return false
}

var errUnreachableStore = errors.New("store: no endpoints available")
