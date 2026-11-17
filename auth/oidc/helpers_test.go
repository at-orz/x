package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
	"github.com/at-orz/x/auth/store/memory"
)

// fakeIdP is a provider that lies as a test needs: a discovery and a token endpoint, where every claim
// of an ID token and every answer to a refresh can be turned wrong on its own.
type fakeIdP struct {
	srv *httptest.Server

	mu     sync.Mutex
	nonce  string
	sub    string
	aud    any
	issuer string
	exp    time.Time
	extra  map[string]any
	omitID bool
	// omitRefresh drops the refresh_token from the answer to the authorization code, which is what a
	// provider without the offline_access scope mapping does.
	omitRefresh bool
	// refuseRefresh and unreachableRefresh are the two endings of a refresh that have to stay apart: a
	// decision of the provider about this token, and the provider not answering the question at all.
	refuseRefresh      bool
	unreachableRefresh bool
	// challenge is the code_challenge of the authorization request the code is for. When set, the code is
	// redeemed only with its verifier; sentVerifier is what the last exchange carried.
	challenge    string
	sentVerifier []string
	// refreshSub is the sub inside the ID token of a refresh answer, empty for the sub of the login.
	refreshSub string
	// omitRefreshIDToken leaves the ID token out of a refresh answer, which is legal and normal.
	omitRefreshIDToken bool
	// authMethods is token_endpoint_auth_methods_supported; clientAuth is how the last token request
	// authenticated ("basic" or "post") and with what.
	authMethods []string
	clientAuth  string
	clientID    string
	secret      string

	refreshes int
	// handedOut is every refresh token this provider issued, in order, so that rotation is visible.
	handedOut []string
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	f := &fakeIdP{sub: "alice", exp: time.Now().Add(time.Hour), authMethods: []string{"client_secret_basic"}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		writeJSON(w, map[string]any{
			"issuer":                                f.srv.URL,
			"authorization_endpoint":                f.srv.URL + "/authorize",
			"token_endpoint":                        f.srv.URL + "/token",
			"token_endpoint_auth_methods_supported": f.authMethods,
		})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		defer f.mu.Unlock()
		if id, secret, ok := r.BasicAuth(); ok {
			f.clientAuth = "basic"
			f.clientID, _ = url.QueryUnescape(id)
			f.secret, _ = url.QueryUnescape(secret)
		} else {
			f.clientAuth, f.clientID, f.secret = "post", r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
		}
		if r.Form.Get("grant_type") == "refresh_token" {
			f.serveRefresh(w)
			return
		}
		f.sentVerifier = r.Form["code_verifier"]
		if f.challenge != "" {
			sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if base64.RawURLEncoding.EncodeToString(sum[:]) != f.challenge {
				w.WriteHeader(http.StatusBadRequest)
				writeJSON(w, map[string]any{"error": "invalid_grant", "error_description": "PKCE verification failed"})
				return
			}
		}
		if f.omitID {
			writeJSON(w, map[string]any{"access_token": "x"})
			return
		}
		body := map[string]any{"id_token": f.idToken(f.sub)}
		if !f.omitRefresh {
			body["refresh_token"] = f.mint()
		}
		writeJSON(w, body)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIdP) serveRefresh(w http.ResponseWriter) {
	f.refreshes++
	switch {
	case f.refuseRefresh:
		// The shape a provider answers with for a token that is no longer good: a 400 carrying
		// invalid_grant, which is the one answer that ends a session.
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]any{"error": "invalid_grant", "error_description": "token is not valid"})
		return
	case f.unreachableRefresh:
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	body := map[string]any{"refresh_token": f.mint()}
	if !f.omitRefreshIDToken {
		sub := f.refreshSub
		if sub == "" {
			sub = f.sub
		}
		body["id_token"] = f.idToken(sub)
	}
	writeJSON(w, body)
}

// mint hands out the next refresh token. Rotation is modelled because providers rotate: the previous
// token stops working the moment a new one is issued.
func (f *fakeIdP) mint() string {
	tok := fmt.Sprintf("refresh-%d", len(f.handedOut)+1)
	f.handedOut = append(f.handedOut, tok)
	return tok
}

func (f *fakeIdP) set(change func(f *fakeIdP)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change(f)
}

func (f *fakeIdP) latestToken() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.handedOut) == 0 {
		return ""
	}
	return f.handedOut[len(f.handedOut)-1]
}

func (f *fakeIdP) refreshCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.refreshes
}

func (f *fakeIdP) idToken(sub string) string {
	aud := f.aud
	if aud == nil {
		aud = "test-client"
	}
	iss := f.issuer
	if iss == "" {
		iss = f.srv.URL
	}
	claims := map[string]any{"iss": iss, "sub": sub, "aud": aud, "exp": f.exp.Unix(), "nonce": f.nonce}
	for k, v := range f.extra {
		claims[k] = v
	}
	return jwt(claims)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// jwt builds a JWT whose signature is garbage, which is an assertion in itself: this package validates by
// TLS instead of by signature under OIDC Core §3.1.3.7(6), so a garbage signature must not stop the flow.
func jwt(claims map[string]any) string {
	body, _ := json.Marshal(claims)
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"RS256"}`)) + "." + enc(body) + "." + enc([]byte("not-a-signature"))
}

// countingStore is a memory.Store that counts reads and can be broken, which is how a test shows that a
// request settled something without reaching the store, and what an unreachable store does.
type countingStore struct {
	*memory.Store

	mu     sync.Mutex
	gets   int
	broken error
	sids   []string
}

func (s *countingStore) Put(ctx context.Context, sid string, rec auth.Record, ttl time.Duration) error {
	s.mu.Lock()
	broken := s.broken
	s.sids = append(s.sids, sid)
	s.mu.Unlock()
	if broken != nil {
		return broken
	}
	return s.Store.Put(ctx, sid, rec, ttl)
}

func (s *countingStore) Get(ctx context.Context, sid string) (auth.Record, error) {
	s.mu.Lock()
	s.gets++
	broken := s.broken
	s.mu.Unlock()
	if broken != nil {
		return auth.Record{}, broken
	}
	return s.Store.Get(ctx, sid)
}

func (s *countingStore) getCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gets
}

// live is every session record that exists, by id.
func (s *countingStore) live() map[string]auth.Record {
	s.mu.Lock()
	sids := slices.Clone(s.sids)
	s.mu.Unlock()
	out := map[string]auth.Record{}
	for _, sid := range sids {
		if rec, err := s.Store.Get(context.Background(), sid); err == nil {
			out[sid] = rec
		}
	}
	return out
}

func (s *countingStore) count() int { return len(s.live()) }

func (s *countingStore) only(t *testing.T) (string, auth.Record) {
	t.Helper()
	live := s.live()
	if len(live) != 1 {
		t.Fatalf("there are %d session records, expected exactly one", len(live))
	}
	for sid, rec := range live {
		return sid, rec
	}
	return "", auth.Record{}
}

// age moves the last verification of a session back: a revalidation only happens for a session the
// provider has not confirmed for a while, so a record written a moment ago has to be aged first.
func (s *countingStore) age(t *testing.T, sid string, by time.Duration) {
	t.Helper()
	ctx := context.Background()
	rec, err := s.Store.Get(ctx, sid)
	if err != nil {
		t.Fatal(err)
	}
	rec.VerifiedAt = rec.VerifiedAt.Add(-by)
	if err := s.Store.Touch(ctx, sid, rec); err != nil {
		t.Fatal(err)
	}
}

// logBuf collects what was logged. The refresh tests drive several requests at once.
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

var testKey = []byte("0123456789abcdef0123456789abcdef")

// env is a Manager on a countingStore with one Provider "corp" at a fake IdP, admitting alice.
type env struct {
	m     *auth.Manager
	p     *Provider
	store *countingStore
	mux   *http.ServeMux
	logs  *logBuf

	mu      sync.Mutex
	allowed []string
}

func newEnv(t *testing.T, issuer string, opts ...func(*auth.Options, *Options)) *env {
	t.Helper()
	e := &env{store: &countingStore{Store: memory.New()}, mux: http.NewServeMux(), logs: &logBuf{},
		allowed: []string{"alice"}}
	ao := auth.Options{
		Store: e.store,
		Key:   testKey,
		Authorize: func(_ context.Context, id auth.Identity) error {
			e.mu.Lock()
			defer e.mu.Unlock()
			if !slices.Contains(e.allowed, id.Subject) {
				return fmt.Errorf("%w: subject %q is not on the allow list", auth.ErrNotAllowed, id.Subject)
			}
			return nil
		},
		Log: slog.New(slog.NewTextHandler(e.logs, nil)),
	}
	cfg := Config{Issuer: issuer, ClientID: "test-client", ClientSecret: "test-client-secret"}
	po := Options{Name: "corp", Config: func() (Config, bool) { return cfg, true }}
	for _, f := range opts {
		f(&ao, &po)
	}
	m, err := auth.New(ao)
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(m, po)
	if err != nil {
		t.Fatal(err)
	}
	m.Routes(e.mux)
	p.Routes(e.mux)
	e.m, e.p = m, p
	return e
}

func (e *env) allow(subjects ...string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.allowed = subjects
}

// authorize walks through the login of p and returns the authorization request and the flow cookie.
func authorize(t *testing.T, h http.Handler, p *Provider, query url.Values) (url.Values, *http.Cookie) {
	t.Helper()
	target := p.loginPath
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, nil))
	if w.Code != http.StatusFound {
		t.Fatalf("login status = %d, body = %s", w.Code, w.Body)
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	q := loc.Query()
	for _, want := range []string{"state", "nonce", "client_id", "redirect_uri"} {
		if q.Get(want) == "" {
			t.Errorf("the authorization request is missing %s: %s", want, loc)
		}
	}
	if q.Get("response_type") != "code" {
		t.Errorf("the shape of the authorization request is wrong: %s", loc.RawQuery)
	}
	if !strings.HasPrefix(q.Get("scope"), "openid offline_access") {
		t.Errorf("scope = %q, want openid offline_access first", q.Get("scope"))
	}
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		t.Errorf("the authorization request carries no S256 code_challenge: %s", loc.RawQuery)
	}
	if q.Has("code_verifier") {
		t.Errorf("the verifier left in the authorization request: %s", loc.RawQuery)
	}
	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == p.flowCookie {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("no flow cookie was set")
	}
	if !cookie.HttpOnly {
		t.Error("the flow cookie is not HttpOnly")
	}
	return q, cookie
}

// login is authorize returning the state and nonce the provider would see.
func (e *env) login(t *testing.T, ret string) (state, nonce string, cookie *http.Cookie) {
	t.Helper()
	q := url.Values{}
	if ret != "" {
		q.Set("ret", ret)
	}
	return e.loginWith(t, q)
}

func (e *env) loginWith(t *testing.T, query url.Values) (state, nonce string, cookie *http.Cookie) {
	t.Helper()
	q, cookie := authorize(t, e.mux, e.p, query)
	return q.Get("state"), q.Get("nonce"), cookie
}

func (e *env) callback(t *testing.T, state string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	return callbackAt(t, e.mux, e.p, state, cookies...)
}

func callbackAt(t *testing.T, h http.Handler, p *Provider, state string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, p.callback+"?code=the-code&state="+url.QueryEscape(state), nil)
	for _, c := range cookies {
		if c != nil {
			r.AddCookie(c)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// signIn runs a whole login and returns the session cookie the browser would hold.
func (e *env) signIn(t *testing.T, f *fakeIdP) *http.Cookie {
	t.Helper()
	state, nonce, flow := e.login(t, "")
	f.set(func(f *fakeIdP) { f.nonce = nonce })
	cb := e.callback(t, state, flow)
	session := sessionCookieOf(cb)
	if session == nil {
		t.Fatalf("no session cookie was received: %d %s", cb.Code, cb.Body)
	}
	return session
}

func sessionCookieOf(w *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == "auth_session" && c.Value != "" {
			return c
		}
	}
	return nil
}

func cookieCleared(w *httptest.ResponseRecorder) bool {
	for _, c := range w.Result().Cookies() {
		if c.Name == "auth_session" && c.Value == "" && c.MaxAge < 0 {
			return true
		}
	}
	return false
}

// cookieAt signs a session cookie whose exp is a chosen distance away, which is how a test reaches the
// refresh window without waiting most of an hour for it. It is the wire format of api.md, spelled out.
func (e *env) cookieAt(t *testing.T, sid string, until time.Duration) *http.Cookie {
	t.Helper()
	value, err := e.m.Seal(map[string]any{"sid": sid, "exp": time.Now().Add(until).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: "auth_session", Value: value}
}

// ask sends one request through Require and reports what happened to it.
func (e *env) ask(t *testing.T, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
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

func (e *env) sessionOf(t *testing.T, cookie *http.Cookie) auth.Session {
	t.Helper()
	var got auth.Session
	protected := e.m.Require(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, _ = auth.SessionFrom(r.Context())
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
