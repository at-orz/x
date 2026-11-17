package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/at-orz/x/auth"
)

func TestCallbackHappyPath(t *testing.T) {
	f := newFakeIdP(t)
	e := newEnv(t, f.srv.URL)
	state, nonce, cookie := e.login(t, "/app/t1")
	f.set(func(f *fakeIdP) { f.nonce, f.extra = nonce, map[string]any{"groups": []string{"admins"}} })

	w := e.callback(t, state, cookie)
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body)
	}
	if got := w.Header().Get("Location"); got != "/app/t1" {
		t.Errorf("the callback redirected to %q, want the address from before the login", got)
	}
	session := sessionCookieOf(w)
	if session == nil {
		t.Fatal("no session cookie was set")
	}
	if !session.HttpOnly || session.SameSite != http.SameSiteLaxMode {
		t.Errorf("the attributes of the session cookie are wrong: %+v", session)
	}
	// The cookie has to outlive its own exp by a long way: the exp is when this process goes back to the
	// provider, while the cookie has to survive as long as a session may sit idle.
	if want := int((24 * time.Hour).Seconds()); session.MaxAge != want {
		t.Errorf("the session cookie has MaxAge %d, want %d", session.MaxAge, want)
	}
	if !cleared(w, e.p.flowCookie) {
		t.Error("the flow cookie was not cleared")
	}

	_, rec := e.store.only(t)
	if rec.Provider != "corp" || rec.Subject != "alice" {
		t.Errorf("the session record is for %q/%q", rec.Provider, rec.Subject)
	}
	var st refreshState
	if err := json.Unmarshal(rec.State, &st); err != nil || st.RefreshToken != f.latestToken() {
		t.Errorf("the record holds state %s, the provider issued %q", rec.State, f.latestToken())
	}
	if strings.Contains(session.Value, f.latestToken()) {
		t.Error("the refresh token is in the cookie, it belongs on the server side alone")
	}
	s := e.sessionOf(t, session)
	if g, _ := s.Identity.Claims["groups"].([]any); len(g) != 1 || g[0] != "admins" {
		t.Errorf("the claims of the ID token did not reach the session: %v", s.Identity.Claims)
	}
	if s.Identity.Claims["iss"] != f.srv.URL {
		t.Errorf("the session claims lack iss: %v", s.Identity.Claims)
	}
}

func TestScopesAreAppended(t *testing.T) {
	f := newFakeIdP(t)
	e := newEnv(t, f.srv.URL, func(_ *auth.Options, o *Options) { o.Scopes = []string{"profile", "groups"} })
	q, _ := authorize(t, e.mux, e.p, nil)
	if got := q.Get("scope"); got != "openid offline_access profile groups" {
		t.Errorf("scope = %q", got)
	}
}

func TestTheCodeIsRedeemedWithTheVerifierOfItsLogin(t *testing.T) {
	f := newFakeIdP(t)
	e := newEnv(t, f.srv.URL)
	q, cookie := authorize(t, e.mux, e.p, nil)
	f.set(func(f *fakeIdP) { f.nonce, f.challenge = q.Get("nonce"), q.Get("code_challenge") })
	if w := e.callback(t, q.Get("state"), cookie); w.Code != http.StatusFound || sessionCookieOf(w) == nil {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body)
	}
	if len(f.sentVerifier) != 1 || len(f.sentVerifier[0]) != 43 {
		t.Errorf("the exchange carried code_verifier %q, want one of 43 characters", f.sentVerifier)
	}
}

// A code issued for another login's challenge is what an intercepted code looks like on its way in.
func TestACodeForAnotherChallengeIsRefused(t *testing.T) {
	f := newFakeIdP(t)
	e := newEnv(t, f.srv.URL)
	mine, cookie := authorize(t, e.mux, e.p, nil)
	theirs, _ := authorize(t, e.mux, e.p, nil)
	if mine.Get("code_challenge") == theirs.Get("code_challenge") {
		t.Fatal("two logins share a code_challenge")
	}
	f.set(func(f *fakeIdP) { f.nonce, f.challenge = mine.Get("nonce"), theirs.Get("code_challenge") })
	w := e.callback(t, mine.Get("state"), cookie)
	if w.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502 (body = %s)", w.Code, w.Body)
	}
	if e.store.count() != 0 || sessionCookieOf(w) != nil {
		t.Error("a code bound to another verifier produced a session")
	}
}

func TestCallbackRejections(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		break_ func(f *fakeIdP)
	}{
		// A replay: the state of one login against the cookie of another.
		{"the nonce does not match", http.StatusBadRequest, func(f *fakeIdP) { f.nonce = "some-other-nonce" }},
		{"a subject the policy refuses", http.StatusForbidden, func(f *fakeIdP) { f.sub = "mallory" }},
		{"an expired id_token", http.StatusBadRequest, func(f *fakeIdP) { f.exp = time.Now().Add(-time.Minute) }},
		{"the aud is not us", http.StatusBadRequest, func(f *fakeIdP) { f.aud = "some-other-client" }},
		// Discovery already cached the real issuer and only the one inside the ID token is changed here.
		{"the iss is not the issuer", http.StatusBadRequest, func(f *fakeIdP) { f.issuer = "https://evil.example" }},
		{"no sub", http.StatusBadRequest, func(f *fakeIdP) { f.sub = "" }},
		{"the token endpoint returns no id_token", http.StatusBadGateway, func(f *fakeIdP) { f.omitID = true }},
		// A provider without the offline_access scope mapping. Accepting the login would build a session that
		// cannot be extended and ends within the hour for no reason the person could act on.
		{"the token endpoint returns no refresh token", http.StatusBadGateway, func(f *fakeIdP) { f.omitRefresh = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeIdP(t)
			e := newEnv(t, f.srv.URL)
			state, nonce, cookie := e.login(t, "")
			f.set(func(f *fakeIdP) {
				f.nonce = nonce
				tc.break_(f)
			})
			w := e.callback(t, state, cookie)
			if w.Code != tc.status {
				t.Fatalf("status = %d, want %d (body = %s)", w.Code, tc.status, w.Body)
			}
			if e.store.count() != 0 || sessionCookieOf(w) != nil {
				t.Error("a refused login left a session behind")
			}
			if tc.name == "the token endpoint returns no refresh token" {
				if !strings.Contains(e.logs.String(), "offline_access") {
					t.Errorf("the log does not name what is missing at the provider: %s", e.logs)
				}
				if strings.Contains(w.Body.String(), "offline_access") {
					t.Errorf("the browser was handed the scope mapping the provider needs: %s", w.Body)
				}
			}
		})
	}
}

// The callback failures a second attempt actually fixes send the browser back through the login instead
// of leaving it on a 400 with no way on but the address bar.
func TestARecoverableCallbackGoesBackThroughTheLogin(t *testing.T) {
	retried := func(t *testing.T, e *env, w *httptest.ResponseRecorder, wantRet string) {
		t.Helper()
		if w.Code != http.StatusFound {
			t.Fatalf("status = %d, want 302 (body = %s)", w.Code, w.Body)
		}
		loc, err := url.Parse(w.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		if loc.Path != e.p.loginPath {
			t.Errorf("the callback redirected to %q, want the login", loc)
		}
		if loc.Query().Get("retry") == "" {
			t.Errorf("the redirect carries nothing to stop a second round: %s", loc)
		}
		if got := loc.Query().Get("ret"); got != wantRet {
			t.Errorf("the redirect carries ret %q, want %q", got, wantRet)
		}
	}

	t.Run("no flow cookie", func(t *testing.T) {
		f := newFakeIdP(t)
		e := newEnv(t, f.srv.URL)
		state, _, _ := e.login(t, "/app/t1")
		retried(t, e, e.callback(t, state), "")
	})

	t.Run("the flow cookie was tampered with", func(t *testing.T) {
		f := newFakeIdP(t)
		e := newEnv(t, f.srv.URL)
		state, _, cookie := e.login(t, "/app/t1")
		cookie.Value = strings.ToUpper(cookie.Value)
		retried(t, e, e.callback(t, state, cookie), "")
	})

	// Left on the login page for longer than flowTTL. The address from before the login survives this one:
	// the cookie was still signed by this process.
	t.Run("the flow cookie has expired", func(t *testing.T) {
		f := newFakeIdP(t)
		e := newEnv(t, f.srv.URL)
		value, err := e.m.Seal(flowState{State: "the-state", Nonce: "n", Verifier: "v", Ret: "/app/t1",
			Exp: time.Now().Add(-time.Minute).Unix()})
		if err != nil {
			t.Fatal(err)
		}
		retried(t, e, e.callback(t, "the-state", &http.Cookie{Name: e.p.flowCookie, Value: value}), "/app/t1")
	})

	// Two tabs, which is where this arises in practice: the login of the second overwrote the flow cookie of
	// the first, so the state the first comes back with belongs to a flow nothing remembers.
	t.Run("a second tab overwrote the flow cookie", func(t *testing.T) {
		f := newFakeIdP(t)
		e := newEnv(t, f.srv.URL)
		first, _, _ := e.login(t, "/app/t1")
		_, _, second := e.login(t, "/app/t2")
		retried(t, e, e.callback(t, first, second), "/app/t2")

		// And the round the browser is sent on lands, rather than failing over again.
		state, nonce, flow := e.loginWith(t, url.Values{"retry": {"1"}, "ret": {"/app/t2"}})
		f.set(func(f *fakeIdP) { f.nonce = nonce })
		w := e.callback(t, state, flow)
		if w.Code != http.StatusFound || w.Header().Get("Location") != "/app/t2" {
			t.Fatalf("the retried login did not land: %d %q", w.Code, w.Header().Get("Location"))
		}
		if e.store.count() != 1 {
			t.Errorf("the retried login left %d session records, want 1", e.store.count())
		}
	})
}

// A second failure in a row stops rather than starting another round, so a browser keeping no cookies at
// all cannot loop between the callback and the provider.
func TestASecondCallbackFailureStops(t *testing.T) {
	f := newFakeIdP(t)
	e := newEnv(t, f.srv.URL)
	state, _, _ := e.loginWith(t, url.Values{"retry": {"1"}})
	if !strings.HasSuffix(state, retryMarker) {
		t.Fatalf("the retried login did not mark its state: %q", state)
	}
	if w := e.callback(t, state); w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (body = %s)", w.Code, w.Body)
	}
}

func TestAudienceMayBeAnArray(t *testing.T) {
	f := newFakeIdP(t)
	e := newEnv(t, f.srv.URL)
	state, nonce, cookie := e.login(t, "")
	f.set(func(f *fakeIdP) { f.nonce, f.aud = nonce, []string{"someone", "test-client"} })
	if w := e.callback(t, state, cookie); w.Code != http.StatusFound {
		t.Errorf("status = %d, want 302 (body = %s)", w.Code, w.Body)
	}
}

// A provider not configured yet answers 503 rather than a 500 or a quiet pass, and says nothing about
// what to run where: whoever reaches the page is not necessarily who deploys.
func TestUnconfiguredIs503(t *testing.T) {
	e := newEnv(t, "https://idp.example", func(_ *auth.Options, o *Options) {
		o.Config = func() (Config, bool) { return Config{}, false }
	})
	for _, path := range []string{e.p.loginPath, e.p.callback + "?state=s&code=c"} {
		w := httptest.NewRecorder()
		e.mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "oidc_unconfigured") {
			t.Errorf("%s: %d %s, want 503 oidc_unconfigured", path, w.Code, w.Body)
		}
	}
}

// What a browser is told when a login fails names nothing from inside this process: not the issuer, not
// what the token endpoint answered, not the account. Both halves are asserted, since a message that says
// nothing and a log that says nothing with it would leave the failure unaccounted for anywhere.
func TestAFailureTellsTheLogAndNotTheBrowser(t *testing.T) {
	t.Run("the provider cannot be reached", func(t *testing.T) {
		down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		t.Cleanup(down.Close)
		e := newEnv(t, down.URL)
		w := httptest.NewRecorder()
		e.mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, e.p.loginPath, nil))
		if w.Code != http.StatusBadGateway {
			t.Fatalf("status = %d, want 502 (body = %s)", w.Code, w.Body)
		}
		for _, secret := range []string{down.URL, "404"} {
			if strings.Contains(w.Body.String(), secret) {
				t.Errorf("the browser was told %q: %s", secret, w.Body)
			}
			if !strings.Contains(e.logs.String(), secret) {
				t.Errorf("the log does not carry %q: %s", secret, e.logs)
			}
		}
	})

	t.Run("an account the policy refuses", func(t *testing.T) {
		f := newFakeIdP(t)
		e := newEnv(t, f.srv.URL)
		state, nonce, cookie := e.login(t, "")
		f.set(func(f *fakeIdP) { f.nonce, f.sub = nonce, "mallory" })
		w := e.callback(t, state, cookie)
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "subject_not_allowed") {
			t.Fatalf("%d %s, want 403 subject_not_allowed", w.Code, w.Body)
		}
		for _, secret := range []string{"mallory", "allow list"} {
			if strings.Contains(w.Body.String(), secret) {
				t.Errorf("the browser was told %q: %s", secret, w.Body)
			}
		}
		if !strings.Contains(e.logs.String(), "mallory") {
			t.Errorf("the log does not name the account that was refused: %s", e.logs)
		}
	})

	t.Run("the provider refused the authorization", func(t *testing.T) {
		f := newFakeIdP(t)
		e := newEnv(t, f.srv.URL)
		state, _, cookie := e.login(t, "")
		r := httptest.NewRequest(http.MethodGet, e.p.callback+"?error=access_denied&state="+url.QueryEscape(state), nil)
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		e.mux.ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body = %s)", w.Code, w.Body)
		}
		if strings.Contains(w.Body.String(), "access_denied") {
			t.Errorf("the browser was handed the answer of the provider: %s", w.Body)
		}
		if !strings.Contains(e.logs.String(), "access_denied") {
			t.Errorf("the log does not carry what the provider answered: %s", e.logs)
		}
	})
}

// redirect_uri is derived from the request, so moving behind a reverse proxy terminating TLS changes no
// configuration.
func TestRedirectURIFollowsTheRequest(t *testing.T) {
	e := newEnv(t, "https://idp.example")
	r := httptest.NewRequest(http.MethodGet, e.p.loginPath, nil)
	r.Host = "192.0.2.10:8080"
	if got := e.p.redirectURI(r); got != "http://192.0.2.10:8080/auth/oidc/corp/callback" {
		t.Errorf("redirectURI = %q", got)
	}
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Host = "app.example.com"
	if got := e.p.redirectURI(r); got != "https://app.example.com/auth/oidc/corp/callback" {
		t.Errorf("redirectURI behind a proxy = %q", got)
	}
}

// Half an hour before the cookie runs out the refresh token goes to the provider: rotated, recorded, and
// the claims of the new ID token replace the old.
func TestRevalidationExchangesTheRefreshToken(t *testing.T) {
	f := newFakeIdP(t)
	e := newEnv(t, f.srv.URL)
	f.set(func(f *fakeIdP) { f.extra = map[string]any{"groups": []string{"admins"}} })
	e.signIn(t, f)
	sid, before := e.store.only(t)
	e.store.age(t, sid, time.Hour)
	f.set(func(f *fakeIdP) { f.extra = map[string]any{"groups": []string{"ops"}} })

	w := e.ask(t, e.cookieAt(t, sid, 10*time.Minute))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body)
	}
	if f.refreshCount() != 1 {
		t.Errorf("the provider saw %d refreshes, want 1", f.refreshCount())
	}
	_, after := e.store.only(t)
	var st refreshState
	if err := json.Unmarshal(after.State, &st); err != nil || st.RefreshToken != f.latestToken() || string(after.State) == string(before.State) {
		t.Errorf("the record holds %s, the provider issued %q", after.State, f.latestToken())
	}
	s := e.sessionOf(t, sessionCookieOf(w))
	if g, _ := s.Identity.Claims["groups"].([]any); len(g) != 1 || g[0] != "ops" {
		t.Errorf("the claims were not replaced at refresh: %v", s.Identity.Claims)
	}
}

// A cookie well inside its lifetime costs a signature check and nothing else once the feed is in sync:
// no store read, no provider.
func TestAFreshCookieTouchesNeitherStoreNorProvider(t *testing.T) {
	f := newFakeIdP(t)
	e := newEnv(t, f.srv.URL)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.m.FollowSessions(ctx, e.store.Follow(ctx))
	session := e.signIn(t, f)

	// The feed reports the sign-in's own write a moment later, which drops what was cached once; after
	// that, a request reads nothing.
	deadline := time.Now().Add(5 * time.Second)
	for {
		before := e.store.getCount()
		if got := e.ask(t, session); got.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", got.Code, got.Body)
		}
		if e.store.getCount() == before {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("every request kept reading the store")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if f.refreshCount() != 0 {
		t.Error("the provider was asked about a fresh cookie")
	}
}

// The point of the whole arrangement: the provider refusing the token ends the session.
func TestARefusalFromTheProviderEndsTheSession(t *testing.T) {
	f := newFakeIdP(t)
	e := newEnv(t, f.srv.URL)
	e.signIn(t, f)
	sid, _ := e.store.only(t)
	e.store.age(t, sid, time.Hour)
	f.set(func(f *fakeIdP) { f.refuseRefresh = true })

	w := e.ask(t, e.cookieAt(t, sid, 5*time.Minute))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body = %s)", w.Code, w.Body)
	}
	if !cookieCleared(w) {
		t.Error("the session cookie was not cleared")
	}
	if e.store.count() != 0 {
		t.Error("the refused session record is still stored")
	}
}

// An ID token about another subject would move a live session to another account, so it ends the
// session instead. OIDC Core §12.2 forbids the provider from doing it at all.
func TestARefreshMayNotChangeTheSubject(t *testing.T) {
	f := newFakeIdP(t)
	e := newEnv(t, f.srv.URL)
	e.allow("alice", "mallory")
	e.signIn(t, f)
	sid, _ := e.store.only(t)
	e.store.age(t, sid, time.Hour)
	f.set(func(f *fakeIdP) { f.refreshSub = "mallory" })

	if got := e.ask(t, e.cookieAt(t, sid, 5*time.Minute)); got.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (body = %s)", got.Code, got.Body)
	}
	if e.store.count() != 0 {
		t.Error("the session record survived an ID token about somebody else")
	}
}

// A refresh answer with no ID token is legal and normal, and rotates the token as usual; the claims stay
// as they were.
func TestARefreshWithoutAnIDTokenIsAccepted(t *testing.T) {
	f := newFakeIdP(t)
	e := newEnv(t, f.srv.URL)
	e.signIn(t, f)
	sid, before := e.store.only(t)
	e.store.age(t, sid, time.Hour)
	f.set(func(f *fakeIdP) { f.omitRefreshIDToken = true })

	if got := e.ask(t, e.cookieAt(t, sid, 5*time.Minute)); got.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body = %s)", got.Code, got.Body)
	}
	_, after := e.store.only(t)
	var st refreshState
	if err := json.Unmarshal(after.State, &st); err != nil || st.RefreshToken != f.latestToken() {
		t.Errorf("the record holds %s, the provider issued %q", after.State, f.latestToken())
	}
	if string(after.Claims) != string(before.Claims) {
		t.Errorf("the claims changed without an ID token: %s → %s", before.Claims, after.Claims)
	}
}

// A provider that cannot be asked is not an answer about the account.
func TestAnUnreachableProviderKeepsTheSession(t *testing.T) {
	f := newFakeIdP(t)
	e := newEnv(t, f.srv.URL)
	e.signIn(t, f)
	sid, _ := e.store.only(t)
	e.store.age(t, sid, time.Hour)
	f.set(func(f *fakeIdP) { f.unreachableRefresh = true })

	if w := e.ask(t, e.cookieAt(t, sid, 5*time.Minute)); w.Code != http.StatusOK {
		t.Fatalf("a provider answering 502 gave status = %d, want 200 (body = %s)", w.Code, w.Body)
	}
	if e.store.count() != 1 {
		t.Error("the record was deleted although the provider said nothing about the account")
	}
}

// A provider whose configuration went away cannot be asked either; that is not an answer about anyone.
func TestAnUnconfiguredProviderKeepsItsSessions(t *testing.T) {
	f := newFakeIdP(t)
	var mu sync.Mutex
	configured := true
	e := newEnv(t, f.srv.URL, func(_ *auth.Options, o *Options) {
		cfg := Config{Issuer: f.srv.URL, ClientID: "test-client", ClientSecret: "test-client-secret"}
		o.Config = func() (Config, bool) {
			mu.Lock()
			defer mu.Unlock()
			return cfg, configured
		}
	})
	e.signIn(t, f)
	sid, _ := e.store.only(t)
	e.store.age(t, sid, time.Hour)
	mu.Lock()
	configured = false
	mu.Unlock()
	if w := e.ask(t, e.cookieAt(t, sid, 5*time.Minute)); w.Code != http.StatusOK || e.store.count() != 1 {
		t.Errorf("status = %d with %d records, want the session kept", w.Code, e.store.count())
	}
	if f.refreshCount() != 0 {
		t.Error("an unconfigured provider was asked")
	}
}

func TestClientAuthentication(t *testing.T) {
	t.Run("basic by default, form-encoded", func(t *testing.T) {
		f := newFakeIdP(t)
		e := newEnv(t, f.srv.URL, func(_ *auth.Options, o *Options) {
			cfg := Config{Issuer: f.srv.URL, ClientID: "test-client", ClientSecret: "s3cr:t&+"}
			o.Config = func() (Config, bool) { return cfg, true }
		})
		e.signIn(t, f)
		if f.clientAuth != "basic" || f.clientID != "test-client" || f.secret != "s3cr:t&+" {
			t.Errorf("the client authenticated by %s as %q/%q", f.clientAuth, f.clientID, f.secret)
		}
	})
	t.Run("post when basic is not supported", func(t *testing.T) {
		f := newFakeIdP(t)
		f.authMethods = []string{"client_secret_post"}
		e := newEnv(t, f.srv.URL)
		e.signIn(t, f)
		if f.clientAuth != "post" || f.clientID != "test-client" || f.secret != "test-client-secret" {
			t.Errorf("the client authenticated by %s as %q/%q", f.clientAuth, f.clientID, f.secret)
		}
	})
	t.Run("neither", func(t *testing.T) {
		f := newFakeIdP(t)
		f.authMethods = []string{"private_key_jwt"}
		e := newEnv(t, f.srv.URL)
		state, nonce, cookie := e.login(t, "")
		f.set(func(f *fakeIdP) { f.nonce = nonce })
		if w := e.callback(t, state, cookie); w.Code != http.StatusBadGateway {
			t.Errorf("status = %d, want 502", w.Code)
		}
	})
}

// The masked and the plain form of a decision the token endpoint made, which is what tells "the provider
// refused this token" from "the provider could not be asked".
func TestTokenErrorRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  tokenError
		want bool
	}{
		{name: "invalid_grant on a 400", err: tokenError{status: 400, code: "invalid_grant"}, want: true},
		{name: "a bare 403", err: tokenError{status: 403}, want: true},
		{name: "an error object on a 200", err: tokenError{status: 200, code: "invalid_grant"}, want: true},
		{name: "a 500", err: tokenError{status: 500}, want: false},
		{name: "a 502", err: tokenError{status: 502}, want: false},
		{name: "no answer at all", err: tokenError{desc: "connection refused"}, want: false},
	} {
		if got := tc.err.refused(); got != tc.want {
			t.Errorf("%s: refused() = %v, want %v", tc.name, got, tc.want)
		}
		if tc.err.Error() == "" {
			t.Errorf("%s: no message", tc.name)
		}
	}
}

// Moving the issuer away and back must not keep a discovery document per issuer ever configured: a
// document past its TTL goes the next time one is stored, while one still fresh is kept.
func TestDiscoverySweepsStaleIssuers(t *testing.T) {
	a, b, c := newFakeIdP(t), newFakeIdP(t), newFakeIdP(t)
	e := newEnv(t, a.srv.URL)
	p, ctx := e.p, context.Background()
	for _, f := range []*fakeIdP{a, b} {
		if _, err := p.discover(ctx, f.srv.URL); err != nil {
			t.Fatal(err)
		}
	}
	p.mu.Lock()
	stale := p.disco[a.srv.URL]
	stale.fetchedAt = time.Now().Add(-discoTTL)
	p.disco[a.srv.URL] = stale
	p.mu.Unlock()

	if _, err := p.discover(ctx, c.srv.URL); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.disco[a.srv.URL]; ok {
		t.Error("the stale document of the first issuer is still cached")
	}
	for _, f := range []*fakeIdP{b, c} {
		if _, ok := p.disco[f.srv.URL]; !ok {
			t.Errorf("the fresh document of %s was dropped", f.srv.URL)
		}
	}
}

// Two providers on one manager: their own paths, flow cookies and sessions, and nothing that leaves the
// process names either of them in a cookie.
func TestTwoProviders(t *testing.T) {
	corpIdP, partnerIdP := newFakeIdP(t), newFakeIdP(t)
	partnerIdP.sub = "bob"
	e := newEnv(t, corpIdP.srv.URL, func(o *auth.Options, _ *Options) {
		o.LoginURL = func(_ *http.Request, ret string) string { return "/sign-in?ret=" + url.QueryEscape(ret) }
	})
	e.allow("alice", "bob")
	cfg := Config{Issuer: partnerIdP.srv.URL, ClientID: "test-client", ClientSecret: "test-client-secret"}
	partner, err := New(e.m, Options{Name: "partner", Config: func() (Config, bool) { return cfg, true }})
	if err != nil {
		t.Fatal(err)
	}
	partner.Routes(e.mux)
	if partner.flowCookie == e.p.flowCookie {
		t.Fatal("two providers share a flow cookie")
	}
	if _, err := New(e.m, Options{Name: "partner", Config: func() (Config, bool) { return cfg, true }}); err == nil {
		t.Error("a second provider named partner was registered")
	}

	// Both logins started at once, as two tabs would: neither overwrites the other's flow.
	cq, cflow := authorize(t, e.mux, e.p, url.Values{"ret": {"/a"}})
	pq, pflow := authorize(t, e.mux, partner, url.Values{"ret": {"/b"}})
	for _, c := range []*http.Cookie{cflow, pflow} {
		for _, name := range []string{"corp", "partner"} {
			if strings.Contains(c.Name, name) || strings.Contains(decoded(t, c.Value), name) {
				t.Errorf("the flow cookie %s names provider %q", c.Name, name)
			}
		}
	}
	if !strings.Contains(pq.Get("redirect_uri"), "/auth/oidc/partner/callback") {
		t.Errorf("partner's redirect_uri is %q", pq.Get("redirect_uri"))
	}

	// A callback reaching the wrong provider's path is refused: it finds no flow of its own there.
	corpIdP.set(func(f *fakeIdP) { f.nonce = cq.Get("nonce") })
	partnerIdP.set(func(f *fakeIdP) { f.nonce = pq.Get("nonce") })
	crossed := callbackAt(t, e.mux, partner, cq.Get("state"), cflow)
	if sessionCookieOf(crossed) != nil || e.store.count() != 0 {
		t.Fatalf("a callback at the wrong provider produced a session: %d", crossed.Code)
	}

	pw := callbackAt(t, e.mux, partner, pq.Get("state"), cflow, pflow)
	if pw.Code != http.StatusFound || pw.Header().Get("Location") != "/b" {
		t.Fatalf("partner's callback gave %d to %q (body %s)", pw.Code, pw.Header().Get("Location"), pw.Body)
	}
	cw := callbackAt(t, e.mux, e.p, cq.Get("state"), cflow)
	if cw.Code != http.StatusFound || cw.Header().Get("Location") != "/a" {
		t.Fatalf("corp's callback gave %d to %q (body %s)", cw.Code, cw.Header().Get("Location"), cw.Body)
	}
	if got := e.ask(t, sessionCookieOf(pw)).Body.String(); got != "partner/bob" {
		t.Errorf("partner's session is %q", got)
	}
	if got := e.ask(t, sessionCookieOf(cw)).Body.String(); got != "corp/alice" {
		t.Errorf("corp's session is %q", got)
	}
	for _, w := range []*httptest.ResponseRecorder{pw, cw} {
		for _, c := range w.Result().Cookies() {
			for _, name := range []string{"corp", "partner", "alice", "bob"} {
				if strings.Contains(c.Name, name) || strings.Contains(decoded(t, c.Value), name) {
					t.Errorf("cookie %s names %q", c.Name, name)
				}
			}
		}
	}
	if e.store.count() != 2 {
		t.Errorf("%d session records, want one per provider", e.store.count())
	}

	// With two interactive methods, an anonymous browser goes to the host's page.
	r := httptest.NewRequest(http.MethodGet, "/app", nil)
	w := httptest.NewRecorder()
	e.m.Require(http.NotFoundHandler()).ServeHTTP(w, r)
	if loc := w.Header().Get("Location"); loc != "/sign-in?ret=%2Fapp" {
		t.Errorf("an anonymous browser was sent to %q", loc)
	}
}

// decoded is the payload of a sealed value as text, or "" for one that is not sealed.
func decoded(t *testing.T, value string) string {
	t.Helper()
	payload, _, ok := strings.Cut(value, ".")
	if !ok {
		return ""
	}
	b, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return ""
	}
	return string(b)
}

func cleared(w *httptest.ResponseRecorder, name string) bool {
	for _, c := range w.Result().Cookies() {
		if c.Name == name && c.MaxAge < 0 {
			return true
		}
	}
	return false
}

func TestLoginURLAndOptions(t *testing.T) {
	e := newEnv(t, "https://idp.example")
	if got := e.p.LoginURL("/app?x=1"); got != "/auth/oidc/corp/login?ret=%2Fapp%3Fx%3D1" {
		t.Errorf("LoginURL = %q", got)
	}
	if got := e.p.LoginURL(""); got != "/auth/oidc/corp/login" {
		t.Errorf("LoginURL(\"\") = %q", got)
	}
	if e.p.Name() != "corp" {
		t.Errorf("Name = %q", e.p.Name())
	}
	cfg := func() (Config, bool) { return Config{}, false }
	for _, o := range []Options{{Name: "Corp", Config: cfg}, {Name: "a/b", Config: cfg}, {Name: "ok"}} {
		if _, err := New(e.m, o); err == nil {
			t.Errorf("New accepted %+v", o)
		}
	}
}

func TestConfigValidate(t *testing.T) {
	good := Config{Issuer: "https://idp.example", ClientID: "test-client", ClientSecret: "test-client-secret"}
	if err := good.Validate(); err != nil {
		t.Errorf("a good config was refused: %v", err)
	}
	for name, change := range map[string]func(*Config){
		"http issuer":     func(c *Config) { c.Issuer = "http://idp.example" },
		"no issuer":       func(c *Config) { c.Issuer = "" },
		"no client id":    func(c *Config) { c.ClientID = "" },
		"no secret":       func(c *Config) { c.ClientSecret = "" },
		"relative issuer": func(c *Config) { c.Issuer = "https:///x" },
	} {
		c := good
		change(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: Validate accepted it", name)
		}
	}
}
