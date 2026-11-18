package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// A cookie well inside its lifetime costs a signature check and nothing else: no store, no authority.
func TestAFreshCookieTouchesNeitherStoreNorMethod(t *testing.T) {
	h := newHarness(t)
	h.synced()
	c, _ := h.signIn(t)
	before := h.store.getCount()

	if got := h.ask(t, c); got.Code != http.StatusOK || got.Body.String() != "alice" {
		t.Fatalf("status = %d, body = %s", got.Code, got.Body)
	}
	if n := h.store.getCount() - before; n != 0 {
		t.Errorf("the store was read %d times", n)
	}
	if h.method.callCount() != 0 {
		t.Error("the method was asked about a fresh cookie")
	}
}

// Half an hour before the cookie runs out the method is asked again, and the browser sees nothing but a
// fresh cookie.
func TestRevalidationHappensBeforeTheCookieExpires(t *testing.T) {
	h := newHarness(t)
	_, sid := h.signIn(t)
	h.age(t, sid, time.Hour)
	_, before := h.store.only(t)

	w := h.ask(t, h.cookieAt(t, sid, 10*time.Minute))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body)
	}
	if h.method.callCount() != 1 {
		t.Errorf("the method was asked %d times, want 1", h.method.callCount())
	}
	_, after := h.store.only(t)
	// An authority that rotates hands back new state, and keeping the old would end the session at the
	// next revalidation.
	if string(after.State) != `{"token":"t1"}` {
		t.Errorf("the record holds state %s, want the rotated one", after.State)
	}
	if !after.VerifiedAt.After(before.VerifiedAt) {
		t.Errorf("verified_at was not moved forward: %s → %s", before.VerifiedAt, after.VerifiedAt)
	}
	if !after.CreatedAt.Equal(before.CreatedAt) {
		t.Errorf("created_at was rewritten: %s → %s", before.CreatedAt, after.CreatedAt)
	}
	fresh := sessionCookieOf(h.m, w)
	if fresh == nil {
		t.Fatal("the revalidation handed back no new cookie")
	}
	var s sessionState
	if err := h.m.Open(fresh.Value, &s); err != nil {
		t.Fatal(err)
	}
	if time.Until(time.Unix(s.Exp, 0)) <= refreshWindow {
		t.Errorf("the new cookie expires in %s, inside the refresh window again", time.Until(time.Unix(s.Exp, 0)))
	}
}

// An exp already in the past is revalidated rather than refused. Coming back to a tab hours later has to
// keep the session, since what says whether it is alive is the record.
func TestAnExpiredCookieIsRevalidatedRatherThanRefused(t *testing.T) {
	h := newHarness(t)
	_, sid := h.signIn(t)
	h.age(t, sid, time.Hour)
	if got := h.ask(t, h.cookieAt(t, sid, -3*time.Hour)); got.Code != http.StatusOK {
		t.Fatalf("an expired cookie gave status = %d, want 200 (body = %s)", got.Code, got.Body)
	}
	if h.method.callCount() != 1 {
		t.Errorf("the method was asked %d times, want 1", h.method.callCount())
	}
}

// The point of the whole arrangement: the authority ending the session ends it, whatever the cookie says.
func TestErrEndedDeletesTheRecord(t *testing.T) {
	h := newHarness(t)
	_, sid := h.signIn(t)
	h.age(t, sid, time.Hour)
	h.method.setAnswer(func(Record) (Record, error) {
		return Record{}, fmt.Errorf("%w: invalid_grant", ErrEnded)
	})

	w := h.ask(t, h.cookieAt(t, sid, 5*time.Minute))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body = %s)", w.Code, w.Body)
	}
	if !cookieCleared(h.m, w) {
		t.Error("the session cookie was not cleared")
	}
	if h.store.count() != 0 {
		t.Error("the ended session record is still stored")
	}
	if got := h.ask(t, h.cookieAt(t, sid, 5*time.Minute)); got.Code != http.StatusUnauthorized {
		t.Errorf("the next request gave status = %d, want 401", got.Code)
	}
}

// An authority that cannot be asked is not an answer about the session: one verified recently carries on,
// and one not confirmed for longer than a record may sit idle ends.
func TestAnUnreachableAuthorityKeepsTheSessionInsideTheGraceWindow(t *testing.T) {
	h := newHarness(t)
	_, sid := h.signIn(t)
	h.age(t, sid, time.Hour)
	h.method.setAnswer(func(Record) (Record, error) { return Record{}, errors.New("token endpoint: HTTP 502") })

	w := h.ask(t, h.cookieAt(t, sid, 5*time.Minute))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body = %s)", w.Code, w.Body)
	}
	if h.store.count() != 1 {
		t.Error("the record was deleted although the authority said nothing about the session")
	}
	if sessionCookieOf(h.m, w) == nil {
		t.Error("the request went through without a fresh cookie, so the next one would try again at once")
	}

	h.store.edit(t, sid, func(r *Record) { r.VerifiedAt = time.Now().Add(-defaultIdleTTL - time.Hour) })
	if got := h.ask(t, h.cookieAt(t, sid, 5*time.Minute)); got.Code != http.StatusUnauthorized {
		t.Errorf("a session unconfirmed for over %s gave status = %d, want 401", defaultIdleTTL, got.Code)
	}
}

// A revalidation whose write loses to a concurrent one keeps that write: it is at least as new.
func TestARevalidationLosingItsWriteKeepsTheOtherWrite(t *testing.T) {
	h := newHarness(t)
	_, sid := h.signIn(t)
	h.age(t, sid, time.Hour)
	h.store.conflicts = 1
	if got := h.ask(t, h.cookieAt(t, sid, 5*time.Minute)); got.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", got.Code, got.Body)
	}
	if _, rec := h.store.only(t); string(rec.State) != `{"token":"t0"}` {
		t.Errorf("the losing write landed anyway: %s", rec.State)
	}
	if _, ok := h.m.live.cached(sid); ok {
		t.Error("the cache still holds the write that lost")
	}
}

// A record removed by hand is the same answer as a refusal, without asking the authority anything.
func TestADeletedRecordEndsTheSession(t *testing.T) {
	h := newHarness(t)
	_, sid := h.signIn(t)
	if err := h.store.Delete(context.Background(), sid); err != nil {
		t.Fatal(err)
	}
	for name, until := range map[string]time.Duration{"outside the window": sessionTTL, "inside": 5 * time.Minute} {
		w := h.ask(t, h.cookieAt(t, sid, until))
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401 (body = %s)", name, w.Code, w.Body)
		}
		if !cookieCleared(h.m, w) {
			t.Errorf("%s: the cookie was not cleared", name)
		}
	}
	if h.method.callCount() != 0 {
		t.Error("the method was asked about a session that no longer exists")
	}
}

// A tab that arrives after another has just revalidated does not ask again. The single flight only holds
// back requests that overlap, while these are in sequence, each carrying the cookie it was loaded with.
func TestASecondRequestDoesNotRevalidateAgain(t *testing.T) {
	h := newHarness(t)
	_, sid := h.signIn(t)
	h.age(t, sid, time.Hour)
	if got := h.ask(t, h.cookieAt(t, sid, 5*time.Minute)); got.Code != http.StatusOK {
		t.Fatalf("the first tab gave status = %d", got.Code)
	}
	second := h.ask(t, h.cookieAt(t, sid, 5*time.Minute))
	if second.Code != http.StatusOK {
		t.Fatalf("the second tab gave status = %d (body = %s)", second.Code, second.Body)
	}
	if n := h.method.callCount(); n != 1 {
		t.Errorf("the method was asked %d times for one session, want 1", n)
	}
	if sessionCookieOf(h.m, second) == nil {
		t.Error("the second tab was let through without a fresh cookie")
	}
}

// Every tab of one browser polls, so they reach the refresh window together.
func TestConcurrentRequestsRevalidateOnce(t *testing.T) {
	h := newHarness(t)
	_, sid := h.signIn(t)
	h.age(t, sid, time.Hour)
	cookie := h.cookieAt(t, sid, 5*time.Minute)

	const tabs = 8
	var wg sync.WaitGroup
	codes := make([]int, tabs)
	for i := range tabs {
		wg.Go(func() { codes[i] = h.ask(t, cookie).Code })
	}
	wg.Wait()
	for i, code := range codes {
		if code != http.StatusOK {
			t.Errorf("tab %d gave status = %d, want 200", i, code)
		}
	}
	if n := h.method.callCount(); n != 1 {
		t.Errorf("the method was asked %d times for one session, want 1", n)
	}
}

// Another instance took the claim in the same moment. Losing it must not end the session: presenting the
// same refresh token again would earn a refusal from an authority that rotates.
func TestLosingTheClaimKeepsTheSession(t *testing.T) {
	fs := newFakeStore()
	cs := &claimingStore{fakeStore: fs}
	h := newHarnessOn(t, fs, cs)
	_, sid := h.signIn(t)
	h.age(t, sid, time.Hour)
	cs.claimTaken = true

	w := h.ask(t, h.cookieAt(t, sid, 5*time.Minute))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body = %s)", w.Code, w.Body)
	}
	if n := h.method.callCount(); n != 0 {
		t.Errorf("the method was asked %d times while another instance held the claim", n)
	}
	if fs.count() != 1 {
		t.Error("losing the claim deleted a live session")
	}
	if sessionCookieOf(h.m, w) == nil {
		t.Error("the request went through without a fresh cookie")
	}
}

// A claim written a moment ago is read before one is taken: no claim is attempted while another instance
// is known to be asking.
func TestAFreshClaimOfAnotherInstanceIsNotTakenOver(t *testing.T) {
	fs := newFakeStore()
	h := newHarnessOn(t, fs, &claimingStore{fakeStore: fs})
	_, sid := h.signIn(t)
	fs.edit(t, sid, func(r *Record) {
		r.VerifiedAt = r.VerifiedAt.Add(-time.Hour)
		r.RefreshingAt = time.Now()
	})
	if got := h.ask(t, h.cookieAt(t, sid, 5*time.Minute)); got.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body = %s)", got.Code, got.Body)
	}
	if n := h.method.callCount(); n != 0 {
		t.Errorf("the method was asked %d times while another instance held a fresh claim", n)
	}

	// A claim older than a revalidation could be outstanding belongs to an instance that died with it.
	fs.edit(t, sid, func(r *Record) { r.RefreshingAt = time.Now().Add(-claimTTL - time.Minute) })
	if got := h.ask(t, h.cookieAt(t, sid, 5*time.Minute)); got.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body = %s)", got.Code, got.Body)
	}
	if n := h.method.callCount(); n != 1 {
		t.Errorf("the method was asked %d times after the stale claim, want 1", n)
	}
	if _, rec := fs.only(t); rec.RefreshingAt.IsZero() || string(rec.State) != `{"token":"t1"}` {
		t.Errorf("the claim or the new state was not written: %+v", rec)
	}
}

// Logging out deletes the record rather than only clearing the cookie: a cleared cookie with a live record
// would leave a credential in the store that nothing will ever use.
func TestLogoutDeletesTheRecord(t *testing.T) {
	h := newHarness(t)
	h.synced()
	c, sid := h.signIn(t)
	mux := http.NewServeMux()
	h.m.Routes(mux)

	r := httptest.NewRequest(http.MethodPost, LogoutPath, nil)
	r.Header.Set("Accept", "application/json")
	r.AddCookie(c)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (body = %s)", w.Code, w.Body)
	}
	if !cookieCleared(h.m, w) {
		t.Error("the session cookie was not cleared")
	}
	if h.store.count() != 0 {
		t.Error("the session record survived the logout")
	}
	// No event from a feed is needed for this process to know: a copy of the cookie is refused at once.
	if got := h.ask(t, c); got.Code != http.StatusUnauthorized {
		t.Errorf("the cookie after the logout gave status = %d, want 401", got.Code)
	}
	if got := h.ask(t, h.cookieAt(t, sid, 5*time.Minute)); got.Code != http.StatusUnauthorized {
		t.Errorf("a cookie in the window after the logout gave status = %d, want 401", got.Code)
	}
}

// A plain form is enough to sign out: the browser is sent on to ret, or to the root without one, and never
// off the site.
func TestLogoutRedirectsABrowser(t *testing.T) {
	for _, tc := range []struct {
		name, target, body, want string
	}{
		{"ret in the form", LogoutPath, "ret=" + url.QueryEscape("/bye?x=1"), "/bye?x=1"},
		{"ret in the query", LogoutPath + "?ret=" + url.QueryEscape("/bye?x=1"), "", "/bye?x=1"},
		{"no ret", LogoutPath, "", "/"},
		{"protocol-relative ret", LogoutPath, "ret=" + url.QueryEscape("//evil.example"), "/"},
		{"absolute ret", LogoutPath, "ret=" + url.QueryEscape("https://evil.example/"), "/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			c, _ := h.signIn(t)
			r := httptest.NewRequest(http.MethodPost, tc.target, strings.NewReader(tc.body))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
			w := h.logout(r, c)
			if w.Code != http.StatusSeeOther {
				t.Fatalf("status = %d, want 303 (body = %s)", w.Code, w.Body)
			}
			if got := w.Header().Get("Location"); got != tc.want {
				t.Errorf("Location = %q, want %q", got, tc.want)
			}
			if !cookieCleared(h.m, w) {
				t.Error("the session cookie was not cleared")
			}
			if h.store.count() != 0 {
				t.Error("the session record survived the logout")
			}
		})
	}
}

// A form on another site must not sign a visitor out. The cookie would not reach the record, but the
// answer would still clear it in the browser.
func TestLogoutRefusesAnotherSite(t *testing.T) {
	h := newHarness(t)
	c, _ := h.signIn(t)
	r := httptest.NewRequest(http.MethodPost, LogoutPath, nil)
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	w := h.logout(r, c)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), `"cross_origin_request"`) {
		t.Fatalf("status = %d, body = %s; want 403 cross_origin_request", w.Code, w.Body)
	}
	if len(w.Result().Cookies()) != 0 {
		t.Errorf("the refusal set cookies: %v", w.Result().Cookies())
	}
	if h.store.count() != 1 {
		t.Error("the refused logout deleted the session record")
	}
}

// The same site, and a client that sends no fetch metadata at all (curl, a Go http.Client), sign out.
func TestLogoutAdmitsTheSameSite(t *testing.T) {
	for _, site := range []string{"same-origin", ""} {
		t.Run("Sec-Fetch-Site="+site, func(t *testing.T) {
			h := newHarness(t)
			c, _ := h.signIn(t)
			r := httptest.NewRequest(http.MethodPost, LogoutPath, nil)
			if site != "" {
				r.Header.Set("Sec-Fetch-Site", site)
			}
			w := h.logout(r, c)
			if w.Code != http.StatusSeeOther {
				t.Fatalf("status = %d, want 303 (body = %s)", w.Code, w.Body)
			}
			if !cookieCleared(h.m, w) {
				t.Error("the session cookie was not cleared")
			}
			if h.store.count() != 0 {
				t.Error("the session record survived the logout")
			}
		})
	}
}

// logout sends r through the routes Routes mounts, with the session cookie when there is one.
func (h *harness) logout(r *http.Request, cookie *http.Cookie) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	h.m.Routes(mux)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

// Signing in again ends the session the browser was holding. A copy taken off that cookie beforehand
// would otherwise go on being revalidated, and signing in again is what somebody who suspects a copy does.
func TestASignInReplacesTheSessionItArrivedWith(t *testing.T) {
	h := newHarness(t)
	held, oldSID := h.signIn(t)
	w, err := h.issue(Grant{Identity: Identity{Provider: "corp", Subject: "alice"}}, held)
	if err != nil {
		t.Fatal(err)
	}
	newSID, _ := h.store.only(t)
	if newSID == oldSID {
		t.Fatal("the second sign-in reused the record of the first")
	}
	if sessionCookieOf(h.m, w) == nil {
		t.Fatal("the second sign-in set no cookie")
	}
	if got := h.ask(t, h.cookieAt(t, oldSID, 5*time.Minute)); got.Code != http.StatusUnauthorized {
		t.Errorf("a copy of the replaced cookie gave status = %d, want 401", got.Code)
	}
}

// Alive is what a handler holding a connection open asks on every keepalive.
func TestAliveFollowsTheRecordThePolicyAndTheDeadline(t *testing.T) {
	h := newHarness(t)
	c, _ := h.signIn(t)
	sess := h.sessionOfRequest(t, c)
	ctx := context.Background()
	if !h.m.Alive(ctx, sess) {
		t.Fatal("a session just signed in is reported dead")
	}

	h.store.setBroken(errUnreachableStore)
	if !h.m.Alive(ctx, sess) {
		t.Error("an unreachable store closed a live session")
	}
	h.store.setBroken(nil)

	h.allow("bob")
	if h.m.Alive(ctx, sess) {
		t.Error("a subject the policy no longer admits is still alive")
	}
	h.allow("alice")

	past := sess
	past.Deadline = time.Now().Add(-time.Second)
	if h.m.Alive(ctx, past) {
		t.Error("a session past its deadline is alive")
	}

	if err := h.store.Delete(ctx, sess.ID); err != nil {
		t.Fatal(err)
	}
	if h.m.Alive(ctx, sess) {
		t.Error("a session whose record is gone is alive")
	}
}

func TestALiveSessionCostsNoStoreRead(t *testing.T) {
	h := newHarness(t)
	c, sid := h.signIn(t)
	h.synced(sid)
	// The Loaded dropped what was cached, so the first request reads once and the next not at all.
	for i, want := range []int{1, 0} {
		before := h.store.getCount()
		if got := h.ask(t, c); got.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d", i, got.Code)
		}
		if n := h.store.getCount() - before; n != want {
			t.Errorf("request %d read the record %d times, want %d", i, n, want)
		}
	}
}

func TestARemovedSessionIsRefusedOnItsNextRequest(t *testing.T) {
	h := newHarness(t)
	h.synced()
	c, sid := h.signIn(t)
	if err := h.store.Delete(context.Background(), sid); err != nil {
		t.Fatal(err)
	}
	h.m.live.apply(Event{Kind: Removed, ID: sid})

	before := h.store.getCount()
	got := h.ask(t, c)
	if got.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", got.Code)
	}
	if !cookieCleared(h.m, got) {
		t.Error("the refusal does not clear the cookie")
	}
	if n := h.store.getCount() - before; n != 1 {
		t.Errorf("the record was read %d times, want once", n)
	}
}

func TestALostFeedReadsEveryRequestUntilItIsBack(t *testing.T) {
	h := newHarness(t)
	h.synced()
	c, sid := h.signIn(t)
	h.m.live.apply(Event{Kind: Lost})
	for i := range 2 {
		before := h.store.getCount()
		if got := h.ask(t, c); got.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d", i, got.Code)
		}
		if n := h.store.getCount() - before; n != 1 {
			t.Errorf("request %d read the record %d times while the feed was lost, want once", i, n)
		}
	}
	h.synced(sid)
	h.ask(t, c)
	before := h.store.getCount()
	if got := h.ask(t, c); got.Code != http.StatusOK {
		t.Fatalf("status after the resync = %d", got.Code)
	}
	if n := h.store.getCount() - before; n != 0 {
		t.Errorf("the record was read %d times after the resync", n)
	}
}

// The cookie names no one, so a session this process has never seen needs its record. One it has seen
// carries on while the store cannot be read.
func TestAnUnreadableStoreTurnsAwayOnlyUnseenSessions(t *testing.T) {
	h := newHarness(t)
	c, sid := h.signIn(t)
	h.store.setBroken(errUnreachableStore)

	if got := h.ask(t, c); got.Code != http.StatusOK {
		t.Errorf("a cached session gave status = %d, want 200", got.Code)
	}
	if !strings.Contains(h.logs.String(), "reading a session record failed") {
		t.Errorf("no warning was logged: %s", h.logs)
	}

	cold := newHarnessOn(t, h.store, nil)
	got := cold.ask(t, cold.cookieAt(t, sid, sessionTTL))
	if got.Code != http.StatusServiceUnavailable || !strings.Contains(got.Body.String(), "session_store_unavailable") {
		t.Errorf("an unseen session gave %d %s, want 503 session_store_unavailable", got.Code, got.Body)
	}
	if got := cold.ask(t, cold.cookieAt(t, sid, 5*time.Minute)); got.Code != http.StatusServiceUnavailable {
		t.Errorf("an unseen session in the window gave %d, want 503", got.Code)
	}
}

// A session with a deadline is decided from the cookie before anything reads the store, and is never
// taken to its method.
func TestADeadlineSession(t *testing.T) {
	h := newHarness(t)
	deadline := time.Now().Add(3 * time.Hour)
	w, err := h.issue(Grant{Identity: Identity{Provider: "corp", Subject: "alice"}, Deadline: deadline}, nil)
	if err != nil {
		t.Fatal(err)
	}
	sid, rec := h.store.only(t)
	if !rec.Deadline.Equal(deadline) || rec.VerifiedAt.IsZero() {
		t.Errorf("the record has deadline %s and verified_at %s", rec.Deadline, rec.VerifiedAt)
	}
	if ttl := h.store.ttls[sid]; ttl < 3*time.Hour-time.Minute || ttl > 3*time.Hour {
		t.Errorf("the record was put for %s, want the time to its deadline", ttl)
	}
	c := sessionCookieOf(h.m, w)
	if want := int((3 * time.Hour).Seconds()); c.MaxAge < want-1 || c.MaxAge > want {
		t.Errorf("MaxAge = %d, want %d", c.MaxAge, want)
	}
	var s sessionState
	if err := h.m.Open(c.Value, &s); err != nil || s.Deadline != deadline.Unix() {
		t.Errorf("the cookie carries dl %d (%v), want %d", s.Deadline, err, deadline.Unix())
	}

	t.Run("in the window it re-reads but never revalidates", func(t *testing.T) {
		h.age(t, sid, time.Hour)
		before := h.store.getCount()
		touches := h.store.touches
		got := h.ask(t, h.cookieWith(t, sessionState{SID: sid, Exp: time.Now().Add(5 * time.Minute).Unix(), Deadline: deadline.Unix()}))
		if got.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", got.Code, got.Body)
		}
		if h.method.callCount() != 0 || h.store.touches != touches {
			t.Error("a deadline session was revalidated")
		}
		if h.store.getCount()-before != 1 {
			t.Error("a deadline session in the window did not re-read its record")
		}
	})

	t.Run("a deleted record ends it", func(t *testing.T) {
		other, osid := h.signInAs(t, Grant{Identity: Identity{Provider: "corp", Subject: "alice"}, Deadline: deadline})
		_ = other
		if err := h.store.Delete(context.Background(), osid); err != nil {
			t.Fatal(err)
		}
		got := h.ask(t, h.cookieWith(t, sessionState{SID: osid, Exp: time.Now().Add(5 * time.Minute).Unix(), Deadline: deadline.Unix()}))
		if got.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", got.Code)
		}
	})

	t.Run("past its deadline it is refused without a read", func(t *testing.T) {
		before := h.store.getCount()
		got := h.ask(t, h.cookieWith(t, sessionState{SID: sid, Exp: time.Now().Add(sessionTTL).Unix(),
			Deadline: time.Now().Add(-time.Minute).Unix()}))
		if got.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", got.Code)
		}
		if !cookieCleared(h.m, got) {
			t.Error("the browser was left holding the cookie of a session that has ended")
		}
		if n := h.store.getCount() - before; n != 0 {
			t.Errorf("deciding a deadline cost %d reads", n)
		}
	})

	if _, err := h.issue(Grant{Identity: Identity{Provider: "corp", Subject: "alice"},
		Deadline: time.Now().Add(-time.Second)}, nil); err == nil {
		t.Error("Issue accepted a deadline already past")
	}
}

// Authorize is asked at sign-in, at revalidation and on every request; a refusal refuses the request and
// keeps the record, since a change of policy can be reversed.
func TestAuthorizeRunsOnEveryOccasion(t *testing.T) {
	h := newHarness(t)
	h.allow("bob")
	w, err := h.issue(Grant{Identity: Identity{Provider: "corp", Subject: "alice"}}, nil)
	if !errors.Is(err, ErrNotAllowed) || h.store.count() != 0 || sessionCookieOf(h.m, w) != nil {
		t.Fatalf("a refused sign-in gave %v and %d records", err, h.store.count())
	}
	if !strings.Contains(h.logs.String(), "alice") {
		t.Errorf("the log does not name the refused subject: %s", h.logs)
	}

	h.allow("alice")
	c, sid := h.signIn(t)
	h.allow("bob")
	got := h.ask(t, c)
	if got.Code != http.StatusUnauthorized {
		t.Errorf("a request after the policy changed gave %d, want 401", got.Code)
	}
	if strings.Contains(got.Body.String(), "alice") || strings.Contains(got.Body.String(), "allow list") {
		t.Errorf("the browser was told why: %s", got.Body)
	}
	if h.store.count() != 1 || cookieCleared(h.m, got) {
		t.Error("a refusal by the policy ended the session")
	}

	h.allow("alice")
	if got := h.ask(t, c); got.Code != http.StatusOK {
		t.Errorf("a request after the policy changed back gave %d, want 200", got.Code)
	}

	// At revalidation the new identity is what is asked about, and the record is written before: the
	// authority may have rotated the token already.
	h.age(t, sid, time.Hour)
	h.method.setAnswer(func(rec Record) (Record, error) {
		rec.State = json.RawMessage(`{"token":"rotated"}`)
		rec.Claims = json.RawMessage(`{"groups":["guests"]}`)
		return rec, nil
	})
	h.m.authorize = func(_ context.Context, id Identity) error {
		if g, _ := id.Claims["groups"].([]any); len(g) == 1 && g[0] == "admins" {
			return nil
		}
		return fmt.Errorf("%w: not an admin", ErrNotAllowed)
	}
	if got := h.ask(t, h.cookieAt(t, sid, 5*time.Minute)); got.Code != http.StatusUnauthorized {
		t.Errorf("a revalidation into a refused identity gave %d, want 401", got.Code)
	}
	if _, rec := h.store.only(t); string(rec.State) != `{"token":"rotated"}` {
		t.Errorf("the rotated state was not stored before the refusal: %s", rec.State)
	}
}

// A write by another instance reaches this one's cache through the feed.
func TestAnAddedEventDropsCachedClaimsAndValues(t *testing.T) {
	h := newHarness(t)
	h.synced()
	c, sid := h.signIn(t)
	if s := h.sessionOfRequest(t, c); s.Values["user"] != "" {
		t.Fatalf("values before: %v", s.Values)
	}
	h.store.edit(t, sid, func(r *Record) {
		r.Values = map[string]string{"user": "42"}
		r.Claims = json.RawMessage(`{"groups":["ops"]}`)
	})
	if s := h.sessionOfRequest(t, c); s.Values["user"] != "" {
		t.Fatal("the cache was bypassed without an event, so this test proves nothing")
	}
	h.m.live.apply(Event{Kind: Added, ID: sid})
	s := h.sessionOfRequest(t, c)
	if s.Values["user"] != "42" {
		t.Errorf("values after the event: %v", s.Values)
	}
	if g, _ := s.Identity.Claims["groups"].([]any); len(g) != 1 || g[0] != "ops" {
		t.Errorf("claims after the event: %v", s.Identity.Claims)
	}
}

func TestLinkSetsTheInitialValues(t *testing.T) {
	var linkErr error
	h := newHarness(t, func(o *Options) {
		o.Link = func(_ context.Context, id Identity) (map[string]string, error) {
			if linkErr != nil {
				return nil, linkErr
			}
			return map[string]string{"user": "u-" + id.Subject}, nil
		}
	})
	c, sid := h.signIn(t)
	if s := h.sessionOfRequest(t, c); s.Values["user"] != "u-alice" {
		t.Errorf("SessionFrom has values %v", s.Values)
	}

	h.age(t, sid, time.Hour)
	if s := h.sessionOfRequest(t, h.cookieAt(t, sid, 5*time.Minute)); s.Values["user"] != "u-alice" {
		t.Errorf("after a revalidation the values are %v", s.Values)
	}
	if h.method.callCount() != 1 {
		t.Fatal("no revalidation happened, so this test proves nothing")
	}

	linkErr = fmt.Errorf("%w: no account", ErrNotAllowed)
	if _, err := h.issue(Grant{Identity: Identity{Provider: "corp", Subject: "alice"}}, nil); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("a Link refusal gave %v, want ErrNotAllowed", err)
	}
	linkErr = errors.New("database down")
	if _, err := h.issue(Grant{Identity: Identity{Provider: "corp", Subject: "alice"}}, nil); !errors.Is(err, ErrStoreUnavailable) {
		t.Errorf("a Link failure gave %v, want ErrStoreUnavailable", err)
	}
	if h.store.count() != 1 {
		t.Errorf("%d records, the refused sign-ins left some behind", h.store.count())
	}
}

func TestSetValue(t *testing.T) {
	h := newHarness(t)
	h.synced()
	c, sid := h.signIn(t)
	ctx := context.Background()

	// Two writes lost to concurrent ones, then the third lands: a value is never dropped silently.
	h.store.conflicts = 2
	if err := h.m.SetValue(ctx, sid, "tenant", "t1"); err != nil {
		t.Fatal(err)
	}
	if s := h.sessionOfRequest(t, c); s.Values["tenant"] != "t1" {
		t.Errorf("values after SetValue: %v", s.Values)
	}
	if err := h.m.DeleteValue(ctx, sid, "tenant"); err != nil {
		t.Fatal(err)
	}
	if s := h.sessionOfRequest(t, c); s.Values["tenant"] != "" {
		t.Errorf("values after DeleteValue: %v", s.Values)
	}

	h.store.conflicts = valueTries
	if err := h.m.SetValue(ctx, sid, "k", "v"); !errors.Is(err, ErrConflict) {
		t.Errorf("SetValue losing every try gave %v, want ErrConflict", err)
	}
	if err := h.m.SetValue(ctx, "no-such-session", "k", "v"); !errors.Is(err, ErrNotFound) {
		t.Errorf("SetValue on an ended session gave %v, want ErrNotFound", err)
	}
}

func TestUnauthenticatedAnswers(t *testing.T) {
	h := newHarness(t)

	w := h.serve(httptest.NewRequest(http.MethodGet, "/app/t1?tab=2", nil), nil)
	if w.Code != http.StatusFound {
		t.Fatalf("an anonymous browser gave status = %d, want 302", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/login/corp?ret=/app/t1?tab=2" {
		t.Errorf("the 302 goes to %q, want the login of the only interactive method", loc)
	}

	// A program receives a 401 in JSON rather than a redirect, since a 302 leaves a CLI with nothing to do.
	w = h.ask(t, nil)
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), `"unauthenticated"`) {
		t.Errorf("an anonymous program gave %d %s, want 401", w.Code, w.Body)
	}
	if w.Header().Get("Content-Type") != "application/json" {
		t.Errorf("the error is %q, not JSON", w.Header().Get("Content-Type"))
	}

	// So does a WebSocket handshake: a browser never follows a redirect on one.
	r := httptest.NewRequest(http.MethodGet, "/ws", nil)
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Connection", "Upgrade")
	if w := h.serve(r, nil); w.Code != http.StatusUnauthorized {
		t.Errorf("an anonymous WebSocket handshake gave status = %d, want 401", w.Code)
	}

	// A handshake carrying a valid session passes like any request.
	c, _ := h.signIn(t)
	r = httptest.NewRequest(http.MethodGet, "/ws", nil)
	r.Header.Set("Upgrade", "websocket")
	if w := h.serve(r, c); w.Code != http.StatusOK {
		t.Errorf("a signed-in WebSocket handshake gave status = %d, want 200", w.Code)
	}
}

func TestLoginURLWithSeveralMethods(t *testing.T) {
	h := newHarness(t)
	if err := h.m.Register(&fakeMethod{name: "partner", login: "/login/partner"}); err == nil {
		t.Fatal("a second interactive method was registered without Options.LoginURL")
	}

	h = newHarness(t, func(o *Options) {
		o.LoginURL = func(_ *http.Request, ret string) string { return "/choose?ret=" + url.QueryEscape(ret) }
	})
	if err := h.m.Register(&fakeMethod{name: "partner", login: "/login/partner"}); err != nil {
		t.Fatal(err)
	}
	w := h.serve(httptest.NewRequest(http.MethodGet, "/app", nil), nil)
	if loc := w.Header().Get("Location"); w.Code != http.StatusFound || loc != "/choose?ret=%2Fapp" {
		t.Errorf("an anonymous browser gave %d to %q, want the host's login page", w.Code, loc)
	}

	// With no interactive method at all there is nowhere to send a browser.
	m, err := New(Options{Store: newFakeStore(), Key: testKey, Authorize: AnyOf()})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Register(&fakeMethod{name: "mint"}); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	m.Require(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/app", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("with no interactive method an anonymous browser gave %d, want 401", w.Code)
	}
}

func TestIssueRefusesAnUnregisteredProvider(t *testing.T) {
	h := newHarness(t)
	if _, err := h.issue(Grant{Identity: Identity{Provider: "nobody", Subject: "alice"}}, nil); err == nil {
		t.Error("Issue accepted a provider that is not registered")
	}
}

func TestAnUnwritableStoreRefusesTheSignIn(t *testing.T) {
	h := newHarness(t)
	h.store.setBroken(errUnreachableStore)
	if _, err := h.issue(Grant{Identity: Identity{Provider: "corp", Subject: "alice"}}, nil); !errors.Is(err, ErrStoreUnavailable) {
		t.Errorf("Issue on a broken store gave %v, want ErrStoreUnavailable", err)
	}
}

func TestARemovedIDStaysRemoved(t *testing.T) {
	l := newLiveSessions(time.Hour)
	l.apply(Event{Kind: Loaded})
	l.drop("gone")
	l.remember(Session{ID: "gone"})
	if l.has("gone") {
		t.Error("remember brought a removed id back")
	}
	if _, ok := l.cached("gone"); ok {
		t.Error("remember cached a removed id")
	}
	l.apply(Event{Kind: Loaded, IDs: []string{"gone"}})
	if l.has("gone") {
		t.Error("a Loaded brought a removed id back")
	}
}

func TestAnUnsyncedSetHoldsNothing(t *testing.T) {
	l := newLiveSessions(time.Hour)
	l.remember(Session{ID: "seen"})
	if l.has("seen") {
		t.Error("has answered for an id while the set was never in sync")
	}
	l.apply(Event{Kind: Loaded, IDs: []string{"seen"}})
	l.apply(Event{Kind: Lost})
	l.remember(Session{ID: "seen"})
	if l.has("seen") {
		t.Error("has answered for an id after the feed was lost")
	}
}

// Events and requests on separate goroutines, for the race detector.
func TestTheLiveSetUnderConcurrentEvents(t *testing.T) {
	h := newHarness(t)
	c, sid := h.signIn(t)

	events := make(chan Event)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.m.FollowSessions(ctx, events)

	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 50 {
				if got := h.ask(t, c); got.Code != http.StatusOK {
					t.Errorf("status = %d", got.Code)
					return
				}
			}
		})
	}
	for i := range 200 {
		switch i % 4 {
		case 0:
			events <- Event{Kind: Loaded, IDs: []string{sid}}
		case 1:
			events <- Event{Kind: Added, ID: fmt.Sprintf("other-%d", i)}
		case 2:
			events <- Event{Kind: Added, ID: sid}
		case 3:
			events <- Event{Kind: Lost}
		}
	}
	wg.Wait()
}
