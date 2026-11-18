package e2e

import (
	"html"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/at-orz/x/examples/auth/internal/stack"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func TestJSONWithoutASession(t *testing.T) {
	t.Parallel()
	s := sharedStack(t)
	r, _ := newClient(t, s).me(s.URLs[0], "")
	if r.StatusCode != http.StatusUnauthorized || r.Header.Get("Location") != "" {
		t.Fatalf("got %d (Location %q), want 401 and no redirect", r.StatusCode, r.Header.Get("Location"))
	}
	if code := errorCode(t, r); code != "unauthenticated" {
		t.Fatalf("code %q", code)
	}
}

func TestTicketDeadline(t *testing.T) {
	t.Parallel()
	s := sharedStack(t)
	c := newClient(t, s)
	path, nonce, _ := strings.Cut(ticket(t, s, s.URLs[0], "bot-one", 3*time.Second), "?t=")

	r := c.do(http.MethodPost, path, url.Values{"t": {nonce}})
	if r.StatusCode != http.StatusFound {
		t.Fatalf("redeeming: %d %s", r.StatusCode, r.body)
	}
	cookie := c.sessionValue()
	r, me := c.me(s.URLs[0], cookie)
	if r.StatusCode != http.StatusOK || me.Provider != "mint" || me.Subject != "bot-one" || me.Deadline.IsZero() {
		t.Fatalf("signed in: %d %+v", r.StatusCode, me)
	}

	// The cookie is sent by hand: the browser drops it at the deadline itself, and what is under test
	// is that the server refuses it too.
	time.Sleep(time.Until(me.Deadline) + 1100*time.Millisecond)
	if r, _ := c.me(s.URLs[0], cookie); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("after the deadline: %d %s", r.StatusCode, r.body)
	}
}

// previewAgent is the User-Agent of a chat client fetching a link to show a preview of it.
const previewAgent = "LinkPreviewBot/1.0 (+https://example.com/bot)"

func TestLinkPreview(t *testing.T) {
	t.Parallel()
	s := sharedStack(t)
	link := ticket(t, s, s.URLs[0], "bot-one", time.Hour)

	bot := newClient(t, s)
	r := bot.get(link, "User-Agent", previewAgent)
	if r.StatusCode != http.StatusOK || bot.sessionValue() != "" {
		t.Fatalf("the preview got %d and a session cookie %q", r.StatusCode, bot.sessionValue())
	}

	// The browser POSTs what the page carries, from the page's own origin.
	c := newClient(t, s)
	page := c.get(link)
	m := pageNonce.FindStringSubmatch(page.body)
	if m == nil {
		t.Fatalf("no ticket on the confirm page: %s", page.body)
	}
	path, _, _ := strings.Cut(link, "?")
	form := url.Values{"t": {html.UnescapeString(m[1])}}
	r = c.do(http.MethodPost, path, form, "Sec-Fetch-Site", "same-origin", "Origin", s.URLs[0])
	if r.StatusCode != http.StatusFound || c.sessionValue() == "" {
		t.Fatalf("the browser after the preview: %d %s", r.StatusCode, r.body)
	}

	again := newClient(t, s)
	r = again.do(http.MethodPost, path, form, "Sec-Fetch-Site", "same-origin", "Origin", s.URLs[0])
	if r.StatusCode != http.StatusBadRequest || errorCode(t, r) != "mint_ticket_stale" {
		t.Fatalf("a second spend: %d %s", r.StatusCode, r.body)
	}
}

func TestCrossSitePOST(t *testing.T) {
	t.Parallel()
	s := sharedStack(t)
	link := ticket(t, s, s.URLs[0], "bot-one", time.Hour)
	path, nonce, _ := strings.Cut(link, "?t=")
	form := url.Values{"t": {nonce}}

	c := newClient(t, s)
	r := c.do(http.MethodPost, path, form, "Sec-Fetch-Site", "cross-site", "Origin", "https://evil.example")
	if r.StatusCode != http.StatusForbidden || errorCode(t, r) != "cross_origin_request" {
		t.Fatalf("cross-site: %d %s", r.StatusCode, r.body)
	}

	// No browser headers at all is the scripted path, and the ticket survived the refusal above.
	r = c.do(http.MethodPost, path, form)
	if r.StatusCode != http.StatusFound || c.sessionValue() == "" {
		t.Fatalf("the scripted POST: %d %s", r.StatusCode, r.body)
	}
}

func TestRefresh(t *testing.T) {
	t.Parallel()
	s := sharedStack(t)
	c := newClient(t, s)
	if r := c.login(s.URLs[0], "/me", stack.Carol); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d %s", r.StatusCode, r.body)
	}
	sid := openSession(t, s, c.sessionValue()).SID
	before := ageRecord(t, s, sid)

	c.setSession(nearExpiry(t, s, c.sessionValue()))
	r, me := c.me(s.URLs[0], "")
	if r.StatusCode != http.StatusOK || me.Claims["email"] != stack.Carol.Email {
		t.Fatalf("near expiry: %d %s", r.StatusCode, r.body)
	}
	if st := openSession(t, s, c.sessionValue()); time.Until(time.Unix(st.Exp, 0)) < 50*time.Minute {
		t.Fatalf("the cookie was not renewed: exp in %s", time.Until(time.Unix(st.Exp, 0)))
	}
	after, err := record(t, s, sid)
	if err != nil {
		t.Fatal(err)
	}
	if string(after.State) == string(before.State) {
		t.Fatal("the refresh token in the record did not change")
	}
	if !after.VerifiedAt.After(before.VerifiedAt) {
		t.Fatalf("VerifiedAt did not move: %s, then %s", before.VerifiedAt, after.VerifiedAt)
	}
}

func TestIdPDown(t *testing.T) {
	t.Parallel()
	s := ownStack(t)
	c := newClient(t, s)
	if r := c.login(s.URLs[0], "/me", stack.Alice); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d %s", r.StatusCode, r.body)
	}
	cookie := c.sessionValue()
	sid := openSession(t, s, cookie).SID
	before := ageRecord(t, s, sid)

	s.Dex.Stop()
	r, _ := c.me(s.URLs[0], nearExpiry(t, s, cookie))
	if r.StatusCode != http.StatusOK {
		t.Fatalf("Dex down, inside the grace window: %d %s", r.StatusCode, r.body)
	}
	if rec, _ := record(t, s, sid); !rec.VerifiedAt.Equal(before.VerifiedAt) {
		t.Fatalf("VerifiedAt moved while Dex was down: %s, then %s", before.VerifiedAt, rec.VerifiedAt)
	}

	if err := s.Dex.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	// The failed attempt left its claim on the record, which holds every instance back for a few
	// seconds, so the next request that refreshes is a few requests away.
	eventually(t, 30*time.Second, "a refresh after Dex came back", func() bool {
		if r, _ := c.me(s.URLs[0], nearExpiry(t, s, cookie)); r.StatusCode != http.StatusOK {
			t.Fatalf("Dex back: %d %s", r.StatusCode, r.body)
		}
		rec, err := record(t, s, sid)
		return err == nil && rec.VerifiedAt.After(before.VerifiedAt)
	})
}

func TestIdPRefuses(t *testing.T) {
	t.Parallel()
	s := ownStack(t)
	c := newClient(t, s)
	if r := c.login(s.URLs[0], "/me", stack.Alice); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d %s", r.StatusCode, r.body)
	}
	sid := openSession(t, s, c.sessionValue()).SID
	ageRecord(t, s, sid)

	// What a revocation does to Dex's storage.
	if _, err := s.Etcd.Delete(t.Context(), stack.DexPrefix+"refresh_token/", clientv3.WithPrefix()); err != nil {
		t.Fatal(err)
	}
	c.setSession(nearExpiry(t, s, c.sessionValue()))
	r, _ := c.me(s.URLs[0], "")
	if r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("after the revocation: %d %s", r.StatusCode, r.body)
	}
	if c.sessionValue() != "" {
		t.Fatal("the session cookie was not cleared")
	}
	if _, err := record(t, s, sid); err == nil {
		t.Fatal("the session record is still there")
	}
	if r := c.get(s.URLs[0] + "/me"); r.StatusCode != http.StatusFound ||
		!strings.Contains(r.Header.Get("Location"), "/auth/oidc/dex/login") {
		t.Fatalf("the next page: %d, Location %q", r.StatusCode, r.Header.Get("Location"))
	}
}

func TestLogoutReachesB(t *testing.T) {
	t.Parallel()
	s := sharedStack(t)
	c := newClient(t, s)
	if r := c.login(s.URLs[0], "/me", stack.Alice); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d %s", r.StatusCode, r.body)
	}
	cookie := c.sessionValue()
	// B has served the session, so it is in B's cache: what has to reach B is the deletion.
	if r, _ := c.me(s.URLs[1], cookie); r.StatusCode != http.StatusOK {
		t.Fatalf("B before the logout: %d %s", r.StatusCode, r.body)
	}

	if r := c.do(http.MethodPost, s.URLs[0]+"/auth/logout", nil); r.StatusCode != http.StatusSeeOther ||
		r.Header.Get("Location") != "/" {
		t.Fatalf("logout on A: %d to %q %s", r.StatusCode, r.Header.Get("Location"), r.body)
	}
	eventually(t, 5*time.Second, "B refusing the logged-out cookie", func() bool {
		r, _ := c.me(s.URLs[1], cookie)
		return r.StatusCode == http.StatusUnauthorized
	})
}

func TestOneRefreshForTwo(t *testing.T) {
	t.Parallel()
	s := sharedStack(t)
	c := newClient(t, s)
	if r := c.login(s.URLs[0], "/me", stack.Dave); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d %s", r.StatusCode, r.body)
	}
	ageRecord(t, s, openSession(t, s, c.sessionValue()).SID)
	near := nearExpiry(t, s, c.sessionValue())

	// Dex refuses a refresh token presented twice, and a refusal ends the session: had both instances
	// refreshed, one of them would answer 401.
	var wg sync.WaitGroup
	results := make([]response, len(s.URLs))
	for i, base := range s.URLs {
		wg.Go(func() { results[i], _ = c.me(base, near) })
	}
	wg.Wait()
	for i, r := range results {
		if r.StatusCode != http.StatusOK {
			t.Fatalf("instance %d: %d %s", i, r.StatusCode, r.body)
		}
	}
	if r, _ := c.me(s.URLs[0], near); r.StatusCode != http.StatusOK {
		t.Fatalf("the third request: %d %s", r.StatusCode, r.body)
	}
}
