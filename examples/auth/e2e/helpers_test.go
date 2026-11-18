package e2e

import (
	"crypto/tls"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/at-orz/x/auth"
	"github.com/at-orz/x/auth/store/etcd"
	"github.com/at-orz/x/auth/store/memory"
	"github.com/at-orz/x/examples/auth/app"
	"github.com/at-orz/x/examples/auth/internal/demo"
	"github.com/at-orz/x/examples/auth/internal/stack"
)

// sessionCookie is the name of the app's session cookie: the default prefix of auth.Options.
const sessionCookie = "auth_session"

// client is one browser's worth of HTTP: a cookie jar, the stack's CA, and no automatic redirects, so
// that every status code is seen.
type client struct {
	t   *testing.T
	s   *stack.Stack
	hc  *http.Client
	jar *cookiejar.Jar
}

func newClient(t *testing.T, s *stack.Stack) *client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: s.CAPool}}
	t.Cleanup(tr.CloseIdleConnections)
	return &client{t: t, s: s, jar: jar, hc: &http.Client{
		Transport:     tr,
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// response is a response with its body read.
type response struct {
	*http.Response
	body string
}

// do sends a request, with headers given as name, value pairs.
func (c *client) do(method, u string, form url.Values, headers ...string) response {
	c.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(c.t.Context(), method, u, body)
	if err != nil {
		c.t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, u, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		c.t.Fatalf("%s %s: reading the body: %v", method, u, err)
	}
	return response{resp, string(b)}
}

func (c *client) get(u string, headers ...string) response {
	c.t.Helper()
	return c.do(http.MethodGet, u, nil, headers...)
}

// follow follows redirects from r until a response that is not one.
func (c *client) follow(r response) response {
	c.t.Helper()
	for range 10 {
		if r.StatusCode < 300 || r.StatusCode >= 400 {
			return r
		}
		next, err := r.Request.URL.Parse(r.Header.Get("Location"))
		if err != nil {
			c.t.Fatal(err)
		}
		r = c.get(next.String())
	}
	c.t.Fatalf("more than 10 redirects, ending at %s", r.Request.URL)
	return r
}

// signingIn serializes the sign-ins of each user. Dex keeps one offline session per user and client,
// and of two sign-ins of one user finishing at once it fails one with a conflicting update, so tests
// running in parallel take turns at signing a user in, and only at that.
var signingIn sync.Map

func lockUser(u stack.User) (unlock func()) {
	mu, _ := signingIn.LoadOrStore(u.Email, &sync.Mutex{})
	mu.(*sync.Mutex).Lock()
	return mu.(*sync.Mutex).Unlock
}

var loginForm = regexp.MustCompile(`<form method="post" action="([^"]+)"`)

// pageNonce is the ticket the confirm page posts back.
var pageNonce = regexp.MustCompile(`name="t" value="([^"]+)"`)

// login signs user in at Dex through the app at base, starting from path, and returns the response
// the app ends on.
func (c *client) login(base, path string, user stack.User) response {
	c.t.Helper()
	defer lockUser(user)()
	form := c.follow(c.get(base + path))
	m := loginForm.FindStringSubmatch(form.body)
	if m == nil {
		c.t.Fatalf("no login form at %s: %d %s", form.Request.URL, form.StatusCode, form.body)
	}
	action, err := form.Request.URL.Parse(html.UnescapeString(m[1]))
	if err != nil {
		c.t.Fatal(err)
	}
	return c.follow(c.do(http.MethodPost, action.String(),
		url.Values{"login": {user.Email}, "password": {user.Password}}))
}

// sessionValue is the session cookie the jar holds for the stack, or "".
func (c *client) sessionValue() string {
	u, _ := url.Parse(c.s.URLs[0])
	for _, k := range c.jar.Cookies(u) {
		if k.Name == sessionCookie {
			return k.Value
		}
	}
	return ""
}

// me is GET /api/me as JSON, sending cookie in place of the jar's when it is set: a test that wants
// to know what the server does with a cookie the browser would already have dropped sends it itself.
func (c *client) me(base, cookie string) (response, app.Me) {
	c.t.Helper()
	var r response
	if cookie == "" {
		r = c.get(base+"/api/me", "Accept", "application/json")
	} else {
		bare := &http.Client{Transport: c.hc.Transport,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		req, err := http.NewRequestWithContext(c.t.Context(), http.MethodGet, base+"/api/me", nil)
		if err != nil {
			c.t.Fatal(err)
		}
		req.Header.Set("Accept", "application/json")
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
		resp, err := bare.Do(req)
		if err != nil {
			c.t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		r = response{resp, string(b)}
	}
	var me app.Me
	if r.StatusCode == http.StatusOK {
		if err := json.Unmarshal([]byte(r.body), &me); err != nil {
			c.t.Fatalf("decoding /api/me: %v: %s", err, r.body)
		}
	}
	return r, me
}

// quickInterval is the revalidation interval of a quickStack: the refresh window and the refresh floor
// are 2s each.
const quickInterval = 4 * time.Second

// untilRefresh waits from a sign-in on a quickStack until its session is due a revalidation. 3s is past
// the 2s floor, and leaves the cookie's exp at most a second out, inside the 2s window, whichever way
// the whole seconds of exp were truncated.
func untilRefresh() {
	time.Sleep(3 * time.Second)
}

// sessionID is the id of the session a cookie value names, read with a Manager on the stack's key.
func sessionID(t *testing.T, s *stack.Stack, cookie string) string {
	t.Helper()
	m, err := auth.New(auth.Options{Store: memory.New(), Key: s.Key, Authorize: auth.AnyOf()})
	if err != nil {
		t.Fatal(err)
	}
	sid, err := m.SessionID(cookie)
	if err != nil {
		t.Fatalf("reading the session cookie: %v", err)
	}
	return sid
}

// record reads a session record straight from etcd, through the store the app uses.
func record(t *testing.T, s *stack.Stack, sid string) (auth.Record, error) {
	t.Helper()
	return etcd.New(s.Etcd, demo.EtcdPrefix).Get(t.Context(), sid)
}

// ticket writes a ticket and returns its link at base.
func ticket(t *testing.T, s *stack.Stack, base, subject string, ttl time.Duration) string {
	t.Helper()
	path, err := app.IssueTicket(t.Context(), app.Config{Tickets: etcd.New(s.Etcd, demo.EtcdPrefix).Tickets()}, subject, ttl)
	if err != nil {
		t.Fatal(err)
	}
	return base + path
}

// errorCode is the code of auth's default JSON error body.
func errorCode(t *testing.T, r response) string {
	t.Helper()
	var e struct {
		Error struct{ Code string } `json:"error"`
	}
	if err := json.Unmarshal([]byte(r.body), &e); err != nil {
		t.Fatalf("not an error body (%d): %s", r.StatusCode, r.body)
	}
	return e.Error.Code
}

// eventually polls cond until it holds or timeout passes.
func eventually(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s did not happen within %s", what, timeout)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
