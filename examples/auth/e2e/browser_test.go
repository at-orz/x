package e2e

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/at-orz/x/examples/auth/internal/stack"
	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// screenshotDir is the repository's .tmp/e2e, from this package's directory.
var screenshotDir = filepath.Join("..", "..", "..", ".tmp", "e2e")

var (
	// browser is one headless Chromium for the whole test binary; each test opens a browser context of
	// its own in it, with its own cookies. Nil when noBrowser is set.
	browser   context.Context
	noBrowser string
)

// startBrowser starts Chromium for the browser tests, and returns what stops it.
func startBrowser(s *stack.Stack) (stop func(), err error) {
	path, err := exec.LookPath("chromium")
	if err != nil {
		noBrowser = "no chromium on PATH; this runs inside the devshell"
		return func() {}, nil
	}
	alloc, cancelAlloc := chromedp.NewExecAllocator(context.Background(), append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(path),
		// ubuntu runners restrict the unprivileged user namespaces Chromium's sandbox needs, and the browser
		// only ever loads pages of the stack.
		chromedp.NoSandbox,
		// Exactly the stack's certificate, rather than every bad one as --ignore-certificate-errors would.
		chromedp.Flag("ignore-certificate-errors-spki-list", s.SPKIHash),
	)...)
	ctx, cancel := chromedp.NewContext(alloc)
	stop = func() {
		cancel()
		cancelAlloc()
	}
	if err := chromedp.Do(ctx); err != nil {
		stop()
		return nil, err
	}
	browser = ctx
	return stop, nil
}

// tab is a fresh browser context and a tab in it. On failure it saves a screenshot.
func tab(t *testing.T) context.Context {
	t.Helper()
	if browser == nil {
		if shared == nil {
			t.Skip(skipped)
		}
		t.Skip(noBrowser)
	}
	ctx, cancel := chromedp.NewContext(browser, chromedp.WithNewBrowserContext())
	t.Cleanup(cancel)
	// The first action opens the tab, and a timeout on it would close the tab with it.
	if err := chromedp.Do(ctx); err != nil {
		t.Fatalf("opening a tab: %v", err)
	}
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		// The text as well as the picture: a machine without fonts renders a screenshot with no glyphs.
		loc, _ := chromedp.Run(ctx, chromedp.Location())
		text, _ := chromedp.Run(ctx, chromedp.Evaluate[string](`document.body ? document.body.textContent : ""`))
		t.Logf("the tab is at %s, showing:\n%s", loc, strings.TrimSpace(text))
		png, err := chromedp.Run(ctx, chromedp.FullScreenshot(100))
		if err != nil {
			t.Logf("no screenshot: %v", err)
			return
		}
		name := filepath.Join(screenshotDir, strings.ReplaceAll(t.Name(), "/", "_")+".png")
		if err := os.MkdirAll(screenshotDir, 0o755); err == nil {
			if err := os.WriteFile(name, png, 0o644); err == nil {
				t.Logf("screenshot: %s", name)
			}
		}
	})
	return ctx
}

// secondTab is another tab in the browser context of ctx, sharing its cookies.
func secondTab(t *testing.T, ctx context.Context) context.Context {
	t.Helper()
	ctx2, cancel := chromedp.NewContext(ctx)
	t.Cleanup(cancel)
	if err := chromedp.Do(ctx2); err != nil {
		t.Fatalf("opening a second tab: %v", err)
	}
	return ctx2
}

// act runs steps with a timeout.
func act(t *testing.T, ctx context.Context, steps ...chromedp.Action[chromedp.Void]) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := chromedp.Do(ctx, steps...); err != nil {
		t.Fatal(err)
	}
}

func value[T any](t *testing.T, ctx context.Context, a chromedp.Action[T]) T {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	v, err := chromedp.Run(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// fillLogin submits Dex's login form, which the tab is on or about to be on.
func fillLogin(user stack.User) []chromedp.Action[chromedp.Void] {
	return []chromedp.Action[chromedp.Void]{
		chromedp.WaitVisible(chromedp.ID("password")),
		chromedp.SetValue(chromedp.ID("login"), user.Email),
		chromedp.SetValue(chromedp.ID("password"), user.Password),
		chromedp.Click(chromedp.ID("submit-login")),
	}
}

// browserLogin opens base+path and signs user in at Dex, ending on the page it was after.
func browserLogin(t *testing.T, ctx context.Context, base, path string, user stack.User) {
	t.Helper()
	defer lockUser(user)()
	act(t, ctx, append(append([]chromedp.Action[chromedp.Void]{chromedp.Navigate(base + path)},
		fillLogin(user)...), chromedp.WaitVisible(chromedp.ID("subject")))...)
}

// sessionCookieIn is the session cookie the browser holds for base, or nil.
func sessionCookieIn(t *testing.T, ctx context.Context, base string) *network.Cookie {
	t.Helper()
	res, err := chromedp.Call(ctx, network.GetCookies, network.GetCookiesParams{URLs: []string{base}})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range res.Cookies {
		if c.Name == sessionCookie {
			return c
		}
	}
	return nil
}

// waitLive waits until the /me page's live connection says want.
func waitLive(t *testing.T, ctx context.Context, want string, timeout time.Duration) {
	t.Helper()
	value(t, ctx, chromedp.Poll[bool](`document.getElementById("live").textContent === "`+want+`"`,
		chromedp.WithPollingTimeout(timeout)))
}

func TestBrowserOIDCRoundTrip(t *testing.T) {
	t.Parallel()
	s := sharedStack(t)
	ctx := tab(t)
	browserLogin(t, ctx, s.URLs[0], "/me", stack.Alice)
	if loc := value(t, ctx, chromedp.Location()); loc != s.URLs[0]+"/me" {
		t.Fatalf("after the login: %s", loc)
	}
	if user := value(t, ctx, chromedp.TextContent(chromedp.ID("user"))); user != "user:"+stack.Alice.Email {
		t.Fatalf("app user %q", user)
	}

	act(t, ctx, chromedp.Click(chromedp.ID("logout")), chromedp.WaitVisible(chromedp.ID("status")))
	if st := value(t, ctx, chromedp.TextContent(chromedp.ID("status"))); st != "Not signed in." {
		t.Fatalf("after the logout: %q", st)
	}
	act(t, ctx, chromedp.Navigate(s.URLs[0]+"/me"), chromedp.WaitVisible(chromedp.ID("password")))
	if loc := value(t, ctx, chromedp.Location()); !strings.HasPrefix(loc, s.Dex.Issuer) {
		t.Fatalf("/me after the logout ended at %s, not at Dex", loc)
	}
}

func TestBrowserReturnURLKept(t *testing.T) {
	t.Parallel()
	s := sharedStack(t)
	ctx := tab(t)
	browserLogin(t, ctx, s.URLs[0], "/me?tab=x", stack.Alice)
	if loc := value(t, ctx, chromedp.Location()); loc != s.URLs[0]+"/me?tab=x" {
		t.Fatalf("after the login: %s", loc)
	}
}

func TestBrowserCookieAttributes(t *testing.T) {
	t.Parallel()
	s := sharedStack(t)
	ctx := tab(t)
	browserLogin(t, ctx, s.URLs[0], "/me", stack.Alice)
	c := sessionCookieIn(t, ctx, s.URLs[0])
	if c == nil {
		t.Fatal("no session cookie")
	}
	if !c.Secure || !c.HTTPOnly || c.SameSite != network.CookieSameSiteLax {
		t.Fatalf("Secure %v, HttpOnly %v, SameSite %q", c.Secure, c.HTTPOnly, c.SameSite)
	}
	if dc := value(t, ctx, chromedp.Evaluate[string]("document.cookie")); strings.Contains(dc, sessionCookie) {
		t.Fatalf("the page's script sees the session cookie: %q", dc)
	}
}

func TestBrowserRefusedSubject(t *testing.T) {
	t.Parallel()
	s := sharedStack(t)
	ctx := tab(t)
	act(t, ctx, chromedp.Navigate(s.URLs[0]+"/me"))
	steps := fillLogin(stack.Bob)
	act(t, ctx, steps[:3]...)
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := chromedp.RunResponse(rctx, steps[3])
	if err != nil {
		t.Fatal(err)
	}
	body := value(t, ctx, chromedp.TextContent(chromedp.CSS("body")))
	if resp.Status != http.StatusForbidden || !strings.Contains(body, "subject_not_allowed") {
		t.Fatalf("got %d: %s", resp.Status, body)
	}
	if c := sessionCookieIn(t, ctx, s.URLs[0]); c != nil {
		t.Fatal("a refused sign-in left a session cookie")
	}
}

func TestBrowserTicketSignIn(t *testing.T) {
	t.Parallel()
	s := sharedStack(t)
	ctx := tab(t)
	act(t, ctx, chromedp.Navigate(ticket(t, s, s.URLs[0], "bot-one", time.Hour)), chromedp.WaitVisible(chromedp.ID("subject")))
	if loc := value(t, ctx, chromedp.Location()); loc != s.URLs[0]+"/" {
		t.Fatalf("after the ticket: %s", loc)
	}
	if sub := value(t, ctx, chromedp.TextContent(chromedp.ID("subject"))); sub != "bot-one" {
		t.Fatalf("signed in as %q", sub)
	}
	if dl := value(t, ctx, chromedp.TextContent(chromedp.ID("deadline"))); dl == "" {
		t.Fatal("no deadline shown")
	}
}

func TestBrowserTicketWithoutScript(t *testing.T) {
	t.Parallel()
	s := sharedStack(t)
	ctx := tab(t)
	if _, err := chromedp.Call(ctx, emulation.SetScriptExecutionDisabled, emulation.SetScriptExecutionDisabledParams{Value: true}); err != nil {
		t.Fatal(err)
	}
	link := ticket(t, s, s.URLs[0], "bot-one", time.Hour)
	act(t, ctx, chromedp.Navigate(link), chromedp.WaitVisible(chromedp.CSS("button")), chromedp.Sleep(500*time.Millisecond))
	if loc := value(t, ctx, chromedp.Location()); loc != link {
		t.Fatalf("the confirm page did not stay: now at %s", loc)
	}
	act(t, ctx, chromedp.Click(chromedp.CSS("button")), chromedp.WaitVisible(chromedp.ID("subject")))
	if sub := value(t, ctx, chromedp.TextContent(chromedp.ID("subject"))); sub != "bot-one" {
		t.Fatalf("signed in as %q", sub)
	}
}

func TestBrowserSharedSession(t *testing.T) {
	t.Parallel()
	s := sharedStack(t)
	ctx := tab(t)
	browserLogin(t, ctx, s.URLs[0], "/me", stack.Alice)
	act(t, ctx, chromedp.Navigate(s.URLs[1]+"/me"), chromedp.WaitVisible(chromedp.ID("subject")))
	if loc := value(t, ctx, chromedp.Location()); loc != s.URLs[1]+"/me" {
		t.Fatalf("/me on B ended at %s", loc)
	}
}

func TestBrowserLiveClosedOnLogout(t *testing.T) {
	t.Parallel()
	s := sharedStack(t)
	ctx := tab(t)
	act(t, ctx, chromedp.Navigate(ticket(t, s, s.URLs[0], "bot-one", time.Hour)), chromedp.WaitVisible(chromedp.ID("subject")),
		chromedp.Navigate(s.URLs[0]+"/me"))
	waitLive(t, ctx, "open", 10*time.Second)

	other := secondTab(t, ctx)
	act(t, other, chromedp.Navigate(s.URLs[0]+"/me"), chromedp.Click(chromedp.ID("logout")),
		chromedp.WaitVisible(chromedp.ID("status")))
	start := time.Now()
	waitLive(t, ctx, "session ended", 10*time.Second)
	t.Logf("closed %s after the logout", time.Since(start).Round(100*time.Millisecond))
}

func TestBrowserLiveClosedOnDeadline(t *testing.T) {
	t.Parallel()
	s := sharedStack(t)
	ctx := tab(t)
	act(t, ctx, chromedp.Navigate(ticket(t, s, s.URLs[0], "bot-one", 4*time.Second)), chromedp.WaitVisible(chromedp.ID("subject")),
		chromedp.Navigate(s.URLs[0]+"/me"))
	waitLive(t, ctx, "open", 10*time.Second)
	waitLive(t, ctx, "session ended", 15*time.Second)
}
