// Package mint signs in by redeeming a one-time ticket issued on the host: the way in for a subject that
// cannot answer an interactive prompt at an identity provider, such as an automated browser or an agent.
//
// The host writes a ticket and hands out the path it returns: with Issue, typically from a command line
// that has no auth.Manager, or with Method.Issue where it already holds the method. Opening that path
// spends nothing: it serves a page that posts the ticket back at once, or offers a button to a browser
// without JavaScript, and that POST spends the ticket and starts a session with a fixed deadline. From the browser on it is an ordinary session of the auth.Manager — the same
// cookie, the same record, the same Require — except that nothing revalidates it: its deadline is what
// ends it.
//
// The two steps are there because whatever fetches a link to preview it, a chat client or a mail
// scanner, would otherwise spend the ticket before the person or agent it was meant for got to open it.
// A fetcher that runs JavaScript still posts the page and spends it; one that does not, never does. A
// scripted client may skip the page and POST t=<nonce> to the path itself.
//
// The POST refuses a browser request from another site, so that the page is the only way a browser
// reaches it. That check reads Sec-Fetch-Site, and falls back to comparing Origin with Host when a
// browser sends none, which a reverse proxy rewriting Host can make misjudge.
package mint

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/at-orz/x/auth"
	"github.com/at-orz/x/auth/internal/web"
)

// Ticket buys one session for one subject. It carries a length rather than an end, because the session
// begins when the browser opens the link, not when the host wrote it.
type Ticket struct {
	Subject    string        `json:"sub"`
	SessionTTL time.Duration `json:"session_ttl"`
	CreatedAt  time.Time     `json:"created_at"`
}

// Tickets is where the host writes tickets and this method spends them.
type Tickets interface {
	// Put stores a ticket under a nonce; an unspent ticket is gone after ttl.
	Put(ctx context.Context, nonce string, t Ticket, ttl time.Duration) error
	// Redeem destroys the ticket as it reads it, so that of two redemptions at once exactly one gets it. It
	// reports auth.ErrNotFound for a ticket that is unknown, spent or expired.
	Redeem(ctx context.Context, nonce string) (Ticket, error)
}

// TicketTTL is how long a ticket may wait to be redeemed.
const TicketTTL = 10 * time.Minute

// Options configure a Method. Tickets is required.
type Options struct {
	// Name is the Provider of the identities this method signs in, and appears in its path. Default
	// "mint".
	Name    string
	Tickets Tickets
}

// Method is the ticket sign-in. It implements auth.Method.
type Method struct {
	m       *auth.Manager
	name    string
	tickets Tickets
	path    string
	cop     *http.CrossOriginProtection
}

var namePattern = regexp.MustCompile(`^[a-z0-9-]+$`)

// resolve is shared by New and Issue, so that a command line refuses the same Options the server does.
func (o Options) resolve() (name, path string, err error) {
	name = o.Name
	if name == "" {
		name = "mint"
	}
	if !namePattern.MatchString(name) {
		return "", "", fmt.Errorf("mint: name %q is not [a-z0-9-]+", name)
	}
	if o.Tickets == nil {
		return "", "", errors.New("mint: Options.Tickets is required")
	}
	return name, "/auth/mint/" + name, nil
}

// New builds a Method and registers it with m.
func New(m *auth.Manager, o Options) (*Method, error) {
	name, path, err := o.resolve()
	if err != nil {
		return nil, err
	}
	mt := &Method{m: m, name: name, tickets: o.Tickets, path: path, cop: http.NewCrossOriginProtection()}
	if err := m.Register(mt); err != nil {
		return nil, err
	}
	return mt, nil
}

// Name is the method's name.
func (mt *Method) Name() string { return mt.name }

// LoginURL is "": a ticket sign-in starts on the host, never from a page.
func (mt *Method) LoginURL(string) string { return "" }

// Revalidate is never asked of a session with a deadline, which every session of this method has. A
// record of this method without one cannot be vouched for by anyone, so it ends.
func (mt *Method) Revalidate(_ context.Context, rec auth.Record) (auth.Record, error) {
	return rec, fmt.Errorf("%w: a minted session has nothing to revalidate", auth.ErrEnded)
}

// Issue writes a ticket for a session of subject lasting sessionTTL from its redemption, and returns the
// path that redeems it, for a host command to print. Opening the path in a browser signs in; a scripted
// client may instead POST its t to the path without the query. The path is a credential until it is
// spent.
func (mt *Method) Issue(ctx context.Context, subject string, sessionTTL time.Duration) (path string, err error) {
	return issue(ctx, mt.tickets, mt.path, subject, sessionTTL)
}

// Issue writes a ticket for a session of subject lasting sessionTTL from its redemption, and returns the
// path that redeems it at a Method built from the same Options. It needs no auth.Manager, so a host
// command can write a ticket without the session key or store. The path is a credential until it is
// spent.
func Issue(ctx context.Context, o Options, subject string, sessionTTL time.Duration) (path string, err error) {
	_, path, err = o.resolve()
	if err != nil {
		return "", err
	}
	return issue(ctx, o.Tickets, path, subject, sessionTTL)
}

func issue(ctx context.Context, tickets Tickets, path, subject string, sessionTTL time.Duration) (string, error) {
	if subject == "" {
		return "", errors.New("mint: a ticket needs a subject")
	}
	if sessionTTL <= 0 {
		return "", fmt.Errorf("mint: a session length of %s", sessionTTL)
	}
	nonce := web.RandomToken()
	if err := tickets.Put(ctx, nonce, Ticket{Subject: subject, SessionTTL: sessionTTL, CreatedAt: time.Now()}, TicketTTL); err != nil {
		return "", fmt.Errorf("mint: writing the ticket: %w", err)
	}
	return path + "?" + url.Values{"t": {nonce}}.Encode(), nil
}

// Routes mounts /auth/mint/<name>, which needs no session itself: holding the ticket is what stands in
// for a login. A GET serves the page that posts the ticket, and the POST spends it.
func (mt *Method) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET "+mt.path, mt.handleConfirm)
	mux.HandleFunc("POST "+mt.path, mt.handleRedeem)
}

// confirmScript is allowed by its hash rather than by a nonce per response: it never changes, and taking
// the hash from the very constant the template inlines keeps the two from drifting apart.
const confirmScript = `document.forms[0].submit()`

var confirmScriptHash = func() string {
	sum := sha256.Sum256([]byte(confirmScript))
	return "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
}()

// The button stays visible for a browser that runs no script; the script comes after the form so that
// the form exists when it runs.
var confirmPage = template.Must(template.New("confirm").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>Sign in</title></head>
<body>
<form method="post" action="{{.Action}}"><input type="hidden" name="t" value="{{.Nonce}}"><button type="submit">Sign in</button></form>
<script>` + confirmScript + `</script>
</body></html>
`))

// handleConfirm serves the page that posts a ticket back, without looking the ticket up: that would need
// a read of Tickets that does not destroy, a contract change for every store, only to show an error one
// round trip sooner.
func (mt *Method) handleConfirm(w http.ResponseWriter, r *http.Request) {
	nonce := r.URL.Query().Get("t")
	if nonce == "" {
		mt.m.Log().Warn("a sign-in link arrived carrying no ticket", "method", mt.name, "remote", r.RemoteAddr)
		mt.m.Fail(w, http.StatusBadRequest, "mint_ticket_stale", web.TicketStale)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	// The page carries the nonce, and so does the URL it was opened at.
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	// frame-ancestors keeps another site from loading the page in a frame, where it would submit itself
	// without anybody seeing it.
	h.Set("Content-Security-Policy", "default-src 'none'; script-src '"+confirmScriptHash+
		"'; form-action 'self'; frame-ancestors 'none'")
	if err := confirmPage.Execute(w, struct{ Action, Nonce string }{mt.path, nonce}); err != nil {
		mt.m.Log().Warn("writing the sign-in page failed", "method", mt.name, "err", err)
	}
}

// handleRedeem spends a ticket and hands back a session.
//
// The nonce is read from the form body alone, never the query, which keeps it out of the access log of
// this request. A browser request from another site is refused before the ticket is touched, so the
// ticket survives a form posted at it from elsewhere.
//
// It takes no ret parameter, unlike a login. Minting is begun on the host, where there is no page
// somebody was trying to reach, and a parameter that redirects would be one more thing to hold to
// SafeReturn.
//
// The nonce appears in no log line and no error: until it is spent it is a credential.
func (mt *Method) handleRedeem(w http.ResponseWriter, r *http.Request) {
	log := mt.m.Log()
	if err := mt.cop.Check(r); err != nil {
		log.Warn("a sign-in link was posted from another site", "method", mt.name, "remote", r.RemoteAddr,
			"err", err)
		mt.m.Fail(w, http.StatusForbidden, "cross_origin_request", web.CrossOrigin)
		return
	}
	nonce := r.PostFormValue("t")
	if nonce == "" {
		log.Warn("a sign-in link arrived carrying no ticket", "method", mt.name, "remote", r.RemoteAddr)
		mt.m.Fail(w, http.StatusBadRequest, "mint_ticket_stale", web.TicketStale)
		return
	}
	ticket, err := mt.tickets.Redeem(r.Context(), nonce)
	if err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			// The browser is not sent back through a login, unlike a callback that lost its flow cookie: that
			// one is fixed by trying again, and a ticket that is gone stays gone.
			log.Warn("a sign-in link was already spent, has expired or never existed", "method", mt.name,
				"remote", r.RemoteAddr)
			mt.m.Fail(w, http.StatusBadRequest, "mint_ticket_stale", web.TicketStale)
			return
		}
		// A ticket that cannot be read is not a ticket that is gone: reporting a dead link over a store that
		// is merely unreachable would send somebody to the host to issue another one for nothing.
		log.Error("redeeming a sign-in ticket failed", "method", mt.name, "err", err)
		mt.m.Fail(w, http.StatusServiceUnavailable, "session_store_unavailable", web.LoginFailedRetry)
		return
	}

	// The length was fixed when the ticket was written and the deadline is fixed now, because a session
	// begins when somebody opens the link rather than when the host prepared it.
	err = mt.m.Issue(w, r, auth.Grant{
		Identity: auth.Identity{Provider: mt.name, Subject: ticket.Subject},
		Deadline: time.Now().Add(ticket.SessionTTL),
	})
	switch {
	case errors.Is(err, auth.ErrNotAllowed):
		mt.m.Fail(w, http.StatusForbidden, "subject_not_allowed", web.NotAllowed)
		return
	case err != nil:
		mt.m.Fail(w, http.StatusServiceUnavailable, "session_store_unavailable", web.LoginFailedRetry)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}
