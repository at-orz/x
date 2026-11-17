// Package mint signs in by redeeming a one-time ticket issued on the host: the way in for a subject that
// cannot answer an interactive prompt at an identity provider, such as an automated browser or an agent.
//
// The host writes a ticket (Method.Issue, typically from a command line) and hands out the path it
// returns; opening that path spends the ticket and starts a session with a fixed deadline. From the
// browser on it is an ordinary session of the auth.Manager — the same cookie, the same record, the same
// Require — except that nothing revalidates it: its deadline is what ends it.
package mint

import (
	"context"
	"errors"
	"fmt"
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
}

var namePattern = regexp.MustCompile(`^[a-z0-9-]+$`)

// New builds a Method and registers it with m.
func New(m *auth.Manager, o Options) (*Method, error) {
	if o.Name == "" {
		o.Name = "mint"
	}
	if !namePattern.MatchString(o.Name) {
		return nil, fmt.Errorf("mint: name %q is not [a-z0-9-]+", o.Name)
	}
	if o.Tickets == nil {
		return nil, errors.New("mint: Options.Tickets is required")
	}
	mt := &Method{m: m, name: o.Name, tickets: o.Tickets, path: "/auth/mint/" + o.Name}
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
// path that redeems it, for a host command to print. The path is a credential until it is spent.
func (mt *Method) Issue(ctx context.Context, subject string, sessionTTL time.Duration) (path string, err error) {
	if subject == "" {
		return "", errors.New("mint: a ticket needs a subject")
	}
	if sessionTTL <= 0 {
		return "", fmt.Errorf("mint: a session length of %s", sessionTTL)
	}
	nonce := web.RandomToken()
	if err := mt.tickets.Put(ctx, nonce, Ticket{Subject: subject, SessionTTL: sessionTTL, CreatedAt: time.Now()}, TicketTTL); err != nil {
		return "", fmt.Errorf("mint: writing the ticket: %w", err)
	}
	return mt.path + "?" + url.Values{"t": {nonce}}.Encode(), nil
}

// Routes mounts GET /auth/mint/<name>, which needs no session itself: holding the ticket is what stands
// in for a login.
func (mt *Method) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET "+mt.path, mt.handleRedeem)
}

// handleRedeem spends a ticket and hands back a session.
//
// It takes no ret parameter, unlike a login. Minting is begun on the host, where there is no page
// somebody was trying to reach, and a parameter that redirects would be one more thing to hold to
// SafeReturn.
//
// The nonce appears in no log line and no error: until it is spent it is a credential.
func (mt *Method) handleRedeem(w http.ResponseWriter, r *http.Request) {
	log := mt.m.Log()
	nonce := r.URL.Query().Get("t")
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
