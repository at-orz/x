package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/at-orz/x/auth/internal/web"
)

// errNoSession is the ordinary way to arrive unauthenticated: no cookie at all. It is told apart from the
// rest so that a cookie which was presented and did not hold earns a line in the log, while the polling of
// a tab whose session has ended does not.
var errNoSession = errors.New("the request carries no session cookie")

// errUnreachable means the authority, or the store, could not be asked at all: a connection failure, a
// timeout, a 5xx. It is not an answer about the session, and ending sessions over it would turn an outage
// of the authority into an outage of the host.
var errUnreachable = errors.New("the authority could not be asked")

// Require admits a request on a valid session and hands the Session on in its context (SessionFrom).
// Without one, a request accepting JSON and a WebSocket handshake receive 401, and anything else a
// redirect to the login.
func (m *Manager) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, err := m.authenticate(w, r)
		if err != nil {
			m.unauthenticated(w, r, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(WithSession(r.Context(), sess)))
	})
}

// Optional admits a request on a valid session as Require does, handing the Session on in its context
// (SessionFrom), and otherwise serves it without one where Require would refuse it. It is for a page
// that serves everybody and shows more to a signed-in visitor.
//
// Whatever Require writes on the way in it writes here too: a renewed session cookie, or the clearing of
// an ended one. A session store that cannot be read, which Require answers with 503, is served as no
// session.
func (m *Manager) Optional(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, err := m.authenticate(w, r)
		if err != nil {
			m.logRefusal(r, err)
			next.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r.WithContext(WithSession(r.Context(), sess)))
	})
}

// authenticate opens the cookie, finds whose session it is, revalidates once the cookie is close enough
// to its end, and asks Authorize.
func (m *Manager) authenticate(w http.ResponseWriter, r *http.Request) (Session, error) {
	c, err := r.Cookie(m.sessionCookie)
	if err != nil {
		return Session{}, errNoSession
	}
	var s sessionState
	if err := m.Open(c.Value, &s); err != nil {
		return Session{}, err
	}
	if s.SID == "" {
		return Session{}, errors.New("the session cookie carries no session")
	}

	// The deadline is decided here, on every request and before anything reads the store, so the first
	// request past it is the one refused. The record carries the same moment, but a comparison there
	// would sit behind the refresh window and could give the session another half interval.
	if s.Deadline != 0 && time.Now().After(time.Unix(s.Deadline, 0)) {
		web.ClearCookie(w, r, m.sessionCookie)
		return Session{}, fmt.Errorf("%w: the session reached its deadline", ErrEnded)
	}

	ctx := r.Context()
	var sess Session
	if time.Until(time.Unix(s.Exp, 0)) > m.refreshWindow {
		// The common case by far, and the one that has to stay cheap: a valid cookie is a signature check
		// and two map lookups, with neither the store nor the authority in the path of a request.
		sess, err = m.lookup(ctx, s.SID)
		if err != nil {
			if errors.Is(err, ErrEnded) {
				web.ClearCookie(w, r, m.sessionCookie)
			}
			return Session{}, err
		}
		if err := m.authorize(ctx, sess.Identity); err != nil {
			return Session{}, fmt.Errorf("%w: %w", ErrNotAllowed, err)
		}
		return sess, nil
	}

	// An exp already in the past is deliberately not refused here, which looks like a missing check and is
	// the point of the whole arrangement: coming back to a tab after lunch has to revalidate rather than
	// send somebody through the sign-in, and what decides whether the session is alive is the record, not
	// this timestamp. A cookie whose record is gone ends in refresh.
	sess, err = m.refresh(ctx, s.SID)
	switch {
	case err == nil:
	case errors.Is(err, ErrEnded):
		web.ClearCookie(w, r, m.sessionCookie)
		return Session{}, err
	case errors.Is(err, errUnreachable):
		// The authority could not be asked, which is not an answer about this session. It carries on and the
		// next request within the window tries again; the grace window bounds how long that may go on.
		m.log.Warn("revalidating a session failed, letting it through", "provider", sess.Identity.Provider,
			"subject", sess.Identity.Subject, "err", err)
	default:
		return Session{}, err
	}
	if err := m.authorize(ctx, sess.Identity); err != nil {
		return Session{}, fmt.Errorf("%w: %w", ErrNotAllowed, err)
	}
	m.setSessionCookie(w, r, sess.ID, sess.Deadline)
	return sess, nil
}

// lookup finds the session of a cookie outside the refresh window: from the live set and the cache when
// both hold it, from its record otherwise.
func (m *Manager) lookup(ctx context.Context, sid string) (Session, error) {
	if m.live.has(sid) {
		if s, ok := m.live.cached(sid); ok {
			return s, nil
		}
	}
	rec, err := m.store.Get(ctx, sid)
	switch {
	case err == nil:
		return m.remember(sid, rec), nil
	case errors.Is(err, ErrNotFound):
		m.live.drop(sid)
		return Session{}, fmt.Errorf("%w: the session record is gone", ErrEnded)
	}
	// A store that cannot be read is not an answer about the session, so one this process has seen carries
	// on as it was. One it has never seen cannot: the cookie names no one, so there is nobody to authorize.
	if s, ok := m.live.cached(sid); ok {
		m.log.Warn("reading a session record failed, letting it through", "provider", s.Identity.Provider,
			"subject", s.Identity.Subject, "err", err)
		return s, nil
	}
	return Session{}, fmt.Errorf("%w: reading a session this process has not seen: %w", ErrStoreUnavailable, err)
}

// Alive reports whether a session held open past its request is still valid: its record exists,
// Authorize still admits it, and its deadline, if any, has not passed. A handler keeping a connection
// open asks it on every keepalive.
//
// It never revalidates: the page holding the connection is making requests of its own, and those do.
func (m *Manager) Alive(ctx context.Context, s Session) bool {
	// The deadline cannot change over the life of a connection, so comparing it costs nothing where a read
	// of the store would.
	if !s.Deadline.IsZero() && time.Now().After(s.Deadline) {
		return false
	}
	id := s.Identity
	rec, err := m.store.Get(ctx, s.ID)
	switch {
	case err == nil:
		id = m.remember(s.ID, rec).Identity
	case errors.Is(err, ErrNotFound):
		m.live.drop(s.ID)
		return false
	default:
		// A store that cannot be read is not an answer about this session, and dropping every open
		// connection over it would be an outage of its own.
		if c, ok := m.live.cached(s.ID); ok {
			id = c.Identity
		}
	}
	return m.authorize(ctx, id) == nil
}

// logRefusal records why a request arrived without a session, unless it simply carried no cookie.
func (m *Manager) logRefusal(r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrStoreUnavailable):
		m.log.Error("a session could not be looked up", "err", err, "remote", r.RemoteAddr)
	case !errors.Is(err, errNoSession):
		// The refusal is only here, so without this line a cookie that failed to verify and an account
		// taken off the policy would both leave no trace at all.
		m.log.Warn("a session was refused", "reason", err, "remote", r.RemoteAddr)
	}
}

func (m *Manager) unauthenticated(w http.ResponseWriter, r *http.Request, err error) {
	m.logRefusal(r, err)
	if errors.Is(err, ErrStoreUnavailable) {
		m.Fail(w, http.StatusServiceUnavailable, "session_store_unavailable", web.LoginFailedRetry)
		return
	}
	// A redirect is meaningless to both of these: a program gets a login page where it expected JSON, and
	// a WebSocket handshake never follows one, leaving the page with nothing but a failed connection. A
	// 401 is something the page can act on, by navigating to the login itself.
	if strings.Contains(r.Header.Get("Accept"), "application/json") ||
		strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		m.Fail(w, http.StatusUnauthorized, "unauthenticated", web.NotSignedIn)
		return
	}
	u := m.loginFor(r, r.URL.RequestURI())
	if u == "" {
		m.Fail(w, http.StatusUnauthorized, "unauthenticated", web.NotSignedIn)
		return
	}
	http.Redirect(w, r, u, http.StatusFound)
}

// loginFor is Options.LoginURL, or the login of the only interactive method.
func (m *Manager) loginFor(r *http.Request, ret string) string {
	if m.loginURL != nil {
		return m.loginURL(r, ret)
	}
	m.methodsMu.RLock()
	defer m.methodsMu.RUnlock()
	if len(m.interactive) != 1 {
		return ""
	}
	return m.interactive[0].LoginURL(ret)
}
