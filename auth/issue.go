package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/at-orz/x/auth/internal/web"
)

// LogoutPath ends the session of the request. Routes mounts it.
//
// A POST to it answers 204 to a request whose Accept contains application/json, and otherwise 303 See
// Other to the ret parameter (form body or query string, an absolute path on this site) or to "/". A
// plain <form method="post" action="/auth/logout"> is therefore enough to sign out. A POST from another
// site is refused with 403 cross_origin_request, leaving the session in place.
const LogoutPath = "/auth/logout"

// Issue starts a session for an identity a method has established: it asks Authorize and Options.Link,
// writes the record, sets the session cookie, and ends the session the request arrived with.
//
// g.Identity.Provider must name a registered method. An error wraps ErrNotAllowed (answer 403
// subject_not_allowed) or ErrStoreUnavailable (answer 503 session_store_unavailable); the method writes
// the response, and on success its redirect.
func (m *Manager) Issue(w http.ResponseWriter, r *http.Request, g Grant) error {
	id := g.Identity
	if m.method(id.Provider) == nil {
		return fmt.Errorf("auth: Issue for %q, which is not a registered method", id.Provider)
	}
	ctx := r.Context()
	// Time may have passed since the method established the identity (a ticket waits on the host for
	// minutes), and the policy is asked on every request: an identity that would be refused at the next
	// request is not given a session here.
	if err := m.authorize(ctx, id); err != nil {
		m.log.Warn("a sign-in was refused", "provider", id.Provider, "subject", id.Subject, "reason", err)
		return fmt.Errorf("%w: %w", ErrNotAllowed, err)
	}
	var values map[string]string
	if m.link != nil {
		v, err := m.link(ctx, id)
		if err != nil {
			if errors.Is(err, ErrNotAllowed) {
				m.log.Warn("linking a sign-in was refused", "provider", id.Provider, "subject", id.Subject, "reason", err)
				return err
			}
			m.log.Error("linking a sign-in failed", "provider", id.Provider, "subject", id.Subject, "err", err)
			return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
		}
		values = v
	}

	now := time.Now()
	rec := Record{
		Provider:   id.Provider,
		Subject:    id.Subject,
		Values:     values,
		State:      g.State,
		CreatedAt:  now,
		VerifiedAt: now,
		Deadline:   g.Deadline,
	}
	if id.Claims != nil {
		claims, err := json.Marshal(id.Claims)
		if err != nil {
			return fmt.Errorf("auth: encoding the claims of %q: %w", id.Subject, err)
		}
		rec.Claims = claims
	}
	// A session with a deadline keeps its record until the deadline rather than for IdleTTL, in both
	// directions: a week-long one must not lose its record to a day idle, and a short one has no use for it
	// past its end.
	ttl := m.idleTTL
	if !g.Deadline.IsZero() {
		ttl = time.Until(g.Deadline)
		if ttl <= 0 {
			return fmt.Errorf("auth: Issue with a deadline already past (%s)", g.Deadline)
		}
	}
	sid := web.RandomToken()
	if err := m.store.Put(ctx, sid, rec, ttl); err != nil {
		m.log.Error("writing the session record failed", "provider", id.Provider, "subject", id.Subject, "err", err)
		return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
	m.remember(sid, rec)
	m.setSessionCookie(w, r, sid, g.Deadline)
	// The session this one replaces ends with it. The browser is overwriting its own cookie either way, so
	// the old record would never be presented from here again — but a copy of that cookie taken off the
	// browser beforehand would go on being revalidated, and signing in again is exactly what somebody who
	// suspects a copy does.
	//
	// Only the record this request arrived with, not every record of the identity: the second would close
	// the connections open on one machine the moment the same person signs in on another.
	m.endSessionOf(r, "sign-in")
	if g.Deadline.IsZero() {
		m.log.Info("signed in", "provider", id.Provider, "subject", id.Subject)
	} else {
		m.log.Info("signed in", "provider", id.Provider, "subject", id.Subject, "deadline", g.Deadline)
	}
	return nil
}

// Routes mounts POST /auth/logout, which needs no session itself. It answers as LogoutPath describes: 204
// to JSON, a 303 to ret or "/" for a browser, 403 to a POST from another site.
func (m *Manager) Routes(mux *http.ServeMux) {
	mux.HandleFunc("POST "+LogoutPath, m.handleLogout)
}

func (m *Manager) handleLogout(w http.ResponseWriter, r *http.Request) {
	// The session cookie is SameSite=Lax, so a POST from another site never reaches the record — but the
	// answer would still clear the cookie, and any page could sign a visitor out with a form.
	if err := m.cop.Check(r); err != nil {
		m.log.Warn("a logout was posted from another site", "remote", r.RemoteAddr, "err", err)
		m.Fail(w, http.StatusForbidden, "cross_origin_request", web.CrossOrigin)
		return
	}
	// The record goes first: clearing the cookie alone would leave a credential in the store that nothing
	// will ever use and only expiry would remove.
	m.endSessionOf(r, "logout")
	web.ClearCookie(w, r, m.sessionCookie)
	// The rule Require uses to choose a 401 over a redirect. A 303 rather than a 302 makes the browser follow
	// with a GET, never a repeated POST.
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	to := web.SafeReturn(r.FormValue("ret"))
	if to == "" {
		to = "/"
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

// endSessionOf deletes the record named by the session cookie of a request, when it names one that
// verifies. Both endings of a session on this side go through it: a logout, and a sign-in replacing the
// session the browser was holding.
func (m *Manager) endSessionOf(r *http.Request, on string) {
	c, err := r.Cookie(m.sessionCookie)
	if err != nil {
		return
	}
	var s sessionState
	if err := m.Open(c.Value, &s); err != nil || s.SID == "" {
		return
	}
	if err := m.store.Delete(r.Context(), s.SID); err != nil {
		m.log.Warn("deleting the session record failed", "on", on, "err", err)
	}
	m.live.drop(s.SID)
}
