package auth

import (
	"context"
	"errors"
	"fmt"
	"time"
)

type refreshCall struct {
	done chan struct{}
	sess Session
	err  error
}

// refresh revalidates one session, at most once at a time per session in this process. Its error wraps
// ErrEnded, errUnreachable (with the Session still set, for the request to carry on with) or
// ErrStoreUnavailable (with nobody to carry on as).
func (m *Manager) refresh(ctx context.Context, sid string) (Session, error) {
	m.refreshMu.Lock()
	if call, ok := m.refreshing[sid]; ok {
		m.refreshMu.Unlock()
		select {
		case <-call.done:
			return call.sess, call.err
		case <-ctx.Done():
			if s, ok := m.live.cached(sid); ok {
				return s, fmt.Errorf("%w: %w", errUnreachable, ctx.Err())
			}
			return Session{}, fmt.Errorf("%w: %w", ErrStoreUnavailable, ctx.Err())
		}
	}
	call := &refreshCall{done: make(chan struct{})}
	m.refreshing[sid] = call
	m.refreshMu.Unlock()

	call.sess, call.err = m.refreshNow(ctx, sid)

	m.refreshMu.Lock()
	delete(m.refreshing, sid)
	m.refreshMu.Unlock()
	close(call.done)
	return call.sess, call.err
}

func (m *Manager) refreshNow(ctx context.Context, sid string) (Session, error) {
	rec, err := m.store.Get(ctx, sid)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			m.live.drop(sid)
			return Session{}, fmt.Errorf("%w: the session record is gone", ErrEnded)
		}
		// The store cannot be read, so VerifiedAt cannot be read either and the grace window cannot be
		// evaluated at all. Letting the request through is bounded by the store itself: the moment it
		// answers again the record is either there or the session ends on the spot.
		if s, ok := m.live.cached(sid); ok {
			return s, fmt.Errorf("%w: reading the session record: %w", errUnreachable, err)
		}
		return Session{}, fmt.Errorf("%w: reading a session this process has not seen: %w", ErrStoreUnavailable, err)
	}
	sess := m.remember(sid, rec)

	// A session with a deadline has nothing to revalidate, and its method's Revalidate is never asked. The
	// read above is not wasted on it: one whose record is gone ends in the branch above, by the same path
	// as any other.
	if !rec.Deadline.IsZero() {
		return sess, nil
	}
	// Somebody revalidated this session a moment ago. Every tab of a browser polls carrying the same
	// cookie, and the single flight only holds back the ones that overlap: a tab arriving a second after
	// the revalidation finished would ask all over again. It is also the first of the two guards between
	// instances: one taking over a session reads the VerifiedAt another wrote.
	if time.Since(rec.VerifiedAt) < refreshFloor {
		return sess, nil
	}
	if m.claimer != nil {
		// The second guard, for what the first cannot answer: another instance is asking right now, so
		// there is no fresh VerifiedAt to read yet. Presenting one refresh token twice is worse than
		// wasteful — an authority that rotates reads the second presentation as a replay and refuses it,
		// and that is the one answer which ends a session. This request carries on instead, and whatever
		// the other instance hears decides the session at the next window.
		if time.Since(rec.RefreshingAt) < claimTTL {
			return sess, nil
		}
		claimed, ok, err := m.claimer.Claim(ctx, sid, rec)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				m.live.drop(sid)
				return Session{}, fmt.Errorf("%w: the session record is gone", ErrEnded)
			}
			return sess, fmt.Errorf("%w: claiming the revalidation: %w", errUnreachable, err)
		}
		if !ok {
			return sess, nil
		}
		rec = claimed
	}

	method := m.method(rec.Provider)
	if method == nil {
		return sess, m.graceOr(rec, fmt.Errorf("no method is registered as %q", rec.Provider))
	}
	next, err := method.Revalidate(ctx, rec)
	if err != nil {
		if errors.Is(err, ErrEnded) {
			// The one path on which the authority ends a session: the account was disabled, the token was
			// revoked or expired. Answering this question every hour is what the arrangement is for.
			m.log.Info("the authority ended a session", "provider", rec.Provider, "subject", rec.Subject, "err", err)
			if derr := m.store.Delete(ctx, sid); derr != nil {
				m.log.Warn("deleting an ended session record failed", "err", derr)
			}
			m.live.drop(sid)
			return Session{}, err
		}
		return sess, m.graceOr(rec, err)
	}
	rec.State, rec.Claims = next.State, next.Claims
	rec.VerifiedAt = time.Now()
	// Written back before Authorize is asked about the new identity: the authority may already have rotated
	// the refresh token, and the new one has to be stored even when the request is then refused.
	if err := m.store.Touch(ctx, sid, rec); err != nil {
		switch {
		case errors.Is(err, ErrNotFound):
			m.live.drop(sid)
			return Session{}, fmt.Errorf("%w: the session record is gone", ErrEnded)
		case errors.Is(err, ErrConflict):
			// Somebody wrote the record since it was read. Their write is at least as new as this one and is
			// the one to keep; the next request reads it.
			m.live.forget(sid)
			return m.sessionOf(sid, rec), nil
		}
		// The authority may have rotated the token already and this side could not record it, so the token
		// in the store may be one the authority just retired. The request goes through and the next
		// revalidation gets the refusal, which ends the session then: one sign-in is the accepted price of
		// a write that failed.
		return m.sessionOf(sid, rec), fmt.Errorf("%w: writing the session record back: %w", errUnreachable, err)
	}
	m.log.Info("session revalidated", "provider", rec.Provider, "subject", rec.Subject)
	return m.remember(sid, rec), nil
}

// graceOr decides what an authority that could not be asked means for one session: inside the grace
// window it carries on and the next request in the refresh window tries again, and past the window it
// ends.
//
// The window is measured from the last successful verification and is IdleTTL. An authority down for
// part of it signs nobody out; one down for longer does. It cannot usefully be longer than IdleTTL
// either, since by then the record has expired anyway.
func (m *Manager) graceOr(rec Record, cause error) error {
	if time.Since(rec.VerifiedAt) < m.idleTTL {
		return fmt.Errorf("%w: %w", errUnreachable, cause)
	}
	return fmt.Errorf("%w: the authority has not confirmed this session for over %s: %w", ErrEnded, m.idleTTL, cause)
}
