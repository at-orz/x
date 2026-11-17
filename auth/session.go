package auth

import (
	"context"
	"time"
)

// Session is the signed-in identity of a request, as Require hands it on.
//
// A handler that keeps a connection open past its request (a WebSocket) keeps the Session and asks
// Manager.Alive about it on every keepalive, which is the only way a connection already open learns
// that its session has ended.
type Session struct {
	ID       string
	Identity Identity
	// Deadline is when the session ends, and zero for one that is revalidated instead.
	Deadline time.Time
	// Values are the host's own (see Manager.SetValue). They are shared with the session cache: read
	// them, never modify them.
	Values map[string]string
}

type sessionKey struct{}

// SessionFrom reads the session Require admitted the request on.
func SessionFrom(ctx context.Context) (Session, bool) {
	s, ok := ctx.Value(sessionKey{}).(Session)
	return s, ok
}

// WithSession is what Require carries the session forward on. It is exported so that the tests of a
// host's handlers can seat a session without signing anyone in.
func WithSession(ctx context.Context, s Session) context.Context {
	return context.WithValue(ctx, sessionKey{}, s)
}
