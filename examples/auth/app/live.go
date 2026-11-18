package app

import (
	"net/http"
	"time"

	"github.com/at-orz/x/auth"
	"github.com/coder/websocket"
)

// KeepaliveEvery is how often /live asks whether its session is still alive, and so the longest a
// connection outlives its session.
const KeepaliveEvery = 2 * time.Second

// live holds a WebSocket open for as long as its session lives. Require admitted the handshake, but
// that is one request: a connection that stays open past it learns of a logout, a revocation or a
// deadline only by asking Manager.Alive, which it does on every keepalive.
func (s *server) live(w http.ResponseWriter, r *http.Request) {
	sess, _ := auth.SessionFrom(r.Context())
	// Accept refuses a handshake from another origin by default, which is what keeps another site's page
	// from opening this socket with the browser's cookie.
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		s.log.Warn("a live connection was refused", "err", err)
		return
	}
	defer c.CloseNow()
	// The page sends nothing; reading in the background is what answers pings and notices a close.
	ctx := c.CloseRead(r.Context())

	t := time.NewTicker(KeepaliveEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if !s.m.Alive(ctx, sess) {
			c.Close(websocket.StatusPolicyViolation, "session ended")
			return
		}
		if err := c.Write(ctx, websocket.MessageText, []byte("alive")); err != nil {
			return
		}
	}
}
