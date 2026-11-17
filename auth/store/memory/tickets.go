package memory

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/at-orz/x/auth"
	"github.com/at-orz/x/auth/mint"
)

// Tickets holds the one-time tickets of auth/mint in one process. It implements mint.Tickets.
type Tickets struct {
	mu   sync.Mutex
	recs map[string]*ticketEntry
}

type ticketEntry struct {
	t     mint.Ticket
	timer *time.Timer
}

// Tickets returns the store's ticket storage, the same one on every call.
func (s *Store) Tickets() *Tickets {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tickets == nil {
		s.tickets = &Tickets{recs: map[string]*ticketEntry{}}
	}
	return s.tickets
}

// Put stores a ticket under a nonce until it is redeemed or ttl passes.
func (t *Tickets) Put(_ context.Context, nonce string, ticket mint.Ticket, ttl time.Duration) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if old, ok := t.recs[nonce]; ok {
		old.timer.Stop()
	}
	e := &ticketEntry{t: ticket}
	e.timer = time.AfterFunc(ttl, func() {
		t.mu.Lock()
		defer t.mu.Unlock()
		if t.recs[nonce] == e {
			delete(t.recs, nonce)
		}
	})
	t.recs[nonce] = e
	return nil
}

// Redeem removes a ticket as it reads it, reporting auth.ErrNotFound for one that is unknown, spent or
// expired.
func (t *Tickets) Redeem(_ context.Context, nonce string) (mint.Ticket, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.recs[nonce]
	if !ok {
		return mint.Ticket{}, fmt.Errorf("mint ticket: %w", auth.ErrNotFound)
	}
	e.timer.Stop()
	delete(t.recs, nonce)
	return e.t, nil
}
