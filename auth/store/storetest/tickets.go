package storetest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/at-orz/x/auth"
	"github.com/at-orz/x/auth/mint"
)

// RunTickets checks the mint.Tickets contract. newTickets returns an empty ticket storage; each sub-test
// calls it once.
func RunTickets(t *testing.T, newTickets func(t *testing.T) mint.Tickets) {
	ticket := mint.Ticket{Subject: "alice", SessionTTL: 24 * time.Hour, CreatedAt: time.Now().Truncate(time.Second)}

	t.Run("redeemed once", func(t *testing.T) {
		t.Parallel()
		s, ctx := newTickets(t), context.Background()
		if err := s.Put(ctx, "nonce-1", ticket, time.Hour); err != nil {
			t.Fatal(err)
		}
		got, err := s.Redeem(ctx, "nonce-1")
		if err != nil {
			t.Fatal(err)
		}
		if got.Subject != ticket.Subject || got.SessionTTL != ticket.SessionTTL || !got.CreatedAt.Equal(ticket.CreatedAt) {
			t.Errorf("Redeem = %+v, want %+v", got, ticket)
		}
		if _, err := s.Redeem(ctx, "nonce-1"); !errors.Is(err, auth.ErrNotFound) {
			t.Errorf("a second Redeem = %v, want ErrNotFound", err)
		}
	})

	t.Run("an unknown nonce is ErrNotFound", func(t *testing.T) {
		t.Parallel()
		if _, err := newTickets(t).Redeem(context.Background(), "nobody"); !errors.Is(err, auth.ErrNotFound) {
			t.Errorf("Redeem = %v, want ErrNotFound", err)
		}
	})

	t.Run("concurrent redemptions have one winner", func(t *testing.T) {
		t.Parallel()
		s, ctx := newTickets(t), context.Background()
		if err := s.Put(ctx, "nonce-1", ticket, time.Hour); err != nil {
			t.Fatal(err)
		}
		const tries = 16
		var wg sync.WaitGroup
		errs := make([]error, tries)
		for i := range tries {
			wg.Go(func() { _, errs[i] = s.Redeem(ctx, "nonce-1") })
		}
		wg.Wait()
		won := 0
		for _, err := range errs {
			switch {
			case err == nil:
				won++
			case !errors.Is(err, auth.ErrNotFound):
				t.Errorf("a losing Redeem = %v, want ErrNotFound", err)
			}
		}
		if won != 1 {
			t.Errorf("%d redemptions of one ticket succeeded, want exactly 1", won)
		}
	})

	t.Run("expiry", func(t *testing.T) {
		t.Parallel()
		s, ctx := newTickets(t), context.Background()
		if err := s.Put(ctx, "nonce-1", ticket, TTL); err != nil {
			t.Fatal(err)
		}
		// Redeem is the only way to look, and it spends what it finds, so this waits rather than polls: three
		// lifetimes leave a store that counts leases in seconds room to round up.
		time.Sleep(3 * TTL)
		if _, err := s.Redeem(ctx, "nonce-1"); !errors.Is(err, auth.ErrNotFound) {
			t.Errorf("Redeem after %s = %v, want ErrNotFound", 3*TTL, err)
		}
	})
}
