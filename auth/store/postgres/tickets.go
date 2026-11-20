package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/at-orz/x/auth"
	"github.com/at-orz/x/auth/mint"
	"github.com/jackc/pgx/v5"
)

var _ mint.Tickets = (*Tickets)(nil)

// Tickets holds the one-time tickets of auth/mint in <prefix>mint_tickets. It implements mint.Tickets.
type Tickets struct {
	s *Store
}

// Tickets returns the ticket storage of the store's tables.
func (s *Store) Tickets() *Tickets { return &Tickets{s: s} }

// Put writes a ticket that expires after ttl on the database's clock, over any row left under the same
// nonce.
func (t *Tickets) Put(ctx context.Context, nonce string, ticket mint.Ticket, ttl time.Duration) error {
	body, err := json.Marshal(ticket)
	if err != nil {
		return err
	}
	if _, err := t.s.pool.Exec(ctx, t.s.q.putTicket, nonce, string(body), ttlSeconds(ttl)); err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	return nil
}

// Redeem takes a ticket out of the table and hands it back, reporting auth.ErrNotFound for a nonce that
// was never issued, has been spent, or has expired.
//
// A single delete does all of it. PostgreSQL returns a row only to the delete that actually removed it,
// so of two redemptions at once, on any number of instances, exactly one is served, with no explicit
// transaction and no lock. An expired ticket is deleted too, and still refused.
//
// The nonce stays out of the error, which ends up in a log, while the nonce is a credential until spent.
func (t *Tickets) Redeem(ctx context.Context, nonce string) (mint.Ticket, error) {
	var body []byte
	var live bool
	err := t.s.pool.QueryRow(ctx, t.s.q.redeem, nonce).Scan(&body, &live)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !live {
		return mint.Ticket{}, fmt.Errorf("mint ticket: %w", auth.ErrNotFound)
	}
	if err != nil {
		return mint.Ticket{}, fmt.Errorf("postgres: %w", err)
	}
	var ticket mint.Ticket
	if err := json.Unmarshal(body, &ticket); err != nil {
		return mint.Ticket{}, fmt.Errorf("decode a mint ticket: %w", err)
	}
	return ticket, nil
}
