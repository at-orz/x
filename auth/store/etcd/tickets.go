package etcd

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/at-orz/x/auth"
	"github.com/at-orz/x/auth/mint"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// Tickets holds the one-time tickets of auth/mint under prefix + "mint_tickets/". It implements
// mint.Tickets.
type Tickets struct {
	s *Store
}

// Tickets returns the ticket storage of the store's keyspace.
func (s *Store) Tickets() *Tickets { return &Tickets{s: s} }

// Put writes a ticket on a lease of ttl, so an abandoned ticket needs no cleanup and leaves nothing
// behind to be found later.
func (t *Tickets) Put(ctx context.Context, nonce string, ticket mint.Ticket, ttl time.Duration) error {
	body, err := json.Marshal(ticket)
	if err != nil {
		return err
	}
	return t.s.putOnLease(ctx, t.s.tickets+nonce, body, ttl)
}

// Redeem takes a ticket out of the keyspace and hands it back, reporting auth.ErrNotFound for a nonce
// that was never issued, has been spent, or has expired.
//
// A single delete does all of it. etcd returns the previous value only to the delete that actually
// removed the key, so of two redemptions at once, on any number of instances, exactly one is served, with
// no transaction and no lock.
//
// The nonce stays out of the error, which ends up in a log, while the nonce is a credential until spent.
func (t *Tickets) Redeem(ctx context.Context, nonce string) (mint.Ticket, error) {
	resp, err := t.s.c.Delete(ctx, t.s.tickets+nonce, clientv3.WithPrevKV())
	if err != nil {
		return mint.Ticket{}, fmt.Errorf("etcd: %w", err)
	}
	if len(resp.PrevKvs) == 0 {
		return mint.Ticket{}, fmt.Errorf("mint ticket: %w", auth.ErrNotFound)
	}
	var ticket mint.Ticket
	if err := json.Unmarshal(resp.PrevKvs[0].Value, &ticket); err != nil {
		return mint.Ticket{}, fmt.Errorf("decode a mint ticket: %w", err)
	}
	return ticket, nil
}
