// Package etcd is an auth.Store, and the mint.Tickets of auth/mint, in etcd: for several instances of a
// host serving the same sessions at once.
//
// Every record sits on a lease of its own, so an unused session expires without a sweeper, and the store
// implements auth.Claimer, so two instances never revalidate one session at the same moment. Follow is
// the feed for auth.Manager.FollowSessions. Connection and TLS stay with the host, which passes a
// *clientv3.Client; everything lives under a prefix the host chooses.
package etcd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/at-orz/x/auth"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// Store keeps session records under prefix + "sessions/".
type Store struct {
	c        *clientv3.Client
	sessions string
	tickets  string
}

// New returns the store of the keyspace under prefix, which has to end in "/" so that one prefix can
// never be the beginning of another's keys. It panics otherwise: the prefix is a constant of the host.
func New(c *clientv3.Client, prefix string) *Store {
	if !strings.HasSuffix(prefix, "/") {
		panic(fmt.Sprintf("etcd: prefix %q does not end in /", prefix))
	}
	return &Store{c: c, sessions: prefix + "sessions/", tickets: prefix + "mint_tickets/"}
}

// leaseSeconds is a lease length in etcd's unit, rounded up so that a lease never ends before ttl.
func leaseSeconds(ttl time.Duration) int64 {
	return max(1, int64(math.Ceil(ttl.Seconds())))
}

// putOnLease writes a value on a lease of its own.
func (s *Store) putOnLease(ctx context.Context, key string, body []byte, ttl time.Duration) error {
	lease, err := s.c.Grant(ctx, leaseSeconds(ttl))
	if err != nil {
		return fmt.Errorf("etcd: %w", err)
	}
	if _, err := s.c.Put(ctx, key, string(body), clientv3.WithLease(lease.ID)); err != nil {
		// A lease no key holds would otherwise sit in etcd for the whole ttl. Detached from ctx, because a
		// put that failed on ctx's deadline leaves ctx unusable for the revoke; a revoke that fails as well
		// is dropped, since the lease still expires by itself.
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, _ = s.c.Revoke(rctx, lease.ID)
		return fmt.Errorf("etcd: %w", err)
	}
	return nil
}

// Put creates the record of a sign-in on a lease of ttl. The lease is what expires an unused session, so
// nothing has to sweep: a browser that stops making requests stops the touches that keep it alive.
func (s *Store) Put(ctx context.Context, sid string, rec auth.Record, ttl time.Duration) error {
	body, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return s.putOnLease(ctx, s.sessions+sid, body, ttl)
}

// Get reads one record, with Version set to its revision, reporting auth.ErrNotFound for a session that
// expired, was logged out or was removed.
func (s *Store) Get(ctx context.Context, sid string) (auth.Record, error) {
	resp, err := s.c.Get(ctx, s.sessions+sid)
	if err != nil {
		return auth.Record{}, fmt.Errorf("etcd: %w", err)
	}
	if len(resp.Kvs) == 0 {
		return auth.Record{}, fmt.Errorf("session %q: %w", sid, auth.ErrNotFound)
	}
	var rec auth.Record
	if err := json.Unmarshal(resp.Kvs[0].Value, &rec); err != nil {
		return auth.Record{}, fmt.Errorf("decode %s: %w", resp.Kvs[0].Key, err)
	}
	rec.Version = resp.Kvs[0].ModRevision
	return rec, nil
}

// Claim takes the right to revalidate one session, writing RefreshingAt, on the condition that the
// record has not been written since rec was read. ok=false means another instance wrote it first:
// it is asking, or has just asked. Only auth.ErrNotFound is an ending.
func (s *Store) Claim(ctx context.Context, sid string, rec auth.Record) (auth.Record, bool, error) {
	key := s.sessions + sid
	rec.RefreshingAt = time.Now()
	body, err := json.Marshal(rec)
	if err != nil {
		return auth.Record{}, false, err
	}
	// WithIgnoreLease keeps the lease the sign-in created, since a claim is not a use of the session.
	done, err := s.c.Txn(ctx).
		If(clientv3.Compare(clientv3.ModRevision(key), "=", rec.Version)).
		Then(clientv3.OpPut(key, string(body), clientv3.WithIgnoreLease())).
		Commit()
	if err != nil {
		return auth.Record{}, false, fmt.Errorf("etcd: %w", err)
	}
	if !done.Succeeded {
		if _, gone := s.Get(ctx, sid); errors.Is(gone, auth.ErrNotFound) {
			return auth.Record{}, false, gone
		}
		return auth.Record{}, false, nil
	}
	rec.Version = done.Header.Revision
	return rec, true, nil
}

// Touch writes a record back and renews its lease, on the condition that the record has not been
// written since rec was read; auth.ErrConflict otherwise.
//
// The value replaces the old one on the existing lease rather than on a new one, so the record keeps the
// lifetime it was created with and a write cannot resurrect a session whose lease is gone.
func (s *Store) Touch(ctx context.Context, sid string, rec auth.Record) error {
	key := s.sessions + sid
	body, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	current, err := s.c.Get(ctx, key)
	if err != nil {
		return fmt.Errorf("etcd: %w", err)
	}
	if len(current.Kvs) == 0 {
		return fmt.Errorf("session %q: %w", sid, auth.ErrNotFound)
	}
	if lease := clientv3.LeaseID(current.Kvs[0].Lease); lease != clientv3.NoLease {
		if _, err := s.c.KeepAliveOnce(ctx, lease); err != nil {
			// A lease that expired in the moment between the read above and this call took the record with
			// it, which is a session that has ended rather than an etcd failure. Asking once tells the two
			// apart without matching on the text of a gRPC error.
			if _, gone := s.Get(ctx, sid); errors.Is(gone, auth.ErrNotFound) {
				return gone
			}
			return fmt.Errorf("etcd: keep the lease of session %q alive: %w", sid, err)
		}
	}
	done, err := s.c.Txn(ctx).
		If(clientv3.Compare(clientv3.ModRevision(key), "=", rec.Version)).
		Then(clientv3.OpPut(key, string(body), clientv3.WithIgnoreLease())).
		Commit()
	if err != nil {
		return fmt.Errorf("etcd: %w", err)
	}
	if !done.Succeeded {
		if _, gone := s.Get(ctx, sid); errors.Is(gone, auth.ErrNotFound) {
			return gone
		}
		return fmt.Errorf("session %q: %w", sid, auth.ErrConflict)
	}
	return nil
}

// Delete removes a record; one that is gone already is not an error.
func (s *Store) Delete(ctx context.Context, sid string) error {
	if _, err := s.c.Delete(ctx, s.sessions+sid); err != nil {
		return fmt.Errorf("etcd: %w", err)
	}
	return nil
}

// Remove removes a record and reports auth.ErrNotFound when there was none. That is its whole difference
// from Delete, and it exists for a host command revoking a session: an id that names nothing has to read
// as a failure, because a revocation that quietly did nothing is the one outcome an operator must not
// mistake for success.
func (s *Store) Remove(ctx context.Context, sid string) error {
	resp, err := s.c.Delete(ctx, s.sessions+sid)
	if err != nil {
		return fmt.Errorf("etcd: %w", err)
	}
	if resp.Deleted == 0 {
		return fmt.Errorf("session %q: %w", sid, auth.ErrNotFound)
	}
	return nil
}

// Entry is one session as a host command listing them shows it. It carries no State, Claims or Values:
// this is the only shape in which a session leaves the store other than to the Manager, so listing
// sessions cannot become a way of reading a credential out.
type Entry struct {
	ID, Provider, Subject           string
	CreatedAt, VerifiedAt, Deadline time.Time
}

// List reads every session, the newest sign-in first.
func (s *Store) List(ctx context.Context) ([]Entry, error) {
	resp, err := s.c.Get(ctx, s.sessions, clientv3.WithPrefix())
	if err != nil {
		return nil, fmt.Errorf("etcd: %w", err)
	}
	out := make([]Entry, 0, len(resp.Kvs))
	for _, kv := range resp.Kvs {
		var rec auth.Record
		if err := json.Unmarshal(kv.Value, &rec); err != nil {
			return nil, fmt.Errorf("decode %s: %w", kv.Key, err)
		}
		out = append(out, Entry{
			ID:         strings.TrimPrefix(string(kv.Key), s.sessions),
			Provider:   rec.Provider,
			Subject:    rec.Subject,
			CreatedAt:  rec.CreatedAt,
			VerifiedAt: rec.VerifiedAt,
			Deadline:   rec.Deadline,
		})
	}
	slices.SortFunc(out, func(a, b Entry) int { return b.CreatedAt.Compare(a.CreatedAt) })
	return out, nil
}

// followBackoff bounds the retries of the list while etcd cannot be read.
const (
	followBackoffMin = time.Second
	followBackoffMax = 30 * time.Second
)

// Follow mirrors which sessions exist, as a list of the prefix followed by a watch from the revision of
// that list, until ctx ends and the channel closes. The list reads keys only, so no credential leaves
// etcd for it.
func (s *Store) Follow(ctx context.Context) <-chan auth.Event {
	out := make(chan auth.Event, 16)
	go func() {
		defer close(out)
		send := func(ev auth.Event) bool {
			select {
			case out <- ev:
				return true
			case <-ctx.Done():
				return false
			}
		}
		// lost keeps an outage to one Lost however many retries it takes.
		lost, wait := false, followBackoffMin
		for ctx.Err() == nil {
			resp, err := s.c.Get(ctx, s.sessions, clientv3.WithPrefix(), clientv3.WithKeysOnly())
			if err != nil {
				if !lost && !send(auth.Event{Kind: auth.Lost}) {
					return
				}
				lost = true
				select {
				case <-time.After(wait):
				case <-ctx.Done():
					return
				}
				wait = min(2*wait, followBackoffMax)
				continue
			}
			ids := make([]string, 0, len(resp.Kvs))
			for _, kv := range resp.Kvs {
				ids = append(ids, strings.TrimPrefix(string(kv.Key), s.sessions))
			}
			if !send(auth.Event{Kind: auth.Loaded, IDs: ids}) {
				return
			}
			lost, wait = false, followBackoffMin

			// WithRequireLeader makes a watch on a member cut off from the cluster fail rather than go quiet,
			// which a feed that others trust to report deletions cannot afford.
			wch := s.c.Watch(clientv3.WithRequireLeader(ctx), s.sessions,
				clientv3.WithPrefix(), clientv3.WithRev(resp.Header.Revision+1))
			for wr := range wch {
				if wr.Err() != nil {
					break
				}
				for _, ev := range wr.Events {
					kind := auth.Added
					if ev.Type == clientv3.EventTypeDelete {
						kind = auth.Removed
					}
					if !send(auth.Event{Kind: kind, ID: strings.TrimPrefix(string(ev.Kv.Key), s.sessions)}) {
						return
					}
				}
			}
			if ctx.Err() != nil {
				return
			}
			if !send(auth.Event{Kind: auth.Lost}) {
				return
			}
			lost = true
		}
	}()
	return out
}
