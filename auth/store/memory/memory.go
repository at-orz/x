// Package memory is an auth.Store held in one process: for a host that runs a single instance, for
// development, and for tests.
//
// Records expire on a timer each, so an expired session is reported to followers the way a store built
// on leases reports it. The store keeps a Version per record and reports auth.ErrConflict from Touch,
// so code that has to survive concurrent writes is tested against the same race here as on a shared
// store. It does not implement auth.Claimer: in one process, the Manager's single flight already keeps
// two revalidations of one session apart.
package memory

import (
	"context"
	"fmt"
	"maps"
	"sync"
	"time"

	"github.com/at-orz/x/auth"
)

// followBuffer is how many events a follower may fall behind before it is resynchronized instead: told
// Lost, then handed a fresh Loaded.
const followBuffer = 1024

// Store is an in-process auth.Store with a feed (Follow). The zero value is not usable; call New.
type Store struct {
	mu        sync.Mutex
	recs      map[string]*entry
	version   int64
	followers map[*follower]struct{}
}

// entry is one record. Touch replaces it rather than editing it, so an expiry timer that fires late
// finds a different entry under the id and leaves it alone.
type entry struct {
	rec   auth.Record
	ttl   time.Duration
	timer *time.Timer
}

// New returns an empty Store.
func New() *Store {
	return &Store{recs: map[string]*entry{}, followers: map[*follower]struct{}{}}
}

// Put stores a record that expires after ttl unless touched.
func (s *Store) Put(_ context.Context, sid string, rec auth.Record, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.recs[sid]; ok {
		old.timer.Stop()
	}
	s.storeLocked(sid, rec, ttl)
	return nil
}

// Get reads a record, reporting auth.ErrNotFound for one that is gone.
func (s *Store) Get(_ context.Context, sid string) (auth.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.recs[sid]
	if !ok {
		return auth.Record{}, fmt.Errorf("session %q: %w", sid, auth.ErrNotFound)
	}
	return clone(e.rec), nil
}

// Touch writes a record back and restarts its expiry, reporting auth.ErrConflict when it was written
// since rec was read.
func (s *Store) Touch(_ context.Context, sid string, rec auth.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.recs[sid]
	if !ok {
		return fmt.Errorf("session %q: %w", sid, auth.ErrNotFound)
	}
	if e.rec.Version != rec.Version {
		return fmt.Errorf("session %q: %w", sid, auth.ErrConflict)
	}
	e.timer.Stop()
	s.storeLocked(sid, rec, e.ttl)
	return nil
}

// Delete removes a record; one that is gone already is not an error.
func (s *Store) Delete(_ context.Context, sid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.recs[sid]; ok {
		e.timer.Stop()
		delete(s.recs, sid)
		s.publishLocked(auth.Event{Kind: auth.Removed, ID: sid})
	}
	return nil
}

func (s *Store) storeLocked(sid string, rec auth.Record, ttl time.Duration) {
	s.version++
	rec = clone(rec)
	rec.Version = s.version
	e := &entry{rec: rec, ttl: ttl}
	e.timer = time.AfterFunc(ttl, func() { s.expire(sid, e) })
	s.recs[sid] = e
	s.publishLocked(auth.Event{Kind: auth.Added, ID: sid})
}

func (s *Store) expire(sid string, e *entry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.recs[sid] != e {
		return
	}
	delete(s.recs, sid)
	s.publishLocked(auth.Event{Kind: auth.Removed, ID: sid})
}

// clone copies the parts of a record a caller could modify in place, so that what is stored never
// changes behind the store's back.
func clone(rec auth.Record) auth.Record {
	rec.Values = maps.Clone(rec.Values)
	rec.Claims = append([]byte(nil), rec.Claims...)
	rec.State = append([]byte(nil), rec.State...)
	return rec
}

type follower struct {
	mu    sync.Mutex
	queue []auth.Event
	wake  chan struct{}
}

// Follow is a feed of which sessions exist, for auth.Manager.FollowSessions: a Loaded first, then an
// Added or Removed for every write, until ctx ends and the channel closes.
func (s *Store) Follow(ctx context.Context) <-chan auth.Event {
	out := make(chan auth.Event)
	f := &follower{wake: make(chan struct{}, 1)}
	s.mu.Lock()
	f.queue = []auth.Event{s.loadedLocked()}
	s.followers[f] = struct{}{}
	s.mu.Unlock()

	go func() {
		defer close(out)
		defer func() {
			s.mu.Lock()
			delete(s.followers, f)
			s.mu.Unlock()
		}()
		for {
			f.mu.Lock()
			batch := f.queue
			f.queue = nil
			f.mu.Unlock()
			for _, ev := range batch {
				select {
				case out <- ev:
				case <-ctx.Done():
					return
				}
			}
			if len(batch) > 0 {
				continue
			}
			select {
			case <-f.wake:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

func (s *Store) loadedLocked() auth.Event {
	ids := make([]string, 0, len(s.recs))
	for id := range s.recs {
		ids = append(ids, id)
	}
	return auth.Event{Kind: auth.Loaded, IDs: ids}
}

// publishLocked hands an event to every follower without waiting on any of them: a follower too far
// behind has its backlog replaced by a resynchronization, taken under the store's lock so that it is
// consistent with every event queued after it.
func (s *Store) publishLocked(ev auth.Event) {
	for f := range s.followers {
		f.mu.Lock()
		if len(f.queue) >= followBuffer {
			f.queue = []auth.Event{{Kind: auth.Lost}, s.loadedLocked()}
		} else {
			f.queue = append(f.queue, ev)
		}
		f.mu.Unlock()
		select {
		case f.wake <- struct{}{}:
		default:
		}
	}
}
