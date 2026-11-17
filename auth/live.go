package auth

import (
	"context"
	"encoding/json"
	"sync"
	"time"
)

// liveSessions is which session records exist, mirrored from a store's feed by FollowSessions, together
// with what this process last read from each: a valid cookie whose record was removed is refused on its
// next request, and one whose record is there is admitted, without that request reading the store.
type liveSessions struct {
	mu     sync.RWMutex
	synced bool
	ids    map[string]struct{}
	// tomb holds the ids removed within the last sessionTTL, so a request that read a record just before
	// its delete event landed cannot put it back. Ids are random and never reused; past sessionTTL every
	// older cookie has reached the refresh window, which reads the record anyway.
	tomb map[string]time.Time

	// cache is the session as last read, keyed by id. The cookie names no one, so this is where the
	// identity of a request on the fast path comes from. An Added event drops an entry, so a write by
	// another instance is read on the next request.
	cache   map[string]cachedSession
	idleTTL time.Duration
	swept   time.Time
}

type cachedSession struct {
	sess Session
	used time.Time
}

func newLiveSessions(idleTTL time.Duration) *liveSessions {
	return &liveSessions{
		ids:     map[string]struct{}{},
		tomb:    map[string]time.Time{},
		cache:   map[string]cachedSession{},
		idleTTL: idleTTL,
	}
}

// has is false for every id while the set is out of sync, which sends each request to its record.
func (l *liveSessions) has(id string) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	_, ok := l.ids[id]
	return l.synced && ok
}

func (l *liveSessions) cached(id string) (Session, bool) {
	l.mu.RLock()
	c, ok := l.cache[id]
	l.mu.RUnlock()
	if ok && time.Since(c.used) > time.Minute {
		// Bumped at most once a minute, so that the fast path takes the write lock almost never.
		l.mu.Lock()
		if c, ok := l.cache[id]; ok {
			c.used = time.Now()
			l.cache[id] = c
		}
		l.mu.Unlock()
	}
	return c.sess, ok
}

// remember records that a session exists as read, unless it was removed meanwhile.
func (l *liveSessions) remember(s Session) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, gone := l.tomb[s.ID]; gone {
		return
	}
	l.ids[s.ID] = struct{}{}
	now := time.Now()
	l.cache[s.ID] = cachedSession{sess: s, used: now}
	// Swept here rather than by a janitor. Without a feed nothing reports an expired record, so an entry
	// unused for longer than a record may sit idle belongs to a session that is gone.
	if now.Sub(l.swept) > time.Minute {
		l.swept = now
		for id, c := range l.cache {
			if now.Sub(c.used) > l.idleTTL {
				delete(l.cache, id)
			}
		}
	}
}

// forget drops what was read of a session that still exists, so that the next request reads it again.
func (l *liveSessions) forget(id string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.cache, id)
}

func (l *liveSessions) drop(id string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.dropLocked(id)
}

func (l *liveSessions) dropLocked(id string) {
	now := time.Now()
	delete(l.ids, id)
	delete(l.cache, id)
	l.tomb[id] = now
	for t, at := range l.tomb {
		if now.Sub(at) > sessionTTL {
			delete(l.tomb, t)
		}
	}
}

func (l *liveSessions) apply(ev Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	switch ev.Kind {
	case Loaded:
		l.ids = make(map[string]struct{}, len(ev.IDs))
		for _, id := range ev.IDs {
			if _, gone := l.tomb[id]; !gone {
				l.ids[id] = struct{}{}
			}
		}
		// Whatever changed while the feed was out of sync was not reported, so nothing read before it can
		// be trusted on the fast path.
		clear(l.cache)
		l.synced = true
	case Added:
		if _, gone := l.tomb[ev.ID]; !gone {
			l.ids[ev.ID] = struct{}{}
		}
		delete(l.cache, ev.ID)
	case Removed:
		l.dropLocked(ev.ID)
	case Lost:
		// The cache is kept: while the store cannot be read, it is what lets a session this process has
		// seen carry on. Every request reads its record meanwhile, which refreshes it.
		l.synced = false
		l.ids = map[string]struct{}{}
	}
}

// FollowSessions keeps the live set current from a store's feed until ctx ends. A Manager never given
// one, or whose feed has ended, reads the record on every request instead.
func (m *Manager) FollowSessions(ctx context.Context, events <-chan Event) {
	go func() {
		defer m.live.apply(Event{Kind: Lost})
		lost := false
		for {
			select {
			case ev, ok := <-events:
				if !ok {
					return
				}
				m.live.apply(ev)
				switch {
				case ev.Kind == Lost:
					lost = true
					m.log.Warn("the session feed lost the store, every request reads its session record until it is back")
				case ev.Kind == Loaded && lost:
					lost = false
					m.log.Info("the session feed is back in sync", "sessions", len(ev.IDs))
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

// sessionOf is the Session a record stands for.
func (m *Manager) sessionOf(sid string, rec Record) Session {
	s := Session{
		ID:       sid,
		Identity: Identity{Provider: rec.Provider, Subject: rec.Subject},
		Deadline: rec.Deadline,
		Values:   rec.Values,
	}
	if len(rec.Claims) > 0 {
		if err := json.Unmarshal(rec.Claims, &s.Identity.Claims); err != nil {
			m.log.Error("the claims of a session record do not decode", "provider", rec.Provider,
				"subject", rec.Subject, "err", err)
		}
	}
	return s
}

// remember caches what was read of a session and returns it.
func (m *Manager) remember(sid string, rec Record) Session {
	s := m.sessionOf(sid, rec)
	m.live.remember(s)
	return s
}
