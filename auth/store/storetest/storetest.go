// Package storetest is the contract every auth.Store keeps, as a test suite an implementation runs
// against itself:
//
//	func TestContract(t *testing.T) {
//		storetest.Run(t, func(t *testing.T) auth.Store { return newEmptyStore(t) })
//	}
//
// The parts of the contract that only some stores take on — auth.Claimer, a feed of events, and
// compare-and-swap on Version — are checked when the store implements them and skipped otherwise.
package storetest

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"reflect"
	"testing"
	"time"

	"github.com/at-orz/x/auth"
)

// TTL is the lifetime the expiry cases put records with. It is seconds rather than milliseconds because
// a store built on leases counts in whole seconds and may round a shorter lease up.
const TTL = 2 * time.Second

// patience bounds every wait for something that happens on a store's own clock.
const patience = 15 * time.Second

// Follower is a store with a feed of which sessions exist, for auth.Manager.FollowSessions.
type Follower interface {
	Follow(ctx context.Context) <-chan auth.Event
}

// Run checks the auth.Store contract. newStore returns an empty store; each sub-test calls it once.
func Run(t *testing.T, newStore func(t *testing.T) auth.Store) {
	t.Run("round trip", func(t *testing.T) {
		t.Parallel()
		s, ctx := newStore(t), context.Background()
		want := sample()
		if err := s.Put(ctx, "sid-1", want, time.Hour); err != nil {
			t.Fatal(err)
		}
		got, err := s.Get(ctx, "sid-1")
		if err != nil {
			t.Fatal(err)
		}
		sameRecord(t, got, want)
	})

	t.Run("an unknown id is ErrNotFound", func(t *testing.T) {
		t.Parallel()
		s, ctx := newStore(t), context.Background()
		if _, err := s.Get(ctx, "nobody"); !errors.Is(err, auth.ErrNotFound) {
			t.Errorf("Get = %v, want ErrNotFound", err)
		}
		if err := s.Touch(ctx, "nobody", sample()); !errors.Is(err, auth.ErrNotFound) {
			t.Errorf("Touch = %v, want ErrNotFound", err)
		}
	})

	t.Run("delete", func(t *testing.T) {
		t.Parallel()
		s, ctx := newStore(t), context.Background()
		put(t, s, "sid-1", time.Hour)
		if err := s.Delete(ctx, "sid-1"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Get(ctx, "sid-1"); !errors.Is(err, auth.ErrNotFound) {
			t.Errorf("Get after Delete = %v, want ErrNotFound", err)
		}
		// Every caller wants the session ended, not a report of who ended it first.
		if err := s.Delete(ctx, "sid-1"); err != nil {
			t.Errorf("a second Delete = %v, want nil", err)
		}
		if err := s.Delete(ctx, "nobody"); err != nil {
			t.Errorf("Delete of an unknown id = %v, want nil", err)
		}
	})

	t.Run("expiry", func(t *testing.T) {
		t.Parallel()
		s := newStore(t)
		put(t, s, "sid-1", TTL)
		waitGone(t, s, "sid-1")
	})

	t.Run("touch restarts expiry", func(t *testing.T) {
		t.Parallel()
		s, ctx := newStore(t), context.Background()
		put(t, s, "sid-1", TTL)
		for end := time.Now().Add(2 * TTL); time.Now().Before(end); time.Sleep(TTL / 5) {
			rec, err := s.Get(ctx, "sid-1")
			if err != nil {
				t.Fatalf("a record touched every %s expired: %v", TTL/5, err)
			}
			if err := s.Touch(ctx, "sid-1", rec); err != nil {
				t.Fatal(err)
			}
		}
		waitGone(t, s, "sid-1")
	})

	t.Run("touch writes the record back", func(t *testing.T) {
		t.Parallel()
		s, ctx := newStore(t), context.Background()
		put(t, s, "sid-1", time.Hour)
		rec, err := s.Get(ctx, "sid-1")
		if err != nil {
			t.Fatal(err)
		}
		rec.Values = map[string]string{"user": "42", "tenant": "t-1"}
		rec.State = json.RawMessage(`{"token":"rotated"}`)
		rec.VerifiedAt = rec.VerifiedAt.Add(time.Minute)
		if err := s.Touch(ctx, "sid-1", rec); err != nil {
			t.Fatal(err)
		}
		got, err := s.Get(ctx, "sid-1")
		if err != nil {
			t.Fatal(err)
		}
		sameRecord(t, got, rec)
	})

	t.Run("touch of a stale read", func(t *testing.T) {
		t.Parallel()
		s, ctx := newStore(t), context.Background()
		put(t, s, "sid-1", time.Hour)
		first, err := s.Get(ctx, "sid-1")
		if err != nil {
			t.Fatal(err)
		}
		if first.Version == 0 {
			t.Skip("the store does not do compare-and-swap (Get leaves Version zero)")
		}
		if err := s.Touch(ctx, "sid-1", first); err != nil {
			t.Fatal(err)
		}
		stale := first
		stale.Values = map[string]string{"lost": "yes"}
		if err := s.Touch(ctx, "sid-1", stale); !errors.Is(err, auth.ErrConflict) {
			t.Errorf("Touch of a stale read = %v, want ErrConflict", err)
		}
		got, err := s.Get(ctx, "sid-1")
		if err != nil {
			t.Fatal(err)
		}
		if got.Values["lost"] != "" {
			t.Error("the stale write landed")
		}
		if got.Version == first.Version {
			t.Error("Version did not move with a write")
		}
	})

	t.Run("claim", func(t *testing.T) {
		t.Parallel()
		s, ctx := newStore(t), context.Background()
		c, ok := s.(auth.Claimer)
		if !ok {
			t.Skip("the store does not implement auth.Claimer")
		}
		put(t, s, "sid-1", time.Hour)
		rec, err := s.Get(ctx, "sid-1")
		if err != nil {
			t.Fatal(err)
		}
		claimed, ok, err := c.Claim(ctx, "sid-1", rec)
		if err != nil || !ok {
			t.Fatalf("Claim of a fresh read = %v, %v", ok, err)
		}
		if claimed.RefreshingAt.IsZero() {
			t.Error("Claim did not write RefreshingAt")
		}
		if got, err := s.Get(ctx, "sid-1"); err != nil || !got.RefreshingAt.Equal(claimed.RefreshingAt) {
			t.Errorf("the claim is not in the store: %v, %v", got.RefreshingAt, err)
		}
		// The read the claim was taken against is stale now, for a second claim and for a write.
		if _, ok, err := c.Claim(ctx, "sid-1", rec); err != nil || ok {
			t.Errorf("a second Claim of the same read = %v, %v, want a lost race", ok, err)
		}
		if err := s.Touch(ctx, "sid-1", rec); !errors.Is(err, auth.ErrConflict) {
			t.Errorf("Touch of the read before the claim = %v, want ErrConflict", err)
		}
		if err := s.Touch(ctx, "sid-1", claimed); err != nil {
			t.Errorf("Touch of the claimed record = %v", err)
		}
		if _, _, err := c.Claim(ctx, "nobody", rec); !errors.Is(err, auth.ErrNotFound) {
			t.Errorf("Claim of an unknown id = %v, want ErrNotFound", err)
		}
	})

	t.Run("feed", func(t *testing.T) {
		t.Parallel()
		s, ctx := newStore(t), context.Background()
		f, ok := s.(Follower)
		if !ok {
			t.Skip("the store has no Follow")
		}
		put(t, s, "before", time.Hour)
		fctx, cancel := context.WithCancel(ctx)
		defer cancel()
		events := f.Follow(fctx)

		ev := next(t, events)
		if ev.Kind != auth.Loaded || len(ev.IDs) != 1 || ev.IDs[0] != "before" {
			t.Fatalf("the first event is %+v, want Loaded [before]", ev)
		}
		put(t, s, "sid-1", time.Hour)
		expect(t, events, auth.Added, "sid-1")
		rec, err := s.Get(ctx, "sid-1")
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Touch(ctx, "sid-1", rec); err != nil {
			t.Fatal(err)
		}
		expect(t, events, auth.Added, "sid-1")
		if err := s.Delete(ctx, "sid-1"); err != nil {
			t.Fatal(err)
		}
		expect(t, events, auth.Removed, "sid-1")
		put(t, s, "short", TTL)
		expect(t, events, auth.Added, "short")
		expect(t, events, auth.Removed, "short")

		cancel()
		for range events {
			// Drained until the store closes the feed, which it has to once ctx ends.
		}
	})
}

func sample() auth.Record {
	now := time.Now().Truncate(time.Second)
	return auth.Record{
		Provider:   "corp",
		Subject:    "alice",
		Claims:     json.RawMessage(`{"iss":"https://idp.example","groups":["admins"]}`),
		Values:     map[string]string{"user": "42"},
		State:      json.RawMessage(`{"refresh_token":"r-1"}`),
		CreatedAt:  now,
		VerifiedAt: now,
		Deadline:   now.Add(24 * time.Hour),
	}
}

func put(t *testing.T, s auth.Store, sid string, ttl time.Duration) {
	t.Helper()
	if err := s.Put(context.Background(), sid, sample(), ttl); err != nil {
		t.Fatal(err)
	}
}

func waitGone(t *testing.T, s auth.Store, sid string) {
	t.Helper()
	for end := time.Now().Add(patience); time.Now().Before(end); time.Sleep(100 * time.Millisecond) {
		if _, err := s.Get(context.Background(), sid); errors.Is(err, auth.ErrNotFound) {
			return
		} else if err != nil {
			t.Fatal(err)
		}
	}
	t.Fatalf("record %q did not expire within %s", sid, patience)
}

func next(t *testing.T, events <-chan auth.Event) auth.Event {
	t.Helper()
	select {
	case ev, ok := <-events:
		if !ok {
			t.Fatal("the feed closed")
		}
		return ev
	case <-time.After(patience):
		t.Fatalf("no event within %s", patience)
	}
	return auth.Event{}
}

func expect(t *testing.T, events <-chan auth.Event, kind auth.EventKind, id string) {
	t.Helper()
	if ev := next(t, events); ev.Kind != kind || ev.ID != id {
		t.Fatalf("event %+v, want kind %d for %q", ev, kind, id)
	}
}

// sameRecord compares what a store persists: everything but Version, with JSON compared as values and
// times as instants.
func sameRecord(t *testing.T, got, want auth.Record) {
	t.Helper()
	if got.Provider != want.Provider || got.Subject != want.Subject {
		t.Errorf("identity %q/%q, want %q/%q", got.Provider, got.Subject, want.Provider, want.Subject)
	}
	for name, pair := range map[string][2]json.RawMessage{"claims": {got.Claims, want.Claims}, "state": {got.State, want.State}} {
		if !sameJSON(pair[0], pair[1]) {
			t.Errorf("%s %s, want %s", name, pair[0], pair[1])
		}
	}
	if !maps.Equal(got.Values, want.Values) {
		t.Errorf("values %v, want %v", got.Values, want.Values)
	}
	for name, pair := range map[string][2]time.Time{
		"created_at": {got.CreatedAt, want.CreatedAt}, "verified_at": {got.VerifiedAt, want.VerifiedAt},
		"deadline": {got.Deadline, want.Deadline}, "refreshing_at": {got.RefreshingAt, want.RefreshingAt},
	} {
		if !pair[0].Equal(pair[1]) {
			t.Errorf("%s %s, want %s", name, pair[0], pair[1])
		}
	}
}

func sameJSON(a, b json.RawMessage) bool {
	if len(a) == 0 || len(b) == 0 {
		return len(a) == len(b)
	}
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}
