package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/at-orz/x/auth"
	"github.com/at-orz/x/auth/mint"
	"github.com/at-orz/x/auth/store/storetest"
)

func TestContract(t *testing.T) {
	needPostgres(t)
	storetest.Run(t, func(t *testing.T) auth.Store { return newStore(t) })
}

func TestTicketsContract(t *testing.T) {
	needPostgres(t)
	storetest.RunTickets(t, func(t *testing.T) mint.Tickets { return newStore(t).Tickets() })
}

func TestNewRefusesABadPrefix(t *testing.T) {
	long := func(n int) string { return "a" + strings.Repeat("b", n-2) + "_" }
	panics := func(f func()) (did bool) {
		defer func() { did = recover() != nil }()
		f()
		return false
	}
	for _, p := range []string{"", "auth", "Auth_", "a-b_", "1a_", "a;drop_", long(40)} {
		if !panics(func() { New(nil, p) }) {
			t.Errorf("New accepted prefix %q", p)
		}
		if !panics(func() { Schema(p) }) {
			t.Errorf("Schema accepted prefix %q", p)
		}
	}
	for _, p := range []string{"auth_", "__", long(39)} {
		if panics(func() { New(nil, p) }) {
			t.Errorf("New refused prefix %q", p)
		}
		if panics(func() { Schema(p) }) {
			t.Errorf("Schema refused prefix %q", p)
		}
	}
}

func record() auth.Record {
	now := time.Now().Truncate(time.Second)
	return auth.Record{Provider: "corp", Subject: "alice", CreatedAt: now, VerifiedAt: now,
		State: json.RawMessage(`{"refresh_token":"r-1"}`)}
}

func put(t *testing.T, s *Store, sid string, rec auth.Record, ttl time.Duration) {
	t.Helper()
	if err := s.Put(context.Background(), sid, rec, ttl); err != nil {
		t.Fatal(err)
	}
}

func get(t *testing.T, s *Store, sid string) auth.Record {
	t.Helper()
	rec, err := s.Get(context.Background(), sid)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

// expire moves a row's expiry into the past on the database's clock, for tests that need an expired row
// without waiting for one.
func expire(t *testing.T, s *Store, table, key, id string) {
	t.Helper()
	_, err := s.pool.Exec(context.Background(),
		`UPDATE `+s.prefix+table+` SET expires_at = now() - interval '1 second' WHERE `+key+` = $1`, id)
	if err != nil {
		t.Fatal(err)
	}
}

func count(t *testing.T, s *Store, table string) int {
	t.Helper()
	var n int
	if err := s.pool.QueryRow(context.Background(), `SELECT count(*) FROM `+s.prefix+table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

type column struct{ name, typ, nullable string }

func columns(t *testing.T, s *Store, table string) []column {
	t.Helper()
	rows, err := s.pool.Query(context.Background(), `SELECT column_name, data_type, is_nullable
FROM information_schema.columns WHERE table_name = $1 ORDER BY ordinal_position`, table)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []column
	for rows.Next() {
		var c column
		if err := rows.Scan(&c.name, &c.typ, &c.nullable); err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// indexes are the definitions of a table's indexes with the table's prefix taken out, so two prefixes'
// tables compare equal.
func indexes(t *testing.T, s *Store, prefix string) []string {
	t.Helper()
	rows, err := s.pool.Query(context.Background(),
		`SELECT indexdef FROM pg_indexes WHERE tablename = $1 ORDER BY indexname`, prefix+"sessions")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var def string
		if err := rows.Scan(&def); err != nil {
			t.Fatal(err)
		}
		out = append(out, strings.ReplaceAll(def, prefix, "<prefix>"))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// A host whose sessions table predates this module keeps it as it is, rows included.
func TestTheHostsExistingTableWorksUnchanged(t *testing.T) {
	db := needPostgres(t)
	ctx := context.Background()
	t.Cleanup(func() { _, _ = db.Exec(context.Background(), `DROP TABLE IF EXISTS auth_sessions, auth_mint_tickets`) })
	if _, err := db.Exec(ctx, `
CREATE TABLE auth_sessions (
    sid         text PRIMARY KEY,
    record      jsonb       NOT NULL,  -- auth.Record as JSON, Version excluded
    version     bigint      NOT NULL,  -- 1 on insert, +1 on every write
    expires_at  timestamptz NOT NULL,
    ttl_seconds bigint      NOT NULL   -- the ttl of Put, which Touch restarts
);
CREATE INDEX auth_sessions_expires_idx ON auth_sessions (expires_at);`); err != nil {
		t.Fatal(err)
	}
	want := record()
	body, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO auth_sessions VALUES ('old', $1::jsonb, 7, now() + interval '1 hour', 3600)`,
		string(body)); err != nil {
		t.Fatal(err)
	}

	s := New(db, "auth_")
	if err := s.CreateTables(ctx); err != nil {
		t.Fatal(err)
	}
	got := get(t, s, "old")
	if got.Version != 7 || got.Subject != want.Subject || !got.CreatedAt.Equal(want.CreatedAt) {
		t.Errorf("Get = %+v, want the hand-written record at version 7", got)
	}
	if err := s.Touch(ctx, "old", got); err != nil {
		t.Fatal(err)
	}
	if r := row(t, s, "old"); r.version != 8 || r.ttlSeconds != 3600 {
		t.Errorf("after Touch: %+v, want version 8 and ttl_seconds 3600", r)
	}
	put(t, s, "new", record(), 90*time.Second)
	if r := row(t, s, "new"); r.version != 1 || r.ttlSeconds != 90 {
		t.Errorf("after Put: %+v, want version 1 and ttl_seconds 90", r)
	}

	fresh := newStore(t)
	if a, b := columns(t, s, "auth_sessions"), columns(t, fresh, fresh.prefix+"sessions"); !slices.Equal(a, b) {
		t.Errorf("columns: host's %v, Schema's %v", a, b)
	}
	if a, b := indexes(t, s, "auth_"), indexes(t, fresh, fresh.prefix); !slices.Equal(a, b) {
		t.Errorf("indexes: host's %v, Schema's %v", a, b)
	}
}

func TestExpiryIsOnTheDatabaseClock(t *testing.T) {
	s := newStore(t)
	put(t, s, "sid", record(), 90*time.Second)
	if r := row(t, s, "sid"); r.ttlSeconds != 90 || r.left <= 88*time.Second || r.left > 90*time.Second {
		t.Errorf("row %+v, want ttl_seconds 90 and expires_at - now() in (88s, 90s]", r)
	}
	put(t, s, "short", record(), 1500*time.Millisecond)
	if r := row(t, s, "short"); r.ttlSeconds != 2 {
		t.Errorf("a 1500ms ttl stored ttl_seconds %d, want 2", r.ttlSeconds)
	}
}

// Instances reaching the refresh window of one session at once: exactly one gets the claim, and the
// others learn they lost without an error.
func TestClaimRaceHasOneWinner(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	put(t, s, "sid", record(), time.Hour)
	read := get(t, s, "sid")
	const n = 8
	oks := make([]bool, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range n {
		wg.Go(func() {
			<-start
			_, oks[i], errs[i] = s.Claim(ctx, "sid", read)
		})
	}
	close(start)
	wg.Wait()
	wins := 0
	for i := range n {
		if errs[i] != nil {
			t.Errorf("claim %d: %v", i, errs[i])
		}
		if oks[i] {
			wins++
		}
	}
	if wins != 1 {
		t.Errorf("%d claims won, want exactly 1", wins)
	}
}

func TestAStaleClaimIsTakenOverAfterAFreshGet(t *testing.T) {
	a := newStore(t)
	b := New(a.pool, a.prefix)
	ctx := context.Background()
	put(t, a, "sid", record(), time.Hour)
	readA, readB := get(t, a, "sid"), get(t, b, "sid")
	first, ok, err := a.Claim(ctx, "sid", readA)
	if err != nil || !ok {
		t.Fatalf("A's claim: ok=%v, %v", ok, err)
	}
	if _, ok, err := b.Claim(ctx, "sid", readB); err != nil || ok {
		t.Fatalf("B's claim on its earlier read: ok=%v, %v; want ok=false and no error", ok, err)
	}
	time.Sleep(10 * time.Millisecond)
	second, ok, err := b.Claim(ctx, "sid", get(t, b, "sid"))
	if err != nil || !ok {
		t.Fatalf("B's claim after a fresh Get: ok=%v, %v", ok, err)
	}
	if !second.RefreshingAt.After(first.RefreshingAt) || second.Version <= first.Version {
		t.Errorf("B's claim %v at version %d, A's %v at version %d; want both later",
			second.RefreshingAt, second.Version, first.RefreshingAt, first.Version)
	}
}

func TestClaimKeepsTheExpiry(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	expiresAt := func() time.Time {
		t.Helper()
		var at time.Time
		if err := s.pool.QueryRow(ctx, `SELECT expires_at FROM `+s.prefix+`sessions WHERE sid = 'sid'`).Scan(&at); err != nil {
			t.Fatal(err)
		}
		return at
	}
	put(t, s, "sid", record(), time.Hour)
	before := expiresAt()
	time.Sleep(10 * time.Millisecond)
	claimed, ok, err := s.Claim(ctx, "sid", get(t, s, "sid"))
	if err != nil || !ok {
		t.Fatalf("Claim: ok=%v, %v", ok, err)
	}
	if after := expiresAt(); !after.Equal(before) {
		t.Errorf("Claim moved expires_at from %v to %v", before, after)
	}
	if err := s.Touch(ctx, "sid", claimed); err != nil {
		t.Fatal(err)
	}
	if after := expiresAt(); !after.After(before) {
		t.Errorf("Touch left expires_at at %v, want it after %v", after, before)
	}
}

// An expired row nobody swept yet is indistinguishable from a missing one, and no write brings it back.
func TestAnExpiredRowStaysEnded(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	// b first, so that it has expired by the time a has.
	put(t, s, "b", record(), time.Second)
	put(t, s, "a", record(), time.Second)
	read := get(t, s, "a")
	for end := time.Now().Add(10 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		if _, err := s.Get(ctx, "a"); errors.Is(err, auth.ErrNotFound) {
			break
		}
		if time.Now().After(end) {
			t.Fatal("a 1s session is still readable after 10s")
		}
	}
	old := row(t, s, "a")
	if err := s.Touch(ctx, "a", read); !errors.Is(err, auth.ErrNotFound) {
		t.Errorf("Touch = %v, want ErrNotFound", err)
	}
	if _, ok, err := s.Claim(ctx, "a", read); !errors.Is(err, auth.ErrNotFound) || ok {
		t.Errorf("Claim = ok=%v, %v; want ErrNotFound", ok, err)
	}
	if list, err := s.List(ctx); err != nil || len(list) != 0 {
		t.Errorf("List = %v, %v; want nothing", list, err)
	}
	if err := s.Remove(ctx, "b"); !errors.Is(err, auth.ErrNotFound) {
		t.Errorf("Remove = %v, want ErrNotFound", err)
	}
	if n := count(t, s, "sessions"); n != 1 {
		t.Errorf("%d rows after Remove, want only the expired one it was not given", n)
	}
	put(t, s, "a", record(), time.Hour)
	if got := get(t, s, "a"); got.Version <= old.version {
		t.Errorf("a new Put over the expired row is at version %d, want above %d", got.Version, old.version)
	}
}

func TestRemove(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.Remove(ctx, "nobody"); !errors.Is(err, auth.ErrNotFound) {
		t.Errorf("Remove of an unknown id = %v, want ErrNotFound", err)
	}
	put(t, s, "sid", record(), time.Hour)
	if err := s.Remove(ctx, "sid"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, "sid"); !errors.Is(err, auth.ErrNotFound) {
		t.Errorf("Get after Remove = %v, want ErrNotFound", err)
	}
}

func TestList(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	base := time.Now().Truncate(time.Second)
	older, newer, gone := record(), record(), record()
	older.CreatedAt, older.Subject = base.Add(-2*time.Hour), "bob"
	newer.CreatedAt, newer.VerifiedAt, newer.Deadline = base.Add(-time.Hour), base, base.Add(time.Hour)
	// A time zone other than the others', which a sort on the JSON text would get wrong.
	newer.CreatedAt = newer.CreatedAt.In(time.FixedZone("east", 10*3600))
	gone.CreatedAt = base
	put(t, s, "older", older, time.Hour)
	put(t, s, "newer", newer, time.Hour)
	put(t, s, "gone", gone, time.Hour)
	expire(t, s, "sessions", "sid", "gone")

	list, err := s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("List = %+v, want the two live sessions", list)
	}
	same := func(e Entry, id string, r auth.Record) {
		t.Helper()
		if e.ID != id || e.Provider != r.Provider || e.Subject != r.Subject || !e.CreatedAt.Equal(r.CreatedAt) ||
			!e.VerifiedAt.Equal(r.VerifiedAt) || !e.Deadline.Equal(r.Deadline) {
			t.Errorf("entry %+v, want %q of %+v", e, id, r)
		}
	}
	same(list[0], "newer", newer)
	same(list[1], "older", older)
}

func TestSweep(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	put(t, s, "live", record(), time.Hour)
	put(t, s, "expired", record(), time.Hour)
	expire(t, s, "sessions", "sid", "expired")
	tickets := s.Tickets()
	for _, nonce := range []string{"live", "expired"} {
		if err := tickets.Put(ctx, nonce, mint.Ticket{Subject: "bot-one", SessionTTL: time.Hour}, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	expire(t, s, "mint_tickets", "nonce", "expired")
	if err := s.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if ns, nt := count(t, s, "sessions"), count(t, s, "mint_tickets"); ns != 1 || nt != 1 {
		t.Errorf("after Sweep: %d sessions and %d tickets, want 1 of each", ns, nt)
	}
	get(t, s, "live")
	if _, err := tickets.Redeem(ctx, "live"); err != nil {
		t.Errorf("the live ticket: %v", err)
	}
}
