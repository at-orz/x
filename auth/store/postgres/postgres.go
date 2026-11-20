// Package postgres is an auth.Store, and the mint.Tickets of auth/mint, in PostgreSQL: for several
// instances of a host sharing sessions in a database it already runs.
//
// The store implements auth.Claimer, with compare-and-swap on a version column, so two instances never
// revalidate one session at the same moment. Connection, TLS and pooling stay with the host, which passes
// a *pgxpool.Pool.
//
// # Tables
//
// New(pool, prefix) keeps sessions in <prefix>sessions and tickets in <prefix>mint_tickets, so several
// stores can share one database. The tables live in the connection's search_path. The host applies
// Schema(prefix) with its migration tool, or calls CreateTables once at startup; both create nothing that
// exists already.
//
// # Expiry
//
// Every expiry is computed and compared on the database's clock, never the application's, so replicas
// whose clocks disagree end a session at the same moment. Reads ignore an expired row, and no write
// brings one back, but the row stays in its table until the host calls Sweep. The store starts no
// goroutine of its own; the host runs Sweep on its own schedule, from a cron job, its job runner, or a
// ticker:
//
//	go func() {
//		for range time.Tick(time.Minute) {
//			if err := store.Sweep(ctx); err != nil {
//				log.Printf("sweep sessions: %v", err)
//			}
//		}
//	}()
//
// # No Follow
//
// The store has no session feed, so it does not support auth.Manager.FollowSessions. FollowSessions
// admits an id into its live set without reading the store, and a row here expires only when it is read
// or swept, so a feed built on triggers or LISTEN/NOTIFY would keep admitting a session that expired but
// was not swept yet.
package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"
	"time"

	"github.com/at-orz/x/auth"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	_ auth.Store   = (*Store)(nil)
	_ auth.Claimer = (*Store)(nil)
)

// prefixPattern keeps a prefix a plain lower-case identifier, which is what lets it be written into SQL
// unquoted. Its length bound keeps the longest derived name, <prefix>mint_tickets_expires_idx, within the
// 63 bytes PostgreSQL keeps of an identifier: a longer one would be truncated silently, and two prefixes
// could then name the same table.
var prefixPattern = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,37}_$`)

func checkPrefix(prefix string) {
	if !prefixPattern.MatchString(prefix) {
		panic(fmt.Sprintf("postgres: prefix %q must match %s", prefix, prefixPattern))
	}
}

// Schema returns the DDL of the tables under prefix, every statement IF NOT EXISTS, for a host's
// migration tool. It panics on a prefix New refuses.
func Schema(prefix string) string {
	checkPrefix(prefix)
	return fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %[1]ssessions (
    sid         text        PRIMARY KEY,
    record      jsonb       NOT NULL,
    version     bigint      NOT NULL,
    expires_at  timestamptz NOT NULL,
    ttl_seconds bigint      NOT NULL
);
CREATE INDEX IF NOT EXISTS %[1]ssessions_expires_idx ON %[1]ssessions (expires_at);
CREATE TABLE IF NOT EXISTS %[1]smint_tickets (
    nonce      text        PRIMARY KEY,
    ticket     jsonb       NOT NULL,
    expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS %[1]smint_tickets_expires_idx ON %[1]smint_tickets (expires_at);
`, prefix)
}

// Store keeps session records in <prefix>sessions. It implements auth.Store and auth.Claimer.
type Store struct {
	pool   *pgxpool.Pool
	prefix string
	schema string
	q      queries
}

// queries are built once from the validated prefix, so no caller data ever reaches the text of a
// statement.
type queries struct {
	put, get, touch, claim, live, delete, remove, list, sweepSessions string
	putTicket, redeem, sweepTickets                                   string
}

// New returns the store of the tables under prefix. It panics when prefix does not match
// ^[a-z_][a-z0-9_]{0,37}_$: the prefix is a constant of the host.
func New(pool *pgxpool.Pool, prefix string) *Store {
	checkPrefix(prefix)
	s := prefix + "sessions"
	t := prefix + "mint_tickets"
	// Every expires_at is now() plus a whole number of seconds and every liveness test is against now(),
	// so the database's clock alone decides when a row ends. Each statement runs in its own implicit
	// transaction, which makes now() the moment of that statement.
	return &Store{pool: pool, prefix: prefix, schema: Schema(prefix), q: queries{
		// version + 1 on conflict covers a sid whose expired row was not swept yet: a stale read of the old
		// row can then never match.
		put: `INSERT INTO ` + s + ` AS r (sid, record, version, expires_at, ttl_seconds)
VALUES ($1, $2::jsonb, 1, now() + $3::bigint * interval '1 second', $3::bigint)
ON CONFLICT (sid) DO UPDATE SET record = EXCLUDED.record, version = r.version + 1,
    expires_at = EXCLUDED.expires_at, ttl_seconds = EXCLUDED.ttl_seconds`,
		get: `SELECT record, version FROM ` + s + ` WHERE sid = $1 AND expires_at > now()`,
		// Under READ COMMITTED the second of two concurrent updates waits for the first's row lock, then
		// re-evaluates its WHERE against the committed row, finds the version moved, and updates nothing.
		// That is the whole compare-and-swap: no explicit transaction or lock.
		touch: `UPDATE ` + s + ` SET record = $2::jsonb, version = version + 1,
    expires_at = now() + ttl_seconds * interval '1 second'
WHERE sid = $1 AND version = $3 AND expires_at > now()`,
		// A claim is not a use of the session, so it leaves expires_at alone.
		claim: `UPDATE ` + s + ` SET record = $2::jsonb, version = version + 1
WHERE sid = $1 AND version = $3 AND expires_at > now() RETURNING version`,
		live:   `SELECT EXISTS (SELECT 1 FROM ` + s + ` WHERE sid = $1 AND expires_at > now())`,
		delete: `DELETE FROM ` + s + ` WHERE sid = $1`,
		remove: `DELETE FROM ` + s + ` WHERE sid = $1 RETURNING expires_at > now()`,
		// The credentials are dropped in the database, so listing sessions never reads one out of it.
		list:          `SELECT sid, record - 'state' - 'claims' - 'values' FROM ` + s + ` WHERE expires_at > now()`,
		sweepSessions: `DELETE FROM ` + s + ` WHERE expires_at <= now()`,
		putTicket: `INSERT INTO ` + t + ` (nonce, ticket, expires_at)
VALUES ($1, $2::jsonb, now() + $3::bigint * interval '1 second')
ON CONFLICT (nonce) DO UPDATE SET ticket = EXCLUDED.ticket, expires_at = EXCLUDED.expires_at`,
		redeem:       `DELETE FROM ` + t + ` WHERE nonce = $1 RETURNING ticket, expires_at > now()`,
		sweepTickets: `DELETE FROM ` + t + ` WHERE expires_at <= now()`,
	}}
}

// CreateTables executes Schema(prefix) on the store's pool. On tables that exist already it does nothing.
func (s *Store) CreateTables(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx, s.schema); err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	return nil
}

// ttlSeconds is a ttl in the unit of the ttl_seconds column, rounded up so that a row never ends before
// ttl.
func ttlSeconds(ttl time.Duration) int64 {
	return max(1, int64(math.Ceil(ttl.Seconds())))
}

// Put creates the record of a sign-in that expires after ttl unless touched.
//
// JSON goes out as text cast to jsonb in the statement, which works in every pgx query exec mode,
// including the simple protocol a host behind a connection pooler may use.
func (s *Store) Put(ctx context.Context, sid string, rec auth.Record, ttl time.Duration) error {
	body, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if _, err := s.pool.Exec(ctx, s.q.put, sid, string(body), ttlSeconds(ttl)); err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	return nil
}

// Get reads one record, with Version set to its version column, reporting auth.ErrNotFound for a session
// that expired, was logged out or was removed.
func (s *Store) Get(ctx context.Context, sid string) (auth.Record, error) {
	var body []byte
	var version int64
	err := s.pool.QueryRow(ctx, s.q.get, sid).Scan(&body, &version)
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.Record{}, fmt.Errorf("session %q: %w", sid, auth.ErrNotFound)
	}
	if err != nil {
		return auth.Record{}, fmt.Errorf("postgres: %w", err)
	}
	var rec auth.Record
	if err := json.Unmarshal(body, &rec); err != nil {
		return auth.Record{}, fmt.Errorf("decode session %q: %w", sid, err)
	}
	rec.Version = version
	return rec, nil
}

// isLive tells apart, after a conditional write matched no row, a session that has ended from one that
// another instance wrote first.
func (s *Store) isLive(ctx context.Context, sid string) (bool, error) {
	var live bool
	if err := s.pool.QueryRow(ctx, s.q.live, sid).Scan(&live); err != nil {
		return false, fmt.Errorf("postgres: %w", err)
	}
	return live, nil
}

// Claim takes the right to revalidate one session, writing RefreshingAt, on the condition that the
// record has not been written since rec was read. ok=false means another instance wrote it first: it is
// asking, or has just asked. Only auth.ErrNotFound is an ending.
//
// RefreshingAt is the application's clock: it is data that auth reads, not an expiry.
func (s *Store) Claim(ctx context.Context, sid string, rec auth.Record) (auth.Record, bool, error) {
	rec.RefreshingAt = time.Now()
	body, err := json.Marshal(rec)
	if err != nil {
		return auth.Record{}, false, err
	}
	var version int64
	err = s.pool.QueryRow(ctx, s.q.claim, sid, string(body), rec.Version).Scan(&version)
	if errors.Is(err, pgx.ErrNoRows) {
		live, err := s.isLive(ctx, sid)
		if err != nil {
			return auth.Record{}, false, err
		}
		if !live {
			return auth.Record{}, false, fmt.Errorf("session %q: %w", sid, auth.ErrNotFound)
		}
		return auth.Record{}, false, nil
	}
	if err != nil {
		return auth.Record{}, false, fmt.Errorf("postgres: %w", err)
	}
	rec.Version = version
	return rec, true, nil
}

// Touch writes a record back and restarts its expiry with the ttl it was put with, on the condition that
// the record has not been written since rec was read; auth.ErrConflict otherwise. A session that has
// ended stays ended: the write matches no expired row.
func (s *Store) Touch(ctx context.Context, sid string, rec auth.Record) error {
	body, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx, s.q.touch, sid, string(body), rec.Version)
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	live, err := s.isLive(ctx, sid)
	if err != nil {
		return err
	}
	if !live {
		return fmt.Errorf("session %q: %w", sid, auth.ErrNotFound)
	}
	return fmt.Errorf("session %q: %w", sid, auth.ErrConflict)
}

// Delete removes a record; one that is gone already is not an error.
func (s *Store) Delete(ctx context.Context, sid string) error {
	if _, err := s.pool.Exec(ctx, s.q.delete, sid); err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	return nil
}

// Remove deletes a record and reports auth.ErrNotFound when there was no live one. That is its whole
// difference from Delete, and it exists for a host command revoking a session: an id that names nothing
// has to read as a failure, because a revocation that quietly did nothing is the one outcome an operator
// must not mistake for success. An expired row is still deleted, and still reported as not found, since
// the session it held had already ended.
func (s *Store) Remove(ctx context.Context, sid string) error {
	var live bool
	err := s.pool.QueryRow(ctx, s.q.remove, sid).Scan(&live)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !live {
		return fmt.Errorf("session %q: %w", sid, auth.ErrNotFound)
	}
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
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

// List reads every live session, the newest sign-in first.
func (s *Store) List(ctx context.Context) ([]Entry, error) {
	rows, err := s.pool.Query(ctx, s.q.list)
	if err != nil {
		return nil, fmt.Errorf("postgres: %w", err)
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var sid string
		var body []byte
		if err := rows.Scan(&sid, &body); err != nil {
			return nil, fmt.Errorf("postgres: %w", err)
		}
		var rec auth.Record
		if err := json.Unmarshal(body, &rec); err != nil {
			return nil, fmt.Errorf("decode session %q: %w", sid, err)
		}
		out = append(out, Entry{
			ID:         sid,
			Provider:   rec.Provider,
			Subject:    rec.Subject,
			CreatedAt:  rec.CreatedAt,
			VerifiedAt: rec.VerifiedAt,
			Deadline:   rec.Deadline,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: %w", err)
	}
	// In Go rather than ORDER BY: the timestamps are JSON text, which does not sort across time zones.
	slices.SortFunc(out, func(a, b Entry) int { return b.CreatedAt.Compare(a.CreatedAt) })
	return out, nil
}

// Sweep deletes the expired rows of both tables, and returns the first error after trying both.
func (s *Store) Sweep(ctx context.Context) error {
	var first error
	for _, q := range []string{s.q.sweepSessions, s.q.sweepTickets} {
		if _, err := s.pool.Exec(ctx, q); err != nil && first == nil {
			first = fmt.Errorf("postgres: %w", err)
		}
	}
	return first
}
