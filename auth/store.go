package auth

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// The errors of this package and of every Store. Each is matched with errors.Is; most arrive wrapped.
var (
	// ErrEnded is the answer that ends a session: the authority refused it, its record is gone, or it
	// reached its deadline. A Method's Revalidate wraps it to end a session; any other error from there
	// means the authority could not be asked.
	ErrEnded = errors.New("the session has ended")
	// ErrNotAllowed is a refusal by Authorize or Options.Link.
	ErrNotAllowed = errors.New("not allowed")
	// ErrStoreUnavailable is a store that could not be read or written when nothing else could stand in.
	ErrStoreUnavailable = errors.New("the session store is unavailable")
	// ErrNotFound is a record or ticket that does not exist, has expired or was deleted.
	ErrNotFound = errors.New("not found")
	// ErrConflict is a write that lost to another write made since the record was read.
	ErrConflict = errors.New("the record was written concurrently")
)

// Record is the server side of a session: who it belongs to, and what its method needs to vouch for it
// again. The cookie carries only the id it is stored under.
type Record struct {
	Provider string `json:"provider"`
	Subject  string `json:"sub"`
	// Claims is the JSON object of claims as of the last sign-in or revalidation.
	Claims json.RawMessage `json:"claims,omitempty"`
	// Values are the host's own, set at sign-in by Options.Link and later by Manager.SetValue.
	Values map[string]string `json:"values,omitempty"`
	// State is private to the method, such as a refresh token. It never leaves the server.
	State json.RawMessage `json:"state,omitempty"`
	// CreatedAt is when the sign-in happened and is never rewritten. VerifiedAt is when the authority last
	// confirmed the session, which the grace window is measured from while the authority cannot be asked.
	CreatedAt  time.Time `json:"created_at"`
	VerifiedAt time.Time `json:"verified_at"`
	// Deadline ends a session that is never revalidated, and is zero on every other.
	Deadline time.Time `json:"deadline,omitzero"`
	// RefreshingAt is when an instance last took the right to revalidate this session, written by a
	// Claimer.
	RefreshingAt time.Time `json:"refreshing_at,omitzero"`

	// Version identifies the read that produced this record. auth never interprets it: a store that does
	// compare-and-swap sets it in Get and Claim and compares it in Claim and Touch; any other ignores it.
	Version int64 `json:"-"`
}

// Store holds session records. Every method may be called concurrently.
type Store interface {
	// Put creates a record that expires after ttl unless touched.
	Put(ctx context.Context, sid string, rec Record, ttl time.Duration) error
	// Get reads a record, reporting ErrNotFound for one that is gone.
	Get(ctx context.Context, sid string) (Record, error)
	// Touch writes a record back and restarts its expiry with the ttl it was put with. It reports
	// ErrNotFound for a record that is gone, and, in a store that does compare-and-swap, ErrConflict for
	// one written since rec was read; a store without compare-and-swap never reports ErrConflict.
	Touch(ctx context.Context, sid string, rec Record) error
	// Delete removes a record. A record that is gone already is not an error: every caller wants the
	// session ended, not a report of who ended it first.
	Delete(ctx context.Context, sid string) error
}

// Claimer is implemented by a store shared by several instances. Claim takes the right to revalidate
// one session, writing RefreshingAt, with ok=false meaning another instance holds it.
//
// It exists because an authority that rotates refresh tokens reads a token presented twice as the
// replay of one it has retired, and refuses it: two instances revalidating one session at the same
// moment would end the very session both meant to extend.
type Claimer interface {
	Claim(ctx context.Context, sid string, rec Record) (claimed Record, ok bool, err error)
}

// EventKind is what one Event says about the sessions of a store.
type EventKind int

const (
	// Loaded carries every session id in IDs; the feed is in sync from here on.
	Loaded EventKind = iota
	// Added is a write of one record: a sign-in, a claim or a touch.
	Added
	// Removed is the deletion of one record, expiry included.
	Removed
	// Lost says the feed is out of sync until the next Loaded.
	Lost
)

// Event is one step of a store's feed of which sessions exist. IDs is set on Loaded alone, ID on Added
// and Removed.
type Event struct {
	Kind EventKind
	ID   string
	IDs  []string
}
