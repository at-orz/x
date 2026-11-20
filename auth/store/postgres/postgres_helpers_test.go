package postgres

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// sunPathMax is the room for a Unix socket path in sockaddr_un, less its terminating NUL.
const sunPathMax = 107

// pool is the one server's pool every test shares; nil when PostgreSQL is not on PATH.
var pool *pgxpool.Pool

// TestMain starts a real PostgreSQL for the whole run, because the properties under test (row locking
// between concurrent writers, the server's clock) belong to PostgreSQL rather than to this code. Without
// initdb on PATH the tests that need the server skip, which is what a runner outside the devshell sees.
// With initdb present, a server that does not start fails the run: the devshell promises one, and a
// silent skip would hide the whole suite.
func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	if _, err := exec.LookPath("initdb"); err != nil {
		return m.Run()
	}
	dir, err := os.MkdirTemp("", "pg")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if len(dir)+len("/.s.PGSQL.5432") > sunPathMax {
		_ = os.RemoveAll(dir)
		if dir, err = os.MkdirTemp("/tmp", "pg"); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	defer os.RemoveAll(dir)
	data, logFile := filepath.Join(dir, "data"), filepath.Join(dir, "log")

	if out, err := exec.Command("initdb", "-D", data, "--auth=trust", "--username=postgres",
		"--encoding=UTF8", "--no-sync").CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "initdb: %v\n%s", err, out)
		return 1
	}
	// A Unix socket only, so no TCP port can collide with anything else on the machine.
	opts := fmt.Sprintf("-c listen_addresses='' -c unix_socket_directories=%s -c fsync=off", dir)
	if out, err := exec.Command("pg_ctl", "-D", data, "-l", logFile, "-w", "-o", opts,
		"start").CombinedOutput(); err != nil {
		log, _ := os.ReadFile(logFile)
		fmt.Fprintf(os.Stderr, "pg_ctl start: %v\n%s%s", err, out, log)
		return 1
	}
	defer func() { _ = exec.Command("pg_ctl", "-D", data, "stop", "-m", "immediate").Run() }()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p, err := pgxpool.New(ctx, fmt.Sprintf("host=%s user=postgres dbname=postgres", dir))
	if err == nil {
		err = p.Ping(ctx)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect to PostgreSQL: %v\n", err)
		return 1
	}
	defer p.Close()
	pool = p
	return m.Run()
}

// needPostgres returns the shared pool, or skips when there is no server.
func needPostgres(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if pool == nil {
		t.Skip("no PostgreSQL on PATH; this runs inside the devshell")
	}
	return pool
}

var prefixes atomic.Int64

// freshPrefix names tables no other test touches.
func freshPrefix() string {
	return fmt.Sprintf("t%d_", prefixes.Add(1))
}

// newStore is a store on tables of its own, created.
func newStore(t *testing.T) *Store {
	t.Helper()
	s := New(needPostgres(t), freshPrefix())
	if err := s.CreateTables(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s
}

// rowState is a session row as the table holds it, below the API.
type rowState struct {
	version, ttlSeconds int64
	// left is expires_at - now() on the database's clock.
	left time.Duration
}

func row(t *testing.T, s *Store, sid string) rowState {
	t.Helper()
	var r rowState
	err := s.pool.QueryRow(context.Background(),
		`SELECT version, ttl_seconds, expires_at - now() FROM `+s.prefix+`sessions WHERE sid = $1`, sid).
		Scan(&r.version, &r.ttlSeconds, &r.left)
	if err != nil {
		t.Fatalf("read the row of %q: %v", sid, err)
	}
	return r
}
