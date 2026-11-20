package postgres_test

import (
	"context"
	"log"
	"time"

	"github.com/at-orz/x/auth/store/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

func Example() {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, "postgres://app@db.example/app")
	if err != nil {
		log.Fatal(err)
	}
	store := postgres.New(pool, "auth_")
	if err := store.CreateTables(ctx); err != nil {
		log.Fatal(err)
	}
	// The store starts no goroutine of its own; the host sweeps on its schedule.
	go func() {
		for range time.Tick(time.Minute) {
			if err := store.Sweep(ctx); err != nil {
				log.Printf("sweep sessions: %v", err)
			}
		}
	}()
	// store goes to auth.Options.Store, and store.Tickets() to mint.Options.Tickets.
}
