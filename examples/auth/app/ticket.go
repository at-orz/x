package app

import (
	"context"
	"crypto/rand"
	"time"

	"github.com/at-orz/x/auth"
	"github.com/at-orz/x/auth/mint"
	"github.com/at-orz/x/auth/store/memory"
)

// IssueTicket writes a ticket for a session of subject lasting ttl and returns the path that redeems
// it, to be appended to the app's https URL. Only cfg.Tickets is used.
//
// A ticket is issued through a mint.Method, which only exists registered with an auth.Manager, so a
// command that writes one ticket builds a Manager it never serves from (XGO-7). The key and store here
// are throwaway and refuse everything: none of them is ever asked.
func IssueTicket(ctx context.Context, cfg Config, subject string, ttl time.Duration) (string, error) {
	m, err := auth.New(auth.Options{
		Store:     memory.New(),
		Key:       []byte(rand.Text() + rand.Text()),
		Authorize: auth.AnyOf(),
	})
	if err != nil {
		return "", err
	}
	mt, err := mint.New(m, mint.Options{Tickets: cfg.Tickets})
	if err != nil {
		return "", err
	}
	return mt.Issue(ctx, subject, ttl)
}
