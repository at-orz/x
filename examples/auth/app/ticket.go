package app

import (
	"context"
	"time"

	"github.com/at-orz/x/auth/mint"
)

// mintOptions is shared by the server and IssueTicket: a ticket is redeemed at the path its Options
// name, so a command that built its own could write tickets no instance redeems.
func mintOptions(cfg Config) mint.Options {
	return mint.Options{Tickets: cfg.Tickets}
}

// IssueTicket writes a ticket for a session of subject lasting ttl and returns the path that redeems
// it, to be appended to the app's https URL. Only cfg.Tickets is used, so a command line needs neither
// the session key nor the sessions store.
func IssueTicket(ctx context.Context, cfg Config, subject string, ttl time.Duration) (string, error) {
	return mint.Issue(ctx, mintOptions(cfg), subject, ttl)
}
