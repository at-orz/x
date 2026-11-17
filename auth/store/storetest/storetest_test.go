package storetest_test

import (
	"testing"

	"github.com/at-orz/x/auth"
	"github.com/at-orz/x/auth/mint"
	"github.com/at-orz/x/auth/store/memory"
	"github.com/at-orz/x/auth/store/storetest"
)

// The suites run against the memory store here too, so that a change to a suite is checked where it is
// made rather than only where it is used.
func TestSuites(t *testing.T) {
	t.Run("store", func(t *testing.T) {
		storetest.Run(t, func(*testing.T) auth.Store { return memory.New() })
	})
	t.Run("tickets", func(t *testing.T) {
		storetest.RunTickets(t, func(*testing.T) mint.Tickets { return memory.New().Tickets() })
	})
}
