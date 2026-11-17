package auth

import (
	"context"
	"errors"
	"fmt"
	"slices"
)

// Identity is who a session belongs to. Subject is unique within Provider only: two providers may each
// have an "alice", and they are two people until the host decides otherwise.
type Identity struct {
	// Provider is the name of the method that signed the session in.
	Provider string
	Subject  string
	// Claims are as of the last sign-in or revalidation, and nil for a method without claims. They are
	// shared with the session cache: read them, never modify them.
	Claims map[string]any
}

// Authorize admits or refuses an identity, refusing with any error. It runs at sign-in, at every
// revalidation and on every request, so a change of policy takes effect on the next request rather than
// when a cookie runs out. It is on the path of every request: it should answer from memory.
type Authorize func(ctx context.Context, id Identity) error

// AllowSubjects admits the listed subjects of one provider. The list is read on every call, so it may
// change while sessions are open. An empty list admits nobody.
func AllowSubjects(provider string, subjects func() []string) Authorize {
	return func(_ context.Context, id Identity) error {
		if id.Provider != provider {
			return fmt.Errorf("%w: the allow list of %q does not cover provider %q", ErrNotAllowed, provider, id.Provider)
		}
		if !slices.Contains(subjects(), id.Subject) {
			return fmt.Errorf("%w: subject %q is not on the allow list of %q", ErrNotAllowed, id.Subject, provider)
		}
		return nil
	}
}

// AnyOf admits what any of its arguments admits, and refuses with all of their reasons otherwise. With
// no arguments it admits nobody.
func AnyOf(a ...Authorize) Authorize {
	return func(ctx context.Context, id Identity) error {
		if len(a) == 0 {
			return fmt.Errorf("%w: no policy admits anyone", ErrNotAllowed)
		}
		errs := make([]error, 0, len(a))
		for _, f := range a {
			err := f(ctx, id)
			if err == nil {
				return nil
			}
			errs = append(errs, err)
		}
		return errors.Join(errs...)
	}
}
