package oidc

import (
	"context"
	"fmt"
	"strings"

	"github.com/at-orz/x/auth"
)

// AllowEmails admits the identities of one provider whose verified email is on the list. It is the allow
// list for a provider whose sub is opaque, where the email claim is what a host can write down. provider
// is the Options.Name of the Provider it covers; emails is called on every call, so the list may change
// while sessions are open, and an empty list admits nobody.
//
// The ID token carries email and email_verified only when the email scope is requested: put "email" in
// that Provider's Options.Scopes, or every identity is refused. An email that is not verified is only what
// somebody typed at sign-up, so it is refused, whether email_verified is false or absent; the boolean true
// and, for providers that send it, the string "true" count as verified. Matching ignores case.
func AllowEmails(provider string, emails func() []string) auth.Authorize {
	return func(_ context.Context, id auth.Identity) error {
		if id.Provider != provider {
			return fmt.Errorf("%w: the email allow list of %q does not cover provider %q", auth.ErrNotAllowed, provider, id.Provider)
		}
		email, _ := id.Claims["email"].(string)
		if email == "" {
			return fmt.Errorf("%w: subject %q of %q has no email", auth.ErrNotAllowed, id.Subject, provider)
		}
		if v := id.Claims["email_verified"]; v != true && v != "true" {
			return fmt.Errorf("%w: the email %q of %q is not verified", auth.ErrNotAllowed, email, provider)
		}
		for _, e := range emails() {
			if strings.EqualFold(e, email) {
				return nil
			}
		}
		return fmt.Errorf("%w: %q is not on the email allow list of %q", auth.ErrNotAllowed, email, provider)
	}
}
