package oidc

import (
	"context"
	"errors"
	"testing"

	"github.com/at-orz/x/auth"
)

func TestAllowEmails(t *testing.T) {
	listed := []string{"alice@example.com"}
	identity := func(provider string, claims map[string]any) auth.Identity {
		return auth.Identity{Provider: provider, Subject: "CiQwOGE4Njg0Yi1kYjg4", Claims: claims}
	}
	verified := func(email any) map[string]any { return map[string]any{"email": email, "email_verified": true} }
	for _, c := range []struct {
		name  string
		list  []string
		id    auth.Identity
		admit bool
	}{
		{"listed and verified", listed, identity("dex", verified("alice@example.com")), true},
		{"verified as the string true", listed,
			identity("dex", map[string]any{"email": "alice@example.com", "email_verified": "true"}), true},
		{"listed in another case", listed, identity("dex", verified("Alice@Example.com")), true},
		{"another provider", listed, identity("corp", verified("alice@example.com")), false},
		{"no email", listed, identity("dex", map[string]any{"email_verified": true}), false},
		{"email not a string", listed, identity("dex", verified(42)), false},
		{"empty email", listed, identity("dex", verified("")), false},
		{"email_verified absent", listed, identity("dex", map[string]any{"email": "alice@example.com"}), false},
		{"email_verified false", listed,
			identity("dex", map[string]any{"email": "alice@example.com", "email_verified": false}), false},
		{"email_verified the string false", listed,
			identity("dex", map[string]any{"email": "alice@example.com", "email_verified": "false"}), false},
		{"email_verified the string TRUE", listed,
			identity("dex", map[string]any{"email": "alice@example.com", "email_verified": "TRUE"}), false},
		{"email_verified 1", listed,
			identity("dex", map[string]any{"email": "alice@example.com", "email_verified": float64(1)}), false},
		{"not on the list", listed, identity("dex", verified("mallory@example.com")), false},
		{"empty list", nil, identity("dex", verified("alice@example.com")), false},
		{"nil claims", listed, identity("dex", nil), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := AllowEmails("dex", func() []string { return c.list })(context.Background(), c.id)
			switch {
			case c.admit && err != nil:
				t.Errorf("refused: %v", err)
			case !c.admit && !errors.Is(err, auth.ErrNotAllowed):
				t.Errorf("err = %v, want a refusal wrapping auth.ErrNotAllowed", err)
			}
		})
	}
}

func TestAllowEmailsReadsTheListOnEveryCall(t *testing.T) {
	var list []string
	allow := AllowEmails("dex", func() []string { return list })
	id := auth.Identity{Provider: "dex", Subject: "CiQwOGE4Njg0Yi1kYjg4",
		Claims: map[string]any{"email": "alice@example.com", "email_verified": true}}
	if err := allow(context.Background(), id); !errors.Is(err, auth.ErrNotAllowed) {
		t.Fatalf("err = %v before alice was listed, want a refusal", err)
	}
	list = []string{"alice@example.com"}
	if err := allow(context.Background(), id); err != nil {
		t.Errorf("refused after alice was listed: %v", err)
	}
}
