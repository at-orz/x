// Package app is a host web app built on auth: the part of the example written to be copied. Its
// comments explain the decisions a host makes, not how auth works.
package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"slices"

	"github.com/at-orz/x/auth"
	"github.com/at-orz/x/auth/mint"
	"github.com/at-orz/x/auth/oidc"
)

// ProviderName is the name the identity provider is registered under. It is the Provider of every
// identity it signs in and appears in its paths, so the callback to register at the provider is
// https://<host>/auth/oidc/dex/callback.
const ProviderName = "dex"

// Config is everything the app needs from its deployment.
type Config struct {
	// Issuer, ClientID and ClientSecret are this app's registration at the identity provider.
	Issuer       string
	ClientID     string
	ClientSecret string
	// IdPCAFile is a PEM bundle trusted for the identity provider in place of the system roots, for a
	// provider whose certificate comes from a private CA. Empty means the system roots.
	IdPCAFile string

	// AllowEmails are the provider's accounts allowed in, by their verified email address.
	AllowEmails []string
	// AllowMinted are the subjects a ticket may sign in, such as an automated browser.
	AllowMinted []string

	// Sessions and Tickets are where sessions and tickets live. Feed, when set, is the sessions store's
	// feed of which sessions exist; without it every request reads its session record.
	Sessions auth.Store
	Tickets  mint.Tickets
	Feed     <-chan auth.Event

	// Key signs every cookie: at least 32 bytes, the same on every instance.
	Key []byte
	Log *slog.Logger
}

// New builds the app's handler. ctx bounds the session feed.
func New(ctx context.Context, cfg Config) (http.Handler, error) {
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	hc, err := idpClient(cfg.IdPCAFile)
	if err != nil {
		return nil, err
	}
	m, err := auth.New(auth.Options{
		Store:     cfg.Sessions,
		Key:       cfg.Key,
		Authorize: Authorize(cfg.AllowEmails, cfg.AllowMinted),
		Log:       log,
		Link:      link,
	})
	if err != nil {
		return nil, err
	}
	if cfg.Feed != nil {
		// Without the feed, a logout on another instance would only be noticed here once the cookie
		// reached its refresh window, up to half an hour later.
		m.FollowSessions(ctx, cfg.Feed)
	}

	// The provider's settings never change while the app runs, so Config answers a constant. A host that
	// reloads its configuration would read it here instead, and a change would apply at once.
	idp := oidc.Config{Issuer: cfg.Issuer, ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret}
	if err := idp.Validate(); err != nil {
		return nil, err
	}
	p, err := oidc.New(m, oidc.Options{
		Name:   ProviderName,
		Config: func() (oidc.Config, bool) { return idp, true },
		// email is what Authorize reads; profile adds the display name the page shows.
		Scopes:     []string{"email", "profile"},
		HTTPClient: hc,
	})
	if err != nil {
		return nil, err
	}
	mt, err := mint.New(m, mintOptions(cfg))
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	m.Routes(mux)
	p.Routes(mux)
	mt.Routes(mux)
	s := &server{m: m, log: log}
	s.routes(mux)
	return mux, nil
}

// idpClient trusts the bundle in caFile alone for the identity provider, or is nil (the system roots)
// without one.
func idpClient(caFile string) (*http.Client, error) {
	if caFile == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("reading the identity provider's CA bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s holds no PEM certificate", caFile)
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return &http.Client{Transport: tr}, nil
}

// Authorize admits the provider's accounts by verified email, and the listed subjects of tickets.
//
// The provider's accounts go by email rather than by subject because Dex's sub is an opaque encoding
// of the user id and connector that nobody would type into an allow list. The email has to be
// verified: an unverified one is only what somebody typed at sign-up. auth has no such policy of its
// own (XGO-8).
func Authorize(emails, minted []string) auth.Authorize {
	return auth.AnyOf(
		allowEmails(ProviderName, func() []string { return emails }),
		auth.AllowSubjects("mint", func() []string { return minted }),
	)
}

func allowEmails(provider string, emails func() []string) auth.Authorize {
	return func(_ context.Context, id auth.Identity) error {
		if id.Provider != provider {
			return fmt.Errorf("%w: the email allow list covers %q, not %q", auth.ErrNotAllowed, provider, id.Provider)
		}
		email, _ := id.Claims["email"].(string)
		if verified, _ := id.Claims["email_verified"].(bool); email == "" || !verified {
			return fmt.Errorf("%w: subject %q has no verified email", auth.ErrNotAllowed, id.Subject)
		}
		if !slices.Contains(emails(), email) {
			return fmt.Errorf("%w: %q is not on the email allow list", auth.ErrNotAllowed, email)
		}
		return nil
	}
}

// UserKey is the session value holding the app's own user id.
const UserKey = "user"

// link maps an identity to the app's own user. A real host looks the identity up in its user table
// here, creating the user on a first sign-in or refusing one it does not know; this example derives
// the id instead, so that it needs no database.
func link(_ context.Context, id auth.Identity) (map[string]string, error) {
	switch id.Provider {
	case ProviderName:
		email, _ := id.Claims["email"].(string)
		if email == "" {
			return nil, fmt.Errorf("%w: no email to link", auth.ErrNotAllowed)
		}
		return map[string]string{UserKey: "user:" + email}, nil
	case "mint":
		return map[string]string{UserKey: "bot:" + id.Subject}, nil
	}
	return nil, errors.New("no link for provider " + id.Provider)
}
