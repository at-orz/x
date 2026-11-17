// Package oidc signs in through one OpenID Connect provider: the authorization code flow with PKCE, a
// session issued by an auth.Manager, and the refresh token exchanged on the back channel whenever the
// Manager asks for the session to be revalidated.
//
// Register one Provider per identity provider, each under its own name. Its endpoints are
// /auth/oidc/<name>/login and /auth/oidc/<name>/callback; the redirect URI to register at the identity
// provider is the callback, with the scheme and host the browser uses.
//
// The signature of an ID token is not verified. Every token this package reads was fetched by this
// process from the token endpoint over TLS, which OIDC Core §3.1.3.7(6) accepts in place of signature
// validation; it saves a whole JOSE dependency tree. iss, aud, exp and nonce are still checked, and on a
// refresh a stable sub.
package oidc

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/at-orz/x/auth"
)

// Config is where one provider is: its issuer and this client's registration there.
type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string
}

// Validate refuses a config that cannot work: an issuer that is not an https URL, or a missing client id
// or secret.
func (c Config) Validate() error {
	u, err := url.Parse(c.Issuer)
	switch {
	case err != nil || u.Scheme != "https" || u.Host == "":
		return fmt.Errorf("oidc: issuer %q is not an https URL", c.Issuer)
	case c.ClientID == "":
		return errors.New("oidc: the client id is missing")
	case c.ClientSecret == "":
		return errors.New("oidc: the client secret is missing")
	}
	return nil
}

// Options configure a Provider. Name and Config are required.
type Options struct {
	// Name identifies the provider among the methods of its Manager, matching [a-z0-9-]+. It is the
	// Provider of the identities it signs in and appears in its paths; a host that would rather not
	// disclose which provider is which names them neutrally ("p1").
	Name string
	// Config is read on every use, so a change of configuration applies at once. Reporting false makes
	// the login answer 503 and counts as "could not ask" for revalidation; closing access when a provider
	// goes away is up to the host's Authorize.
	Config func() (Config, bool)
	// Scopes are requested in addition to "openid offline_access".
	Scopes []string
}

// Provider is the sign-in method of one OpenID Connect provider. It implements auth.Method.
type Provider struct {
	m          *auth.Manager
	name       string
	config     func() (Config, bool)
	scope      string
	flowCookie string
	loginPath  string
	callback   string
	hc         *http.Client

	mu    sync.Mutex
	disco map[string]cachedDiscovery
}

var namePattern = regexp.MustCompile(`^[a-z0-9-]+$`)

// tokenTimeout bounds a call to the provider, and with it the request path of a request that lands in
// the refresh window.
const tokenTimeout = 15 * time.Second

// New builds a Provider and registers it with m.
func New(m *auth.Manager, o Options) (*Provider, error) {
	if !namePattern.MatchString(o.Name) {
		return nil, fmt.Errorf("oidc: name %q is not [a-z0-9-]+", o.Name)
	}
	if o.Config == nil {
		return nil, errors.New("oidc: Options.Config is required")
	}
	p := &Provider{
		m:      m,
		name:   o.Name,
		config: o.Config,
		// offline_access is what asks for a refresh token, without which the session could not be
		// revalidated on the back channel. Some providers grant it only with a matching scope mapping
		// configured on their side; the callback refuses a login that comes back without one.
		scope: strings.Join(append([]string{"openid", "offline_access"}, o.Scopes...), " "),
		// The flow cookie is the provider's own, so that logins started at two providers at once do not
		// overwrite each other. Its name is keyed rather than spelled: an unkeyed hash of a short name is
		// reversed by trying names.
		flowCookie: m.CookieName("flow_" + hex.EncodeToString(m.MAC("flow:" + o.Name))[:16]),
		loginPath:  "/auth/oidc/" + o.Name + "/login",
		callback:   "/auth/oidc/" + o.Name + "/callback",
		hc:         &http.Client{Timeout: tokenTimeout},
		disco:      map[string]cachedDiscovery{},
	}
	if err := m.Register(p); err != nil {
		return nil, err
	}
	return p, nil
}

// Name is the provider's name.
func (p *Provider) Name() string { return p.name }

// LoginURL is where a browser starts a login at this provider, coming back to ret afterwards.
func (p *Provider) LoginURL(ret string) string {
	if ret == "" {
		return p.loginPath
	}
	return p.loginPath + "?" + url.Values{"ret": {ret}}.Encode()
}

// Routes mounts the login and the callback, which need no session themselves.
func (p *Provider) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET "+p.loginPath, p.handleLogin)
	mux.HandleFunc("GET "+p.callback, p.handleCallback)
}
