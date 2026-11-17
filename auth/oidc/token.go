package oidc

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

type discovery struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	AuthMethods           []string `json:"token_endpoint_auth_methods_supported"`
}

type cachedDiscovery struct {
	doc       discovery
	fetchedAt time.Time
}

const discoTTL = time.Hour

func (p *Provider) discover(ctx context.Context, issuer string) (discovery, error) {
	p.mu.Lock()
	if c, ok := p.disco[issuer]; ok && time.Since(c.fetchedAt) < discoTTL {
		p.mu.Unlock()
		return c.doc, nil
	}
	p.mu.Unlock()

	u := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return discovery{}, err
	}
	resp, err := p.hc.Do(req)
	if err != nil {
		return discovery{}, fmt.Errorf("fetch %s: %w", u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return discovery{}, fmt.Errorf("fetch %s: HTTP %d", u, resp.StatusCode)
	}
	var doc discovery
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return discovery{}, fmt.Errorf("decode %s: %w", u, err)
	}
	// The issuer has to state the same identity about itself, or comparing it with the iss of an ID token
	// later means nothing.
	if doc.Issuer != strings.TrimSuffix(issuer, "/") && doc.Issuer != issuer {
		return discovery{}, fmt.Errorf("%s advertises issuer %q, not %q", u, doc.Issuer, issuer)
	}
	if doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" {
		return discovery{}, fmt.Errorf("%s is missing authorization_endpoint or token_endpoint", u)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	// Swept here rather than by a janitor: an entry past its TTL is never read again, and the config names
	// one issuer at a time, so the map holds the issuers of the past hour and nothing older.
	for k, c := range p.disco {
		if time.Since(c.fetchedAt) >= discoTTL {
			delete(p.disco, k)
		}
	}
	p.disco[issuer] = cachedDiscovery{doc: doc, fetchedAt: time.Now()}
	return doc, nil
}

type tokenResponse struct {
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	Error        string `json:"error"`
	Desc         string `json:"error_description"`
}

// tokenError is what the token endpoint answered, carrying the status because that is what tells a
// refusal from a failure to ask: the first ends a session and the second may not.
type tokenError struct {
	// status is 0 when the request never reached an answer at all.
	status int
	code   string
	desc   string
}

func (e *tokenError) Error() string {
	switch {
	case e.code != "":
		return fmt.Sprintf("token endpoint: %s %s", e.code, e.desc)
	case e.status != 0:
		return fmt.Sprintf("token endpoint: HTTP %d", e.status)
	default:
		return "token endpoint: " + e.desc
	}
}

// refused says the provider made a decision about this token. A 5xx, a timeout or a connection failure
// is not a decision; a 4xx is, and so is an error object in the body, which is how invalid_grant arrives.
func (e *tokenError) refused() bool {
	if e.status == 0 || e.status >= 500 {
		return false
	}
	return e.status >= 400 || e.code != ""
}

// exchange trades the authorization code for a token set.
func (p *Provider) exchange(ctx context.Context, cfg Config, doc discovery, code, redirect, verifier string) (tokenResponse, error) {
	tr, err := p.postToken(ctx, cfg, doc, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirect},
		"code_verifier": {verifier},
	})
	if err != nil {
		return tokenResponse{}, err
	}
	if tr.IDToken == "" {
		return tokenResponse{}, errors.New("token endpoint returned no id_token")
	}
	return tr, nil
}

// postToken is the one place that talks to the token endpoint, shared by the login and by every refresh
// after it, so both authenticate the client the same way.
func (p *Provider) postToken(ctx context.Context, cfg Config, doc discovery, form url.Values) (tokenResponse, error) {
	// client_secret_basic is the default of OIDC, and post is used only when a provider says it does not
	// support it.
	basic := true
	if len(doc.AuthMethods) > 0 && !slices.Contains(doc.AuthMethods, "client_secret_basic") {
		if !slices.Contains(doc.AuthMethods, "client_secret_post") {
			return tokenResponse{}, fmt.Errorf("the provider supports neither client_secret_basic nor client_secret_post (%v)",
				doc.AuthMethods)
		}
		basic = false
	}
	if !basic {
		form.Set("client_id", cfg.ClientID)
		form.Set("client_secret", cfg.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, doc.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if basic {
		// RFC 6749 §2.3.1 has the id and secret form-encoded before they go into the header.
		req.SetBasicAuth(url.QueryEscape(cfg.ClientID), url.QueryEscape(cfg.ClientSecret))
	}
	resp, err := p.hc.Do(req)
	if err != nil {
		return tokenResponse{}, &tokenError{desc: err.Error()}
	}
	defer resp.Body.Close()
	var tr tokenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tr); err != nil {
		return tokenResponse{}, &tokenError{status: resp.StatusCode, desc: fmt.Sprintf("decoding the response failed: %s", err)}
	}
	if tr.Error != "" {
		return tokenResponse{}, &tokenError{status: resp.StatusCode, code: tr.Error, desc: tr.Desc}
	}
	if resp.StatusCode != http.StatusOK {
		return tokenResponse{}, &tokenError{status: resp.StatusCode}
	}
	return tr, nil
}

// idToken is an ID token as far as this package checks it, with every claim kept for the session.
type idToken struct {
	Issuer   string          `json:"iss"`
	Subject  string          `json:"sub"`
	Audience json.RawMessage `json:"aud"`
	Expiry   int64           `json:"exp"`
	Nonce    string          `json:"nonce"`

	all map[string]any
}

// parseIDToken decodes the payload alone; the package comment says why the signature is not verified.
func parseIDToken(raw string) (idToken, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return idToken{}, errors.New("the id_token is not a JWT")
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return idToken{}, fmt.Errorf("decode id_token payload: %w", err)
	}
	var t idToken
	if err := json.Unmarshal(body, &t); err != nil {
		return idToken{}, fmt.Errorf("decode id_token claims: %w", err)
	}
	if err := json.Unmarshal(body, &t.all); err != nil {
		return idToken{}, fmt.Errorf("decode id_token claims: %w", err)
	}
	return t, nil
}

func (t idToken) validate(cfg Config, discoveredIssuer, nonce string) error {
	if err := t.validateOrigin(cfg, discoveredIssuer); err != nil {
		return err
	}
	if t.Expiry == 0 || time.Now().After(time.Unix(t.Expiry, 0)) {
		return errors.New("the id_token has expired")
	}
	if t.Nonce == "" || !hmac.Equal([]byte(t.Nonce), []byte(nonce)) {
		return errors.New("id_token nonce mismatch")
	}
	if t.Subject == "" {
		return errors.New("the id_token carries no sub")
	}
	return nil
}

// validateRefreshed is the same check for a token that arrives with a refresh: no nonce to compare, and
// the subject has to be the one the session was created for.
func (t idToken) validateRefreshed(cfg Config, discoveredIssuer, subject string) error {
	if err := t.validateOrigin(cfg, discoveredIssuer); err != nil {
		return err
	}
	if t.Subject != subject {
		return fmt.Errorf("id_token sub %q is not the %q of this session", t.Subject, subject)
	}
	return nil
}

func (t idToken) validateOrigin(cfg Config, discoveredIssuer string) error {
	if t.Issuer != cfg.Issuer && t.Issuer != discoveredIssuer {
		return fmt.Errorf("id_token iss %q is not %q", t.Issuer, cfg.Issuer)
	}
	auds, err := audiences(t.Audience)
	if err != nil {
		return err
	}
	if !slices.Contains(auds, cfg.ClientID) {
		return fmt.Errorf("id_token aud %v does not contain %q", auds, cfg.ClientID)
	}
	return nil
}

// audiences accepts both legal forms of aud: one string, or an array of strings.
func audiences(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return nil, errors.New("the id_token carries no aud")
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return []string{one}, nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return nil, fmt.Errorf("id_token aud is neither a string nor an array: %w", err)
	}
	return many, nil
}
