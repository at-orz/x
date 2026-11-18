package oidc

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/at-orz/x/auth"
	"github.com/at-orz/x/auth/internal/web"
)

const flowTTL = 10 * time.Minute

// retryMarker ends the state of a login that is itself the retry of a callback which could not be
// completed, so that a second failure in a row stops instead of starting another round.
//
// It rides in the state rather than in a cookie because the provider hands the state back untouched: the
// commonest reason to reach the callback twice is a flow cookie that was not there, and a marker kept in
// a cookie would be missing exactly then.
const retryMarker = ".retry"

// flowState is the payload of the flow cookie, which carries a login from its start to its callback.
type flowState struct {
	State string `json:"s"`
	Nonce string `json:"n"`
	// Verifier is the PKCE code_verifier. The cookie is signed rather than encrypted, which is enough:
	// what PKCE guards against is a code that reached someone other than this browser.
	Verifier string `json:"v"`
	Ret      string `json:"r,omitempty"`
	Exp      int64  `json:"e"`
}

// refreshState is the method-private State of a session record.
type refreshState struct {
	RefreshToken string `json:"refresh_token"`
}

func (p *Provider) handleLogin(w http.ResponseWriter, r *http.Request) {
	cfg, err := p.loadConfig()
	if err != nil {
		p.failUnconfigured(w, err)
		return
	}
	doc, err := p.discover(r.Context(), cfg.Issuer)
	if err != nil {
		p.m.Log().Error("OIDC discovery failed", "provider", p.name, "issuer", cfg.Issuer, "err", err)
		p.m.Fail(w, http.StatusBadGateway, "oidc_discovery_failed", web.IdPUnreachable)
		return
	}

	state := web.RandomToken()
	if r.URL.Query().Get("retry") != "" {
		state += retryMarker
	}
	flow := flowState{State: state, Nonce: web.RandomToken(), Verifier: codeVerifier(),
		Ret: web.SafeReturn(r.URL.Query().Get("ret")), Exp: time.Now().Add(flowTTL).Unix()}
	value, err := p.m.Seal(flow)
	if err != nil {
		p.m.Log().Error("signing the login flow cookie failed", "provider", p.name, "err", err)
		p.m.Fail(w, http.StatusInternalServerError, "internal", web.LoginFailed)
		return
	}
	web.SetCookie(w, r, p.flowCookie, value, flowTTL)

	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {cfg.ClientID},
		"redirect_uri":          {p.redirectURI(r)},
		"scope":                 {p.scope},
		"state":                 {flow.State},
		"nonce":                 {flow.Nonce},
		"code_challenge":        {codeChallenge(flow.Verifier)},
		"code_challenge_method": {"S256"},
	}
	http.Redirect(w, r, doc.AuthorizationEndpoint+"?"+q.Encode(), http.StatusFound)
}

func (p *Provider) handleCallback(w http.ResponseWriter, r *http.Request) {
	cfg, err := p.loadConfig()
	if err != nil {
		p.failUnconfigured(w, err)
		return
	}
	var flow flowState
	c, err := r.Cookie(p.flowCookie)
	if err != nil {
		p.retryLogin(w, r, "", "no login in progress (the flow cookie is missing or expired)")
		return
	}
	if err := p.m.Open(c.Value, &flow); err != nil {
		p.retryLogin(w, r, "", "the login flow cookie is invalid")
		return
	}
	if flow.Exp < time.Now().Unix() {
		// The address from before the login survives this one, unlike the two above: an expired cookie was
		// still signed by this process, so what it carries is this browser's own and worth going back to.
		p.retryLogin(w, r, flow.Ret, "the login flow cookie has expired")
		return
	}
	// Comparing the state is the guard against CSRF: the state in the callback has to match the one sent.
	if q := r.URL.Query().Get("state"); q == "" || !hmac.Equal([]byte(q), []byte(flow.State)) {
		p.retryLogin(w, r, flow.Ret, "state mismatch")
		return
	}
	if desc := r.URL.Query().Get("error"); desc != "" {
		p.fail(w, r, "the provider refused: "+desc)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		p.fail(w, r, "the provider returned no authorization code")
		return
	}
	if flow.Verifier == "" {
		p.fail(w, r, "the login flow cookie carries no PKCE verifier")
		return
	}

	doc, err := p.discover(r.Context(), cfg.Issuer)
	if err != nil {
		p.m.Log().Error("OIDC discovery failed", "provider", p.name, "issuer", cfg.Issuer, "err", err)
		p.m.Fail(w, http.StatusBadGateway, "oidc_discovery_failed", web.IdPUnreachable)
		return
	}
	tr, err := p.exchange(r.Context(), cfg, doc, code, p.redirectURI(r), flow.Verifier)
	if err != nil {
		p.m.Log().Warn("exchanging the authorization code for a token failed", "provider", p.name, "err", err)
		p.m.Fail(w, http.StatusBadGateway, "oidc_exchange_failed", web.LoginFailedRetry)
		return
	}
	tok, err := parseIDToken(tr.IDToken)
	if err != nil {
		p.fail(w, r, err.Error())
		return
	}
	if err := tok.validate(cfg, doc.Issuer, flow.Nonce); err != nil {
		p.fail(w, r, err.Error())
		return
	}
	if tr.RefreshToken == "" {
		// Refused rather than accepted, because a session with nothing to refresh would end within the hour
		// and send the person back through the login with no way to tell why.
		p.m.Log().Error("the provider granted no refresh token, so it is missing the offline_access scope mapping",
			"provider", p.name, "subject", tok.Subject)
		p.m.Fail(w, http.StatusBadGateway, "oidc_no_refresh_token", web.LoginFailed)
		return
	}
	state, err := json.Marshal(refreshState{RefreshToken: tr.RefreshToken})
	if err != nil {
		p.m.Log().Error("encoding the session state failed", "provider", p.name, "err", err)
		p.m.Fail(w, http.StatusInternalServerError, "internal", web.LoginFailed)
		return
	}

	err = p.m.Issue(w, r, auth.Grant{
		Identity: auth.Identity{Provider: p.name, Subject: tok.Subject, Claims: tok.all},
		State:    state,
	})
	switch {
	case errors.Is(err, auth.ErrNotAllowed):
		p.m.Fail(w, http.StatusForbidden, "subject_not_allowed", web.NotAllowed)
		return
	case err != nil:
		p.m.Fail(w, http.StatusServiceUnavailable, "session_store_unavailable", web.LoginFailedRetry)
		return
	}
	web.ClearCookie(w, r, p.flowCookie)
	ret := web.SafeReturn(flow.Ret)
	if ret == "" {
		ret = "/"
	}
	http.Redirect(w, r, ret, http.StatusFound)
}

// failUnconfigured answers a login or callback with no usable configuration. The browser is told the same
// whether the config is missing or invalid: why it is invalid is for whoever deploys, so it goes to the log.
func (p *Provider) failUnconfigured(w http.ResponseWriter, err error) {
	if !errors.Is(err, errUnconfigured) {
		p.m.Log().Error("OIDC configuration is invalid", "provider", p.name, "err", err)
	}
	p.m.Fail(w, http.StatusServiceUnavailable, "oidc_unconfigured", web.Unconfigured)
}

// fail ends a callback that a second attempt would not fix. The reason is logged rather than answered:
// a nonce that did not match and an ID token that did not parse are the same event to whoever is looking
// at the browser, and neither is theirs to act on.
func (p *Provider) fail(w http.ResponseWriter, r *http.Request, reason string) {
	p.m.Log().Warn("OIDC callback rejected", "provider", p.name, "reason", reason, "remote", r.RemoteAddr)
	p.m.Fail(w, http.StatusBadRequest, "oidc_callback_rejected", web.LoginFailed)
}

// retryLogin sends the browser through the login once more, for the callback failures a second attempt
// actually fixes: no flow cookie, a flow cookie past its ten minutes, and a state that does not match.
// Two tabs signing in at once produce the last of them every time, since the second login overwrites the
// flow cookie of the first, and a browser left holding a 400 has no way on but the address bar.
//
// Once, and no further: the login it points at marks its state, and a failure carrying that mark falls
// through to fail instead. A browser that keeps no cookies would otherwise go round between here and the
// provider without end.
func (p *Provider) retryLogin(w http.ResponseWriter, r *http.Request, ret, msg string) {
	if strings.HasSuffix(r.URL.Query().Get("state"), retryMarker) {
		p.fail(w, r, msg)
		return
	}
	p.m.Log().Warn("the OIDC callback could not be completed, sending the browser back through the login",
		"provider", p.name, "reason", msg, "remote", r.RemoteAddr)
	q := url.Values{"retry": {"1"}}
	if ret = web.SafeReturn(ret); ret != "" {
		q.Set("ret", ret)
	}
	http.Redirect(w, r, p.loginPath+"?"+q.Encode(), http.StatusFound)
}

// redirectURI is derived from the request. It has to match the one registered at the provider exactly,
// so moving the entry point behind a reverse proxy terminating TLS adds a registration there and changes
// no configuration here.
func (p *Provider) redirectURI(r *http.Request) string {
	scheme := "http"
	if web.IsTLS(r) {
		scheme = "https"
	}
	return scheme + "://" + r.Host + p.callback
}

// codeVerifier is 43 characters, the shortest RFC 7636 allows, from 32 bytes of entropy.
func codeVerifier() string {
	return base64.RawURLEncoding.EncodeToString(web.RandomBytes(32))
}

func codeChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
