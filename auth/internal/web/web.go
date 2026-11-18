// Package web holds the request helpers that auth and its sign-in methods all need, kept out of their
// public API.
package web

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// The sentences a browser is given, in one place so that what leaves the process can be read at a
// glance. Each says what happened and whether trying again is worth anything; what to configure, which
// issuer, what the token endpoint answered and whose account it was go to the log, where whoever can act
// on them is.
const (
	Unconfigured     = "the login has not been set up yet"
	IdPUnreachable   = "the identity provider could not be reached, try again in a moment"
	LoginFailed      = "the login could not be completed"
	LoginFailedRetry = "the login could not be completed, try again in a moment"
	NotAllowed       = "this account is not permitted to sign in"
	NotSignedIn      = "not signed in"
	// TicketStale covers a ticket that is missing, already spent or expired. To whoever is looking at the
	// browser these are one event, and none of them is theirs to act on; which one it was goes to the log.
	TicketStale = "this sign-in link is not valid any more"
	CrossOrigin = "this request came from another site"
)

// IsTLS honours the X-Forwarded-Proto of a reverse proxy terminating TLS in front: behind one the
// cookie has to carry Secure, while carrying it over a direct http connection would make the browser
// drop the cookie entirely.
func IsTLS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// SafeReturn allows an absolute path within this site alone, which closes an open redirect.
//
// Rejecting a leading "//" is not enough. A browser reads a Location header by the WHATWG URL rules,
// where a backslash straight after the leading slash opens an authority exactly as a second slash does,
// so "/\evil.example" is read as "//evil.example" and the browser leaves the site.
//
// url.Parse keeps that backslash inside Path, which is why both checks are here rather than one. What it
// does add is the control characters: a browser strips a tab before it parses, so "/<TAB>/evil.example"
// opens an authority as well, and a tab survives the Location header intact.
func SafeReturn(ret string) string {
	if ret == "" || !strings.HasPrefix(ret, "/") || strings.HasPrefix(ret, "//") || strings.Contains(ret, `\`) {
		return ""
	}
	u, err := url.Parse(ret)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return ""
	}
	return ret
}

// RandomToken is 16 random bytes in hex: session ids, states, nonces.
func RandomToken() string {
	return hex.EncodeToString(RandomBytes(16))
}

// RandomBytes reads n bytes from crypto/rand.
func RandomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand does not fail on a supported platform, and carrying on after a real failure would
		// hand out predictable tokens.
		panic("auth: crypto/rand failed: " + err.Error())
	}
	return b
}

// SetCookie sets a cookie the way every cookie of auth is set: whole site, never readable by script,
// sent on top-level navigation from elsewhere (the IdP's redirect back is one), Secure over TLS.
func SetCookie(w http.ResponseWriter, r *http.Request, name, value string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   IsTLS(r),
		SameSite: http.SameSiteLaxMode,
		// At least a second: a session a moment from its deadline would otherwise get MaxAge 0, which
		// is a cookie without Max-Age, kept until the browser closes.
		MaxAge: max(int(ttl.Seconds()), 1),
	})
}

// ClearCookie tells the browser to drop a cookie set by SetCookie.
func ClearCookie(w http.ResponseWriter, r *http.Request, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   IsTLS(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}
