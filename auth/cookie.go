package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/at-orz/x/auth/internal/web"
)

// sessionState is the payload of the session cookie. It is signed, not encrypted, so it carries nothing
// worth reading: no provider, no subject, no claim. Those come from the record.
type sessionState struct {
	SID string `json:"sid"`
	// Exp is when this process next goes back to the authority, not when the session ends.
	Exp int64 `json:"exp"`
	// Deadline is the end of a session that has one. It is the copy that decides: it is read on every
	// request before anything reads the store, and the cookie is signed here, so it cannot be moved.
	Deadline int64 `json:"dl,omitempty"`
}

// CookieName is the name of a cookie of this manager: CookiePrefix + "_" + suffix. Methods name their
// own short-lived cookies with it, so that every cookie of a host shares one prefix.
func (m *Manager) CookieName(suffix string) string {
	return m.cookiePrefix + "_" + suffix
}

// Seal encodes v as JSON and signs it: base64url(JSON) "." base64url(HMAC-SHA256), without padding.
func (m *Manager) Seal(v any) (string, error) {
	body, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(body)
	return payload + "." + base64.RawURLEncoding.EncodeToString(m.MAC(payload)), nil
}

// Open checks the signature of a value made by Seal and only then decodes it into out.
func (m *Manager) Open(value string, out any) error {
	payload, sig, ok := strings.Cut(value, ".")
	if !ok {
		return errors.New("malformed cookie")
	}
	// Strict, because the signature is compared as bytes while the MAC covers the payload as text: the two
	// padding bits in the last character of a 32-byte MAC fall outside both, so a lenient decoder gives one
	// signature four legal spellings. The payload decode below is reached only past the MAC and needs none.
	want, err := base64.RawURLEncoding.Strict().DecodeString(sig)
	if err != nil {
		return errors.New("malformed cookie signature")
	}
	if !hmac.Equal(want, m.MAC(payload)) {
		return errors.New("bad cookie signature")
	}
	body, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return errors.New("malformed cookie payload")
	}
	return json.Unmarshal(body, out)
}

// MAC is HMAC-SHA256 of data under Options.Key. Besides signing cookies, it lets a method derive a
// name from a secret, so that a cookie name does not spell what it belongs to while staying stable.
func (m *Manager) MAC(data string) []byte {
	h := hmac.New(sha256.New, m.key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

// setSessionCookie signs a session into the cookie the browser keeps for as long as the session may sit
// idle, while the exp inside it is when this process next goes back to the authority.
//
// The two are deliberately different lengths. A cookie expiring with its exp would be dropped by the
// browser after an hour, so returning to a tab in the afternoon would find no cookie at all and go
// through the sign-in again, with a perfectly good session sitting in the store.
func (m *Manager) setSessionCookie(w http.ResponseWriter, r *http.Request, sid string, deadline time.Time) {
	// Exp is left an hour out even on a session close to its deadline. Narrowing it would end nothing
	// sooner, since the deadline is compared on every request anyway, and it would drop the last hour of
	// such a session into the refresh window, where each request reads the store once more.
	state := sessionState{SID: sid, Exp: time.Now().Add(sessionTTL).Unix()}
	// MaxAge follows a deadline because that works in both directions: at the idle TTL, a week-long
	// session would lose its cookie after a day idle, and a two-hour one would keep it a day after it had
	// stopped being worth anything.
	maxAge := m.idleTTL
	if !deadline.IsZero() {
		state.Deadline = deadline.Unix()
		maxAge = time.Until(deadline)
	}
	value, err := m.Seal(state)
	if err != nil {
		// Signing cannot fail for a struct of this shape; carrying on without the cookie would leave a
		// browser in a loop of sign-ins with nothing said about why.
		m.log.Error("signing the session cookie failed", "err", err)
		return
	}
	web.SetCookie(w, r, m.sessionCookie, value, maxAge)
}
