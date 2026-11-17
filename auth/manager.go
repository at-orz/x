package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"sync"
	"time"
)

const (
	// sessionTTL is how long a cookie is good for before this process goes back to the authority. It is
	// not how long a session lasts: an active browser is revalidated hour after hour without noticing,
	// and an idle one lasts until its record expires.
	sessionTTL = time.Hour

	// refreshWindow is how early the revalidation happens. Half of the cookie lifetime, so that a request
	// arriving at any moment of an hour still finds a valid cookie while a failed revalidation is retried
	// several times before it could matter.
	refreshWindow = 30 * time.Minute

	// refreshFloor is how recently a verification counts as this request's own. It follows from the two
	// constants above rather than being a third number: the authority is asked once per hour and the
	// question starts half an hour early, so a verification newer than half an hour belongs to this round.
	refreshFloor = sessionTTL - refreshWindow

	// claimTTL is how long another instance's claim counts for. A revalidation cannot be outstanding for
	// longer than a token request's timeout, so a claim older than this belongs to an instance that either
	// finished, in which case VerifiedAt says so and refreshFloor answers first, or died holding it.
	claimTTL = 15 * time.Second

	defaultIdleTTL = 24 * time.Hour
)

// Options configure a Manager. Store, Key and Authorize are required.
type Options struct {
	Store Store
	// Key signs every cookie. At least 32 bytes, and shared by every instance serving the same sessions.
	Key []byte
	// Authorize decides who may hold a session. There is no implicit "everyone".
	Authorize Authorize

	// Log receives what the browser is not told. Default: discard.
	Log *slog.Logger
	// CookiePrefix names every cookie: the session cookie is CookiePrefix + "_session". Default "auth".
	CookiePrefix string
	// IdleTTL is how long a session survives unused. It is one number used three ways: the lifetime of
	// the record, the MaxAge of the cookie, and the grace window while the authority cannot be asked; a
	// session cannot outlive its own record, so different numbers would make the longer one pointless.
	// Default 24h.
	IdleTTL time.Duration
	// Link runs once per sign-in, after Authorize admits the identity, and returns the session's initial
	// Values, typically the host's own user id for this identity. An error wrapping ErrNotAllowed refuses
	// the sign-in with 403; any other with 503. Optional.
	Link func(ctx context.Context, id Identity) (map[string]string, error)
	// LoginURL is where an unauthenticated browser is sent, given the address it wanted. Default: the
	// login of the only interactive method registered. Required once there are several.
	LoginURL func(r *http.Request, ret string) string
	// WriteError writes an error response. Default: {"error": {"code": …, "message": …}} as JSON.
	WriteError func(w http.ResponseWriter, status int, code, message string)
}

// Method is one way of signing in, registered with a Manager under a unique name. It establishes an
// identity and hands it to Manager.Issue; the Manager calls it back to revalidate the sessions it issued.
type Method interface {
	// Name identifies the method among those of its Manager, matching [a-z0-9-]+. It is the Provider of
	// every identity the method signs in, and it appears in the method's paths.
	Name() string
	// LoginURL is where a browser starts this method, or "" for a method that cannot be started from a
	// page.
	LoginURL(ret string) string
	// Revalidate asks the authority again once a session's cookie enters its refresh window, returning
	// the record to write back; only its State and Claims are taken. An error wrapping ErrEnded ends the
	// session; any other error is "could not ask" and falls under the grace window.
	Revalidate(ctx context.Context, rec Record) (Record, error)
}

// Grant is what a method hands over once it has established an identity.
type Grant struct {
	Identity Identity
	// State is private to the method, such as a refresh token. It is stored, never put in the cookie.
	State json.RawMessage
	// Deadline ends a session that is never revalidated; zero for one that is.
	Deadline time.Time
}

// Manager issues sessions, admits requests on them and keeps them alive.
type Manager struct {
	store         Store
	claimer       Claimer
	key           []byte
	authorize     Authorize
	log           *slog.Logger
	cookiePrefix  string
	sessionCookie string
	idleTTL       time.Duration
	link          func(ctx context.Context, id Identity) (map[string]string, error)
	loginURL      func(r *http.Request, ret string) string
	writeError    func(w http.ResponseWriter, status int, code, message string)

	methodsMu   sync.RWMutex
	methods     map[string]Method
	interactive []Method

	live *liveSessions

	// refreshing is one in-flight revalidation per session id. Every tab of one browser polls, so they
	// reach the refresh window within the same second, and an authority that rotates the refresh token
	// invalidates the old one as it answers: a second revalidation carrying the same token would end the
	// very session it was meant to extend.
	refreshMu  sync.Mutex
	refreshing map[string]*refreshCall
}

var (
	namePattern   = regexp.MustCompile(`^[a-z0-9-]+$`)
	prefixPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

// New builds a Manager. It refuses options without a Store, an Authorize or a Key of 32 bytes.
func New(o Options) (*Manager, error) {
	switch {
	case o.Store == nil:
		return nil, errors.New("auth: Options.Store is required")
	case o.Authorize == nil:
		return nil, errors.New("auth: Options.Authorize is required")
	case len(o.Key) < 32:
		return nil, fmt.Errorf("auth: Options.Key has %d bytes, at least 32 are required", len(o.Key))
	}
	m := &Manager{
		store:        o.Store,
		key:          o.Key,
		authorize:    o.Authorize,
		log:          o.Log,
		cookiePrefix: o.CookiePrefix,
		idleTTL:      o.IdleTTL,
		link:         o.Link,
		loginURL:     o.LoginURL,
		writeError:   o.WriteError,
		methods:      map[string]Method{},
		refreshing:   map[string]*refreshCall{},
	}
	if c, ok := o.Store.(Claimer); ok {
		m.claimer = c
	}
	if m.log == nil {
		m.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if m.cookiePrefix == "" {
		m.cookiePrefix = "auth"
	}
	if !prefixPattern.MatchString(m.cookiePrefix) {
		return nil, fmt.Errorf("auth: Options.CookiePrefix %q is not [A-Za-z0-9_-]+", m.cookiePrefix)
	}
	if m.idleTTL <= 0 {
		m.idleTTL = defaultIdleTTL
	}
	if m.writeError == nil {
		m.writeError = writeJSONError
	}
	m.sessionCookie = m.CookieName("session")
	m.live = newLiveSessions(m.idleTTL)
	return m, nil
}

// Register adds a sign-in method. It refuses a name already taken or not matching [a-z0-9-]+, and a
// second interactive method while Options.LoginURL is unset, since there would be no telling which login
// an unauthenticated browser should be sent to.
func (m *Manager) Register(method Method) error {
	name := method.Name()
	if !namePattern.MatchString(name) {
		return fmt.Errorf("auth: method name %q is not [a-z0-9-]+", name)
	}
	m.methodsMu.Lock()
	defer m.methodsMu.Unlock()
	if _, taken := m.methods[name]; taken {
		return fmt.Errorf("auth: a method named %q is already registered", name)
	}
	interactive := method.LoginURL("/") != ""
	if interactive && len(m.interactive) > 0 && m.loginURL == nil {
		return fmt.Errorf("auth: %q is a second interactive method, which needs Options.LoginURL", name)
	}
	m.methods[name] = method
	if interactive {
		m.interactive = append(m.interactive, method)
	}
	return nil
}

func (m *Manager) method(name string) Method {
	m.methodsMu.RLock()
	defer m.methodsMu.RUnlock()
	return m.methods[name]
}

// Log is the logger of Options.Log, for methods to log through.
func (m *Manager) Log() *slog.Logger { return m.log }

// Fail writes an error response through Options.WriteError.
func (m *Manager) Fail(w http.ResponseWriter, status int, code, message string) {
	m.writeError(w, status, code, message)
}

func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"code": code, "message": message},
	})
}
