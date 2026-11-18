package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestNewRefusesIncompleteOptions(t *testing.T) {
	allow := AllowSubjects("corp", func() []string { return []string{"alice"} })
	for name, o := range map[string]Options{
		"no store":          {Key: testKey, Authorize: allow},
		"no key":            {Store: newFakeStore(), Authorize: allow},
		"a short key":       {Store: newFakeStore(), Key: testKey[:31], Authorize: allow},
		"no authorize":      {Store: newFakeStore(), Key: testKey},
		"a bad cookie name": {Store: newFakeStore(), Key: testKey, Authorize: allow, CookiePrefix: "a b"},
	} {
		if _, err := New(o); err == nil {
			t.Errorf("%s: New accepted it", name)
		}
	}
	m, err := New(Options{Store: newFakeStore(), Key: testKey, Authorize: allow})
	if err != nil {
		t.Fatal(err)
	}
	if m.sessionCookie != "auth_session" || m.idleTTL != defaultIdleTTL || m.Log() == nil {
		t.Errorf("the defaults were not applied: cookie %q, idle %s", m.sessionCookie, m.idleTTL)
	}
}

func TestRegisterRefusesADuplicateOrMalformedName(t *testing.T) {
	h := newHarness(t)
	if err := h.m.Register(&fakeMethod{name: "corp"}); err == nil {
		t.Error("a second method named corp was registered")
	}
	for _, bad := range []string{"", "Corp", "a/b", "a_b"} {
		if err := h.m.Register(&fakeMethod{name: bad}); err == nil {
			t.Errorf("a method named %q was registered", bad)
		}
	}
	if err := h.m.Register(&fakeMethod{name: "mint"}); err != nil {
		t.Errorf("a non-interactive second method was refused: %v", err)
	}
}

func TestSealAndOpen(t *testing.T) {
	h := newHarness(t)
	type payload struct {
		A string `json:"a"`
	}
	value, err := h.m.Seal(payload{A: "x"})
	if err != nil {
		t.Fatal(err)
	}
	var got payload
	if err := h.m.Open(value, &got); err != nil || got.A != "x" {
		t.Fatalf("Open = %+v, %v", got, err)
	}

	// One changed byte invalidates it. The signature is decoded and a byte flipped rather than characters
	// swapped in the text: RawURLEncoding ignores the two padding bits in the last character of a 32-byte
	// MAC, so a textual edit there can decode back to the same signature.
	if err := h.m.Open(flipSignature(t, value), &got); err == nil {
		t.Error("a tampered value was opened")
	}
	// The same signature written a second way is a different value, not the same one: the two padding bits
	// of the last character are outside the MAC, so a decoder that ignores them accepts both spellings.
	if err := h.m.Open(setPaddingBit(t, value), &got); err == nil {
		t.Error("a non-canonical signature was opened")
	}
	for _, bad := range []string{"", "no-dot", "a.!!!"} {
		if err := h.m.Open(bad, &got); err == nil {
			t.Errorf("Open(%q) succeeded", bad)
		}
	}
	other, err := New(Options{Store: newFakeStore(), Key: []byte(strings.Repeat("k", 32)), Authorize: AnyOf()})
	if err != nil {
		t.Fatal(err)
	}
	if err := other.Open(value, &got); err == nil {
		t.Error("a value sealed under another key was opened")
	}
}

// The cookie is signed, not encrypted: whatever it carries, anyone holding it can read.
func TestTheSessionCookieCarriesOnlyItsID(t *testing.T) {
	h := newHarness(t)
	c, sid := h.signIn(t)
	payload, _, _ := strings.Cut(c.Value, ".")
	body, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(body, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 2 || fields["sid"] != sid || fields["exp"] == nil {
		t.Errorf("the session cookie carries %v, want sid and exp alone", fields)
	}
	for _, leak := range []string{"alice", "corp", "admins", "t0"} {
		if strings.Contains(string(body), leak) {
			t.Errorf("the session cookie carries %q: %s", leak, body)
		}
	}
}

func TestAllowSubjects(t *testing.T) {
	ctx := context.Background()
	var list []string
	a := AllowSubjects("corp", func() []string { return list })
	if err := a(ctx, Identity{Provider: "corp", Subject: "alice"}); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("an empty list admitted alice: %v", err)
	}
	list = []string{"alice"}
	if err := a(ctx, Identity{Provider: "corp", Subject: "alice"}); err != nil {
		t.Errorf("a listed subject was refused: %v", err)
	}
	if err := a(ctx, Identity{Provider: "partner", Subject: "alice"}); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("alice of another provider was admitted: %v", err)
	}
	if err := a(ctx, Identity{Provider: "corp", Subject: "bob"}); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("an unlisted subject was admitted: %v", err)
	}
}

func TestAnyOf(t *testing.T) {
	ctx := context.Background()
	corp := AllowSubjects("corp", func() []string { return []string{"alice"} })
	partner := AllowSubjects("partner", func() []string { return []string{"bob"} })
	either := AnyOf(corp, partner)
	if err := either(ctx, Identity{Provider: "partner", Subject: "bob"}); err != nil {
		t.Errorf("AnyOf refused what its second policy admits: %v", err)
	}
	if err := either(ctx, Identity{Provider: "corp", Subject: "bob"}); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("AnyOf admitted what neither policy admits: %v", err)
	}
	if err := AnyOf()(ctx, Identity{Provider: "corp", Subject: "alice"}); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("an empty AnyOf admitted someone: %v", err)
	}
}

// flipSignature rewrites the signature of a sealed value so that it decodes to different bytes: decode,
// flip a byte, encode again.
func flipSignature(t *testing.T, value string) string {
	t.Helper()
	payload, sig, ok := strings.Cut(value, ".")
	if !ok {
		t.Fatalf("the value carries no signature: %q", value)
	}
	raw, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || len(raw) == 0 {
		t.Fatalf("the signature does not decode: %q", sig)
	}
	raw[0] ^= 0xff
	return payload + "." + base64.RawURLEncoding.EncodeToString(raw)
}

// setPaddingBit spells the same signature a second way, by setting one of the two bits the encoding
// leaves unused in the last character. A 32-byte MAC ends on a character whose alphabet index is a
// multiple of four, so the next index up carries the same data bits and one padding bit.
func setPaddingBit(t *testing.T, value string) string {
	t.Helper()
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	i := strings.IndexByte(alphabet, value[len(value)-1])
	if i < 0 || i%4 != 0 {
		t.Fatalf("the signature does not end on a padded character: %q", value)
	}
	return value[:len(value)-1] + string(alphabet[i+1])
}

func TestNewBoundsRevalidateEvery(t *testing.T) {
	allow := AllowSubjects("corp", func() []string { return []string{"alice"} })
	with := func(every, idle time.Duration) Options {
		return Options{Store: newFakeStore(), Key: testKey, Authorize: allow, RevalidateEvery: every, IdleTTL: idle}
	}
	for name, o := range map[string]Options{
		"below two seconds":    with(time.Second, 0),
		"above the idle TTL":   with(defaultIdleTTL+time.Second, 0),
		"above a set idle TTL": with(2*time.Hour, time.Hour),
	} {
		if _, err := New(o); err == nil {
			t.Errorf("%s: New accepted it", name)
		}
	}
	for name, o := range map[string]Options{
		"two seconds":    with(2*time.Second, 0),
		"the idle TTL":   with(defaultIdleTTL, 0),
		"a set idle TTL": with(time.Hour, time.Hour),
	} {
		if _, err := New(o); err != nil {
			t.Errorf("%s: New refused it: %v", name, err)
		}
	}
	m, err := New(with(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if m.revalidateEvery != time.Hour || m.refreshWindow != 30*time.Minute || m.refreshFloor != 30*time.Minute {
		t.Errorf("the default interval is %s with window %s and floor %s, want 1h, 30m, 30m",
			m.revalidateEvery, m.refreshWindow, m.refreshFloor)
	}
}

// Both halves of the condition for a revalidation move with the interval: the cookie's distance from its
// exp, and the record's distance from its last verification.
func TestTheIntervalMovesTheWindowAndTheFloor(t *testing.T) {
	tenMinutes := func(o *Options) { o.RevalidateEvery = 10 * time.Minute }
	h := newHarness(t, tenMinutes)
	_, sid := h.signIn(t)
	h.age(t, sid, 6*time.Minute)
	got := h.ask(t, h.cookieAt(t, sid, 6*time.Minute))
	if got.Code != http.StatusOK || sessionCookieOf(h.m, got) != nil || h.method.callCount() != 0 {
		t.Fatalf("a cookie 6m from its exp gave %d, a new cookie %t and %d revalidations, want the fast path",
			got.Code, sessionCookieOf(h.m, got) != nil, h.method.callCount())
	}
	if got := h.ask(t, h.cookieAt(t, sid, 4*time.Minute)); got.Code != http.StatusOK {
		t.Fatalf("a cookie in the window gave status = %d (body = %s)", got.Code, got.Body)
	}
	if n := h.method.callCount(); n != 1 {
		t.Errorf("a record verified 6m ago was revalidated %d times, want 1", n)
	}

	fresh := newHarness(t, tenMinutes)
	_, sid = fresh.signIn(t)
	fresh.age(t, sid, 4*time.Minute)
	if got := fresh.ask(t, fresh.cookieAt(t, sid, 4*time.Minute)); got.Code != http.StatusOK {
		t.Fatalf("a cookie in the window gave status = %d (body = %s)", got.Code, got.Body)
	}
	if n := fresh.method.callCount(); n != 0 {
		t.Errorf("a record verified 4m ago was revalidated %d times, want 0", n)
	}
}

func TestASignInSetsExpOneIntervalOut(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.RevalidateEvery = 10 * time.Minute })
	c, _ := h.signIn(t)
	var s sessionState
	if err := h.m.Open(c.Value, &s); err != nil {
		t.Fatal(err)
	}
	// exp is in whole seconds, so it can fall up to a second short.
	if until := time.Until(time.Unix(s.Exp, 0)); until <= 10*time.Minute-2*time.Second || until > 10*time.Minute {
		t.Errorf("the cookie's exp is %s out, want 10m", until)
	}
}

func TestSessionID(t *testing.T) {
	h := newHarness(t)
	c, sid := h.signIn(t)
	if got, err := h.m.SessionID(c.Value); err != nil || got != sid {
		t.Errorf("SessionID = %q, %v, want %q", got, err, sid)
	}
	if _, err := h.m.SessionID(flipSignature(t, c.Value)); err == nil {
		t.Error("SessionID read a tampered cookie")
	}
	noSID, err := h.m.Seal(sessionState{Exp: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.m.SessionID(noSID); err == nil {
		t.Error("SessionID read a cookie that names no session")
	}
}
