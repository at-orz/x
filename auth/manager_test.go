package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
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
