package web

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// The backslash forms are the ones a browser reads as an authority although they begin with a single
// slash; the tab form is one a browser strips before it parses, which leaves "//evil.example".
func TestSafeReturnBlocksOpenRedirects(t *testing.T) {
	for _, bad := range []string{
		"https://evil.example/x", "//evil.example/x", "evil", "",
		`/\evil.example`, `/\/evil.example`, `/\\evil.example`, "/\t/evil.example",
	} {
		if got := SafeReturn(bad); got != "" {
			t.Errorf("SafeReturn(%q) = %q, it has to be dropped", bad, got)
		}
	}
	if got := SafeReturn("/app/t1?tab=console#top"); got != "/app/t1?tab=console#top" {
		t.Errorf("SafeReturn dropped an on-site address as well: %q", got)
	}
}

func TestIsTLS(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if IsTLS(r) {
		t.Error("a plain request reads as TLS")
	}
	r.Header.Set("X-Forwarded-Proto", "HTTPS")
	if !IsTLS(r) {
		t.Error("X-Forwarded-Proto: https was not honoured")
	}
	r.Header.Set("X-Forwarded-Proto", "http")
	if IsTLS(r) {
		t.Error("X-Forwarded-Proto: http reads as TLS")
	}
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.TLS = &tls.ConnectionState{}
	if !IsTLS(r) {
		t.Error("a direct TLS connection does not read as TLS")
	}
}

func TestRandomToken(t *testing.T) {
	a, b := RandomToken(), RandomToken()
	if len(a) != 32 || a == b {
		t.Errorf("RandomToken gave %q and %q", a, b)
	}
}

func TestCookies(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()
	SetCookie(w, r, "a", "v", time.Hour)
	SetCookie(w, r, "b", "v", time.Millisecond)
	ClearCookie(w, r, "c")
	cs := w.Result().Cookies()
	if len(cs) != 3 {
		t.Fatalf("%d cookies set, want 3", len(cs))
	}
	for _, c := range cs {
		if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" {
			t.Errorf("cookie %s has the wrong attributes: %+v", c.Name, c)
		}
	}
	if cs[0].MaxAge != 3600 || cs[1].MaxAge != 1 || cs[2].MaxAge >= 0 {
		t.Errorf("MaxAge = %d, %d, %d; want 3600, 1, negative", cs[0].MaxAge, cs[1].MaxAge, cs[2].MaxAge)
	}
}
