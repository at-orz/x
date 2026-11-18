package stack

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// User is a static user of Dex.
type User struct {
	Email    string
	Password string
	id       string
	hash     string
}

// The users of Dex. Bob is never on the allow list. Dex keeps one refresh token per user and client,
// so a test that needs its refresh token to survive signs in a user no other test signs in at the same
// time: Carol and Dave are for those.
var (
	Alice = User{"alice@example.com", "alice-password", "08a8684b-db88-4b73-90a9-3cd1661f5466",
		"$2b$10$10coz1jxXP35WXJ/IaaFPep4KkyXUnBVo40ULdRAj04X4KR3xr.K."}
	Bob = User{"bob@example.com", "bob-password", "41331323-6f44-45e6-b3b9-2c4b60c02be5",
		"$2b$10$spW9N00CBWpHPogc9pC0qOM3pxYJfieiu3pJmC64TC.3pV57iesNG"}
	Carol = User{"carol@example.com", "carol-password", "3f30e66a-ce3c-46df-8210-b9e4e9d63d96",
		"$2b$10$xIYzUjd0nFMZe7MVkTniuufLX9Ft.bvZtyjRZIGhkqam25QUGJjUO"}
	Dave = User{"dave@example.com", "dave-password", "6aba632c-147d-4265-be29-3bc83d3ea5f1",
		"$2b$10$s7EQhdM5ieRMW8lPwjY9ZOfFV9O0KgyxjwzNdlL8n58zxUlFeEAVm"}

	users   = []User{Alice, Bob, Carol, Dave}
	allowed = []User{Alice, Carol, Dave}
)

// The app's registration at Dex.
const (
	ClientID     = "example-app"
	ClientSecret = "test-client-secret"
)

// DexPrefix is Dex's keyspace in etcd. Its refresh tokens are under DexPrefix + "refresh_token/".
const DexPrefix = "dex/"

// Dex is the identity provider of a stack. It can be stopped and started again on the same address,
// keeping its refresh tokens, which live in etcd.
type Dex struct {
	// Issuer is its issuer URL.
	Issuer string

	bin, config string
	ca          *ca
	sink        io.Writer
	// log outlives each process, so that a test failing after a restart still shows what came before.
	log *ring

	mu sync.Mutex
	p  *proc
}

func startDex(ctx context.Context, dir string, c *ca, etcdURL string, callbacks []string, sink io.Writer) (*Dex, error) {
	bin, err := exec.LookPath("dex")
	if err != nil {
		return nil, err
	}
	d := &Dex{bin: bin, config: filepath.Join(dir, "dex.json"), ca: c, sink: sink, log: newRing()}
	err = withRetry(func() error {
		port, err := freePort()
		if err != nil {
			return err
		}
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		d.Issuer = "https://" + addr + "/dex"
		if err := d.writeConfig(addr, etcdURL, callbacks); err != nil {
			return err
		}
		return d.Start(ctx)
	})
	if err != nil {
		return nil, err
	}
	return d, nil
}

// writeConfig writes Dex's configuration as JSON, which its YAML reader takes as it is.
func (d *Dex) writeConfig(addr, etcdURL string, callbacks []string) error {
	var static []map[string]string
	for _, u := range users {
		static = append(static, map[string]string{
			"email": u.Email, "hash": u.hash, "username": strings.TrimSuffix(u.Email, "@example.com"), "userID": u.id,
		})
	}
	cfg := map[string]any{
		"issuer": d.Issuer,
		"storage": map[string]any{
			"type":   "etcd",
			"config": map[string]any{"endpoints": []string{etcdURL}, "namespace": DexPrefix},
		},
		"web": map[string]any{"https": addr, "tlsCert": d.ca.certFile, "tlsKey": d.ca.keyFile},
		// The consent screen would add a click to every login for nothing a test asserts.
		"oauth2": map[string]any{"skipApprovalScreen": true},
		// A refresh token presented twice is refused at once, as a strict provider does. Dex's default
		// accepts a reuse within a few seconds, which would let two instances refreshing one session
		// both succeed, so the test that they do not could not fail.
		"expiry":           map[string]any{"refreshTokens": map[string]any{"reuseInterval": "0s"}},
		"logger":           map[string]any{"level": "info"},
		"enablePasswordDB": true,
		"staticPasswords":  static,
		"staticClients": []map[string]any{{
			"id": ClientID, "secret": ClientSecret, "name": "auth example", "redirectURIs": callbacks,
		}},
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(d.config, b, 0o600)
}

// Start starts Dex and waits for its discovery document. It is a no-op while Dex runs.
func (d *Dex) Start(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.p != nil {
		return nil
	}
	p, err := start("dex", []string{d.bin, "serve", d.config}, os.Environ(), d.log, d.sink)
	if err != nil {
		return err
	}
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: d.ca.pool}}}
	defer hc.CloseIdleConnections()
	err = p.waitReady(ctx, 30*time.Second, func(ctx context.Context) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.Issuer+"/.well-known/openid-configuration", nil)
		if err != nil {
			return err
		}
		resp, err := hc.Do(req)
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("discovery answered %d", resp.StatusCode)
		}
		return nil
	})
	if err != nil {
		p.stop()
		return err
	}
	d.p = p
	return nil
}

// Stop kills Dex. Its state stays in etcd.
func (d *Dex) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.p != nil {
		d.p.stop()
		d.p = nil
	}
}

func (d *Dex) logs() string { return d.log.String() }
