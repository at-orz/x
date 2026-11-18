package stack

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// instanceConfig is what every app instance of a stack is started with.
type instanceConfig struct {
	command []string
	env     []string
	issuer  string
	caFile  string
	etcdURL string
	sink    io.Writer
}

// startInstance starts one app instance and waits for its home page. It returns the process and the
// instance's plain http URL.
func startInstance(ctx context.Context, name string, cfg instanceConfig) (*proc, string, error) {
	var p *proc
	var base string
	err := withRetry(func() error {
		port, err := freePort()
		if err != nil {
			return err
		}
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		base = "http://" + addr
		emails := make([]string, 0, len(allowed))
		for _, u := range allowed {
			emails = append(emails, u.Email)
		}
		argv := append(append([]string{}, cfg.command...),
			"-listen", addr,
			"-issuer", cfg.issuer,
			"-client-id", ClientID,
			"-client-secret", ClientSecret,
			"-idp-ca", cfg.caFile,
			"-etcd", cfg.etcdURL,
			"-allow-email", strings.Join(emails, ","),
			"-allow-minted", strings.Join(AllowedMinted, ","),
		)
		p, err = start(name, argv, cfg.env, nil, cfg.sink)
		if err != nil {
			return err
		}
		err = p.waitReady(ctx, 30*time.Second, func(ctx context.Context) error {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/", nil)
			if err != nil {
				return err
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("GET / answered %d", resp.StatusCode)
			}
			return nil
		})
		if err != nil {
			p.stop()
		}
		return err
	})
	if err != nil {
		return nil, "", err
	}
	return p, base, nil
}
