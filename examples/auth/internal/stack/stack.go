// Package stack starts everything the example app needs on 127.0.0.1: a throwaway CA, etcd, Dex, app
// instances, and a TLS front door before each instance. The end-to-end tests use it, and so does
// demo up.
package stack

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/at-orz/x/examples/auth/internal/demo"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// AllowedMinted are the ticket subjects the app instances allow.
var AllowedMinted = []string{"bot-one"}

// Options configure a stack.
type Options struct {
	// Command starts one app instance; the stack appends the serve flags. demo up passes its own
	// executable and "serve", the tests the test binary.
	Command []string
	// Env is added to the environment of each instance, after the session key.
	Env []string
	// Instances is the number of app instances. Default 2.
	Instances int
	// Log receives the output of every process as it is written. Logs keeps the tail regardless.
	Log io.Writer
	// RevalidateEvery is passed to every instance as -revalidate-every when non-zero.
	RevalidateEvery time.Duration
}

// Stack is a running stack. Browsers scope cookies by host and not by port, so every front door
// shares one browser's cookies; a client picks an instance by picking a URL.
type Stack struct {
	// URLs are the front doors' https URLs, one per instance.
	URLs []string
	// Dex is the identity provider.
	Dex *Dex
	// CAFile and CAPool are the throwaway CA every https address of the stack is signed by.
	CAFile string
	CAPool *x509.CertPool
	// SPKIHash is what Chromium's --ignore-certificate-errors-spki-list takes for that certificate.
	SPKIHash string
	// Key is the session key every instance shares.
	Key []byte
	// Etcd is a client of the stack's etcd, and EtcdURL its address.
	Etcd    *clientv3.Client
	EtcdURL string

	dir       string
	etcd      *proc
	instances []*proc
	doors     []*frontDoor
}

// Start starts a stack. It fails when etcd or dex is not on PATH; the caller decides whether that is a
// skip.
func Start(ctx context.Context, o Options) (s *Stack, err error) {
	if len(o.Command) == 0 {
		return nil, errors.New("stack: Options.Command is required")
	}
	if o.Instances <= 0 {
		o.Instances = 2
	}
	dir, err := os.MkdirTemp("", "auth-stack-")
	if err != nil {
		return nil, err
	}
	s = &Stack{dir: dir, Key: make([]byte, 32)}
	defer func() {
		if err != nil {
			s.Stop()
			s = nil
		}
	}()
	_, _ = rand.Read(s.Key)

	c, err := newCA(dir)
	if err != nil {
		return s, fmt.Errorf("stack: the CA: %w", err)
	}
	s.CAFile, s.CAPool, s.SPKIHash = c.file, c.pool, c.spki

	s.etcd, s.EtcdURL, err = startEtcd(ctx, dir, o.Log)
	if err != nil {
		return s, fmt.Errorf("stack: %w", err)
	}
	s.Etcd, err = clientv3.New(clientv3.Config{Endpoints: []string{s.EtcdURL}, DialTimeout: 5 * time.Second})
	if err != nil {
		return s, fmt.Errorf("stack: etcd client: %w", err)
	}

	var callbacks []string
	for range o.Instances {
		f, err := listenFrontDoor(c)
		if err != nil {
			return s, fmt.Errorf("stack: front door: %w", err)
		}
		s.doors = append(s.doors, f)
		s.URLs = append(s.URLs, f.URL())
		callbacks = append(callbacks, f.URL()+"/auth/oidc/dex/callback")
	}

	s.Dex, err = startDex(ctx, dir, c, s.EtcdURL, callbacks, o.Log)
	if err != nil {
		return s, fmt.Errorf("stack: %w", err)
	}

	env := append(os.Environ(), demo.KeyEnv+"="+hex.EncodeToString(s.Key))
	cfg := instanceConfig{
		command: o.Command,
		env:     append(env, o.Env...),
		issuer:  s.Dex.Issuer,
		caFile:  c.file,
		etcdURL: s.EtcdURL,
		sink:    o.Log,

		revalidateEvery: o.RevalidateEvery,
	}
	for i, f := range s.doors {
		p, base, err := startInstance(ctx, fmt.Sprintf("app-%c", 'a'+i), cfg)
		if err != nil {
			return s, fmt.Errorf("stack: %w", err)
		}
		s.instances = append(s.instances, p)
		if err := f.serve(base); err != nil {
			return s, err
		}
	}
	return s, nil
}

// Stop stops every process of the stack and removes its files.
func (s *Stack) Stop() {
	for _, f := range s.doors {
		f.close()
	}
	for _, p := range s.instances {
		p.stop()
	}
	if s.Dex != nil {
		s.Dex.Stop()
	}
	if s.Etcd != nil {
		_ = s.Etcd.Close()
	}
	if s.etcd != nil {
		s.etcd.stop()
	}
	_ = os.RemoveAll(s.dir)
}

// Logs is the tail of every process's output, for a failing test to print.
func (s *Stack) Logs() string {
	var b strings.Builder
	section := func(name, log string) {
		fmt.Fprintf(&b, "----- %s -----\n%s\n", name, log)
	}
	if s.Dex != nil {
		section("dex", s.Dex.logs())
	}
	for _, p := range s.instances {
		section(p.name, p.log.String())
	}
	return b.String()
}
