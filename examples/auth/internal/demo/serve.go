// Package demo holds the subcommands of the demo command, in a package of their own so that the
// end-to-end tests can run an app instance from the test binary itself.
package demo

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/at-orz/x/auth/store/etcd"
	"github.com/at-orz/x/examples/auth/app"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// KeyEnv names the variable the session key comes from, in hex. It is never a flag, so that it does
// not show in the process list.
const KeyEnv = "AUTH_SESSION_KEY"

// EtcdPrefix is the app's keyspace in etcd.
const EtcdPrefix = "app/"

// Serve runs one app instance until ctx ends.
func Serve(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:8080", "address to serve plain http on, behind a reverse proxy terminating TLS")
	issuer := fs.String("issuer", "", "the identity provider's issuer URL")
	clientID := fs.String("client-id", "", "this app's client id at the identity provider")
	clientSecret := fs.String("client-secret", "", "this app's client secret at the identity provider")
	idpCA := fs.String("idp-ca", "", "PEM bundle trusted for the identity provider instead of the system roots")
	endpoints := fs.String("etcd", "http://127.0.0.1:2379", "etcd endpoints, comma-separated")
	emails := fs.String("allow-email", "", "verified emails allowed to sign in, comma-separated")
	minted := fs.String("allow-minted", "", "ticket subjects allowed to sign in, comma-separated")
	if err := fs.Parse(args); err != nil {
		return err
	}
	key, err := sessionKey()
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	ec, err := dialEtcd(*endpoints)
	if err != nil {
		return err
	}
	defer ec.Close()
	store := etcd.New(ec, EtcdPrefix)

	h, err := app.New(ctx, app.Config{
		Issuer:       *issuer,
		ClientID:     *clientID,
		ClientSecret: *clientSecret,
		IdPCAFile:    *idpCA,
		AllowEmails:  list(*emails),
		AllowMinted:  list(*minted),
		Sessions:     store,
		Tickets:      store.Tickets(),
		Feed:         store.Follow(ctx),
		Key:          key,
		Log:          log,
	})
	if err != nil {
		return err
	}

	l, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Info("serving", "addr", l.Addr().String())
	if err := srv.Serve(l); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Mint writes one ticket and prints the link that redeems it.
func Mint(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("mint", flag.ContinueOnError)
	endpoints := fs.String("etcd", "http://127.0.0.1:2379", "etcd endpoints, comma-separated")
	base := fs.String("base", "https://127.0.0.1:8443", "the app's https URL the link starts with")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: demo mint [flags] <subject> <session length>")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		fs.Usage()
		return errors.New("mint needs a subject and a session length")
	}
	ttl, err := time.ParseDuration(fs.Arg(1))
	if err != nil {
		return fmt.Errorf("session length: %w", err)
	}
	ec, err := dialEtcd(*endpoints)
	if err != nil {
		return err
	}
	defer ec.Close()
	path, err := app.IssueTicket(ctx, app.Config{Tickets: etcd.New(ec, EtcdPrefix).Tickets()}, fs.Arg(0), ttl)
	if err != nil {
		return err
	}
	fmt.Println(strings.TrimSuffix(*base, "/") + path)
	return nil
}

func sessionKey() ([]byte, error) {
	v := os.Getenv(KeyEnv)
	if v == "" {
		return nil, fmt.Errorf("%s is not set: it holds the session key, at least 32 bytes in hex", KeyEnv)
	}
	key, err := hex.DecodeString(v)
	if err != nil {
		return nil, fmt.Errorf("%s is not hex: %w", KeyEnv, err)
	}
	if len(key) < 32 {
		return nil, fmt.Errorf("%s holds %d bytes, at least 32 are required", KeyEnv, len(key))
	}
	return key, nil
}

func dialEtcd(endpoints string) (*clientv3.Client, error) {
	return clientv3.New(clientv3.Config{Endpoints: list(endpoints), DialTimeout: 5 * time.Second})
}

func list(s string) []string {
	var out []string
	for v := range strings.SplitSeq(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
