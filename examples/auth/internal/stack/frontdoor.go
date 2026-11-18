package stack

import (
	"crypto/tls"
	"errors"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync/atomic"
	"time"
)

// frontDoor terminates TLS in front of one app instance, the way a host's reverse proxy does. Its
// listener is opened before anything else starts, so its address is known to Dex's configuration and
// is never lost to another process.
type frontDoor struct {
	l      net.Listener
	srv    *http.Server
	target atomic.Pointer[url.URL]
}

func listenFrontDoor(c *ca) (*frontDoor, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	f := &frontDoor{l: tls.NewListener(l, &tls.Config{Certificates: []tls.Certificate{c.leaf}})}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(f.target.Load())
			// The browser's Host is kept, since the app derives its OIDC callback from it, and the scheme
			// it used is passed on, since the app sets Secure cookies only over TLS.
			pr.Out.Host = pr.In.Host
			pr.Out.Header.Set("X-Forwarded-Proto", "https")
		},
		// A stopped instance is a 502 with nothing logged: the tests stop instances on purpose.
		ErrorLog: log.New(discardWriter{}, "", 0),
	}
	f.srv = &http.Server{Handler: proxy, ReadHeaderTimeout: 10 * time.Second}
	return f, nil
}

// URL is the https URL the front door serves.
func (f *frontDoor) URL() string { return "https://" + f.l.Addr().String() }

// serve proxies to target until close.
func (f *frontDoor) serve(target string) error {
	u, err := url.Parse(target)
	if err != nil {
		return err
	}
	f.target.Store(u)
	go func() {
		if err := f.srv.Serve(f.l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("front door %s: %v", f.URL(), err)
		}
	}()
	return nil
}

func (f *frontDoor) close() {
	_ = f.srv.Close()
	_ = f.l.Close()
}

type discardWriter struct{}

func (discardWriter) Write(b []byte) (int, error) { return len(b), nil }
