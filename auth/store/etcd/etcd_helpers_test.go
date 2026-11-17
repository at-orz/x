package etcd

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

// startEtcd starts a real etcd for one test, because several properties under test (a watch, a lease
// running out, a race between two clients) belong to etcd rather than to this code. It skips when etcd
// is not on PATH and returns the URL of its client port.
func startEtcd(t *testing.T) string {
	t.Helper()
	bin, err := exec.LookPath("etcd")
	if err != nil {
		t.Skip("no etcd on PATH; this runs inside the devshell")
	}
	// freePort hands a port over by number, so another process may bind it before etcd does, and etcd then
	// exits at once. That is a lost race rather than a broken etcd, and fresh ports settle it.
	var lastErr error
	for range 5 {
		url, exited, err := startOnce(t, bin)
		if err == nil {
			return url
		}
		lastErr = err
		if !exited {
			break
		}
	}
	t.Fatalf("etcd did not listen: %v", lastErr)
	return ""
}

func startOnce(t *testing.T, bin string) (clientURL string, exited bool, err error) {
	t.Helper()
	clientURL = fmt.Sprintf("http://127.0.0.1:%d", freePort(t))
	peerURL := fmt.Sprintf("http://127.0.0.1:%d", freePort(t))
	cmd := exec.Command(bin,
		"--name", "test",
		"--data-dir", t.TempDir(),
		"--listen-client-urls", clientURL,
		"--advertise-client-urls", clientURL,
		"--listen-peer-urls", peerURL,
		"--initial-advertise-peer-urls", peerURL,
		"--initial-cluster", "test="+peerURL,
		"--log-level", "error",
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start etcd: %v", err)
	}
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-done
	})
	deadline := time.Now().Add(30 * time.Second)
	// Dialing before the port is up only buys a retry and a warning from the client logger.
	for {
		conn, err := net.DialTimeout("tcp", strings.TrimPrefix(clientURL, "http://"), time.Second)
		if err == nil {
			conn.Close()
			return clientURL, false, nil
		}
		select {
		case <-done:
			return "", true, fmt.Errorf("etcd on %s exited before listening", clientURL)
		default:
		}
		if time.Now().After(deadline) {
			return "", false, err
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// dial returns a client of the etcd at url once it answers a read.
func dial(t *testing.T, url string) *clientv3.Client {
	t.Helper()
	c, err := clientv3.New(clientv3.Config{Endpoints: []string{url}, DialTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("etcd client: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	deadline := time.Now().Add(30 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, err := c.Get(ctx, "probe")
		cancel()
		if err == nil {
			return c
		}
		if time.Now().After(deadline) {
			t.Fatalf("etcd did not answer: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

var prefixes atomic.Int64

// freshPrefix is a keyspace no other test of the same etcd touches.
func freshPrefix() string {
	return fmt.Sprintf("test-%d/", prefixes.Add(1))
}
