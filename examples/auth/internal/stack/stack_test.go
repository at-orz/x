package stack

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"testing"

	"github.com/at-orz/x/examples/auth/internal/demo"
)

// TestMain runs an app instance instead of the tests when the stack started this binary as one.
func TestMain(m *testing.M) {
	if os.Getenv("STACK_TEST_ROLE") == "serve" {
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
		defer stop()
		if err := demo.Serve(ctx, os.Args[1:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	os.Exit(m.Run())
}

func TestStack(t *testing.T) {
	for _, bin := range []string{"etcd", "dex"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("no %s on PATH; this runs inside the devshell", bin)
		}
	}
	s, err := Start(t.Context(), Options{Command: []string{os.Args[0]}, Env: []string{"STACK_TEST_ROLE=serve"}})
	if err != nil {
		t.Fatal(err)
	}
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			s.Stop()
		}
	})

	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: s.CAPool}}}
	defer hc.CloseIdleConnections()
	for _, u := range append([]string{s.Dex.Issuer + "/.well-known/openid-configuration"}, s.URLs...) {
		resp, err := hc.Get(u)
		if err != nil {
			t.Fatalf("GET %s: %v\n%s", u, err, s.Logs())
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: %d\n%s", u, resp.StatusCode, s.Logs())
		}
	}

	var pids []int
	for _, p := range append([]*proc{s.etcd, s.Dex.p}, s.instances...) {
		pids = append(pids, p.cmd.Process.Pid)
	}
	s.Stop()
	stopped = true
	for _, pid := range pids {
		// Each process led a group of its own, so this asks about everything it started as well.
		if err := syscall.Kill(-pid, 0); !errors.Is(err, syscall.ESRCH) {
			t.Errorf("process group %d is still there after Stop (kill: %v)", pid, err)
		}
	}
	if _, err := os.Stat(s.dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the stack dir is still there after Stop: %v", err)
	}
}
