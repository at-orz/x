// Package e2e runs the example app against a real Dex, a real etcd and, for the browser tests, a real
// headless Chromium. Every test skips when a binary it needs is not on PATH; the devshell has them all.
package e2e

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"testing"

	"github.com/at-orz/x/examples/auth/internal/demo"
	"github.com/at-orz/x/examples/auth/internal/stack"
)

// roleEnv makes this test binary an app instance: the stack starts the binary itself rather than a
// separately built one, so no go build runs inside a test and the instances carry -race too.
const roleEnv = "E2E_ROLE"

var (
	// shared is the stack every test uses unless it disturbs Dex for everyone; nil when skipped is set.
	shared  *stack.Stack
	skipped string
)

func TestMain(m *testing.M) {
	if os.Getenv(roleEnv) == "serve" {
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
		defer stop()
		if err := demo.Serve(ctx, os.Args[1:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	os.Exit(run(m))
}

func run(m *testing.M) int {
	for _, bin := range []string{"etcd", "dex"} {
		if _, err := exec.LookPath(bin); err != nil {
			skipped = "no " + bin + " on PATH; this runs inside the devshell"
			return m.Run()
		}
	}
	s, err := startStack(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e: starting the shared stack:", err)
		return 1
	}
	defer s.Stop()
	shared = s
	return m.Run()
}

func startStack(ctx context.Context) (*stack.Stack, error) {
	return stack.Start(ctx, stack.Options{Command: []string{os.Args[0]}, Env: []string{roleEnv + "=serve"}})
}

// sharedStack is the shared stack, or a skip.
func sharedStack(t *testing.T) *stack.Stack {
	t.Helper()
	if shared == nil {
		t.Skip(skipped)
	}
	logsOnFailure(t, shared)
	return shared
}

// ownStack is a stack for this test alone, for a test that stops or empties Dex.
func ownStack(t *testing.T) *stack.Stack {
	t.Helper()
	if shared == nil {
		t.Skip(skipped)
	}
	s, err := startStack(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Stop)
	logsOnFailure(t, s)
	return s
}

// logsOnFailure prints the tails of Dex's and the instances' logs when the test fails. Registered
// after the stack's Stop, so it runs first, while the logs are still there.
func logsOnFailure(t *testing.T, s *stack.Stack) {
	t.Cleanup(func() {
		if t.Failed() {
			t.Log("stack logs:\n" + s.Logs())
		}
	})
}
