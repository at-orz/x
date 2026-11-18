package stack

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// proc is one child process of the stack, in a process group of its own so that whatever it starts
// goes with it.
type proc struct {
	name string
	cmd  *exec.Cmd
	log  *ring
	done chan struct{}
}

// errExited is a process that ended before it was ready: for a port handed over by number, usually a
// lost race for that port, which fresh ports settle.
var errExited = errors.New("exited before it was ready")

func start(name string, argv, env []string, log *ring, sink io.Writer) (*proc, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = env
	if log == nil {
		log = newRing()
	}
	p := &proc{name: name, cmd: cmd, log: log, done: make(chan struct{})}
	var out io.Writer = p.log
	if sink != nil {
		out = io.MultiWriter(p.log, &prefixed{w: sink, prefix: name + ": "})
	}
	cmd.Stdout, cmd.Stderr = out, out
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", name, err)
	}
	go func() {
		_ = cmd.Wait()
		close(p.done)
	}()
	return p, nil
}

// waitReady polls ready until it succeeds, the process exits, or timeout passes.
func (p *proc) waitReady(ctx context.Context, timeout time.Duration, ready func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		err := ready(ctx)
		if err == nil {
			return nil
		}
		select {
		case <-p.done:
			return fmt.Errorf("%s %w:\n%s", p.name, errExited, p.log.String())
		case <-ctx.Done():
			return fmt.Errorf("%s was not ready within %s: %w\n%s", p.name, timeout, err, p.log.String())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// stop kills the process group and waits for the process.
func (p *proc) stop() {
	select {
	case <-p.done:
		return
	default:
	}
	_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
	<-p.done
}

// freePort hands over a free port by number. Another process may bind it first, which is why every
// caller retries a process that exits before it is ready.
func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// retries bounds the attempts at starting a process on fresh ports.
const retries = 5

// withRetry runs try until it succeeds or fails for a reason other than errExited.
func withRetry(try func() error) error {
	var err error
	for range retries {
		if err = try(); err == nil || !errors.Is(err, errExited) {
			return err
		}
	}
	return err
}

// ring keeps the last max bytes written to it.
type ring struct {
	mu  sync.Mutex
	max int
	buf []byte
}

func newRing() *ring { return &ring{max: 64 << 10} }

func (r *ring) Write(b []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = append(r.buf, b...)
	if over := len(r.buf) - r.max; over > 0 {
		r.buf = append(r.buf[:0], r.buf[over:]...)
	}
	return len(b), nil
}

func (r *ring) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return string(r.buf)
}

// prefixed writes each chunk to w with a prefix, so that the logs of several processes on one sink can
// be told apart. A chunk is not always a whole line; for a log read by a person that is good enough.
type prefixed struct {
	mu     sync.Mutex
	w      io.Writer
	prefix string
}

func (p *prefixed) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, err := io.WriteString(p.w, p.prefix); err != nil {
		return 0, err
	}
	return p.w.Write(b)
}
