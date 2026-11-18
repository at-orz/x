package stack

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// startEtcd starts one etcd member and returns it with the URL of its client port.
func startEtcd(ctx context.Context, dir string, sink io.Writer) (*proc, string, error) {
	bin, err := exec.LookPath("etcd")
	if err != nil {
		return nil, "", err
	}
	var p *proc
	var clientURL string
	err = withRetry(func() error {
		cport, err := freePort()
		if err != nil {
			return err
		}
		pport, err := freePort()
		if err != nil {
			return err
		}
		clientURL = fmt.Sprintf("http://127.0.0.1:%d", cport)
		peerURL := fmt.Sprintf("http://127.0.0.1:%d", pport)
		data := filepath.Join(dir, "etcd")
		_ = os.RemoveAll(data)
		p, err = start("etcd", []string{bin,
			"--name", "stack",
			"--data-dir", data,
			"--listen-client-urls", clientURL,
			"--advertise-client-urls", clientURL,
			"--listen-peer-urls", peerURL,
			"--initial-advertise-peer-urls", peerURL,
			"--initial-cluster", "stack=" + peerURL,
			"--log-level", "error",
		}, os.Environ(), nil, sink)
		if err != nil {
			return err
		}
		err = p.waitReady(ctx, 30*time.Second, func(context.Context) error {
			conn, err := net.DialTimeout("tcp", strings.TrimPrefix(clientURL, "http://"), time.Second)
			if err == nil {
				conn.Close()
			}
			return err
		})
		if err != nil {
			p.stop()
		}
		return err
	})
	if err != nil {
		return nil, "", err
	}
	return p, clientURL, nil
}
