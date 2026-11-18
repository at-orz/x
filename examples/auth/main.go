package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/at-orz/x/auth/mint"
	"github.com/at-orz/x/auth/store/etcd"
	"github.com/at-orz/x/examples/auth/app"
	"github.com/at-orz/x/examples/auth/internal/demo"
	"github.com/at-orz/x/examples/auth/internal/stack"
)

const usage = `usage: demo <command> [flags]

  up      start the whole stack locally and run until interrupted
  serve   run one app instance
  mint    write a ticket and print its sign-in link
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch cmd, args := os.Args[1], os.Args[2:]; cmd {
	case "up":
		err = up(ctx)
	case "serve":
		err = demo.Serve(ctx, args)
	case "mint":
		err = demo.Mint(ctx, args)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if errors.Is(err, flag.ErrHelp) {
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "demo:", err)
		os.Exit(1)
	}
}

func up(ctx context.Context) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	s, err := stack.Start(ctx, stack.Options{Command: []string{exe, "serve"}})
	if err != nil {
		return err
	}
	defer s.Stop()

	link, err := app.IssueTicket(ctx, app.Config{Tickets: etcd.New(s.Etcd, demo.EtcdPrefix).Tickets()},
		stack.AllowedMinted[0], time.Hour)
	if err != nil {
		return err
	}
	fmt.Printf("The app, through two instances sharing their sessions:\n  %s\n  %s\n\n", s.URLs[0], s.URLs[1])
	fmt.Printf("Dex users (%s refused, the others allowed):\n", stack.Bob.Email)
	for _, u := range []stack.User{stack.Alice, stack.Bob, stack.Carol, stack.Dave} {
		fmt.Printf("  %-20s %s\n", u.Email, u.Password)
	}
	fmt.Printf("\nA one-hour session for %s, valid for %s:\n  %s\n\n", stack.AllowedMinted[0], mint.TicketTTL, s.URLs[0]+link)
	fmt.Printf("Certificates come from a CA made for this run: %s\nInterrupt to stop.\n", s.CAFile)
	<-ctx.Done()
	return nil
}
