// Command demo is the reference integration of auth: a small web app that signs people in through an
// OpenID Connect provider and automated clients through one-time tickets, with its sessions in etcd
// and shared by several instances behind a reverse proxy terminating TLS.
//
// Package app is the part to copy. It uses only the public API of auth, auth/oidc, auth/mint and
// auth/store/etcd, and its comments explain the decisions a host makes. The rest is the scaffolding
// that runs it: this command, the local stack in internal/stack, and the end-to-end tests in e2e,
// which drive the stack over HTTP and through a headless Chromium.
//
// # Running it
//
// Inside the repository's devshell, which provides etcd, Dex and Chromium:
//
//	cd examples/auth
//	nix develop path:../../.nix -c go run . up
//
// up starts etcd, Dex, two app instances and a TLS front door for each, then prints their URLs, the
// Dex users and a ticket link, and runs until interrupted. The front doors serve a certificate from
// a CA generated for the run, which a browser warns about. The other subcommands are what up runs:
// serve is one app instance, and mint writes a ticket into etcd and prints its link.
//
// # Dex and several devices
//
// Dex keeps one refresh token per user and client: a sign-in revokes the refresh token of that
// user's previous sign-in. With Dex as the provider, signing in on a second device ends the first
// device's session at its next revalidation, within the hour. That is Dex's policy rather than
// auth's, and another provider may keep each device's token.
package main
