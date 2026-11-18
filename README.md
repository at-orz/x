# @orz/x

Small, public Go packages, each its own module so that you only pull in what you use.

```bash
go get github.com/at-orz/x/<module>@latest
```

## Modules

<!-- One row per module, in this shape:
| [`auth`](auth) | What it is for, in one line | [![Go Reference](https://pkg.go.dev/badge/github.com/at-orz/x/auth.svg)](https://pkg.go.dev/github.com/at-orz/x/auth) |
-->

| Module | What it is for | Docs |
|---|---|---|
| [`auth`](auth) | Web login sessions with pluggable sign-in: OpenID Connect providers, one-time tickets | [![Go Reference](https://pkg.go.dev/badge/github.com/at-orz/x/auth.svg)](https://pkg.go.dev/github.com/at-orz/x/auth) |
| [`auth/store/etcd`](auth/store/etcd) | Session and ticket storage for `auth` in etcd, shared by several instances | [![Go Reference](https://pkg.go.dev/badge/github.com/at-orz/x/auth/store/etcd.svg)](https://pkg.go.dev/github.com/at-orz/x/auth/store/etcd) |

No module has been released yet.

Each module is versioned and tagged on its own (`<module>/vX.Y.Z`), keeps its release notes in its
own `CHANGELOG.md`, and supports the older of the two Go releases currently supported. Every module
is still at `v0`: minor versions may break the API, and the changelog says how.

## Examples

Not modules to import: code to read and run from this repository, never released.

| Example | What it shows |
|---|---|
| [`examples/auth`](examples/auth) | A web app on `auth`, `auth/oidc`, `auth/mint` and `auth/store/etcd`, with end-to-end tests against Dex and Chromium. Run it with `cd examples/auth && nix develop path:../../.nix -c go run . up`. |

## Contributing

Rules for working in this repository, for humans and agents alike, are in [AGENTS.md](AGENTS.md);
the release process is in [docs/release.md](docs/release.md).

## License

[BSD-3-Clause](LICENSE).
