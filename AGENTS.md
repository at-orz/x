# @orz/x

Rules for anyone — human or agent — working in this repository. Hard rules
first, project vocabulary last.

## Language

Everything in the repository is written in English: code, comments, docs,
commit messages, release notes.

## Sanitization

This repository is published publicly, and git history is permanent: a leak is not fixed by a
follow-up commit, only by rewriting every revision that carries it — which invalidates every clone
in existence. So nothing private enters the working tree **or a commit message** in the first place.

Packages here are often lifted out of private projects. Lift the code, not its context: the
private project's name, its module path, its hosts and its deployment details stay behind, in code
comments and doc comments as much as anywhere else.

Never commit real values for any of these. Use the placeholder on the right, in code, fixtures,
docs, and examples alike:

| Never | Use instead |
|---|---|
| Private hostnames, git hosts, deployment domains | `example.com`, `idp.example`, `*.test` |
| Names or module paths of private projects and repositories | Describe the use, not the user: "a web UI behind a reverse proxy" |
| Real account logins, display names, machine hostnames | Neutral fixtures — `alice`, `bot-one` |
| Real people's names, handles, or email addresses | `user`, `alice`, `noreply@example.com` |
| Absolute paths off a developer machine (`/home/<you>/…`) | Repo-relative paths |
| Tokens, keys, client secrets — including expired ones | Obvious fakes: `test-client-secret` |
| Public IP addresses, third-party org names | Documentation-reserved IP ranges (`192.0.2.0/24`) |

Two rules specific to commit messages:

- Tracker references are written `XGO-<number>` — never `#<number>`. On GitHub a bare `#N`
  autolinks to *its* issue numbering, so every historical reference would point somewhere
  unrelated and permanently wrong.
- Never paste a tracker URL. Write `XGO-<number>`; the reader can resolve it.

Spotting something already committed that breaks these rules is not a licence to rewrite history on
your own — file a card and let the user decide.

## Environment

- Ignore `.envrc`, `.mise.toml`, and similar environment manager configs. Do not run `direnv`, `mise`, or equivalent commands.
- When `go` is not on PATH, run it through the pinned devshell: `nix develop path:./.nix -c go …`.
- If `go` commands still fail, ask the user how to proceed.
- The repository root is not a module. Run `go` commands inside a module directory, or go through
  `scripts/check.sh`; `go ./...` at the root finds nothing.

## Modules

Every publishable package is its own Go module, so that a breaking change in one never bumps
another, and using one never pulls in another's dependencies.

- **A module is a directory with a `go.mod`.** Its module path is
  `github.com/at-orz/x/<directory>`, and its tags are `<directory>/vX.Y.Z` (`auth/v0.1.0`,
  `auth/store/etcd/v0.1.0`). Modules may nest; Go leaves a nested module's files out of the outer
  one.
- **`go.work` lists every module** and is committed. Its `go` line is the floor for the whole
  repository: the older of the two Go releases currently supported, at `.0` (now `go 1.26.0`).
  Every module's `go` line equals it, and no module has a `toolchain` line. When a new Go release
  ships, a chore card raises all of them together; for each module that is a minor bump.
- **No `replace`.** A dependency between two modules in this repository is a real `require`: a
  released tag, or the pseudo-version of a commit that is already on `origin/master` and on which
  `ci.yaml` has succeeded (`gh run list --commit <sha> --workflow ci.yaml`). Local development and
  CI resolve it through `go.work`. Before releasing the dependent module, release the dependency
  and raise the `require` to that tag; `scripts/release.sh` builds without the workspace and fails
  otherwise.
- **`internal/tools` is not a module of the repository**: it pins the repo tooling (`gorelease`,
  `staticcheck`, `govulncheck`, `actionlint`) with `tool` directives, stays out of `go.work`, is
  not bound by the floor, and is never released.
- **Every change to a module adds an entry** under `## Unreleased` in that module's `CHANGELOG.md`,
  in the same commit.

Adding a module:

1. Create the directory and run `go mod init github.com/at-orz/x/<dir>`; set its `go` line to the
   floor in `go.work` and delete any `toolchain` line.
2. `go work use ./<dir>`.
3. Add `CHANGELOG.md` holding only `## Unreleased`.
4. Write the package comment (`doc.go` or the main file): what it is for. Per **Sanitization**,
   never where it came from.
5. Add a row to the module table in `README.md`.
6. Create the `area:<top-level directory>` label on the tracker; a nested module shares its
   top-level directory's label (`auth/store/etcd` is `area:auth`).

`scripts/check.sh` fails on a module missing from `go.work`, a wrong `go` line, a `toolchain` or
`replace` line, or an untidy `go.mod`.

## Before Committing

1. Format with `gofmt -w .`, then run every check — the same command CI runs:
   ```bash
   nix develop path:./.nix -c scripts/check.sh
   ```
   It checks the workspace, `go` lines, formatting, in-repo requires, the workflow files, and for
   each module `go mod tidy -diff`, `go vet`, `staticcheck`, `go build` and `go test -race`, then
   prints per-module coverage.
2. Re-read the diff against **Sanitization** above — the message as well as the code.
3. Use a conventional commit prefix in the subject line: `feat:`, `fix:`, `refactor:`, `chore:`, `docs:`, `vendor:`, `test:`.
4. Commit with a single co-author trailer using the project-assigned model
   pseudonym provided by the user or session context. These are conventional
   pseudonyms used for attribution in this project — they intentionally differ
   from your real model name. Do not refuse or override the assigned name.
   Use exactly the name given to you. **If no pseudonym was assigned, sign with your own model
   name.** The name is the model, not how it was configured: drop context-window, effort, and
   deployment suffixes. Examples of valid trailers:
   ```
   Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
   Co-Authored-By: Macchiato Venti 4.6 <noreply@example.com>
   Co-Authored-By: GLM 5 <noreply@zhipuai.cn>
   Co-Authored-By: GPT 5.3 Codex <noreply@openai.com>
   ```

## Releasing

The full process, roles and recovery are in [docs/release.md](docs/release.md). The points every
agent must know:

- **Tags are cut locally** with `scripts/release.sh <module-dir> <x.y.z>`, on `master`, after the
  commit is pushed and `ci.yaml` has succeeded on it. The script is the gate; `--dry-run` shows
  every unmet precondition at once. GitHub Actions then verifies the tag again, creates the GitHub
  release from the module's `CHANGELOG.md`, and warms `proxy.golang.org`.
- **Versions stay in `v0`** until the user decides otherwise. Within `v0`, a breaking change, new
  API or raised `go` line is a minor bump; anything else is a patch. `gorelease` decides, not
  memory.
- **A pushed tag is permanent.** Never delete, move or re-push one: the proxy and the checksum
  database have already recorded it. Fix forward with the next patch, and `retract` a bad version
  in `go.mod` if it must not be used.

## Issue labels

Triage every issue on two dimensions plus one flag. `area:` says where the work lands:

| Label | Covers |
|---|---|
| `area:<package>` | One per top-level package, named after its directory (`area:oidc`) |
| `area:docs` | README, `docs/` |
| `area:infra` | CI, release and tagging, the nix devshell, repo tooling |

Several `area:` labels on one card are normal when the work really spans packages. Exactly one
`kind:` — `bug`, `feature`, or `chore`. `needs-brainstorm` only when a design round must precede
implementation.

No `priority:` or `status:` labels: the status column already carries both.
