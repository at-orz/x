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

## Before Committing

1. Format and check:
   ```bash
   gofmt -w . && go vet ./... && go build ./...
   ```
2. Run tests:
   ```bash
   go test ./...
   ```
3. Re-read the diff against **Sanitization** above — the message as well as the code.
4. Use a conventional commit prefix in the subject line: `feat:`, `fix:`, `refactor:`, `chore:`, `docs:`, `vendor:`, `test:`.
5. Commit with a single co-author trailer using the project-assigned model
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
