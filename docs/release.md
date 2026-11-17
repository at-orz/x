# Releasing a module

The whole process from "this module should release" to "`go get` serves the new version". The user
decides and approves; `scripts/release.sh` is the gate and cuts the tag locally; GitHub Actions
verifies it again and publishes.

## Versions and tags

A module's version is its tag, `<module-dir>/vX.Y.Z` — `auth/v0.2.0`, `auth/store/etcd/v0.1.0`.
Nothing in the tree carries a version number, so a release never needs a commit of its own.

- **Every module starts at `v0`.** Moving one to `v1` is the user's call. After it, a breaking
  change means a `/v2` module path, which is expensive for every user, so it is not done lightly.
- **Within `v0`**: a breaking change, new API, or a raised `go` line is a minor bump; anything else
  is a patch.
- **A machine checks the bump.** `gorelease` compares the module against its previous tag. Under
  `v0` it reports incompatible changes but accepts any version, so `release.sh` also requires the
  proposed version to be no lower than the one `gorelease` suggests. A patch over a removed function
  is refused.

## The Go floor

Every module's `go` line equals the `go` line of `go.work`: the older of the two Go releases
currently supported, at `.0`. The devshell's Go comes from `.nix/flake.lock` and may be newer; the
`min-go` job in `ci.yaml` tests every module with exactly the floor, so nothing quietly depends on a
newer release.

When a new Go release ships, a chore card raises `go.work` and every module's `go` line together,
with a `CHANGELOG.md` entry in each module. Each module's next release is then a minor bump.

## Release notes: `<module>/CHANGELOG.md`

The notes live in the module directory, so they ship inside the module zip: a user, or an agent,
can read them in the module cache.

```markdown
# Changelog

## Unreleased

- Next change.

## v0.2.0 — 2026-11-20

### Breaking changes

- **`Store.Get` takes a context.** Pass `context.Background()` where you had none.

### Changes

- **Lease renewal no longer races with `Close`.**
```

- Keep an `## Unreleased` section on top. A commit that changes the module adds its entry there.
- At release, rename it to `## vX.Y.Z — YYYY-MM-DD` and put a new empty `## Unreleased` above it.
- The section under that heading becomes both the tag message and the GitHub release body.

### How to write a section

The reader wants "what do I care about in this version".

- **Conclusion first, bullets not prose.** Bold the claim, one line of why.
- **No preamble, no recap, no closer.**
- **Write for users of the module**: what changed and what it means for them. Implementation detail
  stays in the commits.
- **No tracker references.** The module zip is public and outlives the tracker.
- **Never omitted**: breaking changes (write "None" when there are none), and any migration a user
  has to carry out.

## Cutting a release

1. **Decide** the module and the version.
2. **Draft the section** in `<module>/CHANGELOG.md` on a branch, as part of the release card.
3. **Get it approved** in the tracker's spec review on that card, on the exact version being
   shipped. Nothing is tagged before the verdict.
4. **Land and push it.** In the main checkout:

   ```bash
   git merge --ff-only <release-branch>
   git push origin master
   ```

5. **Wait for `ci.yaml` to succeed on that commit** (`gh run list --workflow ci.yaml --branch
   master`), then cut the tag:

   ```bash
   nix develop path:./.nix -c scripts/release.sh <module-dir> <x.y.z> --dry-run
   nix develop path:./.nix -c scripts/release.sh <module-dir> <x.y.z>
   ```

`release.sh` changes no files and makes no commit. It refuses to tag unless all of these hold:

1. The checkout is on `master`, tracked files are clean, and `HEAD` equals a freshly fetched
   `origin/master`.
2. The push-triggered `ci.yaml` run on `master` for `HEAD` completed successfully. While it is still
   running, the script says so and exits; retry once it finishes.
3. `<module-dir>/go.mod` exists, declares `github.com/at-orz/x/<module-dir>`, and is not under
   `internal/`.
4. The tag exists neither locally nor on `origin`.
5. `CHANGELOG.md` has a non-empty `## vX.Y.Z` section.
6. With the workspace off (`GOWORK=off`), the module passes `go mod tidy -diff`, `go build`,
   `go test -race` and `govulncheck`. This proves it works on its declared `require`s alone, as it
   will for its users.
7. `gorelease` accepts the version against the previous tag (or against none, for a first release),
   and the version is no lower than the one it suggests.

Then it creates an annotated tag (title `<module-dir> vX.Y.Z`, then the CHANGELOG section) and
pushes that tag alone. `--dry-run` turns every failed precondition into a warning and prints the
commands and tag message it would use, so one run shows everything still missing.

## What GitHub Actions does

A pushed tag matching `**/v[0-9]*` starts `release.yaml`:

1. `scripts/release.sh --verify <tag>` — the same code as the local run. It asserts the tag is
   annotated and repeats checks 2 and 5–7 on the tagged commit.
2. Creates the GitHub release, titled `<module-dir> vX.Y.Z`, with the CHANGELOG section as its body.
3. Asks `proxy.golang.org` for the version, so it can be fetched at once; pkg.go.dev picks it up from
   there.

The local run is the real gate. Once a tag is pushed, the proxy and the checksum database may have
recorded it for good, so Actions can only check after the fact. When it finds a problem, the job
fails and no release is created.

## When something goes wrong

- **Never delete, move or re-push a pushed tag.** The proxy and the checksum database keep what they
  saw, so changing the tag only makes users' checksum verification fail.
- **Fix forward.** Release the next patch. If the bad version must not be used, add
  `retract vX.Y.Z // reason` to the module's `go.mod` and ship it in that patch.
- **The tag is fine but the release job failed** (a workflow bug, an outage): fix the workflow, then
  re-run it for the same tag:

  ```bash
  gh workflow run release.yaml -f tag=<module-dir>/vX.Y.Z
  ```

## Releasing modules that depend on each other

A module in this repository requires another by a real version, never a `replace`. Release the
dependency first, raise the dependent module's `require` to the new tag, land that, then release the
dependent module. Step 6 above builds without the workspace, so releasing in the wrong order fails.

## Who does what

| Step | Who |
|---|---|
| Decide which module releases, at which version | the user |
| Draft the CHANGELOG section | an agent, on the release card, on its own branch |
| Approve the notes | the user, through spec review on the release card |
| Merge to `master`, push, run `scripts/release.sh` | the orchestrator, in the main checkout |
| Verify, GitHub release, warm the proxy | GitHub Actions |

## Recommended repository settings

These are set by the repository owner on GitHub; nothing in the repository applies them.

- **A tag ruleset** targeting `**/v*` that blocks deletion and updates (force-push). It turns "never
  move a pushed tag" from a habit into something GitHub enforces.
