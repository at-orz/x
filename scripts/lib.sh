# Shared helpers for scripts/check.sh and scripts/release.sh. Source, do not run.

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
MODULE_PREFIX=github.com/at-orz/x
GITHUB_REPO=at-orz/x
TOOLS_BIN=$REPO_ROOT/.tmp/bin

die() {
	echo "$(basename "$0"): $*" >&2
	exit 1
}

# build_tools builds the tools pinned in internal/tools into .tmp/bin.
# `go tool -modfile` is refused in workspace mode, and running the tools under
# GOWORK=off would leak into the packages they load, so they are built once and
# run as plain binaries. The tools need no cgo; leaving it off keeps this step
# independent of a C compiler.
build_tools() {
	(cd "$REPO_ROOT" && CGO_ENABLED=0 GOWORK=off go build -modfile=internal/tools/go.mod -o "$TOOLS_BIN/" \
		golang.org/x/exp/cmd/gorelease \
		honnef.co/go/tools/cmd/staticcheck \
		golang.org/x/vuln/cmd/govulncheck \
		github.com/rhysd/actionlint/cmd/actionlint) || die "building tools from internal/tools failed"
}

# workspace_modules prints the module directories listed in go.work, one per
# line, relative to the repo root and without a leading "./".
workspace_modules() {
	(cd "$REPO_ROOT" && GOWORK="$REPO_ROOT/go.work" go work edit -json) |
		sed -n 's/^[[:space:]]*"DiskPath": "\(.*\)",\{0,1\}$/\1/p' |
		sed 's|^\./||' | sort
}

# disk_modules prints every directory holding a go.mod that should be in the
# workspace: everything except repo tooling, scratch space and testdata.
disk_modules() {
	(cd "$REPO_ROOT" && find . -name go.mod \
		-not -path './.tmp/*' -not -path './.direnv/*' -not -path './internal/tools/*' \
		-not -path '*/testdata/*') |
		sed 's|^\./||; s|/go.mod$||' | sort
}

# workspace_go_version prints the go line of go.work: the repo-wide floor.
workspace_go_version() {
	sed -n 's/^go \([0-9.]*\)$/\1/p' "$REPO_ROOT/go.work"
}

# module_path prints the module path declared in <dir>/go.mod.
module_path() {
	sed -n 's/^module[[:space:]]\{1,\}\([^[:space:]]*\).*$/\1/p' "$REPO_ROOT/$1/go.mod" | head -n 1
}

# is_pseudo_version reports whether a version is a Go pseudo-version.
is_pseudo_version() {
	[[ $1 =~ [0-9]{14}-[0-9a-f]{12}(\+incompatible)?$ ]]
}

# ci_succeeded_on reports whether a push-triggered ci.yaml run on master
# completed successfully for the given commit.
ci_succeeded_on() {
	local conclusions
	conclusions=$(gh run list -R "$GITHUB_REPO" --commit "$1" --workflow ci.yaml --event push \
		--branch master --json conclusion --jq '.[].conclusion') || return 2
	grep -qx success <<<"$conclusions"
}
