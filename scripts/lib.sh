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
# run as plain binaries. The build runs inside internal/tools so that its go.mod
# is the main module: from the root, with no go.mod there, -modfile alone
# cannot set one. The tools need no cgo; leaving it off keeps this step
# independent of a C compiler.
build_tools() {
	(cd "$REPO_ROOT/internal/tools" && CGO_ENABLED=0 GOWORK=off go build -o "$TOOLS_BIN/" \
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

# ci_status_on prints the state of the push-triggered ci.yaml runs on master
# for a commit: success, running, failed or none. Returns 2 when GitHub cannot
# be queried, so that callers fail instead of skipping.
ci_status_on() {
	local runs
	runs=$(gh run list -R "$GITHUB_REPO" --commit "$1" --workflow ci.yaml --event push \
		--branch master --json status,conclusion --jq '.[] | "\(.status) \(.conclusion)"') || return 2
	if grep -qx 'completed success' <<<"$runs"; then
		echo success
	elif grep -qv '^completed ' <<<"$runs"; then
		echo running
	elif [[ -n $runs ]]; then
		echo failed
	else
		echo none
	fi
}

# split_tag sets TAG_DIR and TAG_VERSION (x.y.z) from <module-dir>/v<x.y.z>.
split_tag() {
	[[ $1 =~ ^(.+)/v([0-9]+\.[0-9]+\.[0-9]+)$ ]] || return 1
	TAG_DIR=${BASH_REMATCH[1]}
	TAG_VERSION=${BASH_REMATCH[2]}
}

# changelog_section prints the body of the "## v<x.y.z>" section of
# <module-dir>/CHANGELOG.md, without leading or trailing blank lines.
changelog_section() {
	local file=$REPO_ROOT/$1/CHANGELOG.md
	[[ -f $file ]] || return 0
	awk -v want="v$2" '
		/^## / { insec = ($2 == want); next }
		insec { lines[++n] = $0 }
		END {
			first = 1; while (first <= n && lines[first] ~ /^[[:space:]]*$/) first++
			last = n; while (last >= first && lines[last] ~ /^[[:space:]]*$/) last--
			for (i = first; i <= last; i++) print lines[i]
		}' "$file"
}

# released_versions prints the x.y.z versions tagged for a module directory,
# lowest first.
released_versions() {
	git -C "$REPO_ROOT" tag -l "$1/v*" | sed -n "s|^$1/v\([0-9]*\.[0-9]*\.[0-9]*\)$|\1|p" | sort -V
}

# version_lt reports whether x.y.z version $1 sorts strictly before $2.
version_lt() {
	[[ $1 != "$2" && $(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n 1) == "$1" ]]
}
