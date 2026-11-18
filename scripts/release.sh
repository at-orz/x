#!/usr/bin/env bash
# Tag a module release. See docs/release.md. Run inside the devshell:
#   scripts/release.sh <module-dir> <x.y.z> [--dry-run]
#   scripts/release.sh --verify <module-dir>/v<x.y.z>
# This script is the gate: once a tag is pushed, proxy.golang.org and the
# checksum database may have recorded it for good, so every check runs before
# the tag exists. --verify repeats the checks that still make sense afterwards,
# for release.yaml.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

usage() {
	echo "usage: scripts/release.sh <module-dir> <x.y.z> [--dry-run]" >&2
	echo "       scripts/release.sh --verify <module-dir>/v<x.y.z>" >&2
	exit 2
}

mode=release
case ${1:-} in
--verify)
	(($# == 2)) || usage
	mode=verify
	tag=$2
	split_tag "$tag" || die "'$tag' is not a <module-dir>/v<x.y.z> tag"
	dir=$TAG_DIR
	version=$TAG_VERSION
	;;
*)
	(($# == 2 || $# == 3)) || usage
	dir=${1%/}
	version=${2#v}
	if (($# == 3)); then
		[[ $3 == --dry-run ]] || usage
		mode=dry-run
	fi
	tag=$dir/v$version
	;;
esac

warnings=0
# check_failed aborts, except under --dry-run, where it only warns so that one
# run shows every unmet precondition.
check_failed() {
	if [[ $mode == dry-run ]]; then
		echo "release: WARN [$1] $2" >&2
		warnings=$((warnings + 1))
	else
		die "[$1] $2"
	fi
}

step() { echo "==> $*"; }

# Ahead of every other check and in every mode: no precondition can make an
# example releasable, so a dry run listing the others would only mislead.
if [[ $dir == examples/* ]]; then
	die "$dir is an example and is never released"
fi

[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "version '$version' is not x.y.z"

if [[ $mode == verify ]]; then
	[[ $(git cat-file -t "refs/tags/$tag" 2>/dev/null) == tag ]] || die "$tag is not an annotated tag"
	commit=$(git rev-parse "$tag^{commit}")
	[[ $(git rev-parse HEAD) == "$commit" ]] || die "HEAD is not the commit tagged $tag; check it out first"
	[[ -f $dir/go.mod ]] || die "$dir/go.mod does not exist at $tag"
else
	step "1 master is clean and pushed"
	git fetch --quiet --tags origin master || die "cannot fetch origin"
	[[ $(git symbolic-ref --short -q HEAD) == master ]] || check_failed 1 "not on master"
	git diff --quiet HEAD -- || check_failed 1 "tracked files have uncommitted changes"
	[[ $(git rev-parse HEAD) == $(git rev-parse origin/master) ]] || check_failed 1 "HEAD is not origin/master"
	commit=$(git rev-parse HEAD)
fi

step "2 ci.yaml succeeded on master for ${commit:0:12}"
if ci=$(ci_status_on "$commit"); then
	case $ci in
	success) ;;
	running) check_failed 2 "ci.yaml is still running for ${commit:0:12}; retry once it finishes" ;;
	*) check_failed 2 "no successful ci.yaml push run on master for ${commit:0:12} (state: $ci)" ;;
	esac
else
	check_failed 2 "cannot query GitHub Actions"
fi

module_ok=1
if [[ $mode != verify ]]; then
	step "3 module"
	if [[ ! -f $dir/go.mod ]]; then
		check_failed 3 "$dir/go.mod does not exist"
		module_ok=
	elif [[ $(module_path "$dir") != "$MODULE_PREFIX/$dir" ]]; then
		check_failed 3 "$dir/go.mod declares '$(module_path "$dir")', want '$MODULE_PREFIX/$dir'"
	fi
	[[ $dir != internal && $dir != internal/* ]] || check_failed 3 "$dir is repo tooling and is never released"

	step "4 tag $tag is new"
	! git rev-parse -q --verify "refs/tags/$tag" >/dev/null || check_failed 4 "tag $tag already exists locally"
	remote=$(git ls-remote --tags origin "refs/tags/$tag") || die "cannot reach origin"
	[[ -z $remote ]] || check_failed 4 "tag $tag already exists on origin"
fi

step "5 CHANGELOG.md has a v$version section"
notes=$(changelog_section "$dir" "$version")
[[ -n $notes ]] || check_failed 5 "$dir/CHANGELOG.md has no '## v$version' section, or it is empty"

if [[ -n $module_ok ]]; then
	build_tools
	step "6 build and test without the workspace"
	(
		cd "$dir"
		export GOWORK=off
		go mod tidy -diff || exit 1
		go build ./... || exit 1
		go test -race ./... || exit 1
		"$TOOLS_BIN/govulncheck" ./... || exit 1
	) || check_failed 6 "$dir does not build, test or scan cleanly on its own requires"

	# gorelease reads the existing versions from the module proxy. Ahead of it,
	# a list-only proxy built from git tags hides the version being released, so
	# that --verify works after the tag is public and a just-pushed earlier tag
	# is never missed because of proxy lag. Downloads fall through to the real
	# proxy.
	listproxy=$REPO_ROOT/.tmp/listproxy
	escaped=$(sed 's/[A-Z]/!\L&/g' <<<"$MODULE_PREFIX/$dir")
	rm -rf "$listproxy"
	mkdir -p "$listproxy/$escaped/@v"
	released_versions "$dir" | grep -vxF "$version" | sed 's/^/v/' >"$listproxy/$escaped/@v/list" || true
	base=none
	while read -r v; do
		if version_lt "$v" "$version"; then base=v$v; fi
	done < <(released_versions "$dir")

	step "7 gorelease against $base"
	(
		cd "$dir"
		export GOWORK=off GOPROXY="file://$listproxy,${GOPROXY:-https://proxy.golang.org,direct}"
		# Under v0, gorelease reports incompatible changes but accepts any
		# version, so the bump is checked against the version it suggests.
		out=$("$TOOLS_BIN/gorelease" -base="$base") || {
			echo "$out"
			exit 1
		}
		echo "$out"
		suggested=$(sed -n 's/^Suggested version: v\([0-9]*\.[0-9]*\.[0-9]*\).*$/\1/p' <<<"$out")
		[[ -n $suggested ]] || {
			echo "release: gorelease suggested no version" >&2
			exit 1
		}
		if version_lt "$version" "$suggested"; then
			echo "release: v$version is below the suggested v$suggested" >&2
			exit 1
		fi
		"$TOOLS_BIN/gorelease" -base="$base" -version="v$version" >/dev/null
	) || check_failed 7 "gorelease rejects v$version against $base"
fi

if [[ $mode == verify ]]; then
	echo "release: $tag verified"
	exit 0
fi

msgfile=$REPO_ROOT/.tmp/tag-message.txt
mkdir -p "$(dirname "$msgfile")"
printf '%s v%s\n\n%s\n' "$dir" "$version" "$notes" >"$msgfile"
# verbatim: the default cleanup would strip "### " subheadings from the notes.
cmd_tag=(git tag -a --cleanup=verbatim "$tag" -F "$msgfile")
cmd_push=(git push origin "refs/tags/$tag")

if [[ $mode == dry-run ]]; then
	echo
	echo "release: dry run, $warnings warning(s). Would run:"
	echo "  ${cmd_tag[*]}"
	echo "  ${cmd_push[*]}"
	echo "with tag message:"
	sed 's/^/  | /' "$msgfile"
	exit 0
fi

"${cmd_tag[@]}"
"${cmd_push[@]}"
echo "release: pushed $tag; release.yaml takes it from here"
