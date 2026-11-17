#!/usr/bin/env bash
# The single check entry point: CI runs exactly this. Run it inside the devshell:
#   nix develop path:./.nix -c scripts/check.sh
# It only checks and never rewrites files.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
export GOWORK=$REPO_ROOT/go.work

fail() {
	local step=$1
	shift
	echo "check: FAIL [$step] $*" >&2
	exit 1
}

step() { echo "==> $*"; }

build_tools
mapfile -t modules < <(workspace_modules)
floor=$(workspace_go_version)
[[ -n $floor ]] || fail "2 go floor" "go.work has no go line"

step "1 workspace"
mapfile -t on_disk < <(disk_modules)
for m in "${on_disk[@]}"; do
	printf '%s\n' "${modules[@]}" | grep -qxF "$m" || fail "1 workspace" "$m/go.mod is not in go.work; run: go work use ./$m"
done
for m in "${modules[@]}"; do
	[[ -f $m/go.mod ]] || fail "1 workspace" "go.work uses ./$m, which has no go.mod"
done

step "2 go floor ($floor)"
for m in "${modules[@]}"; do
	v=$(sed -n 's/^go \([0-9.]*\)$/\1/p' "$m/go.mod")
	[[ $v == "$floor" ]] || fail "2 go floor" "$m: go line is '$v', want '$floor' (the go line of go.work)"
	! grep -q '^toolchain' "$m/go.mod" || fail "2 go floor" "$m: go.mod has a toolchain line"
	[[ $(module_path "$m") == "$MODULE_PREFIX/$m" ]] || fail "2 go floor" "$m: module path is '$(module_path "$m")', want '$MODULE_PREFIX/$m'"
done

step "3 no replace"
for m in "${modules[@]}"; do
	! grep -q '^replace' "$m/go.mod" || fail "3 no replace" "$m: go.mod has a replace directive; require a real version and rely on go.work"
done

step "4 gofmt"
unformatted=$(find . -name '*.go' -not -path './.tmp/*' -not -path './.direnv/*' -print0 | xargs -0 -r gofmt -l) ||
	fail "4 gofmt" "gofmt could not parse some files (errors above)"
[[ -z $unformatted ]] || fail "4 gofmt" "not gofmt-ed (run gofmt -w):"$'\n'"$unformatted"

step "5 in-repo requires"
fetched=
for m in "${modules[@]}"; do
	while read -r path version; do
		[[ $path == "$MODULE_PREFIX/"* ]] || continue
		dir=${path#"$MODULE_PREFIX/"}
		if is_pseudo_version "$version"; then
			short=${version##*-}
			short=${short%+incompatible}
			if [[ -z $fetched ]]; then
				git fetch --quiet origin master || fail "5 in-repo requires" "cannot fetch origin master"
				fetched=1
			fi
			sha=$(git rev-parse --verify --quiet "$short^{commit}") ||
				fail "5 in-repo requires" "$m requires $path@$version: commit $short is unknown here"
			git merge-base --is-ancestor "$sha" origin/master ||
				fail "5 in-repo requires" "$m requires $path@$version: commit $short is not on origin/master"
			ci=$(ci_status_on "$sha") || fail "5 in-repo requires" "$m requires $path@$version: cannot query GitHub Actions"
			[[ $ci == success ]] || fail "5 in-repo requires" "$m requires $path@$version: ci.yaml on master for $short is '$ci', not success"
		else
			out=$(git ls-remote --tags origin "refs/tags/$dir/$version") ||
				fail "5 in-repo requires" "$m requires $path@$version: cannot reach origin"
			[[ -n $out ]] || fail "5 in-repo requires" "$m requires $path@$version: tag $dir/$version does not exist on origin"
		fi
	done < <(go mod edit -json "$m/go.mod" | awk '
		/"Require": \[/ { inreq = 1; next }
		inreq && /^\t\]/ { inreq = 0 }
		inreq && /"Path":/ { gsub(/[",]/, "", $2); p = $2 }
		inreq && /"Version":/ { gsub(/[",]/, "", $2); print p, $2 }')
done

step "6 actionlint"
shopt -s nullglob
workflows=(.github/workflows/*.yaml)
shopt -u nullglob
if ((${#workflows[@]})); then
	"$TOOLS_BIN/actionlint" "${workflows[@]}" || fail "6 actionlint" "workflow files have errors"
else
	echo "no workflow files"
fi

if ((${#modules[@]} == 0)); then
	echo "no modules yet"
	exit 0
fi

coverdir=$REPO_ROOT/.tmp/coverage
rm -rf "$coverdir"
mkdir -p "$coverdir"
for m in "${modules[@]}"; do
	step "7 module $m"
	name=${m//\//_}
	(
		cd "$m"
		go mod tidy -diff || fail "7 $m" "go.mod/go.sum are not tidy (run go mod tidy in $m)"
		go vet ./... || fail "7 $m" "go vet"
		"$TOOLS_BIN/staticcheck" ./... || fail "7 $m" "staticcheck"
		go build ./... || fail "7 $m" "go build"
		go test -race -coverprofile="$coverdir/$name.out" ./... || fail "7 $m" "go test"
		if [[ -s $coverdir/$name.out ]]; then
			go tool cover -html="$coverdir/$name.out" -o "$coverdir/$name.html"
		fi
	)
done

table="| module | coverage |"$'\n'"|---|---|"
for m in "${modules[@]}"; do
	name=${m//\//_}
	total=n/a
	if [[ -s $coverdir/$name.out ]]; then
		total=$(cd "$m" && go tool cover -func="$coverdir/$name.out" | awk '/^total:/ { print $NF }')
	fi
	table+=$'\n'"| $m | $total |"
done
echo
echo "$table"
if [[ -n ${GITHUB_STEP_SUMMARY:-} ]]; then
	printf '## Coverage\n\n%s\n' "$table" >>"$GITHUB_STEP_SUMMARY"
fi
echo "check: all passed"
