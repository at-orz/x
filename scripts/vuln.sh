#!/usr/bin/env bash
# Scans every module with govulncheck; vuln.yaml runs exactly this. Run it
# inside the devshell:
#   nix develop path:./.nix -c scripts/vuln.sh
# Every module is scanned even after one fails, so one run reports them all.
set -uo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT" || exit 1
export GOWORK=$REPO_ROOT/go.work

build_tools
mapfile -t modules < <(workspace_modules)
if ((${#modules[@]} == 0)); then
	echo "no modules yet"
	exit 0
fi
rc=0
for m in "${modules[@]}"; do
	echo "==> $m"
	(cd "$m" && "$TOOLS_BIN/govulncheck" ./...) || rc=1
done
exit $rc
