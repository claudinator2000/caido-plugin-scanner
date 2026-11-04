#!/usr/bin/env bash
# OSV-Scanner on the lockfiles of an untrusted repo.
# Usage: osv-scan.sh <osv-scanner-binary> <source-dir> <output.json>
# The repo cannot steer the scan: --config replaces any osv-scanner.toml in it (e.g.
# PackageOverrides with ignore = true), --no-ignore defeats a .gitignore over lockfiles.
# Exit codes of osv-scanner: 0 nothing found, 1 findings, 128 no lockfile.
set -euo pipefail
osv=$1 src=$2 out=$3
config="$(cd "$(dirname "$0")/.." && pwd)/config/osv-scanner.toml"
rc=0
"$osv" scan source --recursive --no-ignore --config "$config" --format json "$src" > "$out" || rc=$?
case "$rc" in
  0|1) ;;
  128) echo "No lockfile, no dependencies to check"; echo '{"results": []}' > "$out" ;;
  *) echo "ERROR: OSV-Scanner failed (exit $rc)"; exit "$rc" ;;
esac
