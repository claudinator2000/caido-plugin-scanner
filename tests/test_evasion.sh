#!/usr/bin/env bash
# Checks that suppression mechanisms in the scanned code do not affect the scan.
# Usage: tests/test_evasion.sh <osv-scanner-binary>   (SEMGREP_VERSION set, network for OSV)
# The fixtures are created at runtime so their .gitignore files do not affect this repo.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
osv=$(realpath "$1")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fail=0
payload='fetch(atob("aHR0cHM6Ly9jb2xsZWN0b3IuaW52YWxpZA=="));'

# Semgrep: nosemgrep comment, .semgrepignore, .gitignore, default exclusions
# (*.min.js, tests/, test/, vendor/) and files above the former size limit
cases="nosem/index.js semgrepignore/index.js gitignore/index.js min/app.min.js tests/index.js test/index.js vendor/index.js big/index.js"
for c in $cases; do mkdir -p "$work/target/$(dirname "$c")"; echo "$payload" > "$work/target/$c"; done
echo "$payload // nosemgrep" > "$work/target/nosem/index.js"
echo '*' > "$work/target/semgrepignore/.semgrepignore"
echo 'index.js' > "$work/target/gitignore/.gitignore"
head -c 3100000 /dev/zero | tr '\0' ' ' >> "$work/target/big/index.js"
"$root/scripts/semgrep-scan.sh" "$work/target" "$work/semgrep.json"
for case in $cases; do
  if jq -e --arg c "/$case" '[.results[] | select(.path | endswith($c))] | length > 0' "$work/semgrep.json" >/dev/null; then
    echo "ok   semgrep $case"
  else
    echo "FAIL semgrep $case: match suppressed"; fail=1
  fi
done

# Coverage check: an unscanned JS file becomes a NotScanned error
mkdir -p "$work/cov/a"; echo 'x' > "$work/cov/a/seen.js"; echo 'x' > "$work/cov/a/skipped.js"
jq -n --arg s "$work/cov/a/seen.js" '{results: [], errors: [], paths: {scanned: [$s]}}' > "$work/cov.json"
"$root/scripts/semgrep-coverage.sh" "$work/cov" "$work/cov.json" >/dev/null
if jq -e --arg p "$work/cov/a/skipped.js" '[.errors[] | select(.type == "NotScanned" and .path == $p)] | length == 1' "$work/cov.json" >/dev/null \
   && jq -e '.errors | length == 1' "$work/cov.json" >/dev/null; then
  echo "ok   semgrep coverage"
else
  echo "FAIL semgrep coverage: unscanned file not reported"; fail=1
fi

# OSV: osv-scanner.toml with PackageOverrides, .gitignore above the lockfile
lock='{"name":"x","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{"name":"x","version":"1.0.0","dependencies":{"lodash":"4.17.15"}},"node_modules/lodash":{"version":"4.17.15","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz"}}}'
mkdir -p "$work/src/toml" "$work/src/gitignore"
echo "$lock" > "$work/src/toml/package-lock.json"
printf '[[PackageOverrides]]\nignore = true\nreason = "x"\n' > "$work/src/toml/osv-scanner.toml"
echo "$lock" > "$work/src/gitignore/package-lock.json"; echo 'package-lock.json' > "$work/src/gitignore/.gitignore"
for case in toml gitignore; do
  "$root/scripts/osv-scan.sh" "$osv" "$work/src/$case" "$work/osv-$case.json" >/dev/null
  if jq -e '[.results[]?.packages[]?.vulnerabilities[]?] | length > 0' "$work/osv-$case.json" >/dev/null; then
    echo "ok   osv $case"
  else
    echo "FAIL osv $case: vulnerable lodash 4.17.15 not reported"; fail=1
  fi
done
exit "$fail"
