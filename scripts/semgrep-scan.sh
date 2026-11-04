#!/usr/bin/env bash
# Semgrep with this repo's rules on untrusted code.
# Usage: semgrep-scan.sh <target-dir> <output.json>   (SEMGREP_VERSION must be set)
#
# Nothing in the target may hide code: nosemgrep comments, .gitignore and .semgrepignore
# are ignored, and the empty .semgrepignore at the project root also disables Semgrep's
# default exclusions (*.min.js, tests/, vendor/, ...). --timeout-threshold 0 keeps Semgrep
# from silently skipping rules after a timeout (largest store bundle: 58 s for all rules).
# Exit 0 even with findings and timeouts; findings.py evaluates both.
set -euo pipefail
target=$1 out=$2
here="$(cd "$(dirname "$0")" && pwd)"
find "$target" -name .semgrepignore -type f -delete
: > "$target/.semgrepignore"
uvx "semgrep==${SEMGREP_VERSION:?}" scan --metrics=off --timeout "${SEMGREP_RULE_TIMEOUT:-120}" \
  --timeout-threshold 0 --max-target-bytes 0 \
  --disable-nosem --no-git-ignore --project-root "$target" \
  --config "$here/../rules" "$target" --json > "$out"
rm "$target/.semgrepignore"
python3 -I "$here/semgrep_fallback.py" "$target" "$out"
"$here/semgrep-coverage.sh" "$target" "$out"
