#!/usr/bin/env bash
# Adds every JS/TS file in the target that Semgrep did not scan as an error of type
# "NotScanned" to the Semgrep output. findings.py turns these into blocking scan-error
# findings.
# Usage: semgrep-coverage.sh <target-dir> <semgrep.json>   (the file is extended in place)
set -euo pipefail
target=$1 out=$2
expected=$(mktemp) scanned=$(mktemp) missing=$(mktemp)
trap 'rm -f "$expected" "$scanned" "$missing"' EXIT
find "$target" -type f \( -name '*.js' -o -name '*.mjs' -o -name '*.cjs' -o -name '*.jsx' \
  -o -name '*.ts' -o -name '*.mts' -o -name '*.cts' -o -name '*.tsx' \) | sort > "$expected"
jq -r '.paths.scanned[]' "$out" | sort > "$scanned"
comm -23 "$expected" "$scanned" > "$missing"
if [ -s "$missing" ]; then
  echo "WARNING: $(wc -l < "$missing") JS/TS files not scanned by Semgrep"
fi
jq --rawfile m "$missing" '.errors += ($m | split("\n") | map(select(. != ""))
  | map({type: "NotScanned", level: "error", path: ., rule_id: "",
         message: "Semgrep did not scan this file"}))' "$out" > "$out.tmp"
mv "$out.tmp" "$out"
