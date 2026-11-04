#!/usr/bin/env bash
# Plugin list for a single scan (workflow_dispatch input "repo").
# Usage: adhoc-plugin.sh <input> <output.json>
# Accepts maintainer/repo, a GitHub URL or "name maintainer/repo" (extra-repos.txt format).
# The id gets the prefix "adhoc-" so it never collides with a store plugin or a baseline.
set -euo pipefail
input=$1 out=$2
fail() {
  echo "ERROR: invalid input for repo. Expected maintainer/repo, e.g. 53cur3M3/caido-jwt-attacker"
  exit 1
}
[ "${#input}" -le 300 ] || fail
# Strip surrounding whitespace; "name maintainer/repo": only the last part
repo=$(printf '%s' "$input" | tr '\t' ' ' | sed -e 's/^ *//' -e 's/ *$//')
case "$repo" in *$'\n'*) fail ;; esac
repo=${repo##* }
repo=${repo#https://github.com/}
repo=${repo%/}
repo=${repo%.git}
if ! [[ "$repo" =~ ^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$ ]] || [ "${#repo}" -gt 140 ]; then
  fail
fi
name=${repo#*/}
if [ "$name" = "." ] || [ "$name" = ".." ] || [ -z "$name" ]; then
  fail
fi
jq -n -c --arg id "adhoc-$name" --arg repo "$repo" \
  '[{id: $id, repo: $repo, store: false, public_key: ""}]' > "$out"
echo "Single scan: $repo (id adhoc-$name)"
