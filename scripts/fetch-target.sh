#!/usr/bin/env bash
# Fetches a plugin's scan target; untrusted content is only checked, unpacked and cloned.
# Usage: fetch-target.sh <owner/repo> <id> <store:true|false> [<public_key>]
# Writes target/, src/, sha256.txt (release only), source.txt (ref and commit) and MODE to
# $GITHUB_ENV.
#
# - The latest release's tag is resolved once; ZIP, signature and source come from exactly
#   that release.
# - Store plugins: plugin_package.zip.sig must verify against the store's public_key before
#   anything is unpacked.
# - Only a missing package (HTTP 404) falls back to scanning the source. Any other download
#   error aborts, so a network error never swaps the installed package for the source.
# - src/ is always cloned (lockfile for OSV): at the release tag, or the default branch
#   without a release, where src/ (minus node_modules and dist) is also the scan target.
# git output can contain untrusted file names: call this via no-workflow-commands.sh.
# git output can contain untrusted file names: call this via no-workflow-commands.sh.
set -euo pipefail
repo=$1 id=$2 store=$3 public_key=${4:-}
here=$(cd "$(dirname "$0")" && pwd)
latest="https://github.com/$repo/releases/latest/download/plugin_package.zip"

# Downloads $1 to $2. Output: HTTP status of the last response (000 on network error).
download() {
  local url=$1 out=$2 code attempt
  for attempt in 1 2 3; do
    code=$(curl -sL --retry 0 --max-time 120 -o "$out" -w '%{http_code}' "$url" || true)
    case "$code" in
      200|404) break ;;
    esac
    sleep $((attempt * 5))
  done
  echo "$code"
}

# Tag of the latest release: latest/download redirects to releases/download/<tag>/...
# 404 means: no release. Other responses: abort after 3 attempts.
tag=""
for attempt in 1 2 3; do
  answer=$(curl -s -o /dev/null --max-time 60 -w '%{http_code} %{redirect_url}' "$latest" || true)
  status=${answer%% *}
  case "$status" in
    302)
      location=${answer#* }
      tag=${location#"https://github.com/$repo/releases/download/"}
      tag=${tag%/plugin_package.zip}
      if ! [[ "$tag" =~ ^[A-Za-z0-9._+-]{1,128}$ ]] \
          || [ "$location" != "https://github.com/$repo/releases/download/$tag/plugin_package.zip" ]; then
        echo "ERROR: unexpected redirect for the latest release"
        exit 1
      fi
      break ;;
    404) break ;;
  esac
  if [ "$attempt" = 3 ]; then
    echo "ERROR: cannot determine the latest release (HTTP $status)"
    exit 1
  fi
  sleep $((attempt * 5))
done

mkdir -p src
mode=source
code=404
if [ -n "$tag" ]; then
  base="https://github.com/$repo/releases/download/$tag"
  code=$(download "$base/plugin_package.zip" pkg.zip)
fi
case "$code" in
  200)
    mode=release
    sha256sum pkg.zip | tee sha256.txt
    if [ "$store" = true ]; then
      sig_code=$(download "$base/plugin_package.zip.sig" pkg.zip.sig)
      if [ "$sig_code" != 200 ]; then
        echo "ERROR (integrity): cannot download plugin_package.zip.sig (HTTP $sig_code)"
        exit 1
      fi
      python3 -I "$here/prepare_package.py" verify pkg.zip pkg.zip.sig "$public_key"
      python3 -I "$here/prepare_package.py" extract pkg.zip target "$id"
    else
      echo "Repo outside the store: no signature available (unsigned-external)"
      python3 -I "$here/prepare_package.py" extract pkg.zip target
    fi
    ;;
  404)
    echo "Latest release has no plugin_package.zip: scanning the source"
    rm -f pkg.zip
    mkdir -p target
    ;;
  *)
    echo "ERROR: cannot download plugin_package.zip (HTTP $code); the source is not scanned as a substitute"
    exit 1
    ;;
esac
echo "MODE=$mode" >> "${GITHUB_ENV:-/dev/null}"
# Without a clone the lockfile is missing: incomplete scan, the job fails
if [ "$mode" = release ]; then
  "$here/clone-source.sh" "https://github.com/$repo.git" src "$tag"
  ref=$tag
else
  "$here/clone-source.sh" "https://github.com/$repo.git" src
  ref=HEAD
fi
printf 'ref %s\ncommit %s\n' "$ref" "$(git -C src rev-parse HEAD)" | tee source.txt
rm -rf src/.git
find src -type l -delete
if [ "$mode" = source ]; then
  rsync -a --exclude node_modules --exclude dist src/ target/
fi
count=$(find target -type f | wc -l)
echo "$mode: $count files"
if [ "$count" -eq 0 ]; then
  echo "ERROR: nothing to scan (neither release ZIP nor source)"
  exit 1
fi
