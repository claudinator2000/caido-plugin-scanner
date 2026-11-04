#!/usr/bin/env bash
# Downloads the pinned OSV-Scanner binary and verifies its SHA-256.
# Usage: install-osv-scanner.sh <target-path>
set -euo pipefail
version=2.7.0
sha256=160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b
dest=$1
curl -sfL -o "$dest" \
  "https://github.com/google/osv-scanner/releases/download/v$version/osv-scanner_linux_amd64"
echo "$sha256  $dest" | sha256sum -c -
chmod +x "$dest"
