#!/usr/bin/env bash
# Clones a plugin's source shallow into <dir>.
# Usage: clone-source.sh <url> <dir> [<tag>]
# With <tag>: fetch exactly refs/tags/<tag> and check out its commit. `clone --branch`
# picks the branch when a branch and a tag share the name; OSV would then check a different
# lockfile than the release's.
# Without <tag>: the remote's default branch.
#
# The repo is untrusted. For all git calls:
# - Git LFS downloads nothing: LFS files stay pointers (no downloads of arbitrary size
#   from untrusted servers), regardless of whether LFS is set up on the runner;
# - HTTPS is the only transport (GIT_ALLOW_PROTOCOL; the tests set file for local repos),
#   no submodules;
# - received objects are checked (fsckObjects); broken ones abort the clone;
# - symlinks are checked out as files containing the target path, never as links.
set -euo pipefail
url=$1 dir=$2 tag=${3:-}
export GIT_LFS_SKIP_SMUDGE=1 GIT_TERMINAL_PROMPT=0 GIT_ALLOW_PROTOCOL="${GIT_ALLOW_PROTOCOL:-https}"
safe_git() {
  git -c filter.lfs.smudge= -c filter.lfs.process= -c filter.lfs.required=false \
      -c submodule.recurse=false \
      -c transfer.fsckObjects=true -c fetch.fsckObjects=true \
      -c core.symlinks=false -c advice.detachedHead=false "$@"
}
if [ -z "$tag" ]; then
  safe_git clone -q --depth 1 --no-recurse-submodules "$url" "$dir"
  exit 0
fi
if ! [[ "$tag" =~ ^[A-Za-z0-9._+-]{1,128}$ ]]; then
  echo "ERROR: invalid tag name"
  exit 1
fi
git init -q "$dir"
safe_git -C "$dir" fetch -q --depth 1 --no-tags --no-recurse-submodules "$url" "+refs/tags/$tag:refs/tags/$tag"
safe_git -C "$dir" checkout -q --detach "refs/tags/$tag^{commit}"
