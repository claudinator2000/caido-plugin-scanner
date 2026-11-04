#!/usr/bin/env bash
# Runs a command while GitHub workflow commands in the log are switched off.
# Usage: no-workflow-commands.sh <command> [arguments...]
#
# Commands that process plugin content write untrusted data to the log (file names,
# code excerpts). GitHub would otherwise execute a line starting with "::" as a workflow
# command (e.g. ::add-mask::, annotations). stdout and stderr therefore run between
# ::stop-commands::<token> and ::<token>::; the token is random and does not appear in the
# untrusted content. The command's exit code is preserved.
set -uo pipefail
token=$(openssl rand -hex 16)
echo "::stop-commands::$token"
"$@" 2>&1
rc=$?
echo "::$token::"
exit "$rc"
