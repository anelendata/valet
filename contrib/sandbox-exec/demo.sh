#!/usr/bin/env bash
# demo.sh — show the OS sandbox allowing workspace access and denying escapes.
#
# Creates a throwaway workspace, then runs a handful of commands through
# run-sandboxed.sh. Inside the workspace succeeds; reading the home directory,
# reading ~/.aws, and writing outside all fail at the kernel. Network is allowed
# by default (cloud tools need it).
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
run="$here/run-sandboxed.sh"

ws="$(mktemp -d)"
trap 'rm -rf "$ws"' EXIT
echo "hello from inside the workspace" > "$ws/inside.txt"

run_case() {
  local desc="$1"; shift
  echo
  echo "### $desc"
  echo "\$ $*"
  if "$run" "$ws" "$@"; then
    echo "[exit 0]"
  else
    echo "[exit $? — blocked/failed]"
  fi
}

echo "workspace: $ws"

run_case "read a file inside the workspace (expect OK)" \
  cat inside.txt

run_case "write a new file inside the workspace (expect OK)" \
  sh -c 'echo written > created.txt && echo ok'

run_case "list the home directory (expect DENIED)" \
  sh -c 'ls -la "$HOME"'

run_case "read AWS credentials (expect DENIED)" \
  sh -c 'cat "$HOME/.aws/credentials"'

run_case "write into the home directory (expect DENIED)" \
  sh -c 'echo escapee > "$HOME/valet-escapee-demo.txt" && echo wrote'

# Network is allowed by default (cloud tools need it). Uncomment the
# (deny network*) line in workspace.sb to block it, then this would fail.
run_case "reach the network (expect ALLOWED by default)" \
  sh -c 'curl -sS --max-time 5 https://example.com >/dev/null && echo fetched'

echo
echo "Done. Inside the workspace worked; file-system escapes were blocked by the"
echo "kernel, not by command-line analysis. (Network is allowed by default.)"
