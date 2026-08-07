#!/usr/bin/env bash
# run-sandboxed.sh — run a command confined to a workspace via macOS sandbox-exec.
#
# PROTOTYPE, standalone, not part of valet. Demonstrates OS-level containment:
# reads/writes are confined to WORKSPACE and network is denied, regardless of
# what the command tries to do internally.
#
# Usage:
#   run-sandboxed.sh <workspace-dir> <command> [args...]
#
# Examples:
#   run-sandboxed.sh ~/work ls -la .
#   run-sandboxed.sh ~/work sh -c 'cat ~/.aws/credentials'   # -> denied by kernel
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <workspace-dir> <command> [args...]" >&2
  exit 2
fi

if ! command -v sandbox-exec >/dev/null 2>&1; then
  echo "error: sandbox-exec not found (this prototype is macOS-only)." >&2
  exit 1
fi

workspace="$1"; shift
if [[ ! -d "$workspace" ]]; then
  echo "error: workspace directory does not exist: $workspace" >&2
  exit 1
fi

# Resolve to an absolute, symlink-free path — the profile matches on subpath.
workspace="$(cd "$workspace" && pwd -P)"
profile="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/workspace.sb"

exec sandbox-exec -D WORKSPACE="$workspace" -f "$profile" "$@"
