#!/usr/bin/env bash
# Start Minewire server from deploy/minewire/runtime.
# Usage:
#   bash start-wsl.sh           # foreground
#   bash start-wsl.sh --bg      # background (nohup)
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RUNTIME_DIR="${MINEWIRE_RUNTIME_DIR:-$SCRIPT_DIR/runtime}"
BIN="${MINEWIRE_BIN_DIR:-$HOME/.local/bin}/minewire-server"
BG=0
if [[ "${1:-}" == "--bg" || "${1:-}" == "-d" ]]; then
  BG=1
fi

if [[ ! -x "$BIN" ]]; then
  echo "Missing $BIN — run install-wsl.sh first (or copy binary into ~/.local/bin)"
  exit 1
fi
if [[ ! -f "$RUNTIME_DIR/server.yaml" ]]; then
  echo "Missing $RUNTIME_DIR/server.yaml"
  exit 1
fi

if pgrep -f '[m]inewire-server' >/dev/null 2>&1; then
  echo "Minewire already running:"
  pgrep -a minewire || true
  exit 0
fi

cd "$RUNTIME_DIR"
if [[ "$BG" -eq 1 ]]; then
  nohup "$BIN" >/tmp/minewire.log 2>&1 &
  disown || true
  sleep 1
  if pgrep -f '[m]inewire-server' >/dev/null 2>&1; then
    echo "Started in background. log=/tmp/minewire.log"
    pgrep -a minewire || true
    exit 0
  fi
  echo "Failed to start; see /tmp/minewire.log"
  cat /tmp/minewire.log 2>/dev/null || true
  exit 1
fi

exec "$BIN"
