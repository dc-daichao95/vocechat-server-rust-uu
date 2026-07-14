#!/usr/bin/env bash
# Start Minewire server from deploy/minewire/runtime (foreground).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RUNTIME_DIR="${MINEWIRE_RUNTIME_DIR:-$SCRIPT_DIR/runtime}"
BIN="${MINEWIRE_BIN_DIR:-$HOME/.local/bin}/minewire-server"

if [[ ! -x "$BIN" ]]; then
  echo "Missing $BIN — run install-wsl.sh first"
  exit 1
fi
if [[ ! -f "$RUNTIME_DIR/server.yaml" ]]; then
  echo "Missing $RUNTIME_DIR/server.yaml"
  exit 1
fi

cd "$RUNTIME_DIR"
exec "$BIN"
