#!/usr/bin/env bash
# L1: confirm Minewire is listening on TCP port (default 25565).
set -euo pipefail
PORT="${MINEWIRE_PORT:-25565}"
HOST="${MINEWIRE_HOST:-127.0.0.1}"

if command -v ss >/dev/null 2>&1; then
  if ss -lntp 2>/dev/null | grep -E ":${PORT}\\b" >/dev/null; then
    echo "PASS: port ${PORT} is listening (ss)"
    ss -lntp 2>/dev/null | grep -E ":${PORT}\\b" || true
    exit 0
  fi
fi

if timeout 2 bash -c "echo >/dev/tcp/${HOST}/${PORT}" 2>/dev/null; then
  echo "PASS: TCP connect to ${HOST}:${PORT} succeeded"
  exit 0
fi

# WSL sometimes lacks /dev/tcp timeout; try python
if python3 - <<PY 2>/dev/null
import socket
s=socket.socket(); s.settimeout(2)
s.connect(("${HOST}", int("${PORT}")))
s.close(); print("PASS: TCP connect via python to ${HOST}:${PORT}")
PY
then
  exit 0
fi

echo "FAIL: nothing listening on ${HOST}:${PORT}"
exit 1
