#!/usr/bin/env bash
# Install Minewire server binary (official GitHub release) for WSL/Linux.
set -euo pipefail

VERSION="${MINEWIRE_VERSION:-26.7.2}"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) ASSET="minewire-server-linux-amd64" ;;
  aarch64|arm64) ASSET="minewire-server-linux-arm64" ;;
  *) echo "Unsupported arch: $ARCH"; exit 1 ;;
esac

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RUNTIME_DIR="${MINEWIRE_RUNTIME_DIR:-$SCRIPT_DIR/runtime}"
BIN_DIR="${MINEWIRE_BIN_DIR:-$HOME/.local/bin}"
BASE_URL="https://github.com/dmitrymodder/minewire/releases/download/${VERSION}"

mkdir -p "$RUNTIME_DIR" "$BIN_DIR"
cd "$RUNTIME_DIR"

echo "Downloading ${ASSET} @ ${VERSION} ..."
if [[ -f "$RUNTIME_DIR/$ASSET" ]]; then
  echo "Using existing $RUNTIME_DIR/$ASSET"
else
  curl -fsSL -o "$ASSET" "${BASE_URL}/${ASSET}" || {
    echo "curl failed. On Windows host, download with PowerShell into runtime/ then re-run:"
    echo "  Invoke-WebRequest -Uri ${BASE_URL}/${ASSET} -OutFile runtime/${ASSET}"
    exit 1
  }
fi
if [[ ! -f checksums.txt ]]; then
  curl -fsSL -o checksums.txt "${BASE_URL}/checksums.txt"
fi

echo "Verifying SHA256 ..."
EXPECTED="$(grep -E "  ${ASSET}$" checksums.txt | awk '{print $1}')"
ACTUAL="$(sha256sum "$ASSET" | awk '{print $1}')"
if [[ -z "$EXPECTED" || "$EXPECTED" != "$ACTUAL" ]]; then
  echo "Checksum mismatch for $ASSET"
  echo "expected=$EXPECTED actual=$ACTUAL"
  exit 1
fi

install -m 0755 "$ASSET" "$BIN_DIR/minewire-server"
echo "Installed: $BIN_DIR/minewire-server"

if [[ ! -f "$RUNTIME_DIR/server.yaml" ]]; then
  cp "$SCRIPT_DIR/server.yaml.example" "$RUNTIME_DIR/server.yaml"
  echo "Created $RUNTIME_DIR/server.yaml — edit passwords before production use."
fi

# Optional empty icon so config path resolves (Minewire tolerates missing icon in some builds)
if [[ ! -f "$RUNTIME_DIR/server-icon.png" ]]; then
  # 1x1 PNG
  printf '\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82' \
    > "$RUNTIME_DIR/server-icon.png" || true
fi

cat <<EOF

Start (foreground):
  cd "$RUNTIME_DIR" && "$BIN_DIR/minewire-server"

Or:
  bash "$SCRIPT_DIR/start-wsl.sh"

Verify:
  bash "$SCRIPT_DIR/verify-listen.sh"
EOF
