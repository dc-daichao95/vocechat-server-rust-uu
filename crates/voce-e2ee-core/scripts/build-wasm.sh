#!/usr/bin/env bash
# Build voce-e2ee-core for the browser (cargo + wasm-bindgen).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
CRATE="$(cd "$(dirname "$0")/.." && pwd)"
PKG="$CRATE/pkg"

rustup target add wasm32-unknown-unknown >/dev/null
command -v wasm-bindgen >/dev/null || cargo install wasm-bindgen-cli --locked

cd "$ROOT"
cargo build -p voce-e2ee-core --target wasm32-unknown-unknown --features wasm --release
mkdir -p "$PKG"
wasm-bindgen "$ROOT/target/wasm32-unknown-unknown/release/voce_e2ee_core.wasm" \
  --out-dir "$PKG" --target web --typescript
echo "WASM package written to $PKG"
ls -la "$PKG"
