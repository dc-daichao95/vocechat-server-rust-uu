#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CRATE_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
OUTPUT_DIR=${MLS_WASM_OUTPUT:-"$CRATE_DIR/pkg"}
if [ -n "${WASM_BINDGEN:-}" ]; then
  BINDGEN=$WASM_BINDGEN
elif command -v wasm-bindgen >/dev/null 2>&1; then
  BINDGEN=$(command -v wasm-bindgen)
else
  printf '%s\n' 'wasm-bindgen-cli is required to emit JS bindings' >&2
  exit 2
fi

cargo build --manifest-path "$CRATE_DIR/Cargo.toml" \
  --release \
  --target wasm32-unknown-unknown \
  --features wasm
mkdir -p "$OUTPUT_DIR"
"$BINDGEN" \
  --target web \
  --out-dir "$OUTPUT_DIR" \
  --out-name voce_e2ee_core \
  "$CRATE_DIR/../../target/wasm32-unknown-unknown/release/voce_e2ee_core.wasm"
