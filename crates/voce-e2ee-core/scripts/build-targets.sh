#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CRATE_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
WORKSPACE_DIR=$(CDPATH= cd -- "$CRATE_DIR/../.." && pwd)
REPORT_PATH=${MLS_TARGET_REPORT:-"$CRATE_DIR/target-report.json"}
TOOLCHAIN=${RUST_TOOLCHAIN:-1.95.0}

cd "$WORKSPACE_DIR"

check_target() {
  target=$1
  features=${2:-}
  if [ -n "$features" ]; then
    cargo "+$TOOLCHAIN" check -p voce-e2ee-core --target "$target" --features "$features"
  else
    cargo "+$TOOLCHAIN" check -p voce-e2ee-core --target "$target"
  fi
}

check_target wasm32-unknown-unknown wasm
check_target x86_64-pc-windows-gnu
check_target aarch64-linux-android
check_target x86_64-linux-android
check_target aarch64-apple-ios
check_target aarch64-apple-ios-sim

rustc_version=$(rustc "+$TOOLCHAIN" --version)
generated_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
printf '%s\n' \
  '{' \
  "  \"generated_at\": \"$generated_at\"," \
  "  \"rustc\": \"$rustc_version\"," \
  '  "ciphersuite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",' \
  '  "targets": {' \
  '    "wasm32-unknown-unknown": "pass",' \
  '    "x86_64-pc-windows-gnu": "pass",' \
  '    "aarch64-linux-android": "pass",' \
  '    "x86_64-linux-android": "pass",' \
  '    "aarch64-apple-ios": "pass",' \
  '    "aarch64-apple-ios-sim": "pass"' \
  '  }' \
  '}' >"$REPORT_PATH"

printf 'target report: %s\n' "$REPORT_PATH"
