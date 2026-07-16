#!/bin/bash
# Stage a Linux glibc release binary for Dockerfile.prebuilt (debian runtime).
set -euo pipefail
export HOME="${HOME:-/home/dc}"
export PATH="$HOME/.cargo/bin:/usr/bin:/bin"
export RUSTUP_DIST_SERVER="${RUSTUP_DIST_SERVER:-https://rsproxy.cn}"
export RUSTUP_UPDATE_ROOT="${RUSTUP_UPDATE_ROOT:-https://rsproxy.cn/rustup}"
cd /mnt/c/Users/Administrator/repo/vocechat/vocechat-server-rust-uu

rustup default stable

mkdir -p "$HOME/.cargo"
cat > "$HOME/.cargo/config.toml" <<'EOF'
[source.crates-io]
replace-with = "rsproxy-sparse"
[source.rsproxy-sparse]
registry = "sparse+https://rsproxy.cn/index/"
[net]
git-fetch-with-cli = true
EOF

cargo build --release
BIN="target/release/vocechat-server"
ls -la "$BIN"
file "$BIN" || true
mkdir -p build/docker/dist
cp -f "$BIN" build/docker/dist/vocechat-server
chmod +x build/docker/dist/vocechat-server
echo "STAGED=build/docker/dist/vocechat-server"
