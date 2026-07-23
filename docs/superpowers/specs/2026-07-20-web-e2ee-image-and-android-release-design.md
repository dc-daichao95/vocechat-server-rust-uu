# Web E2EE Image and Android Release Design

Date: 2026-07-20  
Status: Approved and implemented

## Scope

Work is performed on `dcjjj@dcjjj888.duckdns.org:61307` under:

`/home/dcjjj/workspace/true_workspace/vocechat/gitwork`

Deliverables:

1. Build `vocechat-server-web-e2ee:latest` from the existing
   `vocechat-server-base:latest`.
2. Provide `vocechat-server-e2ee-compose.yml`, derived from the existing
   `compose.yml`; do not start the deployment.
3. Build a signed Android Release APK from the latest client source using the
   existing remote release keystore.

## Image Architecture

`build/Dockerfile.web-e2ee` uses four stages:

1. `wasm-builder` starts from `vocechat-server-base:latest`, builds the current
   `voce-e2ee-core` for `wasm32-unknown-unknown`, and emits Web bindings with
   the `wasm-bindgen-cli` version pinned by `Cargo.lock`.
2. `web-builder` starts from `vocechat-server-base:latest`, copies only
   `vocechat-web-uu`, installs locked pnpm dependencies, builds release assets,
   consumes the generated WASM bindings, and verifies `index.html`, the E2EE
   WASM core, and an asset-version hash.
3. `server-builder` starts from `vocechat-server-base:latest`, copies only
   `vocechat-server-rust-uu`, runs `cargo build --locked --release`, and verifies
   the server executable.
4. `runtime` starts from `debian:bookworm-slim`, receives CA certificates from
   the builder image, then
   copies the server binary, server configuration, entrypoint, and Web/E2EE
   assets from the builder stages.

The final image does not contain Rust, Cargo, Node, pnpm, source trees, Git
metadata, signing keys, or Android tooling.

## Runtime Layout

- Server binary: `/home/vocechat-server/vocechat-server`
- Server config: `/home/vocechat-server/config`
- Web seed: `/opt/vocechat/web-seed`
- Entrypoint: `/docker-entrypoint.sh`
- Data volume: `/home/vocechat-server/data`
- Port: `3000`
- `VOCECHAT_REQUIRE_WEB_SEED=1`

The entrypoint seeds Web assets into the persistent data directory without
overwriting newer identical assets.

## Compose

The new root-level `vocechat-server-e2ee-compose.yml` preserves the operational
settings from `compose.yml`:

- Server image: `vocechat-server-web-e2ee:latest`
- Build context: the `gitwork` root
- Dockerfile: `build/Dockerfile.web-e2ee`
- Existing data and certificate mounts
- Existing nginx service
- Ports `9443:443` and `9090:80`
- Existing frontend URL and bridge network

The compose file is validated with `docker compose config -q` but is not
started.

## Android Release APK

The Android build runs in the pinned
`ghcr.io/cirruslabs/flutter:3.19.6` container because the remote host has no
Flutter, Java, or Android SDK installed. The client checkout is mounted
read-write only for generated build output; the keystore and password files are
mounted read-only.

- Flutter: `3.19.6`
- JDK: `17`
- Android platform/build tools: API 34
- Command:
  `flutter build apk --release --target-platform android-arm64,android-x64`
- Signing: existing remote `android-release.jks`; passwords are passed through
  environment variables and never printed or copied into source control.
- Output:
  `build/artifacts/vocechat-client-release.apk`
- Integrity:
  `build/artifacts/vocechat-client-release.apk.sha256`

The build must verify that the APK is non-empty and signed before reporting
success.

## Error Handling and Verification

- All builds use locked dependency files.
- Required Web/WASM/server/APK artifacts are checked explicitly.
- Docker image inspection confirms the expected entrypoint and working
  directory.
- The runtime image is not launched.
- Existing uncommitted files in the three remote repositories are preserved.
- No signing secret is logged, embedded in images, or added to Git.
