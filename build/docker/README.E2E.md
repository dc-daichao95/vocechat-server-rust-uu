# Docker / Linux deploy (E2E-ready)

## What this gives you

- **Linux amd64** `vocechat-server` binary built inside Docker (`Dockerfile.linux`)
- **nginx** reverse proxy for HTTP (optional TLS via mounted certs)
- Application **E2E** is in Server API + clients; nginx does **not** decrypt messages
- **Network obfuscation** (REALITY etc.) stays **outside** this stack — optional pack:
  - [`deploy/sing-box-reality/`](../../deploy/sing-box-reality/)
  - overlay: `docker compose -f build/docker/docker-compose.e2e.yml -f build/docker/docker-compose.reality.yml up -d`

## Base image (`vocechat-server-base`)

Shared runtime image for overlays such as `vocechat-server-e2ee`:

```bash
docker compose -f build/vocechat-server-base-compose.yml build
# → vocechat-server-base:latest
# Dockerfile: build/docker/Dockerfile.base
```

E2EE (or other) Dockerfiles should start with `FROM vocechat-server-base:latest`.

## Quick start

```bash
cd vocechat-server-rust-uu
docker compose -f build/docker/docker-compose.e2e.yml up -d --build
```

Open `http://localhost` (or set `HTTP_PORT` / `DOMAIN`).

Data volume: Docker volume `vocechat-data`.

## Without Docker (WSL / Linux host)

```bash
bash build/docker/build-linux-wsl.sh
# stages → build/docker/dist/vocechat-server
```

Requires WSL packages: `build-essential` (needs `sudo apt install build-essential` once).

Then with Docker Engine:

```bash
docker build -f build/docker/Dockerfile.prebuilt -t vocechat-server:latest .
# or full in-docker build (no host rustc needed):
docker compose -f build/docker/docker-compose.e2e.yml up -d --build
```

> This Windows host currently has **no Docker CLI** and WSL lacks `gcc` / passwordless `sudo`, so the Linux binary cannot be compiled here until those are installed. Dockerfiles were updated to **Debian bookworm-slim** (glibc) so a normal `cargo build --release` binary works.

## E2E note

Enable DM E2E in Web DM settings or channel E2E in channel settings. Clients must publish identity keys (`/api/user/e2e/identity`).

## Bot E2EE (server-managed key vault)

Human-to-human E2EE is strict: the server never sees plaintext or private
keys. A **Bot** has no client of its own, so it is the one documented
exception — the server generates and holds a Bot's E2EE key material on
its behalf, and can therefore encrypt a Bot's outbound DMs and decrypt DMs
addressed to that Bot (forwarding plaintext only to that Bot's own
webhook; every other webhook still only ever sees `e2e_opaque`).

That private key material is always AES-256-GCM encrypted at rest with an
operator-supplied master key, and the server **fails closed** (refuses to
initialize/rotate/rebuild/decrypt) if the key is missing or malformed —
there is no plaintext fallback.

### Required secret

Mount a file containing a base64-encoded, exactly-32-byte AES-256 key and
point `VOCECHAT_BOT_E2EE_MASTER_KEY_FILE` at it, e.g. with a Docker
secret:

```yaml
services:
  vocechat-server:
    environment:
      - VOCECHAT_BOT_E2EE_MASTER_KEY_FILE=/run/secrets/bot_e2ee_master_key
    secrets:
      - bot_e2ee_master_key

secrets:
  bot_e2ee_master_key:
    file: ./secrets/bot_e2ee_master_key.b64
```

Generate a key locally with, e.g.:

```bash
openssl rand -base64 32 > secrets/bot_e2ee_master_key.b64
```

The key is read fresh from disk on every vault operation (never cached
in-process), so it can be rotated by replacing the file's contents
without a restart. It is never logged.

### Admin API (server-side contract; Task 8 wires the settings UI)

All endpoints require an admin token and operate on a Bot user's `uid`:

- `POST /api/admin/user/bot-e2ee/:uid/initialize` — generate and encrypt
  this Bot's identity/signed prekey/one-time prekeys/MLS credential seed;
  publishes the public bundle so humans can message the Bot.
- `GET /api/admin/user/bot-e2ee/:uid/status` — initialized?, key
  version, whether the master key is currently available, enabled
  channels. Never returns secret material.
- `POST /api/admin/user/bot-e2ee/:uid/rotate` — regenerate the signed
  prekey + one-time prekeys (key version += 1); identity unchanged.
- `POST /api/admin/user/bot-e2ee/:uid/rebuild` `{"confirm": true}` —
  **destructive**: regenerates the full identity. Omitting/false
  `confirm` returns `400` with a bilingual confirmation-required message.
- `PUT /api/admin/user/bot-e2ee/:uid/channel/:gid` `{"enabled": true}` —
  enable/disable this Bot's MLS admission (credential + one key package)
  for a channel.

Error responses are JSON: `{"code", "message_en", "message_zh"}` (every
new admin message this task adds is bilingual).
