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
