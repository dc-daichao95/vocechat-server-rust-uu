# sing-box REALITY edge for VoceChat

Ops-only: TLS fingerprint camouflage in front of VoceChat. Does **not** modify
`vocechat-server`. Complements Minewire (`../minewire/`) and application E2E.

Upstream: [sing-box](https://github.com/SagerNet/sing-box) REALITY inbound.

## Architecture

```
Client (sing-box REALITY outbound)
        |
        | TCP 443 — looks like TLS to dest (e.g. www.microsoft.com)
        v
sing-box REALITY inbound  -->  vocechat-server :3000  (HTTP, internal)
```

## Quick start (Docker)

```bash
cd deploy/sing-box-reality
cp config.json.example config.json
# edit: uuid, short_ids, server_names, dest, private_key / public_key
# standalone: set outbound server to host.docker.internal (or host IP)
# with e2e compose network: keep outbound server = "vocechat"
docker compose up -d
```

Generate REALITY keypair:

```bash
docker run --rm ghcr.io/sagernet/sing-box:1.10.7 generate reality-keypair
```

Generate UUID:

```bash
docker run --rm ghcr.io/sagernet/sing-box:1.10.7 generate uuid
```

Point VoceChat clients at the REALITY host (or at a local sing-box mixed-inbound
port if you run the client outbound on-device). Server URL is still your normal
HTTP API path after the tunnel (e.g. `https://chat.example.com` terminated on
sing-box, or `http://127.0.0.1:7890` via local mixed inbound).

## Stack with E2E compose

See `../../build/docker/docker-compose.reality.yml` — optional profile that puts
sing-box in front of the e2e nginx/vocechat network.

## Limits (must document to operators)

- Does **not** hide that you run a service; reduces SNI / TLS fingerprint blocking.
- Does **not** replace E2E content encryption.
- Does **not** claim defeat of behavioral DPI (same class of disclaimer as Minewire).
- Replace all placeholders before production; never commit real keys.
