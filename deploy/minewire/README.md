# Minewire deploy package (VoceChat sidecar)

Ops-only integration of [Minewire](https://github.com/dmitrymodder/minewire): Minecraft-camouflage encrypted TCP tunnel **beside** VoceChat. Does not modify `vocechat-server` code.

Full operator guide: [`../../docs/MINEWIRE_TUNNEL.md`](../../docs/MINEWIRE_TUNNEL.md)  
Design: [`../../docs/superpowers/specs/2026-07-14-minewire-ops-sidecar-design.md`](../../docs/superpowers/specs/2026-07-14-minewire-ops-sidecar-design.md)

## Contents

| File | Purpose |
|------|---------|
| `server.yaml.example` | Config template (replace passwords) |
| `install-wsl.sh` | Download official linux binary + checksum, install under WSL/Linux |
| `docker-compose.yml` | Optional Linux+Docker path (not used on this Windows host) |
| `verify-listen.sh` | L1 listen check |
| `runtime/` | Local secrets (gitignored) |

## Quick start (WSL / Linux)

```bash
cd deploy/minewire
cp server.yaml.example runtime/server.yaml
# edit passwords in runtime/server.yaml
bash install-wsl.sh
bash verify-listen.sh
```

Pinned release: **26.7.2** (override with `MINEWIRE_VERSION=...`).
