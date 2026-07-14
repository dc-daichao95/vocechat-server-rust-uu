# Minewire Ops Sidecar — Design Spec

Date: 2026-07-14  
Repo: `vocechat-server-rust-uu`  
Status: Approved (ops path A = deploy beside VoceChat; deliverable B+C)

## Goal

Provide a **reproducible ops package** so operators can run [Minewire](https://github.com/dmitrymodder/minewire) next to VoceChat for Minecraft-camouflage TCP tunneling. VoceChat process stays unchanged. Message E2E remains the content control; Minewire is transport-only.

## Non-goals

- Embedding Minewire protocol into Flutter/Web clients
- Claiming resistance to behavioral / traffic-analysis DPI (upstream disclaimer applies)
- Replacing REALITY / other obfuscation options already documented in `SECURITY_E2E_AND_OBFUSCATION.md`

## Architecture

```
[Restricted network]
        |
        | Minecraft-looking TCP :25565
        v
  Minewire Server (WSL/Linux sidecar)
        |
        | after auth: yamux + AES-GCM streams
        v
  Minewire Client (user device) → local proxy
        |
        | HTTP/WS to VoceChat
        v
  vocechat-server bind :3000
```

## Deliverables

1. `deploy/minewire/` — config example, install scripts, optional compose, README
2. `docs/MINEWIRE_TUNNEL.md` — operator guide + client usage + verification matrix
3. On this Windows host: run server under **WSL Ubuntu 22.04** (no Docker/Go; official binaries are Linux-only) and verify listen + basic status

## Verification levels

| Level | Check | This host |
|-------|--------|-----------|
| L1 | Process up, TCP listen on 25565 | Required |
| L2 | Minecraft-compatible status/handshake responds | Best-effort |
| L3 | Full tunnel: Minewire client → VoceChat API | Document only if no official client binary in releases |

## Security notes

- Passwords in `server.yaml` are secrets; example file uses placeholders; runtime config outside git or gitignored
- Do not commit real passwords
- Upstream: educational / hobby; not a sole high-risk circumvention layer
