# Full E2E + Linux Docker + Windows Client

**Goal:** Complete E2E for DM + channel + files (Web + Flutter Windows DM/channel text); ship Linux server via Docker Compose; ship Windows client release. Voice/Agora frozen. Bot external runner deferred (API already accepts envelopes).

**Out of scope this slice:** Full Signal Double Ratchet, Bot runner container, REALITY in-process.

## Architecture (e2e_ver=1 extended)

| Mode | Envelope | Notes |
| --- | --- | --- |
| DM text | existing `P-256+AES-GCM` | unchanged |
| Channel text | `SK+AES-GCM` + one-time `sk_dist` wraps | Shared AES key per `gid:skid`; wrap to each member via ECDH |
| Files | encrypt bytes → upload opaque → `vocechat/e2e` with `inner_content_type=vocechat/file` | Plaintext upload path unchanged when E2E off |

## Tasks

1. Web channel sender keys (`crypto.ts`, `useSendMessage`, `E2eText`)
2. Web file E2E (upload + message)
3. Flutter `e2e` package + DM/channel send/receive hooks
4. Multi-stage Linux Docker + compose (+ optional nginx)
5. `flutter build windows --release`
6. Update SECURITY / E2E design status

## Verify

- Web: DM + channel text encrypt/decrypt; file when E2E on
- `docker compose build` produces Linux image
- Windows `vocechat_client.exe` exists


## Status 2026-07-14
- Web DM/channel/file: done (DM self-decrypt bug fixed)
- Flutter DM/channel receive decrypt + file send: done
- Windows release: rebuilt
- Docker: musl-only Dockerfile + WSL stage script; host may lack Docker Engine

