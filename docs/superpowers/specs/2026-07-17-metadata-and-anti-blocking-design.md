# Metadata hardening + anti-blocking edge — Design

Date: 2026-07-17  
Status: **Approved for implementation** (user: 先元数据应用层，再 REALITY/sing-box 部署包)  
Repos: `vocechat-server-rust-uu`, `vocechat-web-uu`, `vocechat-client-uu`

## Goals

1. **Metadata (application layer)** — reduce what a curious Server / passive observer learns from ciphertext *length* and from message `properties` on E2E traffic.
2. **Anti-blocking (deployment)** — ship a **REALITY / sing-box** edge template beside Minewire; VoceChat process stays plain HTTP(S) behind it.

## Non-goals

- Hide social graph (`from_uid` / `to` still visible to Server).
- Behavioral traffic analysis resistance (cover traffic / constant-rate).
- In-process REALITY / SNI forge inside `vocechat-server` (existing red line).
- Claiming Minewire/REALITY defeat advanced DPI (document upstream limits).

## Part A — Application metadata

### A1. Ciphertext length bucketing (padding)

Before encrypt (v1 and v2 plaintext):

1. Encode body as UTF-8.
2. Wrap: `{"m":"<mime>","c":"<text>"}` JSON (moves `inner_content_type` off wire properties).
3. Prefix with `u32 BE` plaintext length, append random pad to next bucket:

Buckets (bytes, inclusive of length prefix + JSON + pad):  
`64, 128, 256, 512, 1024, 2048, 4096, 8192, …` (double until fit; max 256 KiB).

4. Encrypt padded blob as today.

Decrypt: AES/DR open → read `u32` len → slice → parse JSON `{m,c}`.

Shared logic preferred in `voce-e2ee-core` (`pad_v1` / `unpad_v1` FFI) so Web WASM + Flutter FFI stay aligned; Web/Flutter may mirror in TS/Dart if FFI call cost is awkward for hot path — **must match wire**.

### A2. Properties minimization

**On the wire** for new E2E messages, allow only:

| Key | Why |
|-----|-----|
| `e2e` | feature flag |
| `e2e_ver` | protocol gate |
| `sender_device_id` | multi-device / fanout decrypt (already inside envelope too; keep for SSE clients that read props) |
| `local_id` / `cid` | client correlation (already used); do not add `peer_device_ids`, `inner_content_type`, debug fields |

Strip / stop emitting: `peer_device_ids`, `inner_content_type`, `e2e_sk_dist` labels where redundant (sk_dist still needs a marker — keep `e2e_sk_dist: true` only on sk_dist messages).

### Success criteria (A)

- Same plaintext lengths that previously produced distinct ciphertext sizes collapse into ≤ bucket count distinct sizes for short messages.
- Server-visible properties for a normal DM text no longer include MIME or peer device list.

## Part B — Anti-blocking deploy pack

### Layout

```
deploy/sing-box-reality/
  README.md
  docker-compose.yml          # sing-box REALITY edge → vocechat:3000
  config.json.example         # placeholders: uuid, short_id, server_names, dest
  client.json.example         # client outbound REALITY
  integrate-with-e2e.md       # how to stack with build/docker/docker-compose.e2e.yml
```

Optional compose profile or override file under `build/docker/`:

- `docker-compose.reality.yml` extends e2e stack: expose only sing-box ports; vocechat+nginx stay internal.

### Client integration (light)

- Docs only this slice: point Web/Flutter “server URL” at tunnel local port / public REALITY host.
- No in-app REALITY stack.

### Success criteria (B)

- Operator can `docker compose -f …` bring up REALITY edge with documented placeholders.
- SECURITY + MINEWIRE docs link to the new pack; state clearly: edge obfuscation ≠ E2E.

## Delivery order

1. Spec (this file)
2. Core pad/unpad + wire clients
3. Properties minify on send paths
4. `deploy/sing-box-reality` + compose glue + doc links
5. Commit
