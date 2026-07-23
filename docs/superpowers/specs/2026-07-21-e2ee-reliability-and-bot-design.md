# E2EE Reliability, Deferred Delivery, and Server-Managed Bot Design

Date: 2026-07-21  
Status: Approved for implementation

## Scope

This design covers:

1. DM delivery when the recipient has no E2EE device key.
2. Channel MLS initialization, catch-up, and send reliability.
3. Consistent sender-local message state and no-key placeholders in Web and
   Flutter.
4. Server-managed Bot encryption for DM and Channel.
5. Complete Chinese and English settings and operation feedback.
6. Password hashing migration to Argon2id with legacy double-MD5 compatibility
   (clients still send plaintext; no forced password-reset campaign).

## Security Invariants

- Human-to-human DM and channels without a Server-managed Bot remain strict
  E2EE against Server.
- There is no plaintext fallback when a recipient lacks a key or MLS is not
  ready.
- Server and generic webhooks store or receive ciphertext plus metadata only.
- A device without a matching key renders an encrypted placeholder, never
  plaintext.
- The sender may keep a local plaintext outbox copy for its own UI.
- Server-managed Bot conversations are a documented exception: Server can
  decrypt Bot DM and every MLS channel in which such a Bot participates.
- Bot private material is encrypted at rest with an operator-supplied master
  key; the master key is never stored in SQLite or returned by an API.

## 1. Deferred DM Envelope

### Wire format

Add E2EE v2 application algorithm `DEFERRED+AES-GCM`:

- A random 256-bit content-encryption key encrypts the application body once.
- The wire object contains ciphertext, nonce, content hash, sender device ID,
  local ID, and zero or more per-device key envelopes.
- At initial send, the sender wraps the content key to all available sender
  devices. If recipient devices exist, their envelopes are included too.
- If no recipient device exists, the message is valid but marked pending.

The Server never receives an unwrapped content key.

### Server persistence

Add:

- `e2e_pending_message(mid, sender_uid, target_uid, completed_at, created_at)`
- `e2e_pending_envelope(mid, recipient_uid, device_id, envelope, created_at)`

The normal message record stores opaque content using the existing
`application/vnd.vocechat.e2ee.v2` content type and `protocol=dr-pending`.

### API and events

- Existing send API accepts `dr-pending` for DM only and returns canonical mid.
- New authenticated endpoint appends recipient-device envelopes to a pending
  message.
- Only the original sender and its linked devices may append envelopes.
- Envelope recipient UID must equal the original DM target and device ID must
  exist in `e2e_identity`.
- Publishing a new identity emits an authenticated SSE identity-change event.
- Online sender devices consume that event, find pending messages for the UID,
  unwrap their sender envelope, and append recipient envelopes.
- Completion means at least one current recipient device has an envelope.
  Future devices may receive additional envelopes later.

If no sender device returns online, the message remains ciphertext and the
recipient continues to see the pending encrypted placeholder.

## 2. Unified Message Outbox and Rendering

Web and Flutter use the same logical states:

- `encrypting`
- `sent_waiting_key`
- `sending`
- `sent`
- `failed`

Before crypto or network work starts, clients create a local outbox row keyed by
`local_id`. The row stores sender-local plaintext and E2EE metadata.

- Canonical mid acknowledgment updates the same row.
- Pending-envelope acknowledgment sets `sent_waiting_key`.
- Envelope completion sets `sent`.
- Failures retain the bubble and input content with retry/copy actions.
- MLS and DM no longer depend on SSE before showing the sender's own message.

Rendering:

- Sender device: local plaintext plus lock and state badge.
- Recipient with envelope/key: decrypted plaintext plus lock.
- Recipient without key: encrypted placeholder.
- Generic webhook and notification: opaque/encrypted placeholder.

## 3. Channel MLS Reliability

### Authorization

`mls_delivery::authorize_group` must use the same authorization semantics as
normal channel send:

- owner is allowed;
- explicit member is allowed;
- authenticated users are allowed for a public channel.

This removes the current public-channel route 403 while retaining private
channel membership enforcement.

### Background bootstrap and record processing

- Bootstrap MLS device credential and key packages after authenticated app
  initialization, not on first send.
- Move Welcome/Commit/Application processing from `ChannelChat` into a
  background MLS synchronizer.
- Persist `(uid, device_id, gid, last_processed_mid, epoch, generation)`.
- Opening a channel only reads synchronized state; it is not responsible for
  advancing cryptographic state.
- A malformed record is quarantined and reported; it does not permanently
  block later records.

### Admission and recovery

Add `mls_admission_request(gid, uid, device_id, created_at, fulfilled_at)`.

- A device with no Welcome creates an admission request rather than entering a
  permanent error state.
- Existing online members receive the request and run `admit`.
- A Server-managed Bot that belongs to the channel may fulfill requests.
- On `E2E_MLS_SEQUENCE_CONFLICT`, the client fetches and processes missing
  records, then retries the application once.
- A second conflict remains failed with a visible diagnostic and retry action.

Members without MLS keys are skipped from the current epoch. They see encrypted
placeholders for earlier applications and join only after publishing a device
key and receiving a Welcome, preserving MLS forward-secrecy semantics.

## 4. Server-Managed Bot Encryption

### Key storage

Add a Bot E2EE device per Bot UID:

- X25519/Ed25519 identity and signed prekey
- one-time prekeys
- Double Ratchet sessions
- MLS credential, key packages, and group states

Private state is serialized and encrypted with AES-256-GCM using a master key
provided through a Docker secret/file. Each record uses a random nonce and key
version.

No Bot private key is returned to Web/Flutter or stored unencrypted.

### DM behavior

- Bot API continues accepting plaintext from the trusted Bot caller.
- Server encrypts Bot outbound content through the existing E2EE v2 send path.
- If the human recipient lacks keys, Server-managed Bot produces a deferred
  envelope message and can complete it when keys appear.
- Human-to-Bot ciphertext is decrypted only in the target Bot context and
  forwarded as plaintext only to that Bot's configured webhook.
- Generic user webhooks continue receiving `e2e_opaque`.

### Channel behavior

- Bot publishes and consumes MLS key packages as a normal channel device.
- Bot maintains MLS epoch/generation and can fulfill admission requests.
- Server can decrypt a channel containing the Bot; enabling the Bot for a
  channel therefore requires an explicit warning confirmation.

### Operations

Admin operations:

- initialize Bot E2EE
- inspect public key and key health
- rotate signed prekey/one-time prekeys
- rotate encrypted private-state master-key version
- rebuild Bot device after explicit destructive confirmation
- enable/disable Bot participation per channel

All operations are audited without logging private keys or plaintext content.

## 5. Settings and Localization

Web resources:

- `public/locales/zh/setting.json`
- `public/locales/en/setting.json`
- `public/locales/zh/chat.json`
- `public/locales/en/chat.json`

Flutter resources:

- `lib/l10n/app_zh.arb`
- `lib/l10n/app_en.arb`

Required bilingual labels include:

- Encrypting / 加密中
- Sent, waiting for recipient key / 已发送，等待对方密钥
- Encrypted message, key unavailable / 加密消息，此设备无可用密钥
- Retry MLS synchronization / 重试 MLS 同步
- Request MLS admission / 请求加入加密频道
- Bot key status / Bot 密钥状态
- Rotate Bot keys / 轮换 Bot 密钥
- Rebuild Bot encrypted device / 重建 Bot 加密设备
- Server can decrypt Bot conversations / 服务端可解密 Bot 会话

Every destructive action requires Chinese and English confirmation, success,
and failure messages.

## 6. Compatibility and Migration

- Existing DR and MLS messages remain readable.
- Existing E2EE identities and MLS key packages are retained.
- New tables are additive.
- Existing plaintext messages are not retroactively encrypted.
- Existing bots remain disabled for E2EE until explicitly initialized.
- Existing password values remain loginable: Argon2id for new writes; legacy
  double-MD5 (and any remaining plaintext) verified and upgraded on successful
  login or password change. Clients continue to send plaintext passwords.

## 7. Verification

Server tests:

- public/private MLS route authorization
- deferred DM send with no recipient key
- authenticated envelope completion and unauthorized rejection
- identity event and pending lookup
- Bot key encryption-at-rest and restart recovery
- Bot DM and MLS send/receive
- generic webhook remains opaque

Web/Flutter tests:

- sender plaintext outbox and all five states
- no-key placeholder
- envelope completion updates existing bubble
- MLS background catch-up and one-time 409 retry
- missing Welcome admission flow
- bilingual settings and operation messages

Cross-platform integration:

- Web ↔ Flutter DM pending completion
- Web ↔ Flutter MLS channel with offline member
- Bot ↔ Web/Flutter DM
- Bot in MLS channel with explicit Server-decryption warning
