# E2EE Reliability and Server-Managed Bot Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make DM and Channel E2EE sends reliably visible and recoverable, support deferred delivery to users without keys, and add explicitly Server-managed Bot encryption with complete Chinese/English settings.

**Architecture:** Add an opaque deferred-envelope message protocol and additive Server tables/APIs; move MLS progression into background synchronizers; introduce a shared five-state local outbox in Web and Flutter; add an encrypted-at-rest Bot key vault and Bot DM/MLS engine. Human-only conversations remain strict E2EE, while Bot conversations are explicitly marked Server-decryptable.

**Tech Stack:** Rust 1.95, SQLite/sqlx, voce-e2ee-core, AES-256-GCM, Poem OpenAPI/SSE, React/Redux/IndexedDB/i18next, Flutter/SQLite/secure storage/ARB.

## Global Constraints

- No plaintext fallback.
- Password: new writes use Argon2id; legacy double-MD5 (and any remaining plaintext) remain verifiable until upgraded on successful login or password change. Clients continue to send plaintext passwords.
- Existing DR/MLS messages and identities remain compatible.
- Bot private state must be encrypted with an operator Docker secret and never logged.
- Every new setting/action has Chinese and English labels, confirmations, success messages, and failures.
- Existing uncommitted user changes must not be overwritten.

---

### Task 1: Fix MLS public-channel authorization

**Files:**
- Modify: `vocechat-server-rust-uu/src/mls_delivery.rs:106-124`
- Modify tests: `vocechat-server-rust-uu/src/api/mls.rs:256-284`

**Interfaces:**
- Consumes: `(db: &SqlitePool, uid: i64, gid: i64)`.
- Produces: authorization matching normal group send semantics.

- [ ] Add a failing test proving an authenticated user can obtain a route for a public channel without a `group_user` row, while a non-member private channel remains 403.
- [ ] Run `cargo test api::mls::tests::public_group_route -- --nocapture`; expect the public assertion to fail.
- [ ] Change the SQL predicate to permit `g.is_public = true` in addition to owner/member.
- [ ] Run all `api::mls` and `mls_delivery` tests; expect pass.

### Task 2: Add deferred DM persistence and authenticated envelope APIs

**Files:**
- Create migration: `vocechat-server-rust-uu/migrations/20260721120000_e2e_pending_envelope.sql`
- Modify: `vocechat-server-rust-uu/src/e2ee_v2.rs`
- Modify: `vocechat-server-rust-uu/src/api/e2e.rs`
- Modify: `vocechat-server-rust-uu/src/api/message.rs`
- Modify: `vocechat-server-rust-uu/src/state.rs`
- Modify SSE serialization: `vocechat-server-rust-uu/src/api/event.rs`

**Interfaces:**
- Wire protocol: `protocol=dr-pending`, algorithm `DEFERRED+AES-GCM`.
- `GET /api/user/e2e/pending/:uid` returns pending mids originally sent by current user to `uid`.
- `POST /api/user/e2e/pending/:mid/envelope` accepts `{recipient_uid, device_id, envelope}`.
- SSE events: `e2e_identity_changed` and `e2e_pending_envelope_added`.

- [ ] Write migration tests for `e2e_pending_message` and unique `(mid, recipient_uid, device_id)` envelopes.
- [ ] Add failing API tests for pending send, sender-only envelope append, wrong-sender rejection, wrong-recipient rejection, and duplicate idempotency.
- [ ] Extend `Protocol` parsing/validation to accept `dr-pending` only for `MessageTarget::User`.
- [ ] Persist pending metadata in the same transaction as canonical message send.
- [ ] Add envelope append/list APIs and emit scoped SSE events.
- [ ] Ensure generic webhook redaction remains `e2e_opaque`.
- [ ] Run targeted tests, then `cargo test --workspace`.

### Task 3: Add deferred-envelope crypto to the shared core

**Files:**
- Create: `vocechat-server-rust-uu/crates/voce-e2ee-core/src/deferred.rs`
- Modify: `vocechat-server-rust-uu/crates/voce-e2ee-core/src/lib.rs`
- Modify: `vocechat-server-rust-uu/crates/voce-e2ee-core/src/ffi.rs`
- Add tests: `vocechat-server-rust-uu/crates/voce-e2ee-core/tests/deferred_envelope.rs`

**Interfaces:**
- `deferred_encrypt(body, metadata) -> {content_key, nonce, ciphertext, sha256}`
- `deferred_wrap_key(content_key, recipient_bundle) -> envelope`
- `deferred_unwrap_key(envelope, local_identity) -> content_key`
- `deferred_decrypt(ciphertext, key, nonce, sha256) -> body`
- FFI JSON methods use base64 for all byte arrays.

- [ ] Write red tests for round-trip, tampered ciphertext, wrong recipient, duplicate envelope, and metadata binding.
- [ ] Implement AES-256-GCM content encryption and existing X3DH/DR primitives for key wrapping.
- [ ] Zeroize content keys after use.
- [ ] Expose FFI/WASM methods and run core native/WASM tests.

### Task 4: Add Server-managed Bot key vault and Bot crypto engine

**Files:**
- Create migration: `vocechat-server-rust-uu/migrations/20260721130000_bot_e2ee.sql`
- Create: `vocechat-server-rust-uu/src/bot_e2ee.rs`
- Modify: `vocechat-server-rust-uu/src/config.rs`
- Modify: `vocechat-server-rust-uu/src/state.rs`
- Modify: `vocechat-server-rust-uu/src/api/bot.rs`
- Modify: `vocechat-server-rust-uu/src/api/admin_user.rs`
- Modify compose docs/config: `vocechat-server-rust-uu/build/docker/README.E2E.md`

**Interfaces:**
- Docker secret path: `VOCECHAT_BOT_E2EE_MASTER_KEY_FILE`.
- Tables: encrypted Bot device state, nonce, key version, channel enablement, and audit log.
- Admin APIs: initialize/status/rotate/rebuild Bot E2EE and enable per-channel participation.
- Existing Bot send APIs accept plaintext but emit E2eV2 messages.

- [ ] Write failing tests for missing master key, encrypted-at-rest state, restart restore, rotation, and destructive rebuild confirmation.
- [ ] Implement key-file loading with exact 32-byte decoded key and fail closed when Bot E2EE is enabled without it.
- [ ] Generate/publish Bot identity, signed prekey, one-time prekeys, MLS credential, and key packages.
- [ ] Encrypt Bot outbound DM; use deferred messages for humans without keys.
- [ ] Decrypt inbound target-Bot DM only inside Bot context and forward plaintext only to that Bot webhook.
- [ ] Maintain Bot MLS state and admission fulfillment for enabled channels.
- [ ] Add audit records without plaintext/private material.
- [ ] Run Bot API, DM, MLS, restart, and webhook tests.

### Task 5: Implement Web outbox and deferred DM completion

**Files:**
- Modify: `vocechat-web-uu/src/app/slices/message.ts`
- Modify: `vocechat-web-uu/src/hooks/useSendMessage.ts`
- Modify: `vocechat-web-uu/src/app/e2e/v2_dm.ts`
- Create: `vocechat-web-uu/src/app/e2e/deferred.ts`
- Modify SSE handlers under: `vocechat-web-uu/src/app/slices/`
- Modify message UI: `vocechat-web-uu/src/components/Message/`

**Interfaces:**
- `delivery_state`: `encrypting | sent_waiting_key | sending | sent | failed`.
- Local outbox is keyed by `local_id`; canonical mid updates the same message.
- Identity-change event triggers pending-envelope completion.

- [ ] Add reducer/hook tests proving a plaintext bubble exists before crypto/network calls and survives failures.
- [ ] Implement deferred crypto bindings and sender-device key retention in IndexedDB.
- [ ] Send `dr-pending` when recipient bundles are absent.
- [ ] Complete recipient envelopes on identity SSE and update the same bubble.
- [ ] Render exact state badges, retry/copy actions, locks, and no-key placeholders.
- [ ] Replace generic E2EE toast with safe, specific bilingual errors.
- [ ] Run Web unit/integration tests and release build.

### Task 6: Implement Web MLS background synchronization

**Files:**
- Modify: `vocechat-web-uu/src/app/e2e/mls.ts`
- Modify: `vocechat-web-uu/src/hooks/useMlsChannel.ts`
- Create: `vocechat-web-uu/src/hooks/useMlsSynchronizer.ts`
- Modify: `vocechat-web-uu/src/hooks/useE2eBootstrap.ts`
- Modify: `vocechat-web-uu/src/routes/chat/ChannelChat/index.tsx`
- Modify: `vocechat-web-uu/src/hooks/useSendMessage.ts`

**Interfaces:**
- Persisted cursor: `(uid, device_id, gid, last_mid, epoch, generation)`.
- Admission request event and one-time sequence-conflict retry.

- [ ] Add tests for eager bootstrap, background Welcome/Commit processing, malformed-record quarantine, no-Welcome admission, and 409 catch-up/retry.
- [ ] Move processing out of `ChannelChat` and start synchronizer after authentication.
- [ ] Create optimistic channel outbox message before MLS work.
- [ ] Preserve draft and expose retry on failure.
- [ ] Run channel integration tests.

### Task 7: Implement Flutter outbox, deferred DM, and MLS synchronization

**Files:**
- Modify: `vocechat-client-uu/lib/services/voce_send_service.dart`
- Create: `vocechat-client-uu/lib/services/e2e_v2_deferred.dart`
- Modify: `vocechat-client-uu/lib/services/e2e_v2_dm.dart`
- Modify: `vocechat-client-uu/lib/services/voce_chat_service.dart`
- Modify: `vocechat-client-uu/lib/services/mls_channel_service.dart`
- Create: `vocechat-client-uu/lib/services/mls_sync_service.dart`
- Modify DAO/UI model files under `lib/dao/` and `lib/models/ui_models/`

**Interfaces:**
- Same five `delivery_state` values and `local_id` semantics as Web.
- Secure storage retains sender content keys until recipient envelope completion.

- [ ] Add DAO/service tests for all outbox transitions and restart persistence.
- [ ] Bind deferred FFI methods and implement pending send/completion.
- [ ] Start MLS sync after authentication, persist cursor, quarantine bad records, and retry one sequence conflict.
- [ ] Keep plaintext sender tile and encrypted no-key placeholder behavior.
- [ ] Run Flutter tests and Android/Windows builds.

### Task 8: Add bilingual settings and Bot operations

**Files:**
- Web: `vocechat-web-uu/public/locales/{zh,en}/{setting,chat}.json`
- Web settings components under `vocechat-web-uu/src/routes/settings/`
- Flutter: `vocechat-client-uu/lib/l10n/{app_zh,app_en}.arb`
- Flutter settings pages under `vocechat-client-uu/lib/ui/settings/`

- [ ] Add translation-key parity tests for every new key.
- [ ] Add E2EE delivery/MLS repair status settings.
- [ ] Add Bot key status/rotate/rebuild/channel enablement with explicit Server-decryption warning.
- [ ] Add Chinese/English confirmation, success, and failure feedback.
- [ ] Run localization generation and UI tests.

### Task 9: Cross-platform integration and deployment

**Files:**
- Add server integration tests under `vocechat-server-rust-uu/tests/`.
- Add Web/Flutter interoperability fixtures.
- Rebuild remote `vocechat-server-web-e2ee:latest`.
- Rebuild Android Release APK and Windows release package.

- [ ] Verify Web→Flutter and Flutter→Web pending DM completion.
- [ ] Verify public/private MLS authorization and offline-member catch-up.
- [ ] Verify Bot DM and Bot-enabled MLS channel behavior.
- [ ] Verify generic webhook receives no plaintext.
- [ ] Verify final runtime image has no build tools or secrets.
- [ ] Validate compose without starting it, then hand deployment control to the user.
- [ ] Verify Argon2id login/register/change-password and legacy double-MD5 upgrade path against a restored `old_data` fixture.

### Task 10: Argon2id migration with legacy double-MD5 compatibility

**Files:**
- Create: `vocechat-server-rust-uu/src/password_hash.rs`
- Modify: `vocechat-server-rust-uu/src/api/token.rs` (login verify + upgrade)
- Modify: `vocechat-server-rust-uu/src/api/user.rs` (register / change_password)
- Modify: `vocechat-server-rust-uu/src/api/admin_user.rs` (admin set password)
- Modify: `vocechat-server-rust-uu/src/create_user.rs` (user creation)
- Modify: `vocechat-server-rust-uu/src/server.rs` (bootstrap admin if applicable)
- Add tests under the above modules; optional fixture notes referencing `old_data`

**Interfaces:**
- Clients still send plaintext passwords over TLS; no client-side prehash change required.
- Stored formats:
  - Legacy: exact string match against historical values, including `MD5(MD5(plaintext))` hex (32 lowercase hex chars) as observed in `old_data`.
  - Current: Argon2id PHC string (`$argon2id$...`).
- `verify_and_upgrade(uid, plaintext, stored) -> Result<bool>`:
  - Accept Argon2id, legacy double-MD5, and any remaining plaintext equality for one release window.
  - On successful non-Argon2id verify, rewrite `user.password` to Argon2id in the same request (best-effort; login must still succeed if rewrite fails).
- All new password writes (register, change, admin update, bootstrap) hash with Argon2id only.
- Never log plaintext or hash material.

- [ ] Add unit tests: Argon2id round-trip; `MD5(MD5("dc950713"))` matches known hex `a75fc917c14138b831247f93fc38bb0b`; wrong password rejects; upgrade rewrites to `$argon2id$`.
- [ ] Add API tests: login with legacy double-MD5 stored hash using plaintext password succeeds and persists Argon2id; second login uses Argon2id only; register/change_password store Argon2id; admin password update stores Argon2id.
- [ ] Implement `password_hash::{hash, verify, looks_like_argon2id, looks_like_double_md5}`.
- [ ] Replace raw string equality in login / change_password / create paths with verify + upgrade / hash-on-write.
- [ ] Ensure cached user password field stays consistent after upgrade (DB + in-memory cache).
- [ ] Document operator note: users whose DB already stores the double-MD5 hex as the “password” must log in with the original plaintext once (or reset) so the server can upgrade; do not instruct users to paste the hex hash.
- [ ] Run `cargo test` for password/token/user/admin_user modules.
