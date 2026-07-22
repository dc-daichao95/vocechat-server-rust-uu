-- Server-managed Bot E2EE key vault (Task 4).
--
-- Bot private key material is the one DOCUMENTED exception to "server
-- never stores private keys" (see 20260713120000_e2e.sql): a Bot has no
-- client of its own, so the server generates/holds its X3DH identity,
-- signed prekey, one-time prekeys and MLS credential seed on its behalf.
-- That material is always AES-256-GCM encrypted at rest with the
-- operator-supplied master key (VOCECHAT_BOT_E2EE_MASTER_KEY_FILE) and is
-- never logged. The server fails closed (refuses to initialize/rotate/
-- rebuild/decrypt) whenever the master key is missing or malformed.

create table bot_e2ee_identity
(
    uid                integer primary key not null,
    device_id          text      not null,
    key_version        integer   not null default 1,
    -- AES-256-GCM(master_key) over the JSON-serialized private key
    -- material (identity + signed prekey + one-time prekey secrets + MLS
    -- credential seed). Never contains plaintext chat content.
    nonce              blob      not null,
    ciphertext         blob      not null,
    -- Public counterparts mirrored into e2e_identity/e2e_prekey so
    -- existing human-facing discovery endpoints (get_bundle/get_identity)
    -- transparently serve a Bot's bundle like any other user.
    identity_key_pub   text      not null,
    signed_prekey_pub  text      not null,
    signed_prekey_sig  text      not null,
    created_at         timestamp not null default current_timestamp,
    updated_at         timestamp not null default current_timestamp,
    rotated_at         timestamp,
    foreign key (uid) references user (uid) on delete cascade
);

-- Encrypted copy of an in-flight Bot-authored deferred-DM content key.
-- Retained only for messages that started out fully pending (target had
-- zero usable devices at send time) so the server can auto-append an
-- envelope on the Bot's behalf once that human later publishes an
-- identity -- mirroring the human "waiting senders" catch-up in
-- src/api/e2e.rs, which a Bot has no live device/session to perform
-- itself. Deleted once the pending message is fully completed.
create table bot_e2ee_pending_secret
(
    mid        integer primary key not null,
    uid        integer   not null,
    nonce      blob      not null,
    ciphertext blob      not null,
    created_at timestamp not null default current_timestamp,
    foreign key (mid) references e2e_pending_message (mid) on delete cascade,
    foreign key (uid) references user (uid) on delete cascade
);

-- Per-channel Bot MLS participation/admission state. Enabling a channel
-- publishes the Bot's MLS credential + one key package via the existing
-- opaque mls_device/mls_key_package tables (src/mls_delivery.rs) so a
-- channel owner's client can admit the Bot exactly like a human device.
create table bot_e2ee_channel
(
    uid                       integer   not null,
    gid                       integer   not null,
    enabled_at                timestamp,
    mls_device_id             text,
    credential_published_at   timestamp,
    key_package_published_at  timestamp,
    updated_at                timestamp not null default current_timestamp,
    primary key (uid, gid),
    foreign key (uid) references user (uid) on delete cascade,
    foreign key (gid) references `group` (gid) on delete cascade
);

-- Audit trail for Bot E2EE admin actions and crypto events. Application
-- code must never place plaintext content, key material, or webhook
-- payloads into `detail` -- only safe identifiers (uid/gid/device_id/
-- key_version/action outcome).
create table bot_e2ee_audit
(
    id         integer primary key autoincrement not null,
    uid        integer   not null,
    actor_uid  integer,
    action     text      not null,
    detail     text,
    created_at timestamp not null default current_timestamp
);

create index bot_e2ee_audit_uid_idx on bot_e2ee_audit (uid, created_at);
