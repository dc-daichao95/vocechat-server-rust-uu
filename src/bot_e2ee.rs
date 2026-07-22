//! Server-managed Bot E2EE key vault and crypto engine (Task 4).
//!
//! Human-to-human E2EE stays strict: the server never sees plaintext or
//! private key material (see `src/e2ee_v2.rs`, `crates/voce-e2ee-core`). A
//! Bot has no client of its own, so it is the one DOCUMENTED exception:
//! the server generates and holds a Bot's X3DH identity, signed prekey,
//! one-time prekeys and MLS credential seed on its behalf, and can
//! therefore encrypt the Bot's outbound DMs and decrypt DMs addressed to
//! that Bot.
//!
//! ## Encrypted-at-rest vault
//!
//! A Bot's private key material is always AES-256-GCM encrypted with an
//! operator-supplied master key before it touches SQLite
//! (`bot_e2ee_identity.nonce`/`ciphertext`). The master key is read from
//! the file named by the `VOCECHAT_BOT_E2EE_MASTER_KEY_FILE` env var
//! (Docker secret convention, mirrors `VOCECHAT_UPDATER_TOKEN_FILE`),
//! base64-decoded, and MUST be exactly 32 bytes. It is read fresh on
//! every vault operation (never cached in-process) and NEVER logged.
//! Every operation that needs it fails closed (`MissingMasterKey` /
//! `InvalidMasterKey`) rather than falling back to plaintext.
//!
//! ## Wire contract (documented for Task 5/6/7 clients)
//!
//! Bot DM traffic (both directions) reuses Task 2's deferred envelope
//! wire format exactly: `protocol = "dr-pending"`,
//! `algorithm = "DEFERRED+AES-GCM"`, `wire_class = "dr_envelope"`, content
//! type `application/vnd.vocechat.e2ee.v2`. The message `content` string
//! is JSON: `{"ciphertext_b64", "nonce_b64", "metadata"}`, where
//! `metadata` MUST include a `local_id` matching the routing property
//! (the deferred per-message id / freshness binding required by
//! `crates/voce-e2ee-core`). The AAD/commitment (`sha256`) is never
//! transmitted -- both sides recompute it from `metadata` via
//! `deferred_metadata_commitment`/`deferred_verify_metadata`, exactly as
//! required by the Task 3 crypto core contract.
//!
//! For X3DH interop with a Bot, `e2e_identity.identity_key_pub` MUST be
//! the JSON serialization of `voce_e2ee_core::IdentityPublic`
//! (`{"identity_dh_pub_b64", "identity_sig_pub_b64"}`); `signed_prekey_pub`/
//! `signed_prekey_sig` stay raw base64. The signed-prekey `key_id` is
//! fixed at 1 (the schema tracks only one live signed prekey per device).
//! A device whose `identity_key_pub` does not parse as that JSON shape is
//! treated as "not deferred-capable" and Bot sends fall back to the
//! genuinely-pending path (see below) rather than erroring.
//!
//! ## Bot outbound (Bot -> human)
//!
//! [`send_bot_dm`] is called by `src/api/bot.rs` for a Bot's plaintext
//! `Text`/`Markdown` sends once the Bot has been initialized. It runs
//! `deferred_encrypt` once, then wraps the content key for every currently
//! usable device of the target (`deferred_wrap_key`), appending each
//! envelope immediately via
//! [`crate::e2ee_v2::append_pending_envelope_internal`]. If the target has
//! no usable device yet, the message is left genuinely pending (as Task 2
//! already models) and the content key is retained -- itself encrypted
//! with the same master key, in `bot_e2ee_pending_secret` -- so the server
//! can catch up automatically once that human publishes an identity
//! ([`catch_up_pending_sends`], hooked into `PUT /user/e2e/identity`).
//! This is the Bot-side analogue of the human "waiting senders" catch-up:
//! a Bot has no live device/session to react to `E2eIdentityChanged`
//! itself, so the server does it on the Bot's behalf.
//!
//! ## Bot inbound (human -> Bot)
//!
//! A human sends a `dr-pending` DM to the Bot's uid exactly like sending
//! to any other user (Task 2 flow, unchanged), using the Bot's published
//! bundle (`GET /user/e2e/bundle/:bot_uid`) to wrap the content key
//! themselves. [`handle_inbound_bot_envelope`] is hooked into
//! `POST /user/e2e/pending/:mid/envelope`: once an envelope lands for a
//! Bot recipient, the server -- and *only* inside this Bot-context code
//! path -- unwraps the content key with the Bot's decrypted local
//! identity, verifies+decrypts, and forwards plaintext to *that Bot's*
//! webhook only ([`crate::state::deliver_bot_webhook_plaintext`]).
//! Generic (non-Bot) webhook forwarding keeps redacting E2E content to
//! `e2e_opaque` (`redact_e2e_chat_message_json`, unchanged).
//!
//! Note on metadata verification: in this wire shape the AAD commitment
//! (`sha256`) is derived locally from the received `metadata` and is never
//! transmitted, so the mandatory `deferred_verify_metadata` call on the
//! inbound path is a tautology (contract compliance, per Task 3), not an
//! independent defense. The actual tamper-evidence is the AES-256-GCM tag
//! inside `deferred_decrypt`, which uses that same `sha256` as AAD -- any
//! tampering with metadata or ciphertext fails the tag with no plaintext
//! fallback. See the inline comment in `handle_inbound_bot_envelope`.
//!
//! ## MLS admission (channels)
//!
//! Enabling a channel for a Bot ([`set_channel_enabled`]) publishes a
//! placeholder MLS credential + one key package via the existing opaque
//! `mls_device`/`mls_key_package` storage (`src/mls_delivery.rs`, which
//! never inspects blob contents), so a channel owner's client can consume
//! the key package and admit the Bot exactly like a human device. Actually
//! applying MLS group crypto to Bot-authored channel messages is out of
//! scope for this task (see the Task 4 report's "what Task 8/9 must
//! wire" section).

use std::collections::HashMap;

use poem::http::StatusCode;
use poem_openapi::Object;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use zeroize::Zeroize;

use voce_e2ee_core::{
    deferred_decrypt, deferred_encrypt, deferred_metadata_commitment, deferred_unwrap_key,
    deferred_verify_metadata, deferred_wrap_key,
    identity::{verify_signed_prekey, SignedPreKeyPublic},
    DeferredEnvelope, DeferredLocalIdentity, IdentityPublic, IdentitySecret, PreKeyBundle,
    DEFERRED_ALG,
};

use crate::{
    api::{
        get_merged_message, send_message, ChatMessageContent, ChatMessagePayload, MessageDetail,
        MessageNormal, MessageTarget,
    },
    api::DateTime,
    mls_delivery, State,
};

/// Fixed signed-prekey / OTP-generation key id. The schema tracks only one
/// live signed prekey per device (no history), so a stable id is enough;
/// see the module docs' "Wire contract" section.
const BOT_KEY_ID: u32 = 1;
/// Number of one-time prekeys (re)generated on initialize/rotate/rebuild.
const OTP_BATCH_SIZE: u32 = 20;

pub fn bot_device_id(uid: i64) -> String {
    format!("bot:{uid}")
}

// ---------------------------------------------------------------------
// Errors (bilingual admin-facing messages per the Task 4 brief)
// ---------------------------------------------------------------------

#[derive(Debug)]
pub enum BotE2eeError {
    NotBot,
    MissingMasterKey,
    InvalidMasterKey,
    VaultDecryptFailed,
    NotInitialized,
    AlreadyInitialized,
    ConfirmationRequired,
    ChannelNotFound,
    NoUsableRecipientDevice,
    MessageNotFound,
    EnvelopeNotFound,
    OneTimePrekeyUnavailable,
    MetadataMismatch,
    Crypto(String),
    Database(String),
    Internal(String),
}

impl BotE2eeError {
    fn status(&self) -> StatusCode {
        use BotE2eeError::*;
        match self {
            NotBot | ConfirmationRequired | MetadataMismatch => StatusCode::BAD_REQUEST,
            MissingMasterKey | InvalidMasterKey | VaultDecryptFailed => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            NotInitialized | AlreadyInitialized | NoUsableRecipientDevice
            | OneTimePrekeyUnavailable => StatusCode::CONFLICT,
            ChannelNotFound | MessageNotFound | EnvelopeNotFound => StatusCode::NOT_FOUND,
            Crypto(_) | Database(_) | Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn code(&self) -> &'static str {
        use BotE2eeError::*;
        match self {
            NotBot => "E2E_BOT_NOT_A_BOT",
            MissingMasterKey => "E2E_BOT_MASTER_KEY_MISSING",
            InvalidMasterKey => "E2E_BOT_MASTER_KEY_INVALID",
            VaultDecryptFailed => "E2E_BOT_VAULT_DECRYPT_FAILED",
            NotInitialized => "E2E_BOT_NOT_INITIALIZED",
            AlreadyInitialized => "E2E_BOT_ALREADY_INITIALIZED",
            ConfirmationRequired => "E2E_BOT_REBUILD_CONFIRMATION_REQUIRED",
            ChannelNotFound => "E2E_BOT_CHANNEL_NOT_FOUND",
            NoUsableRecipientDevice => "E2E_BOT_NO_USABLE_RECIPIENT_DEVICE",
            MessageNotFound => "E2E_BOT_MESSAGE_NOT_FOUND",
            EnvelopeNotFound => "E2E_BOT_ENVELOPE_NOT_FOUND",
            OneTimePrekeyUnavailable => "E2E_BOT_ONE_TIME_PREKEY_UNAVAILABLE",
            MetadataMismatch => "E2E_BOT_METADATA_MISMATCH",
            Crypto(_) => "E2E_BOT_CRYPTO_ERROR",
            Database(_) => "E2E_BOT_DATABASE_ERROR",
            Internal(_) => "E2E_BOT_INTERNAL_ERROR",
        }
    }

    pub fn message_en(&self) -> String {
        use BotE2eeError::*;
        match self {
            NotBot => "This user is not a Bot.".into(),
            MissingMasterKey => {
                "Bot E2EE master key file is missing. Set VOCECHAT_BOT_E2EE_MASTER_KEY_FILE \
                 to a file containing a base64-encoded 32-byte key."
                    .into()
            }
            InvalidMasterKey => {
                "Bot E2EE master key is invalid: it must decode to exactly 32 bytes.".into()
            }
            VaultDecryptFailed => {
                "Failed to decrypt the Bot's stored key material with the current master key."
                    .into()
            }
            NotInitialized => "This Bot's E2EE has not been initialized yet.".into(),
            AlreadyInitialized => "This Bot's E2EE has already been initialized.".into(),
            ConfirmationRequired => {
                "Rebuilding a Bot's E2EE identity is destructive (all prior keys are \
                 discarded and existing sessions with this Bot will need to re-establish). \
                 Resend with \"confirm\": true to proceed."
                    .into()
            }
            ChannelNotFound => "Channel not found.".into(),
            NoUsableRecipientDevice => "The recipient has no usable E2EE device yet.".into(),
            MessageNotFound => "Message not found.".into(),
            EnvelopeNotFound => "Envelope not found.".into(),
            OneTimePrekeyUnavailable => "The referenced one-time prekey is not available.".into(),
            MetadataMismatch => "Message metadata failed commitment verification.".into(),
            Crypto(detail) => format!("Bot E2EE cryptographic operation failed: {detail}"),
            Database(detail) => format!("Bot E2EE database error: {detail}"),
            Internal(detail) => format!("Bot E2EE internal error: {detail}"),
        }
    }

    pub fn message_zh(&self) -> String {
        use BotE2eeError::*;
        match self {
            NotBot => "\u{8be5}\u{7528}\u{6237}\u{4e0d}\u{662f}\u{673a}\u{5668}\u{4eba}\u{ff08}Bot\u{ff09}\u{3002}".into(),
            MissingMasterKey => {
                "\u{7f3a}\u{5c11} Bot \u{7aef}\u{5230}\u{7aef}\u{52a0}\u{5bc6}\u{4e3b}\u{5bc6}\u{94a5}\u{6587}\u{4ef6}\u{3002}\u{8bf7}\u{8bbe}\u{7f6e} VOCECHAT_BOT_E2EE_MASTER_KEY_FILE \
                 \u{6307}\u{5411}\u{4e00}\u{4e2a}\u{5305}\u{542b} base64 \u{7f16}\u{7801}\u{7684} 32 \u{5b57}\u{8282}\u{5bc6}\u{94a5}\u{7684}\u{6587}\u{4ef6}\u{3002}"
                    .into()
            }
            InvalidMasterKey => "Bot \u{7aef}\u{5230}\u{7aef}\u{52a0}\u{5bc6}\u{4e3b}\u{5bc6}\u{94a5}\u{65e0}\u{6548}\u{ff1a}\u{89e3}\u{7801}\u{540e}\u{5fc5}\u{987b}\u{6070}\u{597d}\u{4e3a} 32 \u{5b57}\u{8282}\u{3002}".into(),
            VaultDecryptFailed => "\u{4f7f}\u{7528}\u{5f53}\u{524d}\u{4e3b}\u{5bc6}\u{94a5}\u{89e3}\u{5bc6} Bot \u{7684}\u{5bc6}\u{94a5}\u{6750}\u{6599}\u{5931}\u{8d25}\u{3002}".into(),
            NotInitialized => "\u{8be5} Bot \u{7684}\u{7aef}\u{5230}\u{7aef}\u{52a0}\u{5bc6}\u{5c1a}\u{672a}\u{521d}\u{59cb}\u{5316}\u{3002}".into(),
            AlreadyInitialized => "\u{8be5} Bot \u{7684}\u{7aef}\u{5230}\u{7aef}\u{52a0}\u{5bc6}\u{5df2}\u{7ecf}\u{521d}\u{59cb}\u{5316}\u{8fc7}\u{3002}".into(),
            ConfirmationRequired => {
                "\u{91cd}\u{5efa} Bot \u{7684}\u{7aef}\u{5230}\u{7aef}\u{52a0}\u{5bc6}\u{8eab}\u{4efd}\u{662f}\u{7834}\u{574f}\u{6027}\u{64cd}\u{4f5c}\u{ff08}\u{4f1a}\u{4e22}\u{5f03}\u{6240}\u{6709}\u{65e7}\u{5bc6}\u{94a5}\u{ff0c}\u{4e14}\u{4e0e}\u{8be5} Bot \
                 \u{7684}\u{73b0}\u{6709}\u{4f1a}\u{8bdd}\u{9700}\u{8981}\u{91cd}\u{65b0}\u{5efa}\u{7acb}\u{ff09}\u{3002}\u{8bf7}\u{5728}\u{8bf7}\u{6c42}\u{4e2d}\u{5e26}\u{4e0a} \"confirm\": true \u{4ee5}\u{7ee7}\u{7eed}\u{3002}"
                    .into()
            }
            ChannelNotFound => "\u{672a}\u{627e}\u{5230}\u{8be5}\u{9891}\u{9053}\u{3002}".into(),
            NoUsableRecipientDevice => "\u{63a5}\u{6536}\u{8005}\u{76ee}\u{524d}\u{6ca1}\u{6709}\u{53ef}\u{7528}\u{7684}\u{7aef}\u{5230}\u{7aef}\u{52a0}\u{5bc6}\u{8bbe}\u{5907}\u{3002}".into(),
            MessageNotFound => "\u{672a}\u{627e}\u{5230}\u{8be5}\u{6d88}\u{606f}\u{3002}".into(),
            EnvelopeNotFound => "\u{672a}\u{627e}\u{5230}\u{5bf9}\u{5e94}\u{7684}\u{5bc6}\u{94a5}\u{4fe1}\u{5c01}\u{3002}".into(),
            OneTimePrekeyUnavailable => "\u{5f15}\u{7528}\u{7684}\u{4e00}\u{6b21}\u{6027}\u{9884}\u{5171}\u{4eab}\u{5bc6}\u{94a5}\u{4e0d}\u{53ef}\u{7528}\u{3002}".into(),
            MetadataMismatch => "\u{6d88}\u{606f}\u{5143}\u{6570}\u{636e}\u{672a}\u{901a}\u{8fc7}\u{627f}\u{8bfa}\u{9a8c}\u{8bc1}\u{3002}".into(),
            Crypto(detail) => format!("Bot \u{7aef}\u{5230}\u{7aef}\u{52a0}\u{5bc6}\u{64cd}\u{4f5c}\u{5931}\u{8d25}\u{ff1a}{detail}"),
            Database(detail) => format!("Bot \u{7aef}\u{5230}\u{7aef}\u{52a0}\u{5bc6}\u{6570}\u{636e}\u{5e93}\u{9519}\u{8bef}\u{ff1a}{detail}"),
            Internal(detail) => format!("Bot \u{7aef}\u{5230}\u{7aef}\u{52a0}\u{5bc6}\u{5185}\u{90e8}\u{9519}\u{8bef}\u{ff1a}{detail}"),
        }
    }

    pub fn into_poem_error(self) -> poem::Error {
        let status = self.status();
        let body = serde_json::json!({
            "code": self.code(),
            "message_en": self.message_en(),
            "message_zh": self.message_zh(),
        });
        poem::Error::from_string(body.to_string(), status)
    }
}

impl std::fmt::Display for BotE2eeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code(), self.message_en())
    }
}
impl std::error::Error for BotE2eeError {}

impl From<BotE2eeError> for poem::Error {
    fn from(err: BotE2eeError) -> Self {
        err.into_poem_error()
    }
}

impl From<sqlx::Error> for BotE2eeError {
    fn from(err: sqlx::Error) -> Self {
        BotE2eeError::Database(err.to_string())
    }
}

impl From<voce_e2ee_core::E2eError> for BotE2eeError {
    fn from(err: voce_e2ee_core::E2eError) -> Self {
        BotE2eeError::Crypto(err.to_string())
    }
}

// ---------------------------------------------------------------------
// Master key loading + generic AES-256-GCM seal/open for the vault
// ---------------------------------------------------------------------

/// Load+validate the operator master key. Reads the env var fresh every
/// call (no in-process caching) so the key file can be rotated without a
/// restart; fails closed on anything but an exact 32-byte decode. Never
/// logs the raw file contents, the decoded bytes, or the key.
pub fn load_master_key() -> Result<[u8; 32], BotE2eeError> {
    let raw = crate::config::read_env_file_secret(crate::config::BOT_E2EE_MASTER_KEY_FILE_ENV)
        .ok_or(BotE2eeError::MissingMasterKey)?;
    let decoded = base64::decode(raw.as_bytes()).map_err(|_| BotE2eeError::InvalidMasterKey)?;
    let key: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| BotE2eeError::InvalidMasterKey)?;
    Ok(key)
}

fn seal(master_key: &[u8; 32], plaintext: &[u8]) -> Result<([u8; 12], Vec<u8>), BotE2eeError> {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };
    use rand::{rngs::OsRng, RngCore};

    let cipher =
        Aes256Gcm::new_from_slice(master_key).map_err(|_| BotE2eeError::InvalidMasterKey)?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| BotE2eeError::Crypto("vault seal failed".into()))?;
    Ok((nonce, ciphertext))
}

fn open(master_key: &[u8; 32], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, BotE2eeError> {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };

    let cipher =
        Aes256Gcm::new_from_slice(master_key).map_err(|_| BotE2eeError::InvalidMasterKey)?;
    let nonce: [u8; 12] = nonce
        .try_into()
        .map_err(|_| BotE2eeError::Crypto("vault nonce length".into()))?;
    cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext)
        .map_err(|_| BotE2eeError::VaultDecryptFailed)
}

// ---------------------------------------------------------------------
// Private secret material (encrypted at rest)
// ---------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone)]
struct OtpSecret {
    key_id: u32,
    secret: [u8; 32],
}

impl Drop for OtpSecret {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// The Bot's full private key material. Serialized to JSON, then
/// AES-256-GCM-sealed with the operator master key -- this is the ONLY
/// place a Bot's private keys exist outside of RAM. Never logged, never
/// returned from any API.
#[derive(Serialize, Deserialize)]
struct BotSecretMaterial {
    identity_x25519: [u8; 32],
    identity_ed25519: [u8; 32],
    signed_prekey_secret: [u8; 32],
    one_time_prekeys: Vec<OtpSecret>,
    /// Reserved seed for the Bot's MLS credential; MLS admission in this
    /// task only publishes a placeholder credential/key package (see
    /// module docs), so this is not yet consumed by real MLS crypto.
    mls_seed: [u8; 32],
}

impl Drop for BotSecretMaterial {
    fn drop(&mut self) {
        self.identity_x25519.zeroize();
        self.identity_ed25519.zeroize();
        self.signed_prekey_secret.zeroize();
        self.mls_seed.zeroize();
    }
}

struct GeneratedMaterial {
    secret: BotSecretMaterial,
    identity_public: IdentityPublic,
    signed_prekey_public: SignedPreKeyPublic,
    otp_publics: Vec<(u32, String)>,
}

fn generate_material() -> Result<GeneratedMaterial, BotE2eeError> {
    let (identity_secret, identity_public) = IdentitySecret::generate();

    let (spk_secret, spk_public) = identity_secret
        .generate_signed_prekey(BOT_KEY_ID)
        .map_err(BotE2eeError::from)?;
    let mut otp_secrets = Vec::with_capacity(OTP_BATCH_SIZE as usize);
    let mut otp_publics = Vec::with_capacity(OTP_BATCH_SIZE as usize);
    for key_id in 1..=OTP_BATCH_SIZE {
        // Reuse the signed-prekey generator for plain (unsigned) one-time
        // X25519 keypairs; the signature half is simply discarded.
        let (otk_secret, otk_public) = identity_secret
            .generate_signed_prekey(key_id)
            .map_err(BotE2eeError::from)?;
        otp_secrets.push(OtpSecret {
            key_id,
            secret: otk_secret.secret,
        });
        otp_publics.push((key_id, otk_public.dh_pub_b64));
    }
    let mut mls_seed = [0u8; 32];
    {
        use rand::{rngs::OsRng, RngCore};
        OsRng.fill_bytes(&mut mls_seed);
    }

    Ok(GeneratedMaterial {
        secret: BotSecretMaterial {
            identity_x25519: identity_secret.x25519,
            identity_ed25519: identity_secret.ed25519,
            signed_prekey_secret: spk_secret.secret,
            one_time_prekeys: otp_secrets,
            mls_seed,
        },
        identity_public,
        signed_prekey_public: spk_public,
        otp_publics,
    })
}

async fn load_and_decrypt_material(
    pool: &SqlitePool,
    uid: i64,
    master_key: &[u8; 32],
) -> Result<BotSecretMaterial, BotE2eeError> {
    let row = load_identity_row(pool, uid)
        .await?
        .ok_or(BotE2eeError::NotInitialized)?;
    let mut plaintext = open(master_key, &row.nonce, &row.ciphertext)?;
    let material: BotSecretMaterial =
        serde_json::from_slice(&plaintext).map_err(|e| BotE2eeError::Crypto(e.to_string()))?;
    plaintext.zeroize();
    Ok(material)
}

async fn persist_material(
    pool: &SqlitePool,
    uid: i64,
    master_key: &[u8; 32],
    material: &BotSecretMaterial,
) -> Result<(), BotE2eeError> {
    let mut plaintext =
        serde_json::to_vec(material).map_err(|e| BotE2eeError::Crypto(e.to_string()))?;
    let (nonce, ciphertext) = seal(master_key, &plaintext)?;
    plaintext.zeroize();
    sqlx::query("update bot_e2ee_identity set nonce = ?, ciphertext = ?, updated_at = ? where uid = ?")
        .bind(nonce.to_vec())
        .bind(ciphertext)
        .bind(DateTime::now())
        .bind(uid)
        .execute(pool)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------
// Rows / public status DTOs
// ---------------------------------------------------------------------

struct StoredIdentityRow {
    device_id: String,
    key_version: i64,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    identity_key_pub: String,
    created_at: DateTime,
    updated_at: DateTime,
    rotated_at: Option<DateTime>,
}

async fn load_identity_row(
    pool: &SqlitePool,
    uid: i64,
) -> Result<Option<StoredIdentityRow>, BotE2eeError> {
    let row = sqlx::query_as::<
        _,
        (
            String,
            i64,
            Vec<u8>,
            Vec<u8>,
            String,
            DateTime,
            DateTime,
            Option<DateTime>,
        ),
    >(
        "select device_id, key_version, nonce, ciphertext, identity_key_pub, created_at, updated_at, rotated_at \
         from bot_e2ee_identity where uid = ?",
    )
    .bind(uid)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(
        |(device_id, key_version, nonce, ciphertext, identity_key_pub, created_at, updated_at, rotated_at)| {
            StoredIdentityRow {
                device_id,
                key_version,
                nonce,
                ciphertext,
                identity_key_pub,
                created_at,
                updated_at,
                rotated_at,
            }
        },
    ))
}

async fn ensure_target_is_bot(state: &State, uid: i64) -> Result<(), BotE2eeError> {
    let cache = state.cache.read().await;
    match cache.users.get(&uid) {
        Some(user) if user.is_bot => Ok(()),
        _ => Err(BotE2eeError::NotBot),
    }
}

/// Public Bot E2EE status. Never includes any secret/private material.
#[derive(Debug, Object)]
pub struct BotE2eeStatus {
    pub uid: i64,
    pub initialized: bool,
    pub device_id: Option<String>,
    pub key_version: Option<i64>,
    pub master_key_available: bool,
    pub created_at: Option<DateTime>,
    pub updated_at: Option<DateTime>,
    pub rotated_at: Option<DateTime>,
    pub enabled_channels: Vec<i64>,
}

#[derive(Debug, Object)]
pub struct BotE2eeChannelStatus {
    pub gid: i64,
    pub enabled: bool,
    pub credential_published: bool,
    pub key_package_published: bool,
}

pub async fn status(state: &State, bot_uid: i64) -> Result<BotE2eeStatus, BotE2eeError> {
    let row = load_identity_row(&state.db_pool, bot_uid).await?;
    let master_key_available = load_master_key().is_ok();
    let enabled_channels = sqlx::query_scalar::<_, i64>(
        "select gid from bot_e2ee_channel where uid = ? and enabled_at is not null order by gid",
    )
    .bind(bot_uid)
    .fetch_all(&state.db_pool)
    .await?;
    Ok(BotE2eeStatus {
        uid: bot_uid,
        initialized: row.is_some(),
        device_id: row.as_ref().map(|r| r.device_id.clone()),
        key_version: row.as_ref().map(|r| r.key_version),
        master_key_available,
        created_at: row.as_ref().map(|r| r.created_at),
        updated_at: row.as_ref().map(|r| r.updated_at),
        rotated_at: row.as_ref().and_then(|r| r.rotated_at),
        enabled_channels,
    })
}

async fn audit(pool: &SqlitePool, uid: i64, actor_uid: Option<i64>, action: &str, detail: serde_json::Value) {
    // Best-effort: audit logging must never break the primary action. The
    // caller is responsible for never placing plaintext content or key
    // material into `detail` -- only safe identifiers.
    let _ = sqlx::query(
        "insert into bot_e2ee_audit (uid, actor_uid, action, detail, created_at) values (?, ?, ?, ?, ?)",
    )
    .bind(uid)
    .bind(actor_uid)
    .bind(action)
    .bind(detail.to_string())
    .bind(DateTime::now())
    .execute(pool)
    .await;
}

// ---------------------------------------------------------------------
// Admin lifecycle: initialize / rotate / rebuild / channel admission
// ---------------------------------------------------------------------

pub async fn initialize(
    state: &State,
    actor_uid: i64,
    bot_uid: i64,
) -> Result<BotE2eeStatus, BotE2eeError> {
    ensure_target_is_bot(state, bot_uid).await?;
    if load_identity_row(&state.db_pool, bot_uid).await?.is_some() {
        return Err(BotE2eeError::AlreadyInitialized);
    }
    let master_key = load_master_key()?;
    let generated = generate_material()?;
    let device_id = bot_device_id(bot_uid);
    let now = DateTime::now();

    let identity_key_pub = serde_json::to_string(&generated.identity_public)
        .map_err(|e| BotE2eeError::Crypto(e.to_string()))?;
    let mut plaintext =
        serde_json::to_vec(&generated.secret).map_err(|e| BotE2eeError::Crypto(e.to_string()))?;
    let (nonce, ciphertext) = seal(&master_key, &plaintext)?;
    plaintext.zeroize();

    let mut tx = state.db_pool.begin().await?;
    sqlx::query(
        "insert into device (uid, device, device_token) values (?, ?, null) \
         on conflict(uid, device) do nothing",
    )
    .bind(bot_uid)
    .bind(&device_id)
    .execute(&mut tx)
    .await?;
    sqlx::query(
        "insert into e2e_identity \
           (uid, device_id, identity_key_pub, signed_prekey_pub, signed_prekey_sig, updated_at, key_version, retired_at) \
         values (?, ?, ?, ?, ?, ?, 1, null)",
    )
    .bind(bot_uid)
    .bind(&device_id)
    .bind(&identity_key_pub)
    .bind(&generated.signed_prekey_public.dh_pub_b64)
    .bind(&generated.signed_prekey_public.signature_b64)
    .bind(now)
    .execute(&mut tx)
    .await?;
    for (key_id, public_key) in &generated.otp_publics {
        sqlx::query(
            "insert into e2e_prekey (uid, device_id, key_id, public_key, consumed) values (?, ?, ?, ?, false)",
        )
        .bind(bot_uid)
        .bind(&device_id)
        .bind(*key_id as i32)
        .bind(public_key)
        .execute(&mut tx)
        .await?;
    }
    sqlx::query(
        "insert into bot_e2ee_identity \
           (uid, device_id, key_version, nonce, ciphertext, identity_key_pub, signed_prekey_pub, signed_prekey_sig, created_at, updated_at) \
         values (?, ?, 1, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(bot_uid)
    .bind(&device_id)
    .bind(nonce.to_vec())
    .bind(ciphertext)
    .bind(&identity_key_pub)
    .bind(&generated.signed_prekey_public.dh_pub_b64)
    .bind(&generated.signed_prekey_public.signature_b64)
    .bind(now)
    .bind(now)
    .execute(&mut tx)
    .await?;
    tx.commit().await?;

    audit(
        &state.db_pool,
        bot_uid,
        Some(actor_uid),
        "initialize",
        serde_json::json!({ "device_id": device_id }),
    )
    .await;
    status(state, bot_uid).await
}

pub async fn rotate(
    state: &State,
    actor_uid: i64,
    bot_uid: i64,
) -> Result<BotE2eeStatus, BotE2eeError> {
    ensure_target_is_bot(state, bot_uid).await?;
    let existing = load_identity_row(&state.db_pool, bot_uid)
        .await?
        .ok_or(BotE2eeError::NotInitialized)?;
    let master_key = load_master_key()?;
    let mut material = load_and_decrypt_material(&state.db_pool, bot_uid, &master_key).await?;

    let identity_secret = IdentitySecret {
        x25519: material.identity_x25519,
        ed25519: material.identity_ed25519,
    };
    let (spk_secret, spk_public) = identity_secret
        .generate_signed_prekey(BOT_KEY_ID)
        .map_err(BotE2eeError::from)?;
    let mut otp_secrets = Vec::with_capacity(OTP_BATCH_SIZE as usize);
    let mut otp_publics = Vec::with_capacity(OTP_BATCH_SIZE as usize);
    for key_id in 1..=OTP_BATCH_SIZE {
        let (otk_secret, otk_public) = identity_secret
            .generate_signed_prekey(key_id)
            .map_err(BotE2eeError::from)?;
        otp_secrets.push(OtpSecret {
            key_id,
            secret: otk_secret.secret,
        });
        otp_publics.push((key_id, otk_public.dh_pub_b64));
    }
    material.signed_prekey_secret = spk_secret.secret;
    material.one_time_prekeys = otp_secrets;

    let new_key_version = existing.key_version + 1;
    let mut plaintext =
        serde_json::to_vec(&material).map_err(|e| BotE2eeError::Crypto(e.to_string()))?;
    let (nonce, ciphertext) = seal(&master_key, &plaintext)?;
    plaintext.zeroize();
    let now = DateTime::now();

    let mut tx = state.db_pool.begin().await?;
    sqlx::query("delete from e2e_prekey where uid = ? and device_id = ? and consumed = false")
        .bind(bot_uid)
        .bind(&existing.device_id)
        .execute(&mut tx)
        .await?;
    for (key_id, public_key) in &otp_publics {
        sqlx::query(
            "insert into e2e_prekey (uid, device_id, key_id, public_key, consumed) values (?, ?, ?, ?, false) \
             on conflict(uid, device_id, key_id) do update set public_key = excluded.public_key, consumed = false",
        )
        .bind(bot_uid)
        .bind(&existing.device_id)
        .bind(*key_id as i32)
        .bind(public_key)
        .execute(&mut tx)
        .await?;
    }
    sqlx::query(
        "update e2e_identity set signed_prekey_pub = ?, signed_prekey_sig = ?, key_version = ?, updated_at = ? \
         where uid = ? and device_id = ?",
    )
    .bind(&spk_public.dh_pub_b64)
    .bind(&spk_public.signature_b64)
    .bind(new_key_version)
    .bind(now)
    .bind(bot_uid)
    .bind(&existing.device_id)
    .execute(&mut tx)
    .await?;
    sqlx::query(
        "update bot_e2ee_identity set signed_prekey_pub = ?, signed_prekey_sig = ?, key_version = ?, \
         nonce = ?, ciphertext = ?, updated_at = ?, rotated_at = ? where uid = ?",
    )
    .bind(&spk_public.dh_pub_b64)
    .bind(&spk_public.signature_b64)
    .bind(new_key_version)
    .bind(nonce.to_vec())
    .bind(ciphertext)
    .bind(now)
    .bind(now)
    .bind(bot_uid)
    .execute(&mut tx)
    .await?;
    tx.commit().await?;

    audit(
        &state.db_pool,
        bot_uid,
        Some(actor_uid),
        "rotate",
        serde_json::json!({ "key_version": new_key_version }),
    )
    .await;
    status(state, bot_uid).await
}

pub async fn rebuild(
    state: &State,
    actor_uid: i64,
    bot_uid: i64,
    confirm: bool,
) -> Result<BotE2eeStatus, BotE2eeError> {
    if !confirm {
        return Err(BotE2eeError::ConfirmationRequired);
    }
    ensure_target_is_bot(state, bot_uid).await?;
    let existing = load_identity_row(&state.db_pool, bot_uid)
        .await?
        .ok_or(BotE2eeError::NotInitialized)?;
    let master_key = load_master_key()?;
    let generated = generate_material()?;
    let new_key_version = existing.key_version + 1;

    let identity_key_pub = serde_json::to_string(&generated.identity_public)
        .map_err(|e| BotE2eeError::Crypto(e.to_string()))?;
    let mut plaintext =
        serde_json::to_vec(&generated.secret).map_err(|e| BotE2eeError::Crypto(e.to_string()))?;
    let (nonce, ciphertext) = seal(&master_key, &plaintext)?;
    plaintext.zeroize();
    let now = DateTime::now();

    let mut tx = state.db_pool.begin().await?;
    sqlx::query("delete from e2e_prekey where uid = ? and device_id = ?")
        .bind(bot_uid)
        .bind(&existing.device_id)
        .execute(&mut tx)
        .await?;
    for (key_id, public_key) in &generated.otp_publics {
        sqlx::query(
            "insert into e2e_prekey (uid, device_id, key_id, public_key, consumed) values (?, ?, ?, ?, false)",
        )
        .bind(bot_uid)
        .bind(&existing.device_id)
        .bind(*key_id as i32)
        .bind(public_key)
        .execute(&mut tx)
        .await?;
    }
    sqlx::query(
        "update e2e_identity set identity_key_pub = ?, signed_prekey_pub = ?, signed_prekey_sig = ?, \
         key_version = ?, updated_at = ?, retired_at = null where uid = ? and device_id = ?",
    )
    .bind(&identity_key_pub)
    .bind(&generated.signed_prekey_public.dh_pub_b64)
    .bind(&generated.signed_prekey_public.signature_b64)
    .bind(new_key_version)
    .bind(now)
    .bind(bot_uid)
    .bind(&existing.device_id)
    .execute(&mut tx)
    .await?;
    sqlx::query(
        "update bot_e2ee_identity set identity_key_pub = ?, signed_prekey_pub = ?, signed_prekey_sig = ?, \
         key_version = ?, nonce = ?, ciphertext = ?, updated_at = ?, rotated_at = ? where uid = ?",
    )
    .bind(&identity_key_pub)
    .bind(&generated.signed_prekey_public.dh_pub_b64)
    .bind(&generated.signed_prekey_public.signature_b64)
    .bind(new_key_version)
    .bind(nonce.to_vec())
    .bind(ciphertext)
    .bind(now)
    .bind(now)
    .bind(bot_uid)
    .execute(&mut tx)
    .await?;
    // Old MLS credential/key package are tied to the discarded mls_seed
    // and must be republished before admission is trusted again.
    sqlx::query(
        "update bot_e2ee_channel set credential_published_at = null, key_package_published_at = null, updated_at = ? \
         where uid = ?",
    )
    .bind(now)
    .bind(bot_uid)
    .execute(&mut tx)
    .await?;
    tx.commit().await?;

    audit(
        &state.db_pool,
        bot_uid,
        Some(actor_uid),
        "rebuild",
        serde_json::json!({ "key_version": new_key_version, "destructive": true }),
    )
    .await;
    status(state, bot_uid).await
}

fn bot_mls_credential_bytes(device_id: &str, gid: i64, identity_key_pub: &str) -> Vec<u8> {
    // Placeholder: server-side MLS credential generation/handshake
    // application is out of scope for this task (see module docs); this
    // establishes only the opaque-blob admission plumbing.
    serde_json::to_vec(&serde_json::json!({
        "kind": "vocechat-bot-mls-credential-placeholder-v1",
        "device_id": device_id,
        "gid": gid,
        "identity_key_pub": identity_key_pub,
    }))
    .unwrap_or_default()
}

fn bot_mls_key_package_bytes(device_id: &str, gid: i64) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "kind": "vocechat-bot-mls-key-package-placeholder-v1",
        "device_id": device_id,
        "gid": gid,
        "package_id": uuid::Uuid::new_v4().to_string(),
    }))
    .unwrap_or_default()
}

pub async fn set_channel_enabled(
    state: &State,
    actor_uid: i64,
    bot_uid: i64,
    gid: i64,
    enabled: bool,
) -> Result<BotE2eeChannelStatus, BotE2eeError> {
    ensure_target_is_bot(state, bot_uid).await?;
    let identity = load_identity_row(&state.db_pool, bot_uid)
        .await?
        .ok_or(BotE2eeError::NotInitialized)?;
    let group_exists =
        sqlx::query_scalar::<_, i64>("select count(*) from `group` where gid = ?")
            .bind(gid)
            .fetch_one(&state.db_pool)
            .await?;
    if group_exists == 0 {
        return Err(BotE2eeError::ChannelNotFound);
    }
    let now = DateTime::now();

    if enabled {
        // Fail closed: don't even mark a channel enabled if the vault is
        // currently unusable (we are about to publish credentials that
        // depend on it staying decryptable/rotatable).
        load_master_key()?;

        sqlx::query(
            "insert into bot_e2ee_channel (uid, gid, enabled_at, mls_device_id, updated_at) \
             values (?, ?, ?, ?, ?) \
             on conflict(uid, gid) do update set \
               enabled_at = excluded.enabled_at, mls_device_id = excluded.mls_device_id, updated_at = excluded.updated_at",
        )
        .bind(bot_uid)
        .bind(gid)
        .bind(now)
        .bind(&identity.device_id)
        .bind(now)
        .execute(&state.db_pool)
        .await?;

        let published = sqlx::query_as::<_, (Option<DateTime>, Option<DateTime>)>(
            "select credential_published_at, key_package_published_at from bot_e2ee_channel where uid = ? and gid = ?",
        )
        .bind(bot_uid)
        .bind(gid)
        .fetch_one(&state.db_pool)
        .await?;

        if published.0.is_none() {
            let credential =
                bot_mls_credential_bytes(&identity.device_id, gid, &identity.identity_key_pub);
            mls_delivery::put_credential(&state.db_pool, bot_uid, &identity.device_id, &credential)
                .await
                .map_err(|e| BotE2eeError::Internal(e.to_string()))?;
            sqlx::query(
                "update bot_e2ee_channel set credential_published_at = ? where uid = ? and gid = ?",
            )
            .bind(now)
            .bind(bot_uid)
            .bind(gid)
            .execute(&state.db_pool)
            .await?;
        }
        if published.1.is_none() {
            let package = bot_mls_key_package_bytes(&identity.device_id, gid);
            mls_delivery::publish_key_package(&state.db_pool, bot_uid, &identity.device_id, &package)
                .await
                .map_err(|e| BotE2eeError::Internal(e.to_string()))?;
            sqlx::query(
                "update bot_e2ee_channel set key_package_published_at = ? where uid = ? and gid = ?",
            )
            .bind(now)
            .bind(bot_uid)
            .bind(gid)
            .execute(&state.db_pool)
            .await?;
        }
        audit(
            &state.db_pool,
            bot_uid,
            Some(actor_uid),
            "channel_enabled",
            serde_json::json!({ "gid": gid }),
        )
        .await;
    } else {
        sqlx::query("update bot_e2ee_channel set enabled_at = null, updated_at = ? where uid = ? and gid = ?")
            .bind(now)
            .bind(bot_uid)
            .bind(gid)
            .execute(&state.db_pool)
            .await?;
        audit(
            &state.db_pool,
            bot_uid,
            Some(actor_uid),
            "channel_disabled",
            serde_json::json!({ "gid": gid }),
        )
        .await;
    }

    let row = sqlx::query_as::<_, (Option<DateTime>, Option<DateTime>, Option<DateTime>)>(
        "select enabled_at, credential_published_at, key_package_published_at from bot_e2ee_channel where uid = ? and gid = ?",
    )
    .bind(bot_uid)
    .bind(gid)
    .fetch_optional(&state.db_pool)
    .await?
    .unwrap_or((None, None, None));

    Ok(BotE2eeChannelStatus {
        gid,
        enabled: row.0.is_some(),
        credential_published: row.1.is_some(),
        key_package_published: row.2.is_some(),
    })
}

// ---------------------------------------------------------------------
// Crypto engine: outbound Bot DM (deferred encrypt + per-device wrap)
// ---------------------------------------------------------------------

/// One usable (deferred-crypto capable) device of a user: its id, current
/// identity `key_version`, and validated public identity + signed prekey.
///
/// The one-time prekey is intentionally NOT read/consumed here -- it is
/// peeked and then atomically claimed only *after* a successful wrap (see
/// [`wrap_content_key_for_device`]), so a wrap failure never shrinks the
/// target's OTP pool and two concurrent sends can never share one OTP.
#[derive(Clone)]
struct UsableDevice {
    uid: i64,
    device_id: String,
    key_version: i64,
    identity: IdentityPublic,
    signed_prekey: SignedPreKeyPublic,
}

fn to_usable_device(
    uid: i64,
    device_id: String,
    key_version: i64,
    identity_key_pub: String,
    signed_prekey_pub: Option<String>,
    signed_prekey_sig: Option<String>,
) -> Option<UsableDevice> {
    let signed_prekey_pub = signed_prekey_pub.filter(|v| !v.trim().is_empty())?;
    let signed_prekey_sig = signed_prekey_sig.filter(|v| !v.trim().is_empty())?;
    let identity = serde_json::from_str::<IdentityPublic>(&identity_key_pub).ok()?;
    let signed_prekey = SignedPreKeyPublic {
        key_id: BOT_KEY_ID,
        dh_pub_b64: signed_prekey_pub,
        signature_b64: signed_prekey_sig,
    };
    if verify_signed_prekey(&identity, &signed_prekey).is_err() {
        return None;
    }
    Some(UsableDevice {
        uid,
        device_id,
        key_version,
        identity,
        signed_prekey,
    })
}

/// Every currently usable (non-retired, deferred-crypto capable) device of
/// `target_uid`.
async fn fetch_target_devices(
    state: &State,
    target_uid: i64,
) -> Result<Vec<UsableDevice>, BotE2eeError> {
    let rows = sqlx::query_as::<_, (String, i64, String, Option<String>, Option<String>)>(
        "select device_id, key_version, identity_key_pub, signed_prekey_pub, signed_prekey_sig \
         from e2e_identity where uid = ? and retired_at is null",
    )
    .bind(target_uid)
    .fetch_all(&state.db_pool)
    .await?;

    Ok(rows
        .into_iter()
        .filter_map(|(device_id, key_version, identity_key_pub, spk_pub, spk_sig)| {
            to_usable_device(target_uid, device_id, key_version, identity_key_pub, spk_pub, spk_sig)
        })
        .collect())
}

async fn fetch_one_device(
    pool: &SqlitePool,
    uid: i64,
    device_id: &str,
) -> Result<Option<UsableDevice>, BotE2eeError> {
    let row = sqlx::query_as::<_, (i64, String, Option<String>, Option<String>)>(
        "select key_version, identity_key_pub, signed_prekey_pub, signed_prekey_sig \
         from e2e_identity where uid = ? and device_id = ? and retired_at is null",
    )
    .bind(uid)
    .bind(device_id)
    .fetch_optional(pool)
    .await?;
    let Some((key_version, identity_key_pub, spk_pub, spk_sig)) = row else {
        return Ok(None);
    };
    Ok(to_usable_device(
        uid,
        device_id.to_string(),
        key_version,
        identity_key_pub,
        spk_pub,
        spk_sig,
    ))
}

/// Peek (without consuming) the next unconsumed one-time prekey for a
/// device. Returns `(id, key_id, public_key)`.
async fn peek_one_time_prekey(
    pool: &SqlitePool,
    uid: i64,
    device_id: &str,
) -> Result<Option<(i64, u32, String)>, BotE2eeError> {
    let row = sqlx::query_as::<_, (i64, i32, String)>(
        "select id, key_id, public_key from e2e_prekey \
         where uid = ? and device_id = ? and consumed = false order by id asc limit 1",
    )
    .bind(uid)
    .bind(device_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(id, key_id, public_key)| (id, key_id as u32, public_key)))
}

/// Atomically claim a specific one-time prekey by id. Returns `true` only
/// if *this* call flipped it from unconsumed to consumed -- the
/// `and consumed = false` guard means a concurrent claimer of the same row
/// gets `false` (0 rows affected), so two sends can never share one OTP.
async fn try_consume_one_time_prekey(pool: &SqlitePool, id: i64) -> Result<bool, BotE2eeError> {
    let result = sqlx::query("update e2e_prekey set consumed = true where id = ? and consumed = false")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() == 1)
}

/// Wrap `content_key` for one device, consuming exactly one of the
/// device's one-time prekeys **only after** the wrap succeeds.
///
/// This resolves two forward-secrecy hazards:
/// - Wrap-then-consume ordering (never consume-then-wrap): a failed
///   `deferred_wrap_key` returns `Ok(None)` and leaves the OTP pool
///   untouched, so a bad/corrupt OTP or transient wrap error never burns a
///   prekey (fix for review item 3).
/// - Atomic claim with retry: the OTP is peeked, wrapped, then claimed via
///   [`try_consume_one_time_prekey`]'s `and consumed = false` guard. If a
///   concurrent send claimed the peeked OTP first, we discard that wrap and
///   retry with a fresh peek, so two sends can never reuse one OTP id (fix
///   for review item 2).
///
/// One-time prekeys are optional in X3DH; if none remain (or a bounded
/// number of claim races are lost), we fall back to an OTP-less wrap, which
/// is still a valid X3DH agreement over the signed prekey.
async fn wrap_content_key_for_device(
    pool: &SqlitePool,
    content_key: &[u8; 32],
    device: &UsableDevice,
) -> Result<Option<DeferredEnvelope>, BotE2eeError> {
    const MAX_CLAIM_RETRIES: usize = 8;

    for _ in 0..MAX_CLAIM_RETRIES {
        let otp = peek_one_time_prekey(pool, device.uid, &device.device_id).await?;
        let bundle = PreKeyBundle {
            identity: device.identity.clone(),
            signed_prekey: device.signed_prekey.clone(),
            one_time_prekey_b64: otp.as_ref().map(|(_, _, pk)| pk.clone()),
            one_time_prekey_id: otp.as_ref().map(|(_, key_id, _)| *key_id),
        };
        // Wrap BEFORE consuming: a failure here must not burn the OTP.
        let envelope = match deferred_wrap_key(content_key, &bundle) {
            Ok(envelope) => envelope,
            Err(_) => return Ok(None),
        };
        match otp {
            // No OTP was used -> nothing to claim.
            None => return Ok(Some(envelope)),
            Some((id, _, _)) => {
                if try_consume_one_time_prekey(pool, id).await? {
                    return Ok(Some(envelope));
                }
                // Lost the claim race for this OTP; discard this envelope
                // and retry with a freshly-peeked prekey.
            }
        }
    }

    // Contention fallback: wrap without a one-time prekey (still forward-
    // secret via the signed prekey).
    let bundle = PreKeyBundle {
        identity: device.identity.clone(),
        signed_prekey: device.signed_prekey.clone(),
        one_time_prekey_b64: None,
        one_time_prekey_id: None,
    };
    Ok(deferred_wrap_key(content_key, &bundle).ok())
}

/// Encrypt+send one plaintext DM on behalf of a Bot. Called from
/// `src/api/bot.rs` for a Bot's plaintext `Text`/`Markdown` sends, once
/// the Bot has been initialized. See module docs for the wire format.
pub async fn send_bot_dm(
    state: &State,
    bot_uid: i64,
    target_uid: i64,
    content_type: &str,
    plaintext: &str,
) -> Result<i64, BotE2eeError> {
    // Fail closed unconditionally: a Bot that has been initialized must
    // never silently fall back to something other than this encrypted
    // path just because the master key later became unavailable.
    load_master_key()?;
    let identity = load_identity_row(&state.db_pool, bot_uid)
        .await?
        .ok_or(BotE2eeError::NotInitialized)?;

    let local_id = uuid::Uuid::new_v4().to_string();
    let metadata = serde_json::json!({
        "local_id": local_id,
        "content_type": content_type,
        "from_bot_uid": bot_uid,
        "to_uid": target_uid,
    });
    let encrypted = deferred_encrypt(plaintext.as_bytes(), &metadata)?;
    let content_json = serde_json::json!({
        "ciphertext_b64": base64::encode(&encrypted.ciphertext),
        "nonce_b64": base64::encode(&encrypted.nonce),
        "metadata": metadata,
    })
    .to_string();

    let mut properties: HashMap<String, serde_json::Value> = HashMap::new();
    properties.insert("e2e_version".to_string(), serde_json::json!(2));
    properties.insert("protocol".to_string(), serde_json::json!("dr-pending"));
    properties.insert("algorithm".to_string(), serde_json::json!(DEFERRED_ALG));
    properties.insert("wire_class".to_string(), serde_json::json!("dr_envelope"));
    properties.insert(
        "sender_device_id".to_string(),
        serde_json::json!(identity.device_id),
    );
    properties.insert("local_id".to_string(), serde_json::json!(local_id));

    let payload = ChatMessagePayload {
        from_uid: bot_uid,
        created_at: DateTime::now(),
        target: MessageTarget::user(target_uid),
        detail: MessageDetail::Normal(MessageNormal {
            content: ChatMessageContent {
                properties: Some(properties),
                content_type: crate::e2ee_v2::CONTENT_TYPE.to_owned(),
                content: content_json,
            },
            expires_in: None,
        }),
    };
    let mid = send_message(state, payload)
        .await
        .map_err(|e| BotE2eeError::Internal(e.to_string()))?;

    let devices = fetch_target_devices(state, target_uid).await?;
    let mut appended_any = false;
    for device in devices {
        if let Some(envelope) =
            wrap_content_key_for_device(&state.db_pool, &encrypted.content_key, &device).await?
        {
            let envelope_b64 = base64::encode(serde_json::to_vec(&envelope).unwrap_or_default());
            if crate::e2ee_v2::append_pending_envelope_internal(
                &state.db_pool,
                mid,
                target_uid,
                &device.device_id,
                device.key_version,
                &envelope_b64,
            )
            .await?
            {
                appended_any = true;
            }
        }
    }

    if !appended_any {
        // Genuinely pending: retain the (master-key-encrypted) content
        // key so a later identity publish can be caught up automatically
        // -- see `catch_up_pending_sends`.
        let master_key = load_master_key()?;
        let (nonce, ciphertext) = seal(&master_key, &encrypted.content_key)?;
        sqlx::query(
            "insert into bot_e2ee_pending_secret (mid, uid, nonce, ciphertext) values (?, ?, ?, ?) \
             on conflict(mid) do nothing",
        )
        .bind(mid)
        .bind(bot_uid)
        .bind(nonce.to_vec())
        .bind(ciphertext)
        .execute(&state.db_pool)
        .await?;
    }

    audit(
        &state.db_pool,
        bot_uid,
        Some(bot_uid),
        "outbound_dm",
        serde_json::json!({ "target_uid": target_uid, "mid": mid, "immediate_envelope": appended_any }),
    )
    .await;

    Ok(mid)
}

/// Called from `PUT /user/e2e/identity` for every Bot among the newly
/// published device's "waiting senders". A Bot has no live device/session
/// to react to `E2eIdentityChanged` itself, so the server performs the
/// same catch-up a human sender's own client would perform.
pub async fn catch_up_pending_sends(
    state: &State,
    bot_uid: i64,
    target_uid: i64,
    device_id: &str,
    identity_version: i64,
) -> Result<usize, BotE2eeError> {
    let mids: Vec<i64> = sqlx::query_scalar(
        "select pending.mid from e2e_pending_message pending \
         inner join bot_e2ee_pending_secret secret on secret.mid = pending.mid \
         where pending.sender_uid = ? and pending.target_uid = ? \
           and not exists ( \
             select 1 from e2e_pending_envelope e \
             where e.mid = pending.mid and e.recipient_uid = ? and e.device_id = ? and e.identity_version = ? \
           )",
    )
    .bind(bot_uid)
    .bind(target_uid)
    .bind(target_uid)
    .bind(device_id)
    .bind(identity_version)
    .fetch_all(&state.db_pool)
    .await?;
    if mids.is_empty() {
        return Ok(0);
    }

    let master_key = load_master_key()?;
    let Some(device) = fetch_one_device(&state.db_pool, target_uid, device_id).await? else {
        return Err(BotE2eeError::NoUsableRecipientDevice);
    };

    let mut count = 0;
    for mid in mids {
        let row = sqlx::query_as::<_, (Vec<u8>, Vec<u8>)>(
            "select nonce, ciphertext from bot_e2ee_pending_secret where mid = ?",
        )
        .bind(mid)
        .fetch_optional(&state.db_pool)
        .await?;
        let Some((nonce, ciphertext)) = row else {
            continue;
        };
        let mut content_key_vec = open(&master_key, &nonce, &ciphertext)?;
        let content_key: [u8; 32] = match content_key_vec.as_slice().try_into() {
            Ok(key) => key,
            Err(_) => {
                content_key_vec.zeroize();
                continue;
            }
        };
        content_key_vec.zeroize();
        // Wrap-then-consume (see `wrap_content_key_for_device`): a wrap
        // failure here skips the message without burning an OTP.
        let Some(envelope) =
            wrap_content_key_for_device(&state.db_pool, &content_key, &device).await?
        else {
            continue;
        };
        let envelope_b64 = base64::encode(serde_json::to_vec(&envelope).unwrap_or_default());
        if crate::e2ee_v2::append_pending_envelope_internal(
            &state.db_pool,
            mid,
            target_uid,
            device_id,
            identity_version,
            &envelope_b64,
        )
        .await?
        {
            count += 1;
        }
    }

    if count > 0 {
        audit(
            &state.db_pool,
            bot_uid,
            None,
            "outbound_dm_catchup",
            serde_json::json!({ "target_uid": target_uid, "device_id": device_id, "count": count }),
        )
        .await;
    }
    Ok(count)
}

// ---------------------------------------------------------------------
// Crypto engine: inbound Bot DM (decrypt only in Bot context)
// ---------------------------------------------------------------------

#[derive(Deserialize)]
struct InboundWire {
    ciphertext_b64: String,
    nonce_b64: String,
    metadata: serde_json::Value,
}

/// Called from `POST /user/e2e/pending/:mid/envelope` immediately after a
/// new envelope is durably appended, ONLY when `recipient_uid` is a Bot.
/// Decrypts the message and forwards plaintext to that Bot's own webhook
/// -- and only that Bot's webhook. Best-effort: errors are returned for
/// the caller to log, never surfaced to the (human) envelope-append
/// caller, since the envelope itself was already stored successfully.
pub async fn handle_inbound_bot_envelope(
    state: &State,
    mid: i64,
    bot_uid: i64,
    device_id: &str,
) -> Result<(), BotE2eeError> {
    let merged = get_merged_message(&state.msg_db, mid)
        .map_err(|e| BotE2eeError::Internal(e.to_string()))?
        .ok_or(BotE2eeError::MessageNotFound)?;
    if merged.content.content_type != crate::e2ee_v2::CONTENT_TYPE {
        return Err(BotE2eeError::MessageNotFound);
    }
    let wire: InboundWire = serde_json::from_str(&merged.content.content)
        .map_err(|e| BotE2eeError::Crypto(e.to_string()))?;
    let ciphertext = base64::decode(&wire.ciphertext_b64)
        .map_err(|_| BotE2eeError::Crypto("bad ciphertext_b64".into()))?;
    let nonce_bytes = base64::decode(&wire.nonce_b64)
        .map_err(|_| BotE2eeError::Crypto("bad nonce_b64".into()))?;
    let nonce: [u8; 12] = nonce_bytes
        .as_slice()
        .try_into()
        .map_err(|_| BotE2eeError::Crypto("bad nonce length".into()))?;

    let envelope_b64 = sqlx::query_scalar::<_, String>(
        "select envelope from e2e_pending_envelope \
         where mid = ? and recipient_uid = ? and device_id = ? order by identity_version desc limit 1",
    )
    .bind(mid)
    .bind(bot_uid)
    .bind(device_id)
    .fetch_optional(&state.db_pool)
    .await?
    .ok_or(BotE2eeError::EnvelopeNotFound)?;
    let envelope: DeferredEnvelope = serde_json::from_slice(
        &base64::decode(&envelope_b64).map_err(|_| BotE2eeError::Crypto("bad envelope_b64".into()))?,
    )
    .map_err(|e| BotE2eeError::Crypto(e.to_string()))?;

    let master_key = load_master_key()?;
    let mut material = load_and_decrypt_material(&state.db_pool, bot_uid, &master_key).await?;

    let used_otp_id = envelope.x3dh_initial.used_one_time_prekey_id;
    let otk_secret = match used_otp_id {
        Some(id) => {
            let idx = material
                .one_time_prekeys
                .iter()
                .position(|otp| otp.key_id == id)
                .ok_or(BotE2eeError::OneTimePrekeyUnavailable)?;
            Some(material.one_time_prekeys.remove(idx).secret)
        }
        None => None,
    };
    let local_identity = DeferredLocalIdentity {
        ik_secret: material.identity_x25519,
        spk_secret: material.signed_prekey_secret,
        otk_secret,
    };
    let content_key = deferred_unwrap_key(&envelope, &local_identity)?;

    // Metadata handling for the server-managed Bot wire shape.
    //
    // In this wire format the AAD commitment (`sha256`) is derived locally
    // from the `metadata` we just parsed and is never transmitted (see the
    // module docs' "Wire contract"). So `deferred_verify_metadata` below,
    // which compares `commitment(metadata)` against a `sha256` that *is*
    // `commitment(metadata)`, is a tautology -- it cannot fail and is NOT
    // an independent tamper-evidence layer.
    //
    // The real tamper-evidence is the AEAD tag inside `deferred_decrypt`:
    // `sha256` is used as the AES-256-GCM AAD, so any mutation of the
    // relayed `metadata` (which changes the derived `sha256`) or of the
    // ciphertext makes the tag check fail with no plaintext fallback. The
    // `deferred_verify_metadata` call is kept purely as explicit Task 3
    // contract compliance ("recipients MUST verify the commitment"); it is
    // deliberately not relied upon for security. Do not treat its success
    // as proof of anything -- the AEAD open is the gate.
    let sha256 = deferred_metadata_commitment(&wire.metadata)?;
    if !deferred_verify_metadata(&wire.metadata, &sha256)? {
        return Err(BotE2eeError::MetadataMismatch);
    }
    let plaintext_bytes = deferred_decrypt(&ciphertext, &content_key, &nonce, &sha256)?;

    if used_otp_id.is_some() {
        // One-time-use: persist the vault with that OTP secret removed so
        // the same envelope can never be unwrapped via it again.
        persist_material(&state.db_pool, bot_uid, &master_key, &material).await?;
    }

    let content_type = wire
        .metadata
        .get("content_type")
        .and_then(|v| v.as_str())
        .unwrap_or("text/plain")
        .to_string();
    let sender_uid = merged.from_uid;
    let plaintext = String::from_utf8(plaintext_bytes)
        .map_err(|_| BotE2eeError::Crypto("decrypted content is not valid utf-8".into()))?;

    crate::state::deliver_bot_webhook_plaintext(state, bot_uid, mid, sender_uid, &content_type, &plaintext)
        .await;

    audit(
        &state.db_pool,
        bot_uid,
        None,
        "inbound_decrypted",
        serde_json::json!({ "mid": mid, "sender_uid": sender_uid, "device_id": device_id }),
    )
    .await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex, OnceLock};

    use serde_json::json;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::Mutex as AsyncMutex,
    };

    use super::*;
    use crate::test_harness::TestServer;

    /// The master key env var is process-global; serialize the (small)
    /// set of tests that mutate it so parallel `cargo test` runs don't
    /// race each other.
    fn env_guard() -> &'static Mutex<()> {
        static GUARD: OnceLock<Mutex<()>> = OnceLock::new();
        GUARD.get_or_init(|| Mutex::new(()))
    }

    struct MasterKeyEnvGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        _file: Option<tempfile::TempPath>,
    }

    impl Drop for MasterKeyEnvGuard {
        fn drop(&mut self) {
            std::env::remove_var(crate::config::BOT_E2EE_MASTER_KEY_FILE_ENV);
        }
    }

    fn set_master_key_env(key: &[u8; 32]) -> MasterKeyEnvGuard {
        let lock = env_guard().lock().unwrap_or_else(|e| e.into_inner());
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), base64::encode(key)).unwrap();
        let path = file.into_temp_path();
        std::env::set_var(crate::config::BOT_E2EE_MASTER_KEY_FILE_ENV, path.to_path_buf());
        MasterKeyEnvGuard {
            _lock: lock,
            _file: Some(path),
        }
    }

    fn clear_master_key_env() -> MasterKeyEnvGuard {
        let lock = env_guard().lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var(crate::config::BOT_E2EE_MASTER_KEY_FILE_ENV);
        MasterKeyEnvGuard {
            _lock: lock,
            _file: None,
        }
    }

    fn test_master_key() -> [u8; 32] {
        [7u8; 32]
    }

    // -- unit tests: master key + vault seal/open ------------------------

    #[test]
    fn master_key_missing_env_fails_closed() {
        let _guard = clear_master_key_env();
        assert!(matches!(load_master_key(), Err(BotE2eeError::MissingMasterKey)));
    }

    #[test]
    fn master_key_wrong_length_fails_closed() {
        let _guard = env_guard().lock().unwrap_or_else(|e| e.into_inner());
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), base64::encode([1u8; 16])).unwrap();
        std::env::set_var(crate::config::BOT_E2EE_MASTER_KEY_FILE_ENV, file.path());
        let result = load_master_key();
        std::env::remove_var(crate::config::BOT_E2EE_MASTER_KEY_FILE_ENV);
        assert!(matches!(result, Err(BotE2eeError::InvalidMasterKey)));
    }

    #[test]
    fn master_key_valid_loads_exact_bytes() {
        let key = test_master_key();
        let _guard = set_master_key_env(&key);
        assert_eq!(load_master_key().unwrap(), key);
    }

    #[test]
    fn vault_seal_open_roundtrip_and_wrong_key_fails() {
        let key_a = [3u8; 32];
        let key_b = [9u8; 32];
        let plaintext = b"bot secret material for unit test";
        let (nonce, ciphertext) = seal(&key_a, plaintext).unwrap();
        assert_ne!(ciphertext, plaintext.to_vec(), "must not store plaintext at rest");
        // encrypted-at-rest: ciphertext must not contain the plaintext bytes verbatim.
        assert!(!contains_subslice(&ciphertext, plaintext));
        let opened = open(&key_a, &nonce, &ciphertext).unwrap();
        assert_eq!(opened, plaintext);
        assert!(matches!(open(&key_b, &nonce, &ciphertext), Err(BotE2eeError::VaultDecryptFailed)));
    }

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    // -- helpers for integration tests -----------------------------------

    /// Create a Bot user with a throwaway (always-200) webhook, for tests
    /// that don't care about webhook delivery content.
    async fn create_bot(server: &TestServer, admin_token: &str, email: &str) -> i64 {
        let (webhook_url, _captured) = spawn_webhook_capture().await;
        create_bot_with_webhook(server, admin_token, email, &webhook_url).await
    }

    async fn create_bot_with_webhook(server: &TestServer, admin_token: &str, email: &str, webhook_url: &str) -> i64 {
        let resp = server
            .post("/api/admin/user")
            .header("X-API-Key", admin_token)
            .body_json(&json!({
                "email": email,
                "password": "123456",
                "name": email,
                "gender": 1,
                "language": "en-US",
                "is_admin": false,
                "is_bot": true,
                "webhook_url": webhook_url,
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        resp.json().await.value().object().get("uid").i64()
    }

    /// Minimal raw-HTTP capture server (no new test dependency): accepts
    /// requests, extracts each JSON body via Content-Length, replies 200
    /// OK. Used both as an always-up webhook target for `create_bot`, and
    /// to prove plaintext reaches only the target Bot's own webhook.
    async fn spawn_webhook_capture() -> (String, Arc<AsyncMutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let captured = Arc::new(AsyncMutex::new(Vec::new()));
        let captured_clone = captured.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let captured = captured_clone.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 65536];
                    let mut total = 0usize;
                    let mut headers_end = None;
                    loop {
                        let n = socket.read(&mut buf[total..]).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        total += n;
                        if headers_end.is_none() {
                            if let Some(pos) = buf[..total]
                                .windows(4)
                                .position(|w| w == [b'\r', b'\n', b'\r', b'\n'])
                            {
                                headers_end = Some(pos + 4);
                            }
                        }
                        if let Some(end) = headers_end {
                            let header_str = String::from_utf8_lossy(&buf[..end]);
                            let content_length = header_str.lines().find_map(|line| {
                                let lower = line.to_ascii_lowercase();
                                lower.strip_prefix("content-length:").and_then(|rest| {
                                    rest.trim().parse::<usize>().ok()
                                })
                            });
                            let content_length = content_length.unwrap_or(0);
                            if total >= end + content_length {
                                let body =
                                    String::from_utf8_lossy(&buf[end..end + content_length])
                                        .to_string();
                                if !body.is_empty() {
                                    captured.lock().await.push(body);
                                }
                                break;
                            }
                        }
                        if total >= buf.len() {
                            break;
                        }
                    }
                    let mut response = Vec::new();
                    response.extend_from_slice(b"HTTP/1.1 200 OK");
                    response.extend_from_slice(&[b'\r', b'\n']);
                    response.extend_from_slice(b"Content-Length: 0");
                    response.extend_from_slice(&[b'\r', b'\n']);
                    response.extend_from_slice(b"Connection: close");
                    response.extend_from_slice(&[b'\r', b'\n', b'\r', b'\n']);
                    let _ = socket.write_all(&response).await;
                });
            }
        });
        (format!("http://{addr}/webhook"), captured)
    }

    async fn wait_for_capture(captured: &Arc<AsyncMutex<Vec<String>>>, min_len: usize) {
        for _ in 0..50 {
            if captured.lock().await.len() >= min_len {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    // -- vault lifecycle integration tests --------------------------------

    #[tokio::test]
    async fn initialize_fails_closed_without_master_key() {
        let _guard = clear_master_key_env();
        let server = TestServer::new().await;
        let admin = server.login_admin().await;
        let bot_uid = create_bot(&server, &admin, "novault-bot@voce.chat").await;

        let err = initialize(server.state(), 1, bot_uid).await.unwrap_err();
        assert!(matches!(err, BotE2eeError::MissingMasterKey));
        assert_eq!(err.code(), "E2E_BOT_MASTER_KEY_MISSING");
        assert!(!err.message_zh().is_empty(), "must have a zh message too");

        // Never persisted a row.
        assert!(load_identity_row(&server.state().db_pool, bot_uid).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn initialize_is_encrypted_at_rest_and_status_never_leaks_secrets() {
        let key = test_master_key();
        let _guard = set_master_key_env(&key);
        let server = TestServer::new().await;
        let admin = server.login_admin().await;
        let bot_uid = create_bot(&server, &admin, "vault-bot@voce.chat").await;

        let initialized = initialize(server.state(), 1, bot_uid).await.unwrap();
        assert!(initialized.initialized);
        assert_eq!(initialized.key_version, Some(1));
        assert!(initialized.master_key_available);

        let row = load_identity_row(&server.state().db_pool, bot_uid).await.unwrap().unwrap();
        // Encrypted at rest: raw ciphertext bytes never contain the raw
        // 32-byte identity/signed-prekey/OTP secrets we can recover after
        // decrypting.
        let material = load_and_decrypt_material(&server.state().db_pool, bot_uid, &key).await.unwrap();
        assert!(!contains_subslice(&row.ciphertext, &material.identity_x25519));
        assert!(!contains_subslice(&row.ciphertext, &material.signed_prekey_secret));

        // Wrong master key must not decrypt.
        let wrong_key = [42u8; 32];
        assert!(load_and_decrypt_material(&server.state().db_pool, bot_uid, &wrong_key)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn status_and_admin_api_agree_and_forbid_non_admin() {
        let key = test_master_key();
        let _guard = set_master_key_env(&key);
        let server = TestServer::new().await;
        let admin = server.login_admin().await;
        let bot_uid = create_bot(&server, &admin, "status-bot@voce.chat").await;

        let resp = server
            .get(format!("/api/admin/user/bot-e2ee/{bot_uid}/status"))
            .header("X-API-Key", &admin)
            .send()
            .await;
        resp.assert_status_is_ok();
        assert!(!resp.json().await.value().object().get("initialized").bool());

        let resp = server
            .post(format!("/api/admin/user/bot-e2ee/{bot_uid}/initialize"))
            .header("X-API-Key", &admin)
            .send()
            .await;
        resp.assert_status_is_ok();
        let body = resp.json().await;
        body.value().object().get("initialized").assert_bool(true);
        body.value().object().get("key_version").assert_i64(1);

        // Non-admin forbidden.
        let _non_admin_uid = create_bot(&server, &admin, "status-user@voce.chat").await;
        let user_token = server.login("status-user@voce.chat").await;
        server
            .get(format!("/api/admin/user/bot-e2ee/{bot_uid}/status"))
            .header("X-API-Key", &user_token)
            .send()
            .await
            .assert_status(poem::http::StatusCode::FORBIDDEN);

        // Double-initialize is rejected.
        let resp = server
            .post(format!("/api/admin/user/bot-e2ee/{bot_uid}/initialize"))
            .header("X-API-Key", &admin)
            .send()
            .await;
        resp.assert_status(poem::http::StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn rotate_bumps_key_version_and_replaces_signed_prekey() {
        let key = test_master_key();
        let _guard = set_master_key_env(&key);
        let server = TestServer::new().await;
        let admin = server.login_admin().await;
        let bot_uid = create_bot(&server, &admin, "rotate-bot@voce.chat").await;
        initialize(server.state(), 1, bot_uid).await.unwrap();
        let before = load_identity_row(&server.state().db_pool, bot_uid).await.unwrap().unwrap();

        let rotated = rotate(server.state(), 1, bot_uid).await.unwrap();
        assert_eq!(rotated.key_version, Some(2));

        let after = load_identity_row(&server.state().db_pool, bot_uid).await.unwrap().unwrap();
        assert_eq!(after.device_id, before.device_id, "device id is stable across rotation");
        assert_eq!(after.identity_key_pub, before.identity_key_pub, "identity stays the same on rotate");
        assert_ne!(after.ciphertext, before.ciphertext, "vault ciphertext must change on rotate");
        assert!(after.rotated_at.is_some());
    }

    #[tokio::test]
    async fn rebuild_requires_confirmation_and_is_destructive() {
        let key = test_master_key();
        let _guard = set_master_key_env(&key);
        let server = TestServer::new().await;
        let admin = server.login_admin().await;
        let bot_uid = create_bot(&server, &admin, "rebuild-bot@voce.chat").await;
        initialize(server.state(), 1, bot_uid).await.unwrap();
        let before = load_identity_row(&server.state().db_pool, bot_uid).await.unwrap().unwrap();

        let resp = server
            .post(format!("/api/admin/user/bot-e2ee/{bot_uid}/rebuild"))
            .header("X-API-Key", &admin)
            .body_json(&json!({ "confirm": false }))
            .send()
            .await;
        resp.assert_status(poem::http::StatusCode::BAD_REQUEST);
        let expected_body = serde_json::json!({
            "code": BotE2eeError::ConfirmationRequired.code(),
            "message_en": BotE2eeError::ConfirmationRequired.message_en(),
            "message_zh": BotE2eeError::ConfirmationRequired.message_zh(),
        })
        .to_string();
        resp.assert_text(expected_body).await;
        // Nothing changed.
        let unchanged = load_identity_row(&server.state().db_pool, bot_uid).await.unwrap().unwrap();
        assert_eq!(unchanged.identity_key_pub, before.identity_key_pub);

        let resp = server
            .post(format!("/api/admin/user/bot-e2ee/{bot_uid}/rebuild"))
            .header("X-API-Key", &admin)
            .body_json(&json!({ "confirm": true }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let after = load_identity_row(&server.state().db_pool, bot_uid).await.unwrap().unwrap();
        assert_eq!(after.key_version, before.key_version + 1);
        assert_ne!(after.identity_key_pub, before.identity_key_pub, "rebuild must generate a fresh identity");
    }

    #[tokio::test]
    async fn channel_admission_requires_initialized_bot_and_publishes_key_package() {
        let key = test_master_key();
        let _guard = set_master_key_env(&key);
        let server = TestServer::new().await;
        let admin = server.login_admin().await;
        let bot_uid = create_bot(&server, &admin, "mls-bot@voce.chat").await;
        let gid = {
            let resp = server
                .post("/api/group")
                .header("X-API-Key", &admin)
                .body_json(&json!({ "name": "bot-channel", "is_public": true, "members": [] }))
                .send()
                .await;
            resp.assert_status_is_ok();
            resp.json().await.value().object().get("gid").i64()
        };

        // Fails closed: not initialized yet.
        let err = set_channel_enabled(server.state(), 1, bot_uid, gid, true).await.unwrap_err();
        assert!(matches!(err, BotE2eeError::NotInitialized));

        initialize(server.state(), 1, bot_uid).await.unwrap();
        let channel_status = set_channel_enabled(server.state(), 1, bot_uid, gid, true).await.unwrap();
        assert!(channel_status.enabled);
        assert!(channel_status.credential_published);
        assert!(channel_status.key_package_published);

        // Another client can consume the published key package (real
        // admission plumbing, even though the package content itself is
        // a placeholder -- see module docs).
        let device_id = bot_device_id(bot_uid);
        let package = mls_delivery::consume_key_package(&server.state().db_pool, bot_uid, &device_id)
            .await
            .unwrap();
        assert!(!package.is_empty());

        // Disabling + re-querying status (independent DB round trips ==
        // the restart-equivalent guarantee, since nothing here is cached
        // in-process) shows the channel is no longer enabled.
        set_channel_enabled(server.state(), 1, bot_uid, gid, false).await.unwrap();
        let restatus = status(server.state(), bot_uid).await.unwrap();
        assert!(restatus.enabled_channels.is_empty());
    }

    // -- outbound: Bot -> human, incl. deferred for keyless humans -------

    #[tokio::test]
    async fn outbound_dm_to_keyless_human_is_pending_then_auto_catches_up() {
        let key = test_master_key();
        let _guard = set_master_key_env(&key);
        let server = TestServer::new().await;
        let admin = server.login_admin().await;
        let bot_uid = create_bot(&server, &admin, "sender-bot@voce.chat").await;
        initialize(server.state(), 1, bot_uid).await.unwrap();
        let target_uid = server.create_user(&admin, "keyless-human@voce.chat").await;

        let mid = send_bot_dm(server.state(), bot_uid, target_uid, "text/plain", "hello keyless human")
            .await
            .unwrap();

        // No envelope yet; content key retained encrypted for catch-up.
        let envelope_count: i64 = sqlx::query_scalar("select count(*) from e2e_pending_envelope where mid = ?")
            .bind(mid)
            .fetch_one(&server.state().db_pool)
            .await
            .unwrap();
        assert_eq!(envelope_count, 0);
        let secret_row: Option<(i64,)> =
            sqlx::query_as("select uid from bot_e2ee_pending_secret where mid = ?")
                .bind(mid)
                .fetch_optional(&server.state().db_pool)
                .await
                .unwrap();
        assert_eq!(secret_row, Some((bot_uid,)));

        // Human publishes a real (deferred-crypto-capable) identity ->
        // server auto-catches-up an envelope on the Bot's behalf.
        let token = server.login_with_device("keyless-human@voce.chat", "phone-1").await;
        let (human_secret, human_public) = IdentitySecret::generate();
        let (human_spk_secret, human_spk_public) = human_secret.generate_signed_prekey(1).unwrap();
        server
            .put("/api/user/e2e/identity")
            .header("X-API-Key", &token)
            .body_json(&json!({
                "device_id": "phone-1",
                "identity_key_pub": serde_json::to_string(&human_public).unwrap(),
                "signed_prekey_pub": human_spk_public.dh_pub_b64,
                "signed_prekey_sig": human_spk_public.signature_b64,
            }))
            .send()
            .await
            .assert_status_is_ok();

        let envelope_b64: String = sqlx::query_scalar(
            "select envelope from e2e_pending_envelope where mid = ? and recipient_uid = ? and device_id = ?",
        )
        .bind(mid)
        .bind(target_uid)
        .bind("phone-1")
        .fetch_one(&server.state().db_pool)
        .await
        .unwrap();

        // Prove decryptability end-to-end from the human recipient's
        // perspective, using voce-e2ee-core directly (simulated client).
        let merged = get_merged_message(&server.state().msg_db, mid).unwrap().unwrap();
        let wire: InboundWire = serde_json::from_str(&merged.content.content).unwrap();
        let envelope: DeferredEnvelope =
            serde_json::from_slice(&base64::decode(&envelope_b64).unwrap()).unwrap();
        let local_identity = DeferredLocalIdentity {
            ik_secret: human_secret.x25519,
            spk_secret: human_spk_secret.secret,
            otk_secret: None,
        };
        let content_key = deferred_unwrap_key(&envelope, &local_identity).unwrap();
        let sha256 = deferred_metadata_commitment(&wire.metadata).unwrap();
        assert!(deferred_verify_metadata(&wire.metadata, &sha256).unwrap());
        let ciphertext = base64::decode(&wire.ciphertext_b64).unwrap();
        let nonce_bytes = base64::decode(&wire.nonce_b64).unwrap();
        let nonce: [u8; 12] = nonce_bytes.try_into().unwrap();
        let plaintext = deferred_decrypt(&ciphertext, &content_key, &nonce, &sha256).unwrap();
        assert_eq!(plaintext, b"hello keyless human");
    }

    #[tokio::test]
    async fn outbound_dm_to_human_with_existing_identity_wraps_immediately_and_decrypts() {
        let key = test_master_key();
        let _guard = set_master_key_env(&key);
        let server = TestServer::new().await;
        let admin = server.login_admin().await;
        let bot_uid = create_bot(&server, &admin, "sender-bot2@voce.chat").await;
        initialize(server.state(), 1, bot_uid).await.unwrap();
        let target_uid = server.create_user(&admin, "keyed-human@voce.chat").await;
        let token = server.login_with_device("keyed-human@voce.chat", "phone-1").await;

        let (human_secret, human_public) = IdentitySecret::generate();
        let (human_spk_secret, human_spk_public) = human_secret.generate_signed_prekey(1).unwrap();
        server
            .put("/api/user/e2e/identity")
            .header("X-API-Key", &token)
            .body_json(&json!({
                "device_id": "phone-1",
                "identity_key_pub": serde_json::to_string(&human_public).unwrap(),
                "signed_prekey_pub": human_spk_public.dh_pub_b64,
                "signed_prekey_sig": human_spk_public.signature_b64,
            }))
            .send()
            .await
            .assert_status_is_ok();

        let mid = send_bot_dm(server.state(), bot_uid, target_uid, "text/plain", "hello keyed human")
            .await
            .unwrap();

        let envelope_b64: String = sqlx::query_scalar(
            "select envelope from e2e_pending_envelope where mid = ? and recipient_uid = ? and device_id = ?",
        )
        .bind(mid)
        .bind(target_uid)
        .bind("phone-1")
        .fetch_one(&server.state().db_pool)
        .await
        .unwrap();
        // Immediate wrap: no catch-up secret retained.
        let secret_row: Option<(i64,)> =
            sqlx::query_as("select uid from bot_e2ee_pending_secret where mid = ?")
                .bind(mid)
                .fetch_optional(&server.state().db_pool)
                .await
                .unwrap();
        assert!(secret_row.is_none());

        let merged = get_merged_message(&server.state().msg_db, mid).unwrap().unwrap();
        let wire: InboundWire = serde_json::from_str(&merged.content.content).unwrap();
        let envelope: DeferredEnvelope =
            serde_json::from_slice(&base64::decode(&envelope_b64).unwrap()).unwrap();
        let local_identity = DeferredLocalIdentity {
            ik_secret: human_secret.x25519,
            spk_secret: human_spk_secret.secret,
            otk_secret: None,
        };
        let content_key = deferred_unwrap_key(&envelope, &local_identity).unwrap();
        let sha256 = deferred_metadata_commitment(&wire.metadata).unwrap();
        assert!(deferred_verify_metadata(&wire.metadata, &sha256).unwrap());
        let ciphertext = base64::decode(&wire.ciphertext_b64).unwrap();
        let nonce_bytes = base64::decode(&wire.nonce_b64).unwrap();
        let nonce: [u8; 12] = nonce_bytes.try_into().unwrap();
        let plaintext = deferred_decrypt(&ciphertext, &content_key, &nonce, &sha256).unwrap();
        assert_eq!(plaintext, b"hello keyed human");
    }

    // -- inbound: human -> Bot, decrypt only in Bot context --------------

    #[tokio::test]
    async fn inbound_dm_to_bot_decrypts_and_reaches_only_that_bots_webhook() {
        let key = test_master_key();
        let _guard = set_master_key_env(&key);
        let server = TestServer::new().await;
        let admin = server.login_admin().await;
        let (webhook_url, captured) = spawn_webhook_capture().await;
        let bot_uid = create_bot_with_webhook(&server, &admin, "recipient-bot@voce.chat", &webhook_url).await;
        initialize(server.state(), 1, bot_uid).await.unwrap();

        let _sender_uid = server.create_user(&admin, "sender-human@voce.chat").await;
        let sender_token = server.login_with_device("sender-human@voce.chat", "phone-1").await;

        // Fetch the Bot's real published bundle exactly like a client would.
        let resp = server
            .get(format!("/api/user/e2e/bundle/{bot_uid}"))
            .header("X-API-Key", &sender_token)
            .send()
            .await;
        resp.assert_status_is_ok();
        let bundle_json = resp.json().await;
        let bundle_obj = bundle_json.value().object();
        let bot_device_id_value = bundle_obj.get("device_id").string().to_string();
        let bot_identity: IdentityPublic =
            serde_json::from_str(bundle_obj.get("identity_key_pub").string()).unwrap();
        let bot_signed_prekey = SignedPreKeyPublic {
            key_id: 1,
            dh_pub_b64: bundle_obj.get("signed_prekey_pub").string().to_string(),
            signature_b64: bundle_obj.get("signed_prekey_sig").string().to_string(),
        };
        let bundle = PreKeyBundle {
            identity: bot_identity,
            signed_prekey: bot_signed_prekey,
            one_time_prekey_b64: None,
            one_time_prekey_id: None,
        };

        let local_id = "human-to-bot-local-id-1";
        let plaintext = b"secret hello for the bot";
        let metadata = json!({ "local_id": local_id });
        let encrypted = deferred_encrypt(plaintext, &metadata).unwrap();
        let envelope = deferred_wrap_key(&encrypted.content_key, &bundle).unwrap();

        let content_json = json!({
            "ciphertext_b64": base64::encode(&encrypted.ciphertext),
            "nonce_b64": base64::encode(&encrypted.nonce),
            "metadata": metadata,
        })
        .to_string();
        let properties = json!({
            "e2e_version": 2,
            "protocol": "dr-pending",
            "algorithm": "DEFERRED+AES-GCM",
            "wire_class": "dr_envelope",
            "sender_device_id": "phone-1",
            "local_id": local_id,
        });

        let resp = server
            .post(format!("/api/user/{bot_uid}/send"))
            .header("X-API-Key", &sender_token)
            .header("X-Properties", base64::encode(properties.to_string()))
            .content_type(crate::e2ee_v2::CONTENT_TYPE)
            .body(content_json)
            .send()
            .await;
        resp.assert_status_is_ok();
        let mid = resp.json().await.value().i64();

        let envelope_b64 = base64::encode(serde_json::to_vec(&envelope).unwrap());
        server
            .post(format!("/api/user/e2e/pending/{mid}/envelope"))
            .header("X-API-Key", &sender_token)
            .body_json(&json!({
                "recipient_uid": bot_uid,
                "device_id": bot_device_id_value,
                "envelope": envelope_b64,
            }))
            .send()
            .await
            .assert_status_is_ok();

        // Two deliveries should land at this Bot's webhook: the generic
        // (opaque, unchanged) forwarder at send time, and the Bot-context
        // plaintext delivery once the envelope completed.
        wait_for_capture(&captured, 2).await;
        let bodies = captured.lock().await.clone();
        assert!(bodies.len() >= 2, "expected both generic-opaque and bot-plaintext deliveries, got {bodies:?}");
        assert!(
            bodies.iter().any(|b| b.contains("e2e_opaque")),
            "generic webhook forwarding must still redact E2E content"
        );
        assert!(
            bodies.iter().any(|b| b.contains("secret hello for the bot")),
            "the target bot's own webhook must receive the decrypted plaintext"
        );

        // Audit trail carries identifiers only, never the plaintext.
        let audit_rows: Vec<(String, String)> = sqlx::query_as(
            "select action, detail from bot_e2ee_audit where uid = ? order by id",
        )
        .bind(bot_uid)
        .fetch_all(&server.state().db_pool)
        .await
        .unwrap();
        assert!(audit_rows.iter().any(|(action, _)| action == "inbound_decrypted"));
        for (_, detail) in &audit_rows {
            assert!(!detail.contains("secret hello for the bot"));
        }
    }

    #[tokio::test]
    async fn send_bot_dm_fails_closed_if_master_key_removed_after_initialize() {
        let key = test_master_key();
        let _guard = set_master_key_env(&key);
        let server = TestServer::new().await;
        let admin = server.login_admin().await;
        let bot_uid = create_bot(&server, &admin, "revoked-key-bot@voce.chat").await;
        initialize(server.state(), 1, bot_uid).await.unwrap();
        let target_uid = server.create_user(&admin, "revoked-key-target@voce.chat").await;

        // Key present: normal send succeeds.
        send_bot_dm(server.state(), bot_uid, target_uid, "text/plain", "before revoke")
            .await
            .unwrap();

        // Operator removes the key file/env mid-flight: further sends must
        // fail closed rather than silently falling back to plaintext.
        std::env::remove_var(crate::config::BOT_E2EE_MASTER_KEY_FILE_ENV);
        let err = send_bot_dm(server.state(), bot_uid, target_uid, "text/plain", "after revoke")
            .await
            .unwrap_err();
        assert!(matches!(err, BotE2eeError::MissingMasterKey));
    }

    // -- review-fix helpers ----------------------------------------------

    async fn create_bot_api_key(server: &TestServer, admin_token: &str, bot_uid: i64) -> String {
        let resp = server
            .post(format!("/api/admin/user/bot-api-key/{bot_uid}"))
            .header("X-API-Key", admin_token)
            .body_json(&json!({ "name": "primary" }))
            .send()
            .await;
        resp.assert_status_is_ok();
        resp.json().await.value().string().to_string()
    }

    /// Publish a real deferred-crypto-capable identity (JSON `IdentityPublic`
    /// in `identity_key_pub`, per the wire contract) for `token`'s device.
    async fn publish_deferred_identity(server: &TestServer, token: &str, device_id: &str) {
        let (secret, public) = IdentitySecret::generate();
        let (_spk_secret, spk_public) = secret.generate_signed_prekey(1).unwrap();
        server
            .put("/api/user/e2e/identity")
            .header("X-API-Key", token)
            .body_json(&json!({
                "device_id": device_id,
                "identity_key_pub": serde_json::to_string(&public).unwrap(),
                "signed_prekey_pub": spk_public.dh_pub_b64,
                "signed_prekey_sig": spk_public.signature_b64,
            }))
            .send()
            .await
            .assert_status_is_ok();
    }

    /// Insert one one-time prekey row for a device with a real
    /// (X3DH-decodable) X25519 public key, so `deferred_wrap_key` succeeds.
    async fn insert_valid_otp(pool: &SqlitePool, uid: i64, device_id: &str, key_id: i32) {
        let (_sec, _pub) = IdentitySecret::generate();
        let (_spk_sec, spk_pub) = _sec.generate_signed_prekey(key_id as u32).unwrap();
        sqlx::query(
            "insert into e2e_prekey (uid, device_id, key_id, public_key, consumed) values (?, ?, ?, ?, false)",
        )
        .bind(uid)
        .bind(device_id)
        .bind(key_id)
        .bind(spk_pub.dh_pub_b64)
        .execute(pool)
        .await
        .unwrap();
    }

    // -- IMPORTANT 1: HTTP transparent-encryption path -------------------

    #[tokio::test]
    async fn http_bot_send_transparently_encrypts_plaintext_for_human_with_devices() {
        let key = test_master_key();
        let _guard = set_master_key_env(&key);
        let server = TestServer::new().await;
        let admin = server.login_admin().await;
        let bot_uid = create_bot(&server, &admin, "http-enc-bot@voce.chat").await;
        initialize(server.state(), 1, bot_uid).await.unwrap();
        let bot_key = create_bot_api_key(&server, &admin, bot_uid).await;

        let target_uid = server.create_user(&admin, "http-enc-target@voce.chat").await;
        let token = server
            .login_with_device("http-enc-target@voce.chat", "phone-1")
            .await;
        publish_deferred_identity(&server, &token, "phone-1").await;

        // Plain Text POST to the real Bot send API -> must be intercepted by
        // maybe_send_as_managed_bot and stored as an E2EE v2 envelope, not
        // plaintext.
        let resp = server
            .post(format!("/api/bot/send_to_user/{target_uid}"))
            .header("x-api-key", &bot_key)
            .content_type("text/plain")
            .body("hello from bot over http")
            .send()
            .await;
        resp.assert_status_is_ok();
        let mid = resp.json().await.value().i64();

        let merged = get_merged_message(&server.state().msg_db, mid).unwrap().unwrap();
        assert_eq!(
            merged.content.content_type,
            crate::e2ee_v2::CONTENT_TYPE,
            "plain Bot send must be transparently encrypted, not stored as plaintext"
        );
        assert!(
            !merged.content.content.contains("hello from bot over http"),
            "stored content must not contain the plaintext body"
        );
        // An envelope was wrapped immediately for the human's usable device.
        let envelope_count: i64 = sqlx::query_scalar(
            "select count(*) from e2e_pending_envelope where mid = ? and recipient_uid = ?",
        )
        .bind(mid)
        .bind(target_uid)
        .fetch_one(&server.state().db_pool)
        .await
        .unwrap();
        assert_eq!(envelope_count, 1);
    }

    #[tokio::test]
    async fn http_bot_send_not_intercepted_when_uninitialized_or_bot_to_bot() {
        use poem::http::StatusCode;

        let key = test_master_key();
        let _guard = set_master_key_env(&key);
        let server = TestServer::new().await;
        let admin = server.login_admin().await;

        // (a) Uninitialized Bot -> human: NOT intercepted, so it falls
        // through to the normal send path, which (gen-2) rejects plaintext
        // with E2E_REQUIRED. A 200 here would mean it was wrongly
        // intercepted+encrypted.
        let uninit_bot = create_bot(&server, &admin, "http-uninit-bot@voce.chat").await;
        let uninit_key = create_bot_api_key(&server, &admin, uninit_bot).await;
        let human_uid = server.create_user(&admin, "http-uninit-human@voce.chat").await;
        let human_token = server
            .login_with_device("http-uninit-human@voce.chat", "phone-1")
            .await;
        publish_deferred_identity(&server, &human_token, "phone-1").await;

        let resp = server
            .post(format!("/api/bot/send_to_user/{human_uid}"))
            .header("x-api-key", &uninit_key)
            .content_type("text/plain")
            .body("should not be intercepted")
            .send()
            .await;
        resp.assert_status(StatusCode::FORBIDDEN);
        resp.assert_text("E2E_REQUIRED").await;

        // (b) Initialized Bot -> another Bot: Bot-to-Bot is NOT intercepted
        // (Bot conversations with the *target* Bot are that Bot's inbound
        // concern, not the sender's transparent-encryption path). Falls
        // through to the normal path -> E2E_REQUIRED.
        let sender_bot = create_bot(&server, &admin, "http-sender-bot@voce.chat").await;
        initialize(server.state(), 1, sender_bot).await.unwrap();
        let sender_key = create_bot_api_key(&server, &admin, sender_bot).await;
        let other_bot = create_bot(&server, &admin, "http-other-bot@voce.chat").await;

        let resp = server
            .post(format!("/api/bot/send_to_user/{other_bot}"))
            .header("x-api-key", &sender_key)
            .content_type("text/plain")
            .body("bot to bot")
            .send()
            .await;
        resp.assert_status(StatusCode::FORBIDDEN);
        resp.assert_text("E2E_REQUIRED").await;
    }

    // -- IMPORTANT 2: atomic OTP consumption -----------------------------

    #[tokio::test]
    async fn concurrent_otp_consumes_never_share_an_id() {
        let key = test_master_key();
        let _guard = set_master_key_env(&key);
        let server = TestServer::new().await;
        let admin = server.login_admin().await;
        let target_uid = server.create_user(&admin, "otp-race-target@voce.chat").await;
        let token = server
            .login_with_device("otp-race-target@voce.chat", "phone-1")
            .await;
        publish_deferred_identity(&server, &token, "phone-1").await;
        for key_id in 1..=4 {
            insert_valid_otp(&server.state().db_pool, target_uid, "phone-1", key_id).await;
        }

        let device = fetch_one_device(&server.state().db_pool, target_uid, "phone-1")
            .await
            .unwrap()
            .expect("device is deferred-capable");
        let content_key = [5u8; 32];

        // Two concurrent wraps against the same OTP pool. The atomic
        // `and consumed = false` claim + retry must hand each a distinct OTP
        // id; neither may reuse the other's prekey.
        let (r1, r2) = tokio::join!(
            wrap_content_key_for_device(&server.state().db_pool, &content_key, &device),
            wrap_content_key_for_device(&server.state().db_pool, &content_key, &device),
        );
        let e1 = r1.unwrap().expect("wrap 1 produced an envelope");
        let e2 = r2.unwrap().expect("wrap 2 produced an envelope");
        let id1 = e1.x3dh_initial.used_one_time_prekey_id;
        let id2 = e2.x3dh_initial.used_one_time_prekey_id;
        assert!(id1.is_some() && id2.is_some(), "both wraps should use an OTP");
        assert_ne!(id1, id2, "two concurrent consumes must not share an OTP id");

        // Exactly two OTPs were consumed.
        let consumed: i64 = sqlx::query_scalar(
            "select count(*) from e2e_prekey where uid = ? and device_id = ? and consumed = true",
        )
        .bind(target_uid)
        .bind("phone-1")
        .fetch_one(&server.state().db_pool)
        .await
        .unwrap();
        assert_eq!(consumed, 2);
    }

    #[tokio::test]
    async fn try_consume_one_time_prekey_is_single_winner() {
        let key = test_master_key();
        let _guard = set_master_key_env(&key);
        let server = TestServer::new().await;
        let admin = server.login_admin().await;
        let uid = server.create_user(&admin, "otp-guard@voce.chat").await;
        let token = server.login_with_device("otp-guard@voce.chat", "phone-1").await;
        publish_deferred_identity(&server, &token, "phone-1").await;
        insert_valid_otp(&server.state().db_pool, uid, "phone-1", 1).await;

        let (id, _, _) = peek_one_time_prekey(&server.state().db_pool, uid, "phone-1")
            .await
            .unwrap()
            .unwrap();
        // First claim wins; second claim of the same id loses (guard works).
        assert!(try_consume_one_time_prekey(&server.state().db_pool, id).await.unwrap());
        assert!(!try_consume_one_time_prekey(&server.state().db_pool, id).await.unwrap());
    }

    // -- IMPORTANT 3: failed wrap must not burn an OTP -------------------

    #[tokio::test]
    async fn failed_wrap_does_not_consume_otp() {
        let key = test_master_key();
        let _guard = set_master_key_env(&key);
        let server = TestServer::new().await;
        let admin = server.login_admin().await;
        let target_uid = server.create_user(&admin, "otp-wrapfail-target@voce.chat").await;
        let token = server
            .login_with_device("otp-wrapfail-target@voce.chat", "phone-1")
            .await;
        publish_deferred_identity(&server, &token, "phone-1").await;
        // A single, corrupt OTP whose public key cannot be X3DH-decoded, so
        // `deferred_wrap_key` fails.
        sqlx::query(
            "insert into e2e_prekey (uid, device_id, key_id, public_key, consumed) values (?, ?, ?, ?, false)",
        )
        .bind(target_uid)
        .bind("phone-1")
        .bind(1_i32)
        .bind("!!!not-a-valid-x25519-public-key!!!")
        .execute(&server.state().db_pool)
        .await
        .unwrap();

        let device = fetch_one_device(&server.state().db_pool, target_uid, "phone-1")
            .await
            .unwrap()
            .unwrap();
        let content_key = [9u8; 32];
        let result = wrap_content_key_for_device(&server.state().db_pool, &content_key, &device)
            .await
            .unwrap();
        assert!(result.is_none(), "wrap over a corrupt OTP must fail (None)");

        // The corrupt OTP must remain UNCONSUMED (a failed wrap must not
        // shrink the target's prekey pool).
        let consumed: i64 = sqlx::query_scalar(
            "select count(*) from e2e_prekey where uid = ? and device_id = ? and consumed = true",
        )
        .bind(target_uid)
        .bind("phone-1")
        .fetch_one(&server.state().db_pool)
        .await
        .unwrap();
        assert_eq!(consumed, 0, "failed wrap must not consume the OTP");
    }

    // -- MINOR 5: restart-restore ----------------------------------------

    #[tokio::test]
    async fn restart_restore_reopens_vault_from_disk() {
        let key = test_master_key();
        let _guard = set_master_key_env(&key);
        let server = TestServer::new().await;
        let admin = server.login_admin().await;
        let bot_uid = create_bot(&server, &admin, "restart-bot@voce.chat").await;
        initialize(server.state(), 1, bot_uid).await.unwrap();

        // Simulate a process restart: open a brand-new pool against the same
        // on-disk sqlite file, with no shared in-process state.
        let path = server.state().config.system.sqlite_filename();
        let dsn = format!("sqlite:{}", path.display());
        let fresh_pool = sqlx::SqlitePool::connect(&dsn).await.unwrap();

        let row = load_identity_row(&fresh_pool, bot_uid).await.unwrap();
        assert!(row.is_some(), "vault identity row must survive a restart");
        assert_eq!(row.as_ref().unwrap().key_version, 1);

        // The encrypted material still decrypts with the master key and
        // yields a well-formed identity.
        let material = load_and_decrypt_material(&fresh_pool, bot_uid, &key)
            .await
            .unwrap();
        let identity = IdentitySecret {
            x25519: material.identity_x25519,
            ed25519: material.identity_ed25519,
        };
        assert!(identity.public().is_ok());
        fresh_pool.close().await;
    }
}
