//! Deferred-envelope crypto (algorithm label `DEFERRED+AES-GCM`).
//!
//! This is the crypto behind the server's deferred DM flow (`protocol =
//! "dr-pending"`, `wire_class = "dr_envelope"`, Task 2): the sender encrypts
//! message content once, up front, and independently wraps a copy of the
//! content key for each recipient device afterward (possibly much later,
//! e.g. once a new device publishes its prekey bundle). The server only
//! stores/routes the opaque envelope bytes; it never sees plaintext or the
//! content key.
//!
//! ## Content encryption + metadata binding
//!
//! [`deferred_encrypt`] generates a random AES-256-GCM content key and seals
//! `body` with it. Metadata (arbitrary caller JSON — chat id, sender device,
//! content type, etc.) is bound to the ciphertext as AEAD associated data
//! (AAD) so that tampering with metadata invalidates the ciphertext, exactly
//! like tampering with the ciphertext itself. Concretely:
//!
//! - `metadata` is canonicalized to bytes (`serde_json::to_vec`, which is
//!   deterministic here because this crate does not enable serde_json's
//!   `preserve_order` feature, so `Value` objects are backed by a
//!   `BTreeMap` and always serialize with sorted keys).
//! - `sha256 = SHA-256(canonical metadata bytes)` is returned to the caller
//!   *and* used directly as the AES-GCM AAD.
//! - [`deferred_decrypt`] takes that same `sha256` back (not the metadata
//!   itself) and uses it as the AAD to open the AEAD box.
//!
//! Because `sha256` is a deterministic commitment to the metadata, a caller
//! cannot swap in different metadata without also changing `sha256` — and
//! decrypting with a `sha256` that doesn't match the one used at seal time
//! fails the AEAD tag check, with no plaintext fallback. This lets
//! [`deferred_decrypt`] stay a pure function of `(ciphertext, key, nonce,
//! sha256)` per the required interface, while still cryptographically
//! binding metadata.
//!
//! ## MANDATORY caller responsibility: verify the metadata commitment
//!
//! `sha256` binds metadata to the ciphertext **only if the recipient
//! re-derives it from the metadata it actually received** and refuses to use
//! any transmitted digest blindly. The transport (server) can rewrite the
//! plaintext `metadata` it relays while leaving `ciphertext`/`nonce`/`sha256`
//! untouched; AES-GCM would still open successfully, because the AEAD only
//! knows the 32-byte AAD, not what metadata "should" hash to. A recipient
//! that trusted the relayed metadata would therefore accept
//! attacker-controlled `chat_id`/`content_type`/etc.
//!
//! To close this, recipients MUST, before trusting any received metadata:
//! 1. recompute the commitment from the metadata they received —
//!    [`deferred_metadata_commitment`] (FFI: `deferred_metadata_commitment`),
//!    or check it directly with [`deferred_verify_metadata`] (FFI:
//!    `deferred_verify_metadata`); and
//! 2. compare it against the `sha256` used for decryption (the digest that
//!    successfully opened the ciphertext), rejecting the message on
//!    mismatch.
//!
//! Only the digest that both (a) opened the AEAD and (b) equals
//! `commitment(received_metadata)` proves the received metadata is the
//! metadata the sender bound. Never trust a transmitted digest without
//! recomputing it from the received metadata.
//!
//! ## MANDATORY caller responsibility: replay / freshness
//!
//! This crate provides **no replay defense** for deferred envelopes — unlike
//! the Double Ratchet path, unwrapping/decrypting is a pure, repeatable
//! function with no per-message state. A captured `(ciphertext, envelope,
//! sha256, metadata)` tuple decrypts identically every time it is delivered.
//! Callers therefore MUST:
//! - include a unique-per-message field (message id and/or timestamp) inside
//!   `metadata`, so it enters the `sha256` AAD commitment and cannot be
//!   altered without detection; and
//! - enforce message-id uniqueness / freshness upstream (reject a message id
//!   already seen, and/or reject stale timestamps).
//!
//! ## SECURITY: envelopes are NOT sender-authenticated ("sealed sender")
//!
//! [`deferred_wrap_key`] wraps the content key using a throwaway, unverified
//! sender identity (see below). It follows that **anyone in possession of the
//! recipient's public `PreKeyBundle` can forge a well-formed envelope that
//! the recipient will happily unwrap.** `deferred_unwrap_key` succeeding
//! proves only "someone who had my public bundle wrapped this for me" — it
//! proves nothing about *who*. Sender authorization is therefore a hard
//! requirement that MUST be enforced at another layer (Task 5/7 clients + the
//! server): the enclosing message/route must authenticate the sender (e.g.
//! authenticated API + the outer message envelope's sender identity), and
//! that authenticated sender identity must be reflected inside `metadata` so
//! it is bound by the commitment and cross-checked on receipt.
//!
//! ## Key wrapping
//!
//! [`deferred_wrap_key`] / [`deferred_unwrap_key`] reuse the crate's
//! existing X3DH primitives (`crate::x3dh::x3dh_initiator` /
//! `x3dh_responder`) to derive a per-recipient wrapping key, then seal the
//! content key with AES-256-GCM. The deferred flow does not authenticate a
//! specific sender (the whole point is to defer/decouple delivery from any
//! live session), so wrapping generates a throwaway, single-use identity
//! purely to drive X3DH's DH1 term; it is discarded immediately after use
//! and never persisted or reused. This mirrors Signal-style "sealed sender"
//! key wrapping: the resulting envelope binds the content key to one
//! recipient identity + signed prekey (+ optional one-time prekey), and
//! unwrapping is a pure function of `(envelope, local_identity)` — safe to
//! run more than once for the same envelope (e.g. on redelivery).

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::error::E2eError;
use crate::identity::IdentitySecret;
use crate::kdf::hkdf_sha256;
use crate::x3dh::{x3dh_initiator, x3dh_responder, PreKeyBundle, X3dhInitialMessage};

/// Algorithm label matching the server-side (Task 2) deferred DM wire format.
pub const DEFERRED_ALG: &str = "DEFERRED+AES-GCM";

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;

/// HKDF info label deriving the AES-256-GCM key-wrapping key from the X3DH
/// shared secret (domain-separated from `crate::kdf`'s DR/X3DH labels).
const WRAP_KDF_INFO: &[u8] = b"VoceChat_Deferred_WrapKey_v2";
/// Fixed AAD for the key-wrap AEAD. The content key itself carries no
/// metadata; metadata binding happens at the content layer (see module docs
/// and [`deferred_encrypt`]).
const WRAP_AAD: &[u8] = b"VoceChat_Deferred_WrapAad_v2";

/// Output of [`deferred_encrypt`]: a freshly generated content key, its
/// nonce, the sealed ciphertext, and the metadata-commitment digest used as
/// AAD (and required again by [`deferred_decrypt`]).
pub struct DeferredEncrypted {
    pub content_key: [u8; KEY_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
    pub sha256: [u8; KEY_LEN],
}

impl Drop for DeferredEncrypted {
    fn drop(&mut self) {
        self.content_key.zeroize();
    }
}

/// Wire envelope produced by [`deferred_wrap_key`] — the opaque payload
/// carried as the server's `dr_envelope` (Task 2) per (message, recipient,
/// device). Contains no secret material.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeferredEnvelope {
    pub alg: String,
    pub x3dh_initial: X3dhInitialMessage,
    pub nonce_b64: String,
    pub wrapped_key_b64: String,
}

/// Recipient-side secret material needed to unwrap a [`DeferredEnvelope`]:
/// the recipient's identity key, the signed prekey secret matching
/// `envelope.x3dh_initial.used_signed_prekey_id`, and — if
/// `used_one_time_prekey_id` is set — that one-time prekey secret.
///
/// Deliberately does not derive `Debug`/`Serialize`: this struct only ever
/// holds raw secret key bytes, and callers (including the FFI layer) must
/// build/consume it without ever formatting or logging it.
pub struct DeferredLocalIdentity {
    pub ik_secret: [u8; KEY_LEN],
    pub spk_secret: [u8; KEY_LEN],
    pub otk_secret: Option<[u8; KEY_LEN]>,
}

impl Drop for DeferredLocalIdentity {
    fn drop(&mut self) {
        self.ik_secret.zeroize();
        self.spk_secret.zeroize();
        if let Some(ref mut otk) = self.otk_secret {
            otk.zeroize();
        }
    }
}

/// Canonical (sorted-key) JSON bytes for `metadata`. `serde_json::Value`'s
/// default map is a `BTreeMap` (this crate does not enable serde_json's
/// `preserve_order` feature), so this is deterministic regardless of the
/// caller's field insertion order.
fn canonical_metadata_bytes(metadata: &serde_json::Value) -> Result<Vec<u8>, E2eError> {
    serde_json::to_vec(metadata).map_err(E2eError::from)
}

/// Deterministic commitment to `metadata`: `SHA-256(canonical JSON)`. This is
/// the exact value returned as `DeferredEncrypted::sha256` and used as the
/// AES-GCM AAD. Recipients call this to re-derive the commitment from the
/// metadata they actually received and compare it against the digest that
/// decrypted the message (see the "verify the metadata commitment" section in
/// the module docs). Order-independent for JSON objects.
pub fn deferred_metadata_commitment(
    metadata: &serde_json::Value,
) -> Result<[u8; KEY_LEN], E2eError> {
    let bytes = canonical_metadata_bytes(metadata)?;
    let mut sha256 = [0u8; KEY_LEN];
    sha256.copy_from_slice(&Sha256::digest(&bytes));
    Ok(sha256)
}

/// Constant-time-ish equality for two 32-byte commitments. The commitment is
/// public (not secret), so timing is not truly sensitive; we still avoid an
/// early-exit compare to keep the verification path uniform.
fn ct_eq(a: &[u8; KEY_LEN], b: &[u8; KEY_LEN]) -> bool {
    let mut diff = 0u8;
    for i in 0..KEY_LEN {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Verify that `metadata` matches a `sha256` commitment. Recipients pass the
/// metadata they received and the `sha256` that decrypted the ciphertext;
/// `true` proves the received metadata is exactly what the sender bound.
/// Never trust a transmitted digest without recomputing it here from the
/// received metadata.
pub fn deferred_verify_metadata(
    metadata: &serde_json::Value,
    sha256: &[u8; KEY_LEN],
) -> Result<bool, E2eError> {
    Ok(ct_eq(&deferred_metadata_commitment(metadata)?, sha256))
}

fn decode_fixed(b64: &str, len: usize, what: &str) -> Result<Vec<u8>, E2eError> {
    let bytes = B64
        .decode(b64)
        .map_err(|e| E2eError::InvalidEnvelope(format!("{what}: {e}")))?;
    if bytes.len() != len {
        return Err(E2eError::InvalidEnvelope(format!(
            "{what} must be {len} bytes, got {}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

/// Encrypt `body` under a freshly generated AES-256-GCM content key, binding
/// `metadata` to the ciphertext via AAD (see module docs for how).
///
/// No plaintext fallback: any AEAD failure surfaces as
/// [`E2eError::DecryptFailed`] from the corresponding [`deferred_decrypt`]
/// call; this function itself only fails on metadata that cannot be
/// serialized to JSON.
pub fn deferred_encrypt(
    body: &[u8],
    metadata: &serde_json::Value,
) -> Result<DeferredEncrypted, E2eError> {
    let sha256 = deferred_metadata_commitment(metadata)?;

    let mut content_key = [0u8; KEY_LEN];
    OsRng.fill_bytes(&mut content_key);
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let cipher = Aes256Gcm::new_from_slice(&content_key)
        .map_err(|_| E2eError::InvalidKey("aes key".into()))?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: body,
                aad: &sha256,
            },
        )
        .map_err(|_| E2eError::EncryptFailed)?;

    Ok(DeferredEncrypted {
        content_key,
        nonce,
        ciphertext,
        sha256,
    })
}

/// Decrypt content sealed by [`deferred_encrypt`]. `sha256` must be the
/// exact digest returned by the matching `deferred_encrypt` call — it is
/// re-used as the AES-GCM AAD, so a mismatched/forged `sha256` (i.e.
/// tampered metadata) fails the same way a tampered `ciphertext` does: via
/// AEAD tag verification, with no plaintext fallback.
pub fn deferred_decrypt(
    ciphertext: &[u8],
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    sha256: &[u8; KEY_LEN],
) -> Result<Vec<u8>, E2eError> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| E2eError::InvalidKey("aes key".into()))?;
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: sha256,
            },
        )
        .map_err(|_| E2eError::DecryptFailed)
}

/// Wrap a content key for one recipient device, reusing the crate's
/// existing X3DH agreement (see module docs for the throwaway-identity
/// rationale).
pub fn deferred_wrap_key(
    content_key: &[u8; KEY_LEN],
    recipient_bundle: &PreKeyBundle,
) -> Result<DeferredEnvelope, E2eError> {
    let (throwaway_secret, throwaway_public) = IdentitySecret::generate();

    let (mut shared_secret, x3dh_initial, mut eka_secret) =
        x3dh_initiator(&throwaway_secret.x25519, &throwaway_public, recipient_bundle)?;
    eka_secret.zeroize();
    // `throwaway_secret` zeroizes on drop (`IdentitySecret` derives
    // `ZeroizeOnDrop`); nothing about it is reused or persisted.

    let wrap_key_bytes = hkdf_sha256(&shared_secret.0, &[], WRAP_KDF_INFO, KEY_LEN)?;
    shared_secret.0.zeroize();
    let mut wrap_key = [0u8; KEY_LEN];
    wrap_key.copy_from_slice(&wrap_key_bytes);

    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let cipher =
        Aes256Gcm::new_from_slice(&wrap_key).map_err(|_| E2eError::InvalidKey("aes key".into()))?;
    let wrapped = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &content_key[..],
                aad: WRAP_AAD,
            },
        )
        .map_err(|_| E2eError::EncryptFailed)?;
    wrap_key.zeroize();

    Ok(DeferredEnvelope {
        alg: DEFERRED_ALG.to_string(),
        x3dh_initial,
        nonce_b64: B64.encode(nonce),
        wrapped_key_b64: B64.encode(wrapped),
    })
}

/// Unwrap the content key from a [`DeferredEnvelope`] using the recipient's
/// local identity + matching signed prekey (+ optional one-time prekey).
///
/// Pure/stateless: unwrapping the same envelope twice with the same
/// identity yields the same content key both times (a deferred envelope may
/// legitimately be delivered — and thus decrypted — more than once, unlike
/// a Double Ratchet message).
pub fn deferred_unwrap_key(
    envelope: &DeferredEnvelope,
    local_identity: &DeferredLocalIdentity,
) -> Result<[u8; KEY_LEN], E2eError> {
    if envelope.alg != DEFERRED_ALG {
        return Err(E2eError::InvalidEnvelope(format!(
            "unexpected alg: {}",
            envelope.alg
        )));
    }

    let mut shared_secret = x3dh_responder(
        &local_identity.ik_secret,
        &local_identity.spk_secret,
        local_identity.otk_secret.as_ref(),
        &envelope.x3dh_initial,
    )?;

    let wrap_key_bytes = hkdf_sha256(&shared_secret.0, &[], WRAP_KDF_INFO, KEY_LEN)?;
    shared_secret.0.zeroize();
    let mut wrap_key = [0u8; KEY_LEN];
    wrap_key.copy_from_slice(&wrap_key_bytes);

    let nonce = decode_fixed(&envelope.nonce_b64, NONCE_LEN, "nonce_b64")?;
    let wrapped = B64
        .decode(&envelope.wrapped_key_b64)
        .map_err(|e| E2eError::InvalidEnvelope(format!("wrapped_key_b64: {e}")))?;

    let cipher =
        Aes256Gcm::new_from_slice(&wrap_key).map_err(|_| E2eError::InvalidKey("aes key".into()))?;
    let mut opened = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: wrapped.as_slice(),
                aad: WRAP_AAD,
            },
        )
        .map_err(|_| E2eError::DecryptFailed)?;
    wrap_key.zeroize();

    if opened.len() != KEY_LEN {
        opened.zeroize();
        return Err(E2eError::InvalidKey("unwrapped content key length".into()));
    }
    let mut content_key = [0u8; KEY_LEN];
    content_key.copy_from_slice(&opened);
    opened.zeroize();
    Ok(content_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn recipient() -> (PreKeyBundle, DeferredLocalIdentity) {
        let (sec, pub_) = IdentitySecret::generate();
        let (spk_sec, spk_pub) = sec.generate_signed_prekey(1).unwrap();
        let bundle = PreKeyBundle {
            identity: pub_,
            signed_prekey: spk_pub,
            one_time_prekey_b64: None,
            one_time_prekey_id: None,
        };
        let local = DeferredLocalIdentity {
            ik_secret: sec.x25519,
            spk_secret: spk_sec.secret,
            otk_secret: None,
        };
        (bundle, local)
    }

    #[test]
    fn unit_round_trip() {
        let (bundle, local) = recipient();
        let enc = deferred_encrypt(b"unit body", &json!({"k": "v"})).unwrap();
        let envelope = deferred_wrap_key(&enc.content_key, &bundle).unwrap();
        let key = deferred_unwrap_key(&envelope, &local).unwrap();
        let pt = deferred_decrypt(&enc.ciphertext, &key, &enc.nonce, &enc.sha256).unwrap();
        assert_eq!(pt, b"unit body");
    }

    #[test]
    fn unit_one_time_prekey_is_used_when_present() {
        let (sec, pub_) = IdentitySecret::generate();
        let (spk_sec, spk_pub) = sec.generate_signed_prekey(1).unwrap();
        let otk = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let otk_pub = x25519_dalek::PublicKey::from(&otk);
        let bundle = PreKeyBundle {
            identity: pub_,
            signed_prekey: spk_pub,
            one_time_prekey_b64: Some(B64.encode(otk_pub.as_bytes())),
            one_time_prekey_id: Some(9),
        };
        let local = DeferredLocalIdentity {
            ik_secret: sec.x25519,
            spk_secret: spk_sec.secret,
            otk_secret: Some(otk.to_bytes()),
        };

        let enc = deferred_encrypt(b"otk body", &json!({})).unwrap();
        let envelope = deferred_wrap_key(&enc.content_key, &bundle).unwrap();
        assert_eq!(envelope.x3dh_initial.used_one_time_prekey_id, Some(9));
        let key = deferred_unwrap_key(&envelope, &local).unwrap();
        assert_eq!(key, enc.content_key);
    }
}
