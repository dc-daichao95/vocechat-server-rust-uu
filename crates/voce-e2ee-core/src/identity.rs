//! Identity: X25519 DH identity + Ed25519 signing key.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as XPublic, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::E2eError;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct IdentitySecret {
    pub x25519: [u8; 32],
    pub ed25519: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityPublic {
    /// X25519 public (32 bytes, base64)
    pub identity_dh_pub_b64: String,
    /// Ed25519 verifying key (32 bytes, base64)
    pub identity_sig_pub_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPreKeyPublic {
    pub key_id: u32,
    pub dh_pub_b64: String,
    pub signature_b64: String,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SignedPreKeySecret {
    pub key_id: u32,
    pub secret: [u8; 32],
}

impl IdentitySecret {
    pub fn generate() -> (Self, IdentityPublic) {
        let x_secret = StaticSecret::random_from_rng(OsRng);
        let x_public = XPublic::from(&x_secret);
        let ed = SigningKey::generate(&mut OsRng);
        let secret = Self {
            x25519: x_secret.to_bytes(),
            ed25519: ed.to_bytes(),
        };
        let public = IdentityPublic {
            identity_dh_pub_b64: B64.encode(x_public.as_bytes()),
            identity_sig_pub_b64: B64.encode(ed.verifying_key().as_bytes()),
        };
        (secret, public)
    }

    pub fn x25519_secret(&self) -> StaticSecret {
        StaticSecret::from(self.x25519)
    }

    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.ed25519)
    }

    pub fn public(&self) -> Result<IdentityPublic, E2eError> {
        let x_public = XPublic::from(&self.x25519_secret());
        let ed = self.signing_key();
        Ok(IdentityPublic {
            identity_dh_pub_b64: B64.encode(x_public.as_bytes()),
            identity_sig_pub_b64: B64.encode(ed.verifying_key().as_bytes()),
        })
    }

    pub fn generate_signed_prekey(&self, key_id: u32) -> Result<(SignedPreKeySecret, SignedPreKeyPublic), E2eError> {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = XPublic::from(&secret);
        let ed = self.signing_key();
        let sig = ed.sign(public.as_bytes());
        Ok((
            SignedPreKeySecret {
                key_id,
                secret: secret.to_bytes(),
            },
            SignedPreKeyPublic {
                key_id,
                dh_pub_b64: B64.encode(public.as_bytes()),
                signature_b64: B64.encode(sig.to_bytes()),
            },
        ))
    }
}

pub fn verify_signed_prekey(identity: &IdentityPublic, spk: &SignedPreKeyPublic) -> Result<(), E2eError> {
    let vk_bytes = B64
        .decode(&identity.identity_sig_pub_b64)
        .map_err(|e| E2eError::InvalidKey(e.to_string()))?;
    let vk = VerifyingKey::from_bytes(
        vk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| E2eError::InvalidKey("sig pub len".into()))?,
    )
    .map_err(|e| E2eError::InvalidKey(e.to_string()))?;
    let dh = B64
        .decode(&spk.dh_pub_b64)
        .map_err(|e| E2eError::InvalidKey(e.to_string()))?;
    let sig_bytes = B64
        .decode(&spk.signature_b64)
        .map_err(|e| E2eError::InvalidKey(e.to_string()))?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|e| E2eError::InvalidKey(e.to_string()))?;
    vk.verify(&dh, &sig)
        .map_err(|_| E2eError::InvalidKey("signed prekey signature".into()))
}

/// Numeric safety fingerprint over both parties' DH identity pubs (sorted).
pub fn safety_number(a: &IdentityPublic, b: &IdentityPublic) -> String {
    let (lo, hi) = if a.identity_dh_pub_b64 <= b.identity_dh_pub_b64 {
        (a, b)
    } else {
        (b, a)
    };
    let mut hasher = Sha256::new();
    hasher.update(b"VoceChat_Safety_v2");
    hasher.update(lo.identity_dh_pub_b64.as_bytes());
    hasher.update(hi.identity_dh_pub_b64.as_bytes());
    hasher.update(lo.identity_sig_pub_b64.as_bytes());
    hasher.update(hi.identity_sig_pub_b64.as_bytes());
    let digest = hasher.finalize();
    // 12 groups of 5 decimal digits (Signal-style presentation)
    let mut out = String::new();
    for chunk in digest.chunks(2).take(12) {
        let n = u32::from(u16::from_be_bytes([
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
        ])) % 100_000;
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(&format!("{n:05}"));
    }
    out
}

pub fn decode_x25519_pub(b64: &str) -> Result<XPublic, E2eError> {
    let bytes = B64.decode(b64).map_err(|e| E2eError::InvalidKey(e.to_string()))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| E2eError::InvalidKey("x25519 pub len".into()))?;
    Ok(XPublic::from(arr))
}

pub fn decode_x25519_secret(bytes: &[u8]) -> Result<StaticSecret, E2eError> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| E2eError::InvalidKey("x25519 secret len".into()))?;
    Ok(StaticSecret::from(arr))
}
