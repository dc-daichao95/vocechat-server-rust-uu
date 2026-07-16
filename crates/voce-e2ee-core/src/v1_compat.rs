//! Read-only decrypt for VoceChat E2EE v1 (P-256 ECDH + AES-GCM / MK wraps).

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use elliptic_curve::sec1::ToEncodedPoint;
use hkdf::Hkdf;
use p256::{PublicKey as P256Public, SecretKey as P256Secret};
use serde::Deserialize;
use sha2::Sha256;

use crate::error::E2eError;

#[derive(Debug, Deserialize)]
struct V1Wrap {
    uid: Option<i64>,
    rpk: String,
    spk: String,
    iv: String,
    ct: String,
    salt: String,
}

#[derive(Debug, Deserialize)]
struct V1Envelope {
    v: u8,
    alg: String,
    spk: Option<String>,
    rpk: Option<String>,
    iv: Option<String>,
    ct: Option<String>,
    salt: Option<String>,
    wraps: Option<Vec<V1Wrap>>,
}

/// Decrypt v1 packed content (base64(JSON)) given our P-256 private scalar `d` (32 bytes)
/// and our public SPKI (base64) for wrap matching.
pub fn decrypt_v1_text(
    private_d: &[u8],
    my_spki_b64: &str,
    packed_content_b64: &str,
) -> Result<String, E2eError> {
    let raw = B64
        .decode(packed_content_b64)
        .map_err(|e| E2eError::InvalidEnvelope(e.to_string()))?;
    let env: V1Envelope = serde_json::from_slice(&raw)?;
    if env.v != 1 {
        return Err(E2eError::UnsupportedVersion(env.v));
    }

    let secret = P256Secret::from_slice(private_d)
        .map_err(|e| E2eError::InvalidKey(e.to_string()))?;

    let aes_key = match env.alg.as_str() {
        "MK+AES-GCM" => {
            let wraps = env
                .wraps
                .as_ref()
                .ok_or_else(|| E2eError::InvalidEnvelope("missing wraps".into()))?;
            unwrap_mk(&secret, my_spki_b64, wraps)?
        }
        "P-256+AES-GCM" => {
            let salt = decode_b64(env.salt.as_deref().unwrap_or(""))?;
            let peer = env
                .spk
                .as_ref()
                .or(env.rpk.as_ref())
                .ok_or_else(|| E2eError::InvalidEnvelope("missing peer pub".into()))?;
            derive_v1_aes_key(&secret, peer, &salt)?
        }
        other => return Err(E2eError::InvalidEnvelope(format!("unsupported alg {other}"))),
    };

    let iv = decode_b64(env.iv.as_deref().ok_or_else(|| E2eError::InvalidEnvelope("iv".into()))?)?;
    let ct = decode_b64(env.ct.as_deref().ok_or_else(|| E2eError::InvalidEnvelope("ct".into()))?)?;
    let pt = aes_gcm_open(&aes_key, &iv, &ct)?;
    String::from_utf8(pt).map_err(|e| E2eError::InvalidEnvelope(e.to_string()))
}

fn unwrap_mk(secret: &P256Secret, my_spki_b64: &str, wraps: &[V1Wrap]) -> Result<[u8; 32], E2eError> {
    let mut ordered: Vec<&V1Wrap> = wraps.iter().filter(|w| w.rpk == my_spki_b64).collect();
    ordered.extend(wraps.iter().filter(|w| w.rpk != my_spki_b64));
    for w in ordered {
        let salt = decode_b64(&w.salt)?;
        let wrap_key = match derive_v1_aes_key(secret, &w.spk, &salt) {
            Ok(k) => k,
            Err(_) => continue,
        };
        let iv = decode_b64(&w.iv)?;
        let ct = decode_b64(&w.ct)?;
        if let Ok(mk) = aes_gcm_open(&wrap_key, &iv, &ct) {
            if mk.len() == 32 {
                let mut out = [0u8; 32];
                out.copy_from_slice(&mk);
                return Ok(out);
            }
        }
    }
    Err(E2eError::DecryptFailed)
}

fn derive_v1_aes_key(secret: &P256Secret, peer_spki_b64: &str, salt: &[u8]) -> Result<[u8; 32], E2eError> {
    let peer = parse_p256_spki_or_raw(peer_spki_b64)?;
    let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
    // Web Crypto deriveBits(256) on P-256 returns the raw shared secret x-coordinate (32 bytes).
    let shared_bytes = shared.raw_secret_bytes();
    let hk = Hkdf::<Sha256>::new(Some(salt), shared_bytes.as_ref());
    let mut okm = [0u8; 32];
    hk.expand(b"vocechat-e2e-v1", &mut okm)
        .map_err(|_| E2eError::InvalidKey("hkdf".into()))?;
    Ok(okm)
}

fn parse_p256_spki_or_raw(b64: &str) -> Result<P256Public, E2eError> {
    let bytes = B64.decode(b64).map_err(|e| E2eError::InvalidKey(e.to_string()))?;
    let point = if bytes.len() > 65 && bytes[0] == 0x30 {
        // SubjectPublicKeyInfo — uncompressed point is last 65 bytes (0x04||X||Y)
        bytes[bytes.len() - 65..].to_vec()
    } else {
        bytes
    };
    P256Public::from_sec1_bytes(&point).map_err(|e| E2eError::InvalidKey(e.to_string()))
}

fn aes_gcm_open(key: &[u8; 32], iv: &[u8], ct: &[u8]) -> Result<Vec<u8>, E2eError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| E2eError::InvalidKey("aes".into()))?;
    if iv.len() != 12 {
        return Err(E2eError::InvalidEnvelope("iv len".into()));
    }
    let nonce = Nonce::from_slice(iv);
    cipher.decrypt(nonce, ct.as_ref()).map_err(|_| E2eError::DecryptFailed)
}

fn decode_b64(s: &str) -> Result<Vec<u8>, E2eError> {
    B64.decode(s).map_err(|e| E2eError::InvalidEnvelope(e.to_string()))
}

/// Encrypt helper for v1 round-trip tests (not used for new production sends).
pub fn encrypt_v1_p256_for_test(
    sender_d: &[u8],
    sender_spki_b64: &str,
    recipient_spki_b64: &str,
    plaintext: &str,
) -> Result<String, E2eError> {
    use rand::rngs::OsRng;
    use rand::RngCore;

    let secret = P256Secret::from_slice(sender_d).map_err(|e| E2eError::InvalidKey(e.to_string()))?;
    let mut salt = [0u8; 16];
    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut iv);
    let key = derive_v1_aes_key(&secret, recipient_spki_b64, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| E2eError::InvalidKey("aes".into()))?;
    let ct = cipher
        .encrypt(Nonce::from_slice(&iv), plaintext.as_bytes())
        .map_err(|_| E2eError::DecryptFailed)?;
    let env = serde_json::json!({
        "v": 1,
        "alg": "P-256+AES-GCM",
        "spk": sender_spki_b64,
        "rpk": recipient_spki_b64,
        "iv": B64.encode(iv),
        "ct": B64.encode(ct),
        "salt": B64.encode(salt),
    });
    Ok(B64.encode(env.to_string().as_bytes()))
}

pub fn p256_spki_b64_from_secret(d: &[u8]) -> Result<String, E2eError> {
    let secret = P256Secret::from_slice(d).map_err(|e| E2eError::InvalidKey(e.to_string()))?;
    let public = secret.public_key();
    let point = public.to_encoded_point(false);
    // SPKI prefix matching Flutter/Web Crypto
    let prefix: [u8; 26] = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];
    let mut spki = Vec::with_capacity(91);
    spki.extend_from_slice(&prefix);
    spki.extend_from_slice(point.as_bytes());
    Ok(B64.encode(spki))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn v1_p256_roundtrip() {
        let a = P256Secret::random(&mut OsRng);
        let b = P256Secret::random(&mut OsRng);
        let a_d = a.to_bytes();
        let b_d = b.to_bytes();
        let a_spki = p256_spki_b64_from_secret(a_d.as_slice()).unwrap();
        let b_spki = p256_spki_b64_from_secret(b_d.as_slice()).unwrap();
        let packed = encrypt_v1_p256_for_test(a_d.as_slice(), &a_spki, &b_spki, "secret v1").unwrap();
        let pt = decrypt_v1_text(b_d.as_slice(), &b_spki, &packed).unwrap();
        assert_eq!(pt, "secret v1");
    }
}
