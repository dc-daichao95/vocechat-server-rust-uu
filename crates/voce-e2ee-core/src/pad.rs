//! Application-layer length bucketing for E2E plaintext (metadata hardening).
//!
//! Wire blob (before AEAD):
//!   `u32_be(payload_len) || payload || random_pad`
//! where `payload` is UTF-8 JSON `{"m":"<mime>","c":"<text>"}`.
//! Total length snaps to the next power-of-two bucket (≥ 64, ≤ 256 KiB).

use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::error::E2eError;

const MIN_BUCKET: usize = 64;
const MAX_BUCKET: usize = 256 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InnerBody<'a> {
    m: &'a str,
    c: &'a str,
}

fn next_bucket(need: usize) -> Result<usize, E2eError> {
    if need > MAX_BUCKET {
        return Err(E2eError::InvalidKey(format!(
            "plaintext too large for pad bucket ({need} > {MAX_BUCKET})"
        )));
    }
    let mut b = MIN_BUCKET;
    while b < need {
        b = b.saturating_mul(2);
        if b > MAX_BUCKET {
            return Ok(MAX_BUCKET);
        }
    }
    Ok(b)
}

/// Wrap MIME + text, then pad to a length bucket.
pub fn pad_message(mime: &str, text: &str) -> Result<Vec<u8>, E2eError> {
    let payload = serde_json::to_vec(&InnerBody { m: mime, c: text })?;
    let need = 4 + payload.len();
    let bucket = next_bucket(need)?;
    let mut out = Vec::with_capacity(bucket);
    let len = payload.len() as u32;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&payload);
    let pad_len = bucket - out.len();
    if pad_len > 0 {
        let mut pad = vec![0u8; pad_len];
        OsRng.fill_bytes(&mut pad);
        out.extend_from_slice(&pad);
    }
    Ok(out)
}

/// Inverse of [`pad_message`]. Also accepts legacy raw UTF-8 (no length prefix).
pub fn unpad_message(blob: &[u8]) -> Result<(String, String), E2eError> {
    if blob.len() >= 4 {
        let len = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]) as usize;
        if len > 0 && 4 + len <= blob.len() && len <= MAX_BUCKET {
            let payload = &blob[4..4 + len];
            if let Ok(body) = serde_json::from_slice::<InnerBodyOwned>(payload) {
                return Ok((body.m, body.c));
            }
        }
    }
    // Legacy: treat entire blob as UTF-8 plaintext, default mime.
    let text = String::from_utf8(blob.to_vec())
        .map_err(|e| E2eError::InvalidKey(format!("unpad utf8: {e}")))?;
    Ok(("text/plain".into(), text))
}

#[derive(Deserialize)]
struct InnerBodyOwned {
    m: String,
    c: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_roundtrip_and_bucket() {
        let padded = pad_message("text/plain", "hi").unwrap();
        assert_eq!(padded.len(), 64);
        let (m, c) = unpad_message(&padded).unwrap();
        assert_eq!(m, "text/plain");
        assert_eq!(c, "hi");
    }

    #[test]
    fn legacy_utf8_still_decrypts() {
        let (m, c) = unpad_message(b"hello legacy").unwrap();
        assert_eq!(m, "text/plain");
        assert_eq!(c, "hello legacy");
    }

    #[test]
    fn same_bucket_for_nearby_lengths() {
        let a = pad_message("text/plain", "a").unwrap();
        let b = pad_message("text/plain", "abcd").unwrap();
        assert_eq!(a.len(), b.len());
    }
}
