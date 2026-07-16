//! Channel sender keys (symmetric chain + rotation hook).

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::error::E2eError;
use crate::kdf::hkdf_sha256;

#[derive(Clone, Zeroize)]
pub struct SenderKey {
    pub skid: String,
    pub chain_key: [u8; 32],
    pub iteration: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SenderKeyHeader {
    pub skid: String,
    pub iteration: u32,
}

impl SenderKey {
    pub fn generate(skid: impl Into<String>) -> Self {
        let mut chain_key = [0u8; 32];
        OsRng.fill_bytes(&mut chain_key);
        Self {
            skid: skid.into(),
            chain_key,
            iteration: 0,
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(SenderKeyHeader, Vec<u8>), E2eError> {
        let (mk, next) = derive_chain(&self.chain_key)?;
        self.chain_key = next;
        let header = SenderKeyHeader {
            skid: self.skid.clone(),
            iteration: self.iteration,
        };
        self.iteration += 1;
        let ct = seal(&mk, plaintext, &header)?;
        Ok((header, ct))
    }

    pub fn decrypt(&mut self, header: &SenderKeyHeader, ciphertext: &[u8]) -> Result<Vec<u8>, E2eError> {
        if header.skid != self.skid {
            return Err(E2eError::InvalidKey("skid mismatch".into()));
        }
        while self.iteration < header.iteration {
            let (_, next) = derive_chain(&self.chain_key)?;
            self.chain_key = next;
            self.iteration += 1;
        }
        if self.iteration != header.iteration {
            return Err(E2eError::Replay(header.iteration));
        }
        let (mk, next) = derive_chain(&self.chain_key)?;
        let pt = open(&mk, ciphertext, header)?;
        self.chain_key = next;
        self.iteration += 1;
        Ok(pt)
    }

    /// Membership change → new random chain (PCS).
    pub fn rotate(&mut self, new_skid: impl Into<String>) {
        self.skid = new_skid.into();
        OsRng.fill_bytes(&mut self.chain_key);
        self.iteration = 0;
    }
}

fn derive_chain(ck: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), E2eError> {
    let okm = hkdf_sha256(ck, &[], b"VoceChat_SK_Chain_v2", 64)?;
    let mut mk = [0u8; 32];
    let mut next = [0u8; 32];
    mk.copy_from_slice(&okm[..32]);
    next.copy_from_slice(&okm[32..]);
    Ok((mk, next))
}

fn aad(h: &SenderKeyHeader) -> Vec<u8> {
    format!("sk|{}|{}", h.skid, h.iteration).into_bytes()
}

fn seal(mk: &[u8; 32], plaintext: &[u8], header: &SenderKeyHeader) -> Result<Vec<u8>, E2eError> {
    let cipher = Aes256Gcm::new_from_slice(mk).map_err(|_| E2eError::InvalidKey("aes".into()))?;
    let nonce_bytes = hkdf_sha256(mk, &[], b"VoceChat_SK_Nonce_v2", 12)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher
        .encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad: &aad(header),
            },
        )
        .map_err(|_| E2eError::DecryptFailed)
}

fn open(mk: &[u8; 32], ciphertext: &[u8], header: &SenderKeyHeader) -> Result<Vec<u8>, E2eError> {
    let cipher = Aes256Gcm::new_from_slice(mk).map_err(|_| E2eError::InvalidKey("aes".into()))?;
    let nonce_bytes = hkdf_sha256(mk, &[], b"VoceChat_SK_Nonce_v2", 12)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher
        .decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: ciphertext,
                aad: &aad(header),
            },
        )
        .map_err(|_| E2eError::DecryptFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sender_key_roundtrip_and_rotate() {
        let mut send = SenderKey::generate("sk-1");
        let mut recv = SenderKey {
            skid: send.skid.clone(),
            chain_key: send.chain_key,
            iteration: 0,
        };
        let (h, c) = send.encrypt(b"channel hi").unwrap();
        assert_eq!(recv.decrypt(&h, &c).unwrap(), b"channel hi");
        send.rotate("sk-2");
        assert_ne!(send.skid, "sk-1");
    }
}
