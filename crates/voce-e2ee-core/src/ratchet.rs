//! Minimal Double Ratchet (DM) — Signal DR construction on X25519 + AES-GCM.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use x25519_dalek::{PublicKey as XPublic, StaticSecret};

use crate::error::E2eError;
use crate::identity::decode_x25519_pub;
use crate::kdf::{kdf_ck, kdf_rk};

const MAX_SKIP: u32 = 100;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RatchetHeader {
    pub dh_pub_b64: String,
    pub pn: u32,
    pub n: u32,
}

/// Serializable ratchet session (persisted by clients via FFI/WASM JSON).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatchetStateDto {
    pub dhs_b64: String,
    pub dhr_b64: Option<String>,
    pub rk_b64: String,
    pub cks_b64: Option<String>,
    pub ckr_b64: Option<String>,
    pub ns: u32,
    pub nr: u32,
    pub pn: u32,
    pub mkskipped: Vec<SkippedMk>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkippedMk {
    pub dh_pub_b64: String,
    pub n: u32,
    pub mk_b64: String,
}

#[derive(Clone)]
pub struct RatchetState {
    pub dhs: StaticSecret,
    pub dhr: Option<XPublic>,
    pub rk: [u8; 32],
    pub cks: Option<[u8; 32]>,
    pub ckr: Option<[u8; 32]>,
    pub ns: u32,
    pub nr: u32,
    pub pn: u32,
    pub mkskipped: HashMap<(String, u32), [u8; 32]>,
}

impl RatchetState {
    pub fn to_dto(&self) -> RatchetStateDto {
        RatchetStateDto {
            dhs_b64: B64.encode(self.dhs.to_bytes()),
            dhr_b64: self.dhr.map(|p| B64.encode(p.as_bytes())),
            rk_b64: B64.encode(self.rk),
            cks_b64: self.cks.map(|c| B64.encode(c)),
            ckr_b64: self.ckr.map(|c| B64.encode(c)),
            ns: self.ns,
            nr: self.nr,
            pn: self.pn,
            mkskipped: self
                .mkskipped
                .iter()
                .map(|((dh, n), mk)| SkippedMk {
                    dh_pub_b64: dh.clone(),
                    n: *n,
                    mk_b64: B64.encode(mk),
                })
                .collect(),
        }
    }

    pub fn from_dto(dto: &RatchetStateDto) -> Result<Self, E2eError> {
        let dhs_bytes: [u8; 32] = B64
            .decode(&dto.dhs_b64)
            .map_err(|e| E2eError::InvalidKey(e.to_string()))?
            .try_into()
            .map_err(|_| E2eError::InvalidKey("dhs len".into()))?;
        let rk: [u8; 32] = B64
            .decode(&dto.rk_b64)
            .map_err(|e| E2eError::InvalidKey(e.to_string()))?
            .try_into()
            .map_err(|_| E2eError::InvalidKey("rk len".into()))?;
        let decode32 = |s: &str| -> Result<[u8; 32], E2eError> {
            B64.decode(s)
                .map_err(|e| E2eError::InvalidKey(e.to_string()))?
                .try_into()
                .map_err(|_| E2eError::InvalidKey("32-byte field".into()))
        };
        let mut mkskipped = HashMap::new();
        for s in &dto.mkskipped {
            mkskipped.insert((s.dh_pub_b64.clone(), s.n), decode32(&s.mk_b64)?);
        }
        Ok(Self {
            dhs: StaticSecret::from(dhs_bytes),
            dhr: match &dto.dhr_b64 {
                Some(b) => Some(decode_x25519_pub(b)?),
                None => None,
            },
            rk,
            cks: match &dto.cks_b64 {
                Some(b) => Some(decode32(b)?),
                None => None,
            },
            ckr: match &dto.ckr_b64 {
                Some(b) => Some(decode32(b)?),
                None => None,
            },
            ns: dto.ns,
            nr: dto.nr,
            pn: dto.pn,
            mkskipped,
        })
    }
}

impl RatchetState {
    /// Alice: after X3DH, Bob's signed prekey is the initial remote DH.
    pub fn init_alice(sk: [u8; 32], bob_dh_pub: &XPublic) -> Result<Self, E2eError> {
        let dhs = StaticSecret::random_from_rng(OsRng);
        let dh_out = dhs.diffie_hellman(bob_dh_pub).to_bytes();
        let (rk, cks) = kdf_rk(&sk, &dh_out)?;
        Ok(Self {
            dhs,
            dhr: Some(*bob_dh_pub),
            rk,
            cks: Some(cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            mkskipped: HashMap::new(),
        })
    }

    /// Bob: after X3DH, keep SPK secret as DH; Alice's EK arrives in first header.
    pub fn init_bob(sk: [u8; 32], bob_spk_secret: [u8; 32]) -> Self {
        Self {
            dhs: StaticSecret::from(bob_spk_secret),
            dhr: None,
            rk: sk,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            mkskipped: HashMap::new(),
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(RatchetHeader, Vec<u8>), E2eError> {
        let cks = self
            .cks
            .as_mut()
            .ok_or_else(|| E2eError::Ratchet("sending chain missing".into()))?;
        let (mk, next) = kdf_ck(cks)?;
        *cks = next;
        let header = RatchetHeader {
            dh_pub_b64: B64.encode(XPublic::from(&self.dhs).as_bytes()),
            pn: self.pn,
            n: self.ns,
        };
        self.ns += 1;
        let ct = seal_aes_gcm(&mk, plaintext, &header)?;
        Ok((header, ct))
    }

    pub fn decrypt(&mut self, header: &RatchetHeader, ciphertext: &[u8]) -> Result<Vec<u8>, E2eError> {
        if let Some(pt) = self.try_skipped(header, ciphertext)? {
            return Ok(pt);
        }
        let dhr = decode_x25519_pub(&header.dh_pub_b64)?;
        if self.dhr.as_ref() != Some(&dhr) {
            self.skip_message_keys(header.pn)?;
            self.dh_ratchet(&dhr)?;
        }
        self.skip_message_keys(header.n)?;
        let ckr = self
            .ckr
            .as_mut()
            .ok_or_else(|| E2eError::Ratchet("recv chain missing".into()))?;
        let (mk, next) = kdf_ck(ckr)?;
        *ckr = next;
        self.nr += 1;
        open_aes_gcm(&mk, ciphertext, header)
    }

    fn try_skipped(
        &mut self,
        header: &RatchetHeader,
        ciphertext: &[u8],
    ) -> Result<Option<Vec<u8>>, E2eError> {
        let key = (header.dh_pub_b64.clone(), header.n);
        if let Some(mk) = self.mkskipped.remove(&key) {
            return open_aes_gcm(&mk, ciphertext, header).map(Some);
        }
        Ok(None)
    }

    fn skip_message_keys(&mut self, until: u32) -> Result<(), E2eError> {
        if self.nr.saturating_add(MAX_SKIP) < until {
            return Err(E2eError::Ratchet("too many skipped keys".into()));
        }
        if self.ckr.is_none() {
            return Ok(());
        }
        while self.nr < until {
            let ckr = self.ckr.as_mut().unwrap();
            let (mk, next) = kdf_ck(ckr)?;
            *ckr = next;
            let dhr = self
                .dhr
                .ok_or_else(|| E2eError::Ratchet("dhr missing while skipping".into()))?;
            let pub_b64 = B64.encode(dhr.as_bytes());
            self.mkskipped.insert((pub_b64, self.nr), mk);
            self.nr += 1;
        }
        Ok(())
    }

    fn dh_ratchet(&mut self, remote: &XPublic) -> Result<(), E2eError> {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dhr = Some(*remote);
        let dh_out = self.dhs.diffie_hellman(remote).to_bytes();
        let (rk, ckr) = kdf_rk(&self.rk, &dh_out)?;
        self.rk = rk;
        self.ckr = Some(ckr);

        self.dhs = StaticSecret::random_from_rng(OsRng);
        let dh_out2 = self.dhs.diffie_hellman(remote).to_bytes();
        let (rk2, cks) = kdf_rk(&self.rk, &dh_out2)?;
        self.rk = rk2;
        self.cks = Some(cks);
        Ok(())
    }
}

fn associated_data(header: &RatchetHeader) -> Vec<u8> {
    format!("v2|{}|{}|{}", header.dh_pub_b64, header.pn, header.n).into_bytes()
}

fn seal_aes_gcm(mk: &[u8; 32], plaintext: &[u8], header: &RatchetHeader) -> Result<Vec<u8>, E2eError> {
    let cipher = Aes256Gcm::new_from_slice(mk).map_err(|_| E2eError::InvalidKey("aes".into()))?;
    // 12-byte nonce from first 12 of HKDF(mk, "nonce")
    let nonce_bytes = crate::kdf::hkdf_sha256(mk, &[], b"VoceChat_DR_Nonce_v2", 12)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher
        .encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad: &associated_data(header),
            },
        )
        .map_err(|_| E2eError::DecryptFailed)
}

fn open_aes_gcm(mk: &[u8; 32], ciphertext: &[u8], header: &RatchetHeader) -> Result<Vec<u8>, E2eError> {
    let cipher = Aes256Gcm::new_from_slice(mk).map_err(|_| E2eError::InvalidKey("aes".into()))?;
    let nonce_bytes = crate::kdf::hkdf_sha256(mk, &[], b"VoceChat_DR_Nonce_v2", 12)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher
        .decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: ciphertext,
                aad: &associated_data(header),
            },
        )
        .map_err(|_| E2eError::DecryptFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentitySecret;
    use crate::x3dh::{x3dh_initiator, x3dh_responder, PreKeyBundle};

    #[test]
    fn ratchet_roundtrip() {
        let (alice_sec, alice_pub) = IdentitySecret::generate();
        let (bob_sec, bob_pub) = IdentitySecret::generate();
        let (spk_sec, spk_pub) = bob_sec.generate_signed_prekey(1).unwrap();
        let bundle = PreKeyBundle {
            identity: bob_pub,
            signed_prekey: spk_pub.clone(),
            one_time_prekey_b64: None,
            one_time_prekey_id: None,
        };
        let (sk_a, msg, _) = x3dh_initiator(&alice_sec.x25519, &alice_pub, &bundle).unwrap();
        let sk_b = x3dh_responder(&bob_sec.x25519, &spk_sec.secret, None, &msg).unwrap();
        assert_eq!(sk_a.0, sk_b.0);

        let bob_spk_pub = decode_x25519_pub(&spk_pub.dh_pub_b64).unwrap();
        let mut alice = RatchetState::init_alice(sk_a.0, &bob_spk_pub).unwrap();
        let mut bob = RatchetState::init_bob(sk_b.0, spk_sec.secret);

        let (h1, c1) = alice.encrypt(b"hello bob").unwrap();
        let p1 = bob.decrypt(&h1, &c1).unwrap();
        assert_eq!(p1, b"hello bob");

        let (h2, c2) = bob.encrypt(b"hello alice").unwrap();
        let p2 = alice.decrypt(&h2, &c2).unwrap();
        assert_eq!(p2, b"hello alice");
    }
}
