//! HKDF-SHA256 helpers (Signal-style info labels).

use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::E2eError;

pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], out_len: usize) -> Result<Vec<u8>, E2eError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; out_len];
    hk.expand(info, &mut okm)
        .map_err(|_| E2eError::InvalidKey("hkdf expand".into()))?;
    Ok(okm)
}

/// X3DH KDF: F || KM  with F = 0xFF * 32 (Curve25519), info = "VoceChat_X3DH_v2"
pub fn kdf_x3dh(dh_concat: &[u8]) -> Result<[u8; 32], E2eError> {
    let mut ikm = Vec::with_capacity(32 + dh_concat.len());
    ikm.extend(std::iter::repeat(0xff).take(32));
    ikm.extend_from_slice(dh_concat);
    let okm = hkdf_sha256(&ikm, &[], b"VoceChat_X3DH_v2", 32)?;
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&okm);
    Ok(sk)
}

pub fn kdf_rk(rk: &[u8; 32], dh_out: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), E2eError> {
    let okm = hkdf_sha256(dh_out, rk, b"VoceChat_DR_Root_v2", 64)?;
    let mut new_rk = [0u8; 32];
    let mut ck = [0u8; 32];
    new_rk.copy_from_slice(&okm[..32]);
    ck.copy_from_slice(&okm[32..]);
    Ok((new_rk, ck))
}

pub fn kdf_ck(ck: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), E2eError> {
    // message key || next chain key
    let okm = hkdf_sha256(ck, &[], b"VoceChat_DR_Chain_v2", 64)?;
    let mut mk = [0u8; 32];
    let mut next = [0u8; 32];
    mk.copy_from_slice(&okm[..32]);
    next.copy_from_slice(&okm[32..]);
    Ok((mk, next))
}
