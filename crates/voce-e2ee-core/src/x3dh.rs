//! X3DH session agreement (Signal X3DH §2.2 construction on X25519).

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as XPublic, StaticSecret};
use zeroize::Zeroize;

use crate::error::E2eError;
use crate::identity::{decode_x25519_pub, verify_signed_prekey, IdentityPublic, SignedPreKeyPublic};
use crate::kdf::kdf_x3dh;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreKeyBundle {
    pub identity: IdentityPublic,
    pub signed_prekey: SignedPreKeyPublic,
    /// Optional one-time prekey (X25519 pub, base64)
    pub one_time_prekey_b64: Option<String>,
    pub one_time_prekey_id: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X3dhInitialMessage {
    pub identity_dh_pub_b64: String,
    pub ephemeral_pub_b64: String,
    pub used_signed_prekey_id: u32,
    pub used_one_time_prekey_id: Option<u32>,
}

#[derive(Clone, Zeroize)]
pub struct SharedSecret(pub [u8; 32]);

fn dh(secret: &StaticSecret, public: &XPublic) -> [u8; 32] {
    secret.diffie_hellman(public).to_bytes()
}

/// Alice (initiator) → Bob bundle.
pub fn x3dh_initiator(
    alice_ik_secret: &[u8; 32],
    alice_ik_public: &IdentityPublic,
    bob: &PreKeyBundle,
) -> Result<(SharedSecret, X3dhInitialMessage, [u8; 32]), E2eError> {
    verify_signed_prekey(&bob.identity, &bob.signed_prekey)?;

    let ika = StaticSecret::from(*alice_ik_secret);
    let ikb = decode_x25519_pub(&bob.identity.identity_dh_pub_b64)?;
    let spkb = decode_x25519_pub(&bob.signed_prekey.dh_pub_b64)?;

    let eka = StaticSecret::random_from_rng(OsRng);
    let eka_pub = XPublic::from(&eka);

    let mut concat = Vec::with_capacity(32 * 4);
    concat.extend_from_slice(&dh(&ika, &spkb)); // DH1
    concat.extend_from_slice(&dh(&eka, &ikb)); // DH2
    concat.extend_from_slice(&dh(&eka, &spkb)); // DH3

    let mut otk_id = None;
    if let Some(ref otk_b64) = bob.one_time_prekey_b64 {
        let otkb = decode_x25519_pub(otk_b64)?;
        concat.extend_from_slice(&dh(&eka, &otkb)); // DH4
        otk_id = bob.one_time_prekey_id;
    }

    let sk = kdf_x3dh(&concat)?;
    concat.zeroize();

    let msg = X3dhInitialMessage {
        identity_dh_pub_b64: alice_ik_public.identity_dh_pub_b64.clone(),
        ephemeral_pub_b64: B64.encode(eka_pub.as_bytes()),
        used_signed_prekey_id: bob.signed_prekey.key_id,
        used_one_time_prekey_id: otk_id,
    };

    Ok((SharedSecret(sk), msg, eka.to_bytes()))
}

/// Bob (responder) processes Alice's initial message.
pub fn x3dh_responder(
    bob_ik_secret: &[u8; 32],
    bob_spk_secret: &[u8; 32],
    bob_otk_secret: Option<&[u8; 32]>,
    alice_msg: &X3dhInitialMessage,
) -> Result<SharedSecret, E2eError> {
    let ikb = StaticSecret::from(*bob_ik_secret);
    let spkb = StaticSecret::from(*bob_spk_secret);
    let ika = decode_x25519_pub(&alice_msg.identity_dh_pub_b64)?;
    let eka = decode_x25519_pub(&alice_msg.ephemeral_pub_b64)?;

    let mut concat = Vec::with_capacity(32 * 4);
    concat.extend_from_slice(&dh(&spkb, &ika)); // DH1
    concat.extend_from_slice(&dh(&ikb, &eka)); // DH2
    concat.extend_from_slice(&dh(&spkb, &eka)); // DH3

    if alice_msg.used_one_time_prekey_id.is_some() {
        let otk = bob_otk_secret.ok_or_else(|| E2eError::X3dh("missing OTK secret".into()))?;
        let otkb = StaticSecret::from(*otk);
        concat.extend_from_slice(&dh(&otkb, &eka)); // DH4
    }

    let sk = kdf_x3dh(&concat)?;
    concat.zeroize();
    Ok(SharedSecret(sk))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentitySecret;

    #[test]
    fn x3dh_alice_bob_agree() {
        let (alice_sec, alice_pub) = IdentitySecret::generate();
        let (bob_sec, bob_pub) = IdentitySecret::generate();
        let (spk_sec, spk_pub) = bob_sec.generate_signed_prekey(1).unwrap();
        let otk = StaticSecret::random_from_rng(OsRng);
        let otk_pub = XPublic::from(&otk);

        let bundle = PreKeyBundle {
            identity: bob_pub,
            signed_prekey: spk_pub,
            one_time_prekey_b64: Some(B64.encode(otk_pub.as_bytes())),
            one_time_prekey_id: Some(7),
        };

        let (sk_a, msg, _) =
            x3dh_initiator(&alice_sec.x25519, &alice_pub, &bundle).unwrap();
        let sk_b = x3dh_responder(
            &bob_sec.x25519,
            &spk_sec.secret,
            Some(&otk.to_bytes()),
            &msg,
        )
        .unwrap();
        assert_eq!(sk_a.0, sk_b.0);
    }
}
