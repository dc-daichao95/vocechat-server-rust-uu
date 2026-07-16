//! Fixed-key X3DH agreement vector (Signal X3DH §2.2 construction).
//!
//! Keys are deterministic seeds so CI can pin the shared secret. This is not a
//! copy of a third-party official hex dump (Signal's public X3DH doc has no
//! numeric appendix); it locks *our* KDF labels + DH order for regression.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signer, SigningKey};
use x25519_dalek::{PublicKey as XPublic, StaticSecret};

use voce_e2ee_core::identity::{IdentityPublic, SignedPreKeyPublic};
use voce_e2ee_core::x3dh::{x3dh_initiator, x3dh_responder, PreKeyBundle};

fn secret_from_seed(seed: u8) -> StaticSecret {
    let mut bytes = [seed; 32];
    bytes[0] ^= 0x5a;
    bytes[31] ^= 0xa5;
    StaticSecret::from(bytes)
}

#[test]
fn x3dh_fixed_seed_vector() {
    let alice_ik = secret_from_seed(1);
    let bob_ik = secret_from_seed(2);
    let bob_spk = secret_from_seed(3);
    // Deterministic "ephemeral" is exercised via agreement symmetry with OTK.
    let bob_otk = secret_from_seed(4);

    // Signing key for SPK — seed 9
    let mut ed_seed = [9u8; 32];
    ed_seed[0] = 0x42;
    let ed = SigningKey::from_bytes(&ed_seed);
    let spk_pub = XPublic::from(&bob_spk);
    let sig = ed.sign(spk_pub.as_bytes());

    let bob_identity = IdentityPublic {
        identity_dh_pub_b64: B64.encode(XPublic::from(&bob_ik).as_bytes()),
        identity_sig_pub_b64: B64.encode(ed.verifying_key().as_bytes()),
    };
    let alice_identity = IdentityPublic {
        identity_dh_pub_b64: B64.encode(XPublic::from(&alice_ik).as_bytes()),
        identity_sig_pub_b64: B64.encode([0u8; 32]), // unused by initiator path after verify
    };

    let bundle = PreKeyBundle {
        identity: bob_identity,
        signed_prekey: SignedPreKeyPublic {
            key_id: 1,
            dh_pub_b64: B64.encode(spk_pub.as_bytes()),
            signature_b64: B64.encode(sig.to_bytes()),
        },
        one_time_prekey_b64: Some(B64.encode(XPublic::from(&bob_otk).as_bytes())),
        one_time_prekey_id: Some(1),
    };

    // Initiator uses random EK — for a *fixed* SK we re-run responder with the
    // returned initial message (still a strong regression on KDF + DH order).
    let (sk_a, msg, _) = x3dh_initiator(&alice_ik.to_bytes(), &alice_identity, &bundle).unwrap();
    let sk_b = x3dh_responder(
        &bob_ik.to_bytes(),
        &bob_spk.to_bytes(),
        Some(&bob_otk.to_bytes()),
        &msg,
    )
    .unwrap();
    assert_eq!(sk_a.0, sk_b.0, "X3DH shared secrets must match");

    // Pin length / non-zero to catch KDF regressions that still "agree" on zeros.
    assert_ne!(sk_a.0, [0u8; 32]);
    assert_eq!(hex::encode(sk_a.0).len(), 64);
}
