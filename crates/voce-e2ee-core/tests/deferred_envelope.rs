//! TDD tests for Task 3: deferred-envelope crypto (`DEFERRED+AES-GCM`).
//!
//! Covers the module API (`voce_e2ee_core::deferred`) directly and the
//! FFI/WASM JSON dispatch surface (`voce_e2ee_core::ffi::dispatch`) that Web
//! and Flutter will bind to.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde_json::json;

use voce_e2ee_core::deferred::{
    deferred_decrypt, deferred_encrypt, deferred_metadata_commitment, deferred_unwrap_key,
    deferred_verify_metadata, deferred_wrap_key, DeferredLocalIdentity, DEFERRED_ALG,
};
use voce_e2ee_core::ffi;
use voce_e2ee_core::identity::IdentitySecret;
use voce_e2ee_core::x3dh::PreKeyBundle;

/// Build a fresh recipient identity + published bundle (identity + signed
/// prekey, no one-time prekey) and the matching local secret material.
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

fn sample_metadata() -> serde_json::Value {
    json!({
        "chat_id": 42,
        "sender_device_id": "device-a",
        "content_type": "text/plain",
    })
}

// ---------------------------------------------------------------------------
// Module API
// ---------------------------------------------------------------------------

#[test]
fn round_trip_encrypt_wrap_unwrap_decrypt() {
    let (bundle, local) = recipient();
    let body = b"hello from the deferred flow";
    let metadata = sample_metadata();

    let enc = deferred_encrypt(body, &metadata).expect("encrypt");
    assert_ne!(enc.ciphertext, body, "ciphertext must not equal plaintext");

    let envelope = deferred_wrap_key(&enc.content_key, &bundle).expect("wrap");
    assert_eq!(envelope.alg, DEFERRED_ALG);

    let unwrapped_key = deferred_unwrap_key(&envelope, &local).expect("unwrap");
    assert_eq!(unwrapped_key, enc.content_key);

    let decrypted =
        deferred_decrypt(&enc.ciphertext, &unwrapped_key, &enc.nonce, &enc.sha256).expect("decrypt");
    assert_eq!(decrypted, body);
}

#[test]
fn tampered_ciphertext_fails_to_decrypt() {
    let metadata = sample_metadata();
    let enc = deferred_encrypt(b"secret body", &metadata).expect("encrypt");

    let mut tampered = enc.ciphertext.clone();
    tampered[0] ^= 0x01;

    let result = deferred_decrypt(&tampered, &enc.content_key, &enc.nonce, &enc.sha256);
    assert!(result.is_err(), "tampered ciphertext must not decrypt");
}

#[test]
fn tampered_metadata_binding_fails_to_decrypt() {
    // Same body/key/nonce, but the metadata (and thus its sha256 commitment)
    // differs from what was used at encrypt time -> AAD mismatch -> fail.
    let enc = deferred_encrypt(b"secret body", &sample_metadata()).expect("encrypt");

    let tampered_metadata = json!({
        "chat_id": 42,
        "sender_device_id": "device-a",
        "content_type": "image/png", // <- tampered
    });
    let retagged = deferred_encrypt(b"secret body", &tampered_metadata).expect("encrypt");
    // Sanity: different metadata really does produce a different commitment.
    assert_ne!(enc.sha256, retagged.sha256);

    let result = deferred_decrypt(&enc.ciphertext, &enc.content_key, &enc.nonce, &retagged.sha256);
    assert!(
        result.is_err(),
        "decrypting with a different metadata commitment must fail (AAD binding)"
    );
}

#[test]
fn metadata_key_order_does_not_change_binding() {
    // Canonicalization must be order-independent so equivalent metadata
    // objects bind identically regardless of client-side field ordering.
    let a = json!({"chat_id": 1, "kind": "dm"});
    let b = json!({"kind": "dm", "chat_id": 1});
    let enc_a = deferred_encrypt(b"same body", &a).unwrap();
    let enc_b = deferred_encrypt(b"same body", &b).unwrap();
    assert_eq!(enc_a.sha256, enc_b.sha256);
}

#[test]
fn wrong_recipient_cannot_unwrap_content_key() {
    let (bundle, _correct_local) = recipient();
    let (_other_bundle, wrong_local) = recipient();

    let enc = deferred_encrypt(b"body", &sample_metadata()).unwrap();
    let envelope = deferred_wrap_key(&enc.content_key, &bundle).unwrap();

    let result = deferred_unwrap_key(&envelope, &wrong_local);
    assert!(
        result.is_err() || result.unwrap() != enc.content_key,
        "unwrap with the wrong recipient identity must not yield the real content key"
    );
}

#[test]
fn duplicate_envelope_unwrap_is_idempotent() {
    let (bundle, local) = recipient();
    let enc = deferred_encrypt(b"body", &sample_metadata()).unwrap();
    let envelope = deferred_wrap_key(&enc.content_key, &bundle).unwrap();

    let first = deferred_unwrap_key(&envelope, &local).expect("first unwrap");
    let second = deferred_unwrap_key(&envelope, &local).expect("second unwrap (redelivery)");
    assert_eq!(first, enc.content_key);
    assert_eq!(second, enc.content_key);
}

#[test]
fn metadata_commitment_matches_encrypt_output() {
    let metadata = sample_metadata();
    let enc = deferred_encrypt(b"body", &metadata).unwrap();
    // The recipient re-derives the commitment from the metadata it received.
    let recomputed = deferred_metadata_commitment(&metadata).unwrap();
    assert_eq!(recomputed, enc.sha256);
    assert!(deferred_verify_metadata(&metadata, &enc.sha256).unwrap());
}

#[test]
fn spoofed_metadata_detected_even_when_ciphertext_and_sha256_are_valid() {
    // Threat model: a compromised server keeps the sender's real
    // ciphertext/nonce/sha256 (so `deferred_decrypt` still succeeds) but
    // rewrites the plaintext `metadata` it relays. The recipient MUST catch
    // this by recomputing the commitment from the *received* metadata.
    let real_metadata = sample_metadata();
    let enc = deferred_encrypt(b"body", &real_metadata).unwrap();

    // Decryption of the (untouched) ciphertext still works with the real
    // digest — decryption alone does NOT protect metadata.
    assert!(deferred_decrypt(&enc.ciphertext, &enc.content_key, &enc.nonce, &enc.sha256).is_ok());

    // Attacker-relayed metadata differs from what the sender bound.
    let spoofed_metadata = json!({
        "chat_id": 999,               // <- rewritten
        "sender_device_id": "attacker",
        "content_type": "text/plain",
    });

    // The caller-facing verification path rejects it.
    assert!(!deferred_verify_metadata(&spoofed_metadata, &enc.sha256).unwrap());
    assert_ne!(
        deferred_metadata_commitment(&spoofed_metadata).unwrap(),
        enc.sha256
    );
}

#[test]
fn rejects_envelope_with_wrong_algorithm_label() {
    let (bundle, local) = recipient();
    let enc = deferred_encrypt(b"body", &sample_metadata()).unwrap();
    let mut envelope = deferred_wrap_key(&enc.content_key, &bundle).unwrap();
    envelope.alg = "DR+AES-GCM".to_string();

    assert!(deferred_unwrap_key(&envelope, &local).is_err());
}

// ---------------------------------------------------------------------------
// FFI / WASM JSON dispatch surface
// ---------------------------------------------------------------------------

fn ffi_call(method: &str, args: &serde_json::Value) -> serde_json::Value {
    let out = ffi::dispatch(method, args);
    serde_json::from_str(&out).unwrap_or_else(|e| panic!("invalid JSON from {method}: {e}: {out}"))
}

#[test]
fn ffi_round_trip() {
    let recipient_identity = ffi_call("generate_identity", &json!({}));
    let recipient_spk = ffi_call(
        "generate_signed_prekey",
        &json!({
            "secret_x25519_b64": recipient_identity["result"]["secret_x25519_b64"],
            "secret_ed25519_b64": recipient_identity["result"]["secret_ed25519_b64"],
            "key_id": 1,
        }),
    );
    let bundle = json!({
        "identity": recipient_identity["result"]["public"],
        "signed_prekey": recipient_spk["result"]["public"],
        "one_time_prekey_b64": null,
        "one_time_prekey_id": null,
    });

    let enc = ffi_call(
        "deferred_encrypt",
        &json!({
            "body_b64": B64.encode(b"ffi body"),
            "metadata": {"chat_id": 7},
        }),
    );
    assert_eq!(enc["ok"], true, "{enc}");
    let content_key_b64 = enc["result"]["content_key_b64"].as_str().unwrap();
    let nonce_b64 = enc["result"]["nonce_b64"].as_str().unwrap();
    let ciphertext_b64 = enc["result"]["ciphertext_b64"].as_str().unwrap();
    let sha256_b64 = enc["result"]["sha256_b64"].as_str().unwrap();

    let wrap = ffi_call(
        "deferred_wrap_key",
        &json!({
            "content_key_b64": content_key_b64,
            "recipient_bundle": bundle,
        }),
    );
    assert_eq!(wrap["ok"], true, "{wrap}");
    assert_eq!(wrap["result"]["envelope"]["alg"], DEFERRED_ALG);

    let unwrap = ffi_call(
        "deferred_unwrap_key",
        &json!({
            "envelope": wrap["result"]["envelope"],
            "local_identity": {
                "ik_secret_b64": recipient_identity["result"]["secret_x25519_b64"],
                "spk_secret_b64": recipient_spk["result"]["secret_b64"],
                "otk_secret_b64": null,
            },
        }),
    );
    assert_eq!(unwrap["ok"], true, "{unwrap}");
    assert_eq!(unwrap["result"]["content_key_b64"], content_key_b64);

    let dec = ffi_call(
        "deferred_decrypt",
        &json!({
            "ciphertext_b64": ciphertext_b64,
            "content_key_b64": unwrap["result"]["content_key_b64"],
            "nonce_b64": nonce_b64,
            "sha256_b64": sha256_b64,
        }),
    );
    assert_eq!(dec["ok"], true, "{dec}");
    assert_eq!(
        B64.decode(dec["result"]["body_b64"].as_str().unwrap()).unwrap(),
        b"ffi body"
    );
    assert_eq!(dec["result"]["body"], "ffi body");
}

#[test]
fn ffi_verify_metadata_detects_spoof() {
    let real_metadata = json!({"chat_id": 42, "content_type": "text/plain"});
    let enc = ffi_call(
        "deferred_encrypt",
        &json!({"body_b64": B64.encode(b"ffi body"), "metadata": real_metadata}),
    );
    assert_eq!(enc["ok"], true, "{enc}");
    let sha256_b64 = enc["result"]["sha256_b64"].as_str().unwrap();

    // Commitment method re-derives the same digest from the real metadata.
    let commit = ffi_call(
        "deferred_metadata_commitment",
        &json!({"metadata": real_metadata}),
    );
    assert_eq!(commit["ok"], true, "{commit}");
    assert_eq!(commit["result"]["sha256_b64"], sha256_b64);

    // Genuine metadata verifies true.
    let ok_verify = ffi_call(
        "deferred_verify_metadata",
        &json!({"metadata": real_metadata, "sha256_b64": sha256_b64}),
    );
    assert_eq!(ok_verify["ok"], true, "{ok_verify}");
    assert_eq!(ok_verify["result"]["matches"], true);

    // Spoofed metadata (with the sender's valid sha256) verifies false.
    let spoof_verify = ffi_call(
        "deferred_verify_metadata",
        &json!({
            "metadata": {"chat_id": 999, "content_type": "text/plain"},
            "sha256_b64": sha256_b64,
        }),
    );
    assert_eq!(spoof_verify["ok"], true, "{spoof_verify}");
    assert_eq!(spoof_verify["result"]["matches"], false);
}

#[test]
fn ffi_encrypt_requires_metadata_field() {
    // Omitting `metadata` entirely is a caller bug and must error, not
    // silently bind `null`.
    let missing = ffi_call("deferred_encrypt", &json!({"body_b64": B64.encode(b"x")}));
    assert_eq!(missing["ok"], false, "{missing}");

    // Explicit null is allowed (caller intent is unambiguous).
    let explicit_null =
        ffi_call("deferred_encrypt", &json!({"body_b64": B64.encode(b"x"), "metadata": null}));
    assert_eq!(explicit_null["ok"], true, "{explicit_null}");
}

#[test]
fn ffi_tampered_ciphertext_rejected() {
    let enc = ffi_call(
        "deferred_encrypt",
        &json!({"body_b64": B64.encode(b"ffi body"), "metadata": {"a": 1}}),
    );
    let mut ct = B64.decode(enc["result"]["ciphertext_b64"].as_str().unwrap()).unwrap();
    ct[0] ^= 1;

    let dec = ffi_call(
        "deferred_decrypt",
        &json!({
            "ciphertext_b64": B64.encode(&ct),
            "content_key_b64": enc["result"]["content_key_b64"],
            "nonce_b64": enc["result"]["nonce_b64"],
            "sha256_b64": enc["result"]["sha256_b64"],
        }),
    );
    assert_eq!(dec["ok"], false, "{dec}");
}

#[test]
fn ffi_wrong_recipient_rejected() {
    let recipient_identity = ffi_call("generate_identity", &json!({}));
    let recipient_spk = ffi_call(
        "generate_signed_prekey",
        &json!({
            "secret_x25519_b64": recipient_identity["result"]["secret_x25519_b64"],
            "secret_ed25519_b64": recipient_identity["result"]["secret_ed25519_b64"],
            "key_id": 1,
        }),
    );
    let bundle = json!({
        "identity": recipient_identity["result"]["public"],
        "signed_prekey": recipient_spk["result"]["public"],
        "one_time_prekey_b64": null,
        "one_time_prekey_id": null,
    });

    let other_identity = ffi_call("generate_identity", &json!({}));
    let other_spk = ffi_call(
        "generate_signed_prekey",
        &json!({
            "secret_x25519_b64": other_identity["result"]["secret_x25519_b64"],
            "secret_ed25519_b64": other_identity["result"]["secret_ed25519_b64"],
            "key_id": 1,
        }),
    );

    let enc = ffi_call(
        "deferred_encrypt",
        &json!({"body_b64": B64.encode(b"ffi body"), "metadata": {"a": 1}}),
    );
    let wrap = ffi_call(
        "deferred_wrap_key",
        &json!({
            "content_key_b64": enc["result"]["content_key_b64"],
            "recipient_bundle": bundle,
        }),
    );

    let unwrap = ffi_call(
        "deferred_unwrap_key",
        &json!({
            "envelope": wrap["result"]["envelope"],
            "local_identity": {
                "ik_secret_b64": other_identity["result"]["secret_x25519_b64"],
                "spk_secret_b64": other_spk["result"]["secret_b64"],
                "otk_secret_b64": null,
            },
        }),
    );
    assert_eq!(unwrap["ok"], false, "wrong recipient must not unwrap: {unwrap}");
}

#[test]
fn ffi_duplicate_envelope_unwrap_is_idempotent() {
    let recipient_identity = ffi_call("generate_identity", &json!({}));
    let recipient_spk = ffi_call(
        "generate_signed_prekey",
        &json!({
            "secret_x25519_b64": recipient_identity["result"]["secret_x25519_b64"],
            "secret_ed25519_b64": recipient_identity["result"]["secret_ed25519_b64"],
            "key_id": 1,
        }),
    );
    let bundle = json!({
        "identity": recipient_identity["result"]["public"],
        "signed_prekey": recipient_spk["result"]["public"],
        "one_time_prekey_b64": null,
        "one_time_prekey_id": null,
    });
    let enc = ffi_call(
        "deferred_encrypt",
        &json!({"body_b64": B64.encode(b"ffi body"), "metadata": {"a": 1}}),
    );
    let wrap = ffi_call(
        "deferred_wrap_key",
        &json!({
            "content_key_b64": enc["result"]["content_key_b64"],
            "recipient_bundle": bundle,
        }),
    );
    let local_identity = json!({
        "ik_secret_b64": recipient_identity["result"]["secret_x25519_b64"],
        "spk_secret_b64": recipient_spk["result"]["secret_b64"],
        "otk_secret_b64": null,
    });

    let first = ffi_call(
        "deferred_unwrap_key",
        &json!({"envelope": wrap["result"]["envelope"], "local_identity": local_identity}),
    );
    let second = ffi_call(
        "deferred_unwrap_key",
        &json!({"envelope": wrap["result"]["envelope"], "local_identity": local_identity}),
    );
    assert_eq!(first["ok"], true, "{first}");
    assert_eq!(second["ok"], true, "{second}");
    assert_eq!(
        first["result"]["content_key_b64"],
        second["result"]["content_key_b64"]
    );
    assert_eq!(
        first["result"]["content_key_b64"],
        enc["result"]["content_key_b64"]
    );
}
