//! Task 9: cross-client (Web <-> Flutter) deferred-DM wire compatibility
//! fixture.
//!
//! Neither the Web nor the Flutter test suite can talk to each other
//! directly, and no shared multi-language E2E harness exists. Instead, this
//! test drives the exact same FFI JSON dispatch surface
//! (`voce_e2ee_core::ffi::dispatch`) that BOTH clients bind to
//! (`src/app/e2e/deferred.ts` on Web, `lib/services/e2e_v2_deferred.dart` on
//! Flutter — see task-3-report.md §5/§12 and task-5-6/task-7 reports), and
//! assembles the literal wire JSON each client sends/receives for a
//! `protocol=dr-pending` DM:
//!
//!   1. "Web sender": deferred_encrypt -> deferred_wrap_key, packed into the
//!      exact `dr-pending` message properties + body shape
//!      `src/app/e2e/deferred.ts::buildDeferredDmSend` produces (matches the
//!      server's `Protocol::DrPending` validation in `src/e2ee_v2.rs`).
//!   2. The resulting JSON is written to
//!      `testdata/cross-client-deferred-dm-fixture.json` as a durable,
//!      reviewable artifact.
//!   3. "Flutter recipient": reads the fixture back (simulating receipt over
//!      the wire/SSE), calls `deferred_verify_metadata` on the metadata it
//!      received (the MANDATORY recipient check both clients implement),
//!      then `deferred_unwrap_key` + `deferred_decrypt`
//!      (`E2eV2Deferred.verifyUnwrapAndDecrypt` in
//!      `lib/services/e2e_v2_deferred.dart`), and asserts the recovered
//!      plaintext matches exactly what "Web" sent.
//!   4. Negative controls: a recipient that tampers with the received
//!      metadata, or that is not the addressed device, must be rejected
//!      fail-closed — proving both clients' "never fall back to plaintext"
//!      contract holds across the wire boundary.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;

use voce_e2ee_core::ffi::dispatch;

fn call(method: &str, args: &Value) -> Value {
    let raw = dispatch(method, args);
    let parsed: Value = serde_json::from_str(&raw).expect("valid JSON from dispatch");
    assert_eq!(
        parsed["ok"],
        Value::Bool(true),
        "{method} failed: {parsed}"
    );
    parsed["result"].clone()
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join("cross-client-deferred-dm-fixture.json")
}

/// "Web sender" step: build the exact dr-pending wire message the Web
/// client's `buildDeferredDmSend` sends (see task-5-6-report.md), using a
/// fresh recipient identity that stands in for a Flutter client's published
/// bundle.
fn web_sender_builds_wire_message() -> Value {
    let identity = call("generate_identity", &json!({}));
    let spk = call(
        "generate_signed_prekey",
        &json!({
            "secret_x25519_b64": identity["secret_x25519_b64"],
            "secret_ed25519_b64": identity["secret_ed25519_b64"],
            "key_id": 1,
        }),
    );

    let recipient_bundle = json!({
        "identity": identity["public"],
        "signed_prekey": spk["public"],
        "one_time_prekey_b64": null,
        "one_time_prekey_id": null,
    });
    let local_identity = json!({
        "ik_secret_b64": identity["secret_x25519_b64"],
        "spk_secret_b64": spk["secret_b64"],
        "otk_secret_b64": null,
    });

    // Per Task 3's finalized contract (§12): metadata MUST carry a unique
    // per-message id, and is transmitted on the wire so the recipient can
    // recompute/verify the commitment.
    let metadata = json!({
        "id": "018f8dd2-c87e-7b40-bf45-4df46c08e591:1721638400000",
        "sender_device_id": "web-device-alice-1",
        "mime": "text/plain",
    });

    let plaintext = "hello from Web, decrypt me on Flutter";
    let enc = call(
        "deferred_encrypt",
        &json!({ "body": plaintext, "metadata": metadata }),
    );

    let wrap = call(
        "deferred_wrap_key",
        &json!({
            "content_key_b64": enc["content_key_b64"],
            "recipient_bundle": recipient_bundle,
        }),
    );

    // The exact `dr-pending` message shape both clients send: routing
    // properties (matching src/e2ee_v2.rs's `Protocol::DrPending` validator)
    // plus the opaque `dr_envelope` body (ciphertext + metadata + commitment
    // + the recipient's wrap envelope, packed exactly as
    // `DrPendingRoutingProperties`/`E2eV2Dm.encryptTextDeferred` do).
    json!({
        "_fixture_purpose": "Task 9 cross-client (Web -> Flutter) deferred DM wire compatibility",
        "routing_properties": {
            "e2e_version": 2,
            "protocol": "dr-pending",
            "algorithm": "DEFERRED+AES-GCM",
            "wire_class": "dr_envelope",
            "sender_device_id": "web-device-alice-1",
            "local_id": "018f8dd2-c87e-7b40-bf45-4df46c08e591"
        },
        "body": {
            "ciphertext_b64": enc["ciphertext_b64"],
            "nonce_b64": enc["nonce_b64"],
            "metadata": metadata,
            "metadata_sha256_b64": enc["sha256_b64"],
            "wrap_envelope": wrap["envelope"],
        },
        // Retained only so this test can also exercise the "correct
        // recipient" happy path without a second live device; a real
        // Flutter recipient already holds its own secrets locally and never
        // receives them over the wire.
        "_recipient_local_identity_for_test_only": local_identity,
        "_expected_plaintext_for_test_only": plaintext,
    })
}

/// "Flutter recipient" step: exactly mirrors
/// `E2eV2Deferred.verifyUnwrapAndDecrypt` in
/// `vocechat-client-uu/lib/services/e2e_v2_deferred.dart` — verify metadata
/// commitment FIRST, then unwrap, then decrypt. Fails closed (returns Err)
/// on any mismatch instead of ever returning plaintext.
fn flutter_recipient_verify_unwrap_decrypt(
    wire: &Value,
    local_identity: &Value,
) -> Result<String, String> {
    let body = &wire["body"];
    let metadata = &body["metadata"];
    let sha256_b64 = &body["metadata_sha256_b64"];

    let verify = call(
        "deferred_verify_metadata",
        &json!({ "metadata": metadata, "sha256_b64": sha256_b64 }),
    );
    if verify["matches"] != Value::Bool(true) {
        return Err("metadata commitment mismatch".to_string());
    }

    let unwrap_raw = dispatch(
        "deferred_unwrap_key",
        &json!({
            "envelope": body["wrap_envelope"],
            "local_identity": local_identity,
        }),
    );
    let unwrap: Value = serde_json::from_str(&unwrap_raw).unwrap();
    if unwrap["ok"] != Value::Bool(true) {
        return Err(format!("unwrap failed: {unwrap}"));
    }
    let content_key_b64 = unwrap["result"]["content_key_b64"].clone();

    let dec_raw = dispatch(
        "deferred_decrypt",
        &json!({
            "ciphertext_b64": body["ciphertext_b64"],
            "content_key_b64": content_key_b64,
            "nonce_b64": body["nonce_b64"],
            "sha256_b64": sha256_b64,
        }),
    );
    let dec: Value = serde_json::from_str(&dec_raw).unwrap();
    if dec["ok"] != Value::Bool(true) {
        return Err(format!("decrypt failed: {dec}"));
    }
    Ok(dec["result"]["body"].as_str().unwrap().to_string())
}

#[test]
fn web_sender_flutter_recipient_wire_round_trip() {
    let wire = web_sender_builds_wire_message();

    // Sanity: routing properties match the server's Protocol::DrPending
    // validator exactly (protocol/algorithm/wire_class strings, no
    // recipient_device_id, no MLS fields).
    let props = &wire["routing_properties"];
    assert_eq!(props["protocol"], "dr-pending");
    assert_eq!(props["algorithm"], "DEFERRED+AES-GCM");
    assert_eq!(props["wire_class"], "dr_envelope");
    assert!(props.get("recipient_device_id").is_none());
    assert!(props.get("mls_epoch").is_none());

    // Persist the fixture for review / reuse.
    let path = fixture_path();
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, serde_json::to_string_pretty(&wire).unwrap()).unwrap();

    // Re-read from disk exactly as a Flutter client would receive it off the
    // wire/SSE (proves the fixture is self-contained JSON, not depending on
    // any in-memory state from the "Web" step).
    let read_back: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    let local_identity = read_back["_recipient_local_identity_for_test_only"].clone();
    let expected_plaintext = read_back["_expected_plaintext_for_test_only"]
        .as_str()
        .unwrap();

    let recovered = flutter_recipient_verify_unwrap_decrypt(&read_back, &local_identity)
        .expect("Flutter recipient must successfully decrypt the Web-sent envelope");
    assert_eq!(recovered, expected_plaintext);
}

#[test]
fn flutter_recipient_rejects_tampered_metadata_from_wire() {
    let wire = web_sender_builds_wire_message();
    let local_identity = wire["_recipient_local_identity_for_test_only"].clone();

    let mut tampered = wire.clone();
    tampered["body"]["metadata"]["mime"] = json!("text/evil-injected");

    let err = flutter_recipient_verify_unwrap_decrypt(&tampered, &local_identity)
        .expect_err("tampered metadata must be rejected before any unwrap/decrypt");
    assert!(err.contains("commitment"));
}

#[test]
fn flutter_recipient_on_wrong_device_cannot_unwrap() {
    let wire = web_sender_builds_wire_message();

    // A different Flutter device (not the one Web addressed the envelope to).
    let other_identity = call("generate_identity", &json!({}));
    let other_spk = call(
        "generate_signed_prekey",
        &json!({
            "secret_x25519_b64": other_identity["secret_x25519_b64"],
            "secret_ed25519_b64": other_identity["secret_ed25519_b64"],
            "key_id": 1,
        }),
    );
    let wrong_local_identity = json!({
        "ik_secret_b64": other_identity["secret_x25519_b64"],
        "spk_secret_b64": other_spk["secret_b64"],
        "otk_secret_b64": null,
    });

    let err = flutter_recipient_verify_unwrap_decrypt(&wire, &wrong_local_identity)
        .expect_err("wrong recipient device must fail to unwrap");
    assert!(err.contains("unwrap failed"));
}

#[test]
fn fixture_file_is_valid_and_matches_current_wire_contract() {
    // Regression gate: if this ever fails to parse/validate, the committed
    // fixture is stale relative to the current wire contract and must be
    // regenerated by re-running `web_sender_flutter_recipient_wire_round_trip`.
    let path = fixture_path();
    let contents = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("fixture missing at {path:?}: {e}"));
    let wire: Value = serde_json::from_str(&contents).unwrap();
    let local_identity = wire["_recipient_local_identity_for_test_only"].clone();
    let expected_plaintext = wire["_expected_plaintext_for_test_only"]
        .as_str()
        .unwrap()
        .to_string();
    let recovered = flutter_recipient_verify_unwrap_decrypt(&wire, &local_identity).unwrap();
    assert_eq!(recovered, expected_plaintext);

    // Byte-for-byte sanity on the base64 fields (never accidentally empty).
    let body = &wire["body"];
    for field in ["ciphertext_b64", "nonce_b64", "metadata_sha256_b64"] {
        let v = body[field].as_str().unwrap();
        assert!(!v.is_empty());
        assert!(B64.decode(v).is_ok());
    }
}
