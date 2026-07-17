//! VoceChat E2EE v2 shared crypto core.
//!
//! Consumed by:
//! - Web client via `wasm-pack` (`--features wasm`)
//! - Flutter desktop/mobile via C FFI (`voce_e2ee_call` / `voce_e2ee_free`)
//!
//! v1 decrypt lives in [`v1_compat`] (read-only). New messages use v2 only after cutover.

pub mod envelope;
pub mod error;
pub mod ffi;
pub mod identity;
pub mod kdf;
pub mod pad;
pub mod ratchet;
pub mod sender_keys;
pub mod v1_compat;
pub mod x3dh;

pub use envelope::{E2eVersion, EnvelopeV2, ReplayWindow};
pub use error::E2eError;
pub use identity::{safety_number, IdentityPublic, IdentitySecret};
pub use pad::{pad_message, unpad_message};
pub use ratchet::{RatchetHeader, RatchetState, RatchetStateDto};
pub use x3dh::{x3dh_initiator, x3dh_responder, PreKeyBundle, SharedSecret};

/// Library version string for FFI/WASM diagnostics.
#[must_use]
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_non_empty() {
        assert!(!version().is_empty());
    }

    #[test]
    fn ffi_version_dispatch() {
        let out = ffi::dispatch("version", &serde_json::json!({}));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["result"], version());
    }

    #[test]
    fn ffi_dm_session_roundtrip() {
        let alice = ffi::dispatch("generate_identity", &serde_json::json!({}));
        let bob = ffi::dispatch("generate_identity", &serde_json::json!({}));
        let alice_v: serde_json::Value = serde_json::from_str(&alice).unwrap();
        let bob_v: serde_json::Value = serde_json::from_str(&bob).unwrap();
        assert_eq!(alice_v["ok"], true);
        assert_eq!(bob_v["ok"], true);

        let bob_spk = ffi::dispatch(
            "generate_signed_prekey",
            &serde_json::json!({
                "secret_x25519_b64": bob_v["result"]["secret_x25519_b64"],
                "secret_ed25519_b64": bob_v["result"]["secret_ed25519_b64"],
                "key_id": 1,
            }),
        );
        let bob_spk_v: serde_json::Value = serde_json::from_str(&bob_spk).unwrap();
        assert_eq!(bob_spk_v["ok"], true);

        let open = ffi::dispatch(
            "dm_session_open_initiator",
            &serde_json::json!({
                "alice_x25519_b64": alice_v["result"]["secret_x25519_b64"],
                "alice_public": alice_v["result"]["public"],
                "bundle": {
                    "identity": bob_v["result"]["public"],
                    "signed_prekey": bob_spk_v["result"]["public"],
                    "one_time_prekey_b64": null,
                    "one_time_prekey_id": null,
                },
                "plaintext": "hello bob",
            }),
        );
        let open_v: serde_json::Value = serde_json::from_str(&open).unwrap();
        assert_eq!(open_v["ok"], true, "{open}");

        let resp = ffi::dispatch(
            "dm_session_open_responder",
            &serde_json::json!({
                "bob_x25519_b64": bob_v["result"]["secret_x25519_b64"],
                "bob_spk_secret_b64": bob_spk_v["result"]["secret_b64"],
                "x3dh_initial": open_v["result"]["x3dh_initial"],
                "header": open_v["result"]["header"],
                "ciphertext_b64": open_v["result"]["ciphertext_b64"],
            }),
        );
        let resp_v: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(resp_v["ok"], true, "{resp}");
        assert_eq!(resp_v["result"]["plaintext"], "hello bob");

        let reply = ffi::dispatch(
            "ratchet_encrypt",
            &serde_json::json!({
                "state": resp_v["result"]["state"],
                "plaintext": "hello alice",
            }),
        );
        let reply_v: serde_json::Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(reply_v["ok"], true, "{reply}");

        let dec = ffi::dispatch(
            "ratchet_decrypt",
            &serde_json::json!({
                "state": open_v["result"]["state"],
                "header": reply_v["result"]["header"],
                "ciphertext_b64": reply_v["result"]["ciphertext_b64"],
            }),
        );
        let dec_v: serde_json::Value = serde_json::from_str(&dec).unwrap();
        assert_eq!(dec_v["ok"], true, "{dec}");
        assert_eq!(dec_v["result"]["plaintext"], "hello alice");
    }
}
