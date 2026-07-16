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
pub mod ratchet;
pub mod sender_keys;
pub mod v1_compat;
pub mod x3dh;

pub use envelope::{E2eVersion, EnvelopeV2, ReplayWindow};
pub use error::E2eError;
pub use identity::{safety_number, IdentityPublic, IdentitySecret};
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
}
