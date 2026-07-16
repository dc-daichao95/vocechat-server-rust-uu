//! VoceChat E2EE v2 shared crypto core.
//!
//! Consumed by:
//! - Web client via `wasm-pack`
//! - Flutter desktop/mobile via C FFI
//! - Server integration tests (optional)
//!
//! v1 decrypt lives in `v1_compat` (read-only). New messages use v2 only.

pub mod envelope;
pub mod error;

pub use envelope::{E2eVersion, Envelope};
pub use error::E2eError;

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
}
