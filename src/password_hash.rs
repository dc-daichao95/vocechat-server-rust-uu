//! Password hashing and legacy-compatibility helpers.
//!
//! Historically this server stored passwords as either plaintext or
//! `MD5(MD5(plaintext))` hex digests. New passwords must be hashed with
//! Argon2id. This module provides:
//!
//! - [`hash`] / [`verify`]: Argon2id hashing and verification.
//! - [`looks_like_argon2id`] / [`looks_like_double_md5`]: format sniffing so
//!   callers can tell which scheme a stored value uses.
//! - [`verify_and_upgrade`]: the compatibility flow used by login /
//!   change-password call sites. It accepts Argon2id, legacy double-MD5, and
//!   (for one release window) raw plaintext equality, and tells the caller
//!   whether the stored value should be rewritten to Argon2id.
//!
//! Nothing in this module ever logs the plaintext password or the hash
//! material; functions return plain booleans/strings for the caller to use,
//! and no `tracing`/`println` calls are made here.
//!
//! # Timing
//!
//! The legacy comparisons in [`verify_and_upgrade`] (the double-MD5 digest
//! comparison and the raw-plaintext equality fallback) use ordinary `==`
//! string comparison and are therefore **not constant-time**. This is an
//! accepted trade-off: the HTTP login/change-password endpoints already
//! reveal the match/no-match result to the caller, so a timing side channel
//! does not leak anything the response itself does not. Argon2id
//! verification (the steady-state path once every credential is migrated)
//! goes through the `argon2`/`password-hash` crates, whose verifier does use
//! a constant-time tag comparison.

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use md5::{Digest, Md5};

/// Prefix used by the `password-hash` crate for Argon2id PHC strings.
const ARGON2ID_PREFIX: &str = "$argon2id$";

/// Opaque error returned when Argon2id hashing/parsing fails.
///
/// Deliberately does not carry the underlying `argon2` error message, since
/// that message could (in principle) be built from attacker-controlled input
/// paths; callers only need to know that hashing failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashError;

impl std::fmt::Display for HashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("failed to hash password")
    }
}

impl std::error::Error for HashError {}

/// Hash a plaintext password into an Argon2id PHC string
/// (e.g. `$argon2id$v=19$m=19456,t=2,p=1$...`).
///
/// This is the *only* function that should be used to produce a value for
/// the `user.password` column going forward.
pub fn hash(password: &str) -> Result<String, HashError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| HashError)?;
    Ok(hash.to_string())
}

/// Verify a plaintext password against a stored Argon2id PHC string.
///
/// Returns `false` (rather than erroring) if `stored` is not a valid
/// Argon2id PHC string, since from the caller's perspective that's simply a
/// non-match.
pub fn verify(password: &str, stored: &str) -> bool {
    let parsed = match PasswordHash::new(stored) {
        Ok(parsed) => parsed,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// Returns `true` if `stored` is an Argon2id PHC string (i.e. already
/// migrated).
pub fn looks_like_argon2id(stored: &str) -> bool {
    stored.starts_with(ARGON2ID_PREFIX)
}

/// Returns `true` if `stored` looks like a legacy `MD5(MD5(plaintext))`
/// hex digest: exactly 32 lowercase hex characters.
pub fn looks_like_double_md5(stored: &str) -> bool {
    stored.len() == 32
        && stored
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Compute `MD5(MD5(plaintext))` as a lowercase hex string, matching the
/// legacy scheme used by old VoceChat databases (inner MD5 is hex-encoded
/// before being fed into the outer MD5, matching PHP's default
/// `md5(md5($password))` behavior).
pub fn double_md5_hex(password: &str) -> String {
    let first = hex::encode(Md5::digest(password.as_bytes()));
    hex::encode(Md5::digest(first.as_bytes()))
}

/// Outcome of [`verify_and_upgrade`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyAndUpgrade {
    /// Whether `plaintext` matches `stored` under any supported scheme.
    pub matched: bool,
    /// If `Some`, the caller should persist this Argon2id hash in place of
    /// `stored` (best-effort: login/verification must still be treated as
    /// successful even if the caller fails to persist the upgrade).
    pub upgraded_hash: Option<String>,
}

/// The core compatibility flow: verify `plaintext` against `stored`,
/// accepting Argon2id, legacy double-MD5, and (for a limited release
/// window) raw plaintext equality. When a match is found via a non-Argon2id
/// scheme, a freshly computed Argon2id hash is returned so the caller can
/// upgrade the stored value in the database and in-memory cache.
///
/// This function is pure (no I/O, no locks) so it can be unit tested in
/// isolation; DB/cache persistence of `upgraded_hash` is the caller's
/// responsibility.
pub fn verify_and_upgrade(plaintext: &str, stored: &str) -> VerifyAndUpgrade {
    if looks_like_argon2id(stored) {
        return VerifyAndUpgrade {
            matched: verify(plaintext, stored),
            upgraded_hash: None,
        };
    }

    // SECURITY: if `stored` already looks like a recognized hash format
    // (here: a legacy double-MD5 digest), the ONLY accepted proof is the
    // plaintext whose double-MD5 equals it. We must NOT fall through to
    // `stored == plaintext`, because that would let an attacker who has read
    // the stored hash (from a DB dump / backup) authenticate by submitting
    // the hash string itself as the "password" — and the subsequent upgrade
    // would then persist Argon2id(hash-string), a durable account takeover.
    // The raw plaintext-equality fallback is reserved for values that are
    // neither Argon2id (early-returned above) nor double-MD5 shaped, i.e.
    // genuinely still-plaintext legacy rows.
    let legacy_match = if looks_like_double_md5(stored) {
        double_md5_hex(plaintext) == stored
    } else {
        stored == plaintext
    };

    if legacy_match {
        VerifyAndUpgrade {
            matched: true,
            // Best-effort: if hashing fails for some reason, the caller
            // still treats this as a successful login and simply skips the
            // upgrade this time.
            upgraded_hash: hash(plaintext).ok(),
        }
    } else {
        VerifyAndUpgrade {
            matched: false,
            upgraded_hash: None,
        }
    }
}

/// Async wrapper around [`hash`] that offloads the CPU/memory-hard Argon2id
/// computation to a blocking thread via `tokio::task::spawn_blocking`, so it
/// never monopolizes an async runtime worker (a DoS risk under concurrent
/// logins/registrations).
///
/// Callers must NOT hold any lock (e.g. the global `state.cache` `RwLock`)
/// across this call.
pub async fn hash_async(password: String) -> Result<String, HashError> {
    tokio::task::spawn_blocking(move || hash(&password))
        .await
        .map_err(|_| HashError)?
}

/// Async wrapper around [`verify_and_upgrade`] that offloads the Argon2id
/// verify + (on a legacy match) the Argon2id upgrade hash to a blocking
/// thread via `tokio::task::spawn_blocking`.
///
/// Callers must NOT hold any lock across this call; capture the `stored`
/// value out of the cache first, release the lock, then verify.
pub async fn verify_and_upgrade_async(plaintext: String, stored: String) -> VerifyAndUpgrade {
    tokio::task::spawn_blocking(move || verify_and_upgrade(&plaintext, &stored))
        .await
        // A join error (blocking pool panic/shutdown) is treated as a
        // non-match; login/verification simply fails safe.
        .unwrap_or(VerifyAndUpgrade {
            matched: false,
            upgraded_hash: None,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2id_round_trip() {
        let hashed = hash("correct horse battery staple").expect("hash should succeed");
        assert!(looks_like_argon2id(&hashed));
        assert!(verify("correct horse battery staple", &hashed));
    }

    #[test]
    fn argon2id_wrong_password_rejects() {
        let hashed = hash("correct horse battery staple").expect("hash should succeed");
        assert!(!verify("wrong password", &hashed));
    }

    #[test]
    fn double_md5_matches_known_vector() {
        // plaintext "dc950713" -> MD5(MD5(...)) == a75fc917c14138b831247f93fc38bb0b
        // (verified independently via certutil -hashfile, double hex-encode).
        assert_eq!(double_md5_hex("dc950713"), "a75fc917c14138b831247f93fc38bb0b");
    }

    #[test]
    fn looks_like_double_md5_detects_legacy_format() {
        assert!(looks_like_double_md5("a75fc917c14138b831247f93fc38bb0b"));
        assert!(!looks_like_double_md5("A75FC917C14138B831247F93FC38BB0B"));
        assert!(!looks_like_double_md5("not-a-hex-string"));
        assert!(!looks_like_double_md5(
            "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2g"
        ));
    }

    #[test]
    fn looks_like_argon2id_detects_phc_prefix() {
        assert!(looks_like_argon2id(
            "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2g"
        ));
        assert!(!looks_like_argon2id("a75fc917c14138b831247f93fc38bb0b"));
        assert!(!looks_like_argon2id("plaintext"));
    }

    #[test]
    fn verify_and_upgrade_accepts_legacy_double_md5_and_upgrades() {
        let stored = double_md5_hex("dc950713");
        let outcome = verify_and_upgrade("dc950713", &stored);
        assert!(outcome.matched);
        let upgraded = outcome.upgraded_hash.expect("should produce an upgrade hash");
        assert!(looks_like_argon2id(&upgraded));
        assert!(verify("dc950713", &upgraded));
    }

    #[test]
    fn verify_and_upgrade_rejects_wrong_password_for_legacy_double_md5() {
        let stored = double_md5_hex("dc950713");
        let outcome = verify_and_upgrade("wrong-password", &stored);
        assert!(!outcome.matched);
        assert!(outcome.upgraded_hash.is_none());
    }

    #[test]
    fn verify_and_upgrade_rejects_stored_hash_as_password_for_legacy_double_md5() {
        // SECURITY regression: submitting the STORED double-MD5 hash string
        // itself as the password must NOT authenticate. Only the real
        // plaintext (whose double-MD5 equals `stored`) may match.
        let stored = double_md5_hex("dc950713");
        let outcome = verify_and_upgrade(&stored, &stored);
        assert!(
            !outcome.matched,
            "submitting the stored hash as the password must be rejected"
        );
        assert!(outcome.upgraded_hash.is_none());
    }

    #[test]
    fn verify_and_upgrade_accepts_plaintext_equality_and_upgrades() {
        // One-release-window compatibility for any values that are still raw
        // plaintext (neither Argon2id nor double-MD5 shaped).
        let outcome = verify_and_upgrade("some-plain-password", "some-plain-password");
        assert!(outcome.matched);
        let upgraded = outcome.upgraded_hash.expect("should produce an upgrade hash");
        assert!(looks_like_argon2id(&upgraded));
    }

    #[test]
    fn verify_and_upgrade_matches_argon2id_without_reupgrading() {
        let stored = hash("already-migrated").unwrap();
        let outcome = verify_and_upgrade("already-migrated", &stored);
        assert!(outcome.matched);
        assert!(outcome.upgraded_hash.is_none());
    }

    #[test]
    fn verify_and_upgrade_rejects_wrong_password_for_argon2id() {
        let stored = hash("already-migrated").unwrap();
        let outcome = verify_and_upgrade("nope", &stored);
        assert!(!outcome.matched);
        assert!(outcome.upgraded_hash.is_none());
    }
}
