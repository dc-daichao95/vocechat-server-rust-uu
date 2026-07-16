use thiserror::Error;

#[derive(Debug, Error)]
pub enum E2eError {
    #[error("unsupported E2EE version: {0}")]
    UnsupportedVersion(u8),
    #[error("invalid envelope: {0}")]
    InvalidEnvelope(String),
    #[error("invalid key material: {0}")]
    InvalidKey(String),
    #[error("decryption failed")]
    DecryptFailed,
    #[error("replay detected (n={0})")]
    Replay(u32),
    #[error("x3dh failed: {0}")]
    X3dh(String),
    #[error("ratchet error: {0}")]
    Ratchet(String),
    #[error("json: {0}")]
    Json(String),
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),
}

impl From<serde_json::Error> for E2eError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e.to_string())
    }
}
