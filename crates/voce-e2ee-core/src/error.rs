use thiserror::Error;

#[derive(Debug, Error)]
pub enum E2eError {
    #[error("unsupported E2EE version: {0}")]
    UnsupportedVersion(u8),
    #[error("invalid envelope: {0}")]
    InvalidEnvelope(String),
    #[error("decryption failed")]
    DecryptFailed,
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),
}
