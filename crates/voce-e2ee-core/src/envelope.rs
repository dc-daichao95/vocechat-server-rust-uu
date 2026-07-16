use serde::{Deserialize, Serialize};

use crate::error::E2eError;

/// Wire-format version carried in message `properties.e2e_ver`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum E2eVersion {
    V1 = 1,
    V2 = 2,
}

impl TryFrom<u8> for E2eVersion {
    type Error = E2eError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::V1),
            2 => Ok(Self::V2),
            other => Err(E2eError::UnsupportedVersion(other)),
        }
    }
}

/// Opaque v2 payload (ratchet header + ciphertext). Parsing crypto is Phase B+.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub e2e_ver: u8,
    pub sender_device_id: String,
    pub ciphertext_b64: String,
}

impl Envelope {
    pub fn parse_json(raw: &str) -> Result<Self, E2eError> {
        serde_json::from_str(raw).map_err(|e| E2eError::InvalidEnvelope(e.to_string()))
    }
}
