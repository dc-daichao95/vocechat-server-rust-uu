use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::error::E2eError;
use crate::ratchet::RatchetHeader;
use crate::sender_keys::SenderKeyHeader;

/// Wire-format version carried in message `properties.e2e_ver`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "alg")]
pub enum EnvelopeV2Body {
    #[serde(rename = "DR+AES-GCM")]
    DoubleRatchet {
        header: RatchetHeader,
        ciphertext_b64: String,
    },
    #[serde(rename = "SK+AES-GCM")]
    SenderKey {
        header: SenderKeyHeader,
        ciphertext_b64: String,
        gid: i64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeV2 {
    pub v: u8,
    pub sender_device_id: String,
    #[serde(flatten)]
    pub body: EnvelopeV2Body,
}

impl EnvelopeV2 {
    pub fn parse_json(raw: &str) -> Result<Self, E2eError> {
        let env: Self = serde_json::from_str(raw)?;
        if env.v != 2 {
            return Err(E2eError::UnsupportedVersion(env.v));
        }
        Ok(env)
    }

    pub fn to_json(&self) -> Result<String, E2eError> {
        Ok(serde_json::to_string(self)?)
    }
}

/// Sliding replay window keyed by (sender_device, n) or (skid, iteration).
#[derive(Default)]
pub struct ReplayWindow {
    seen: HashSet<String>,
    capacity: usize,
}

impl ReplayWindow {
    pub fn new(capacity: usize) -> Self {
        Self {
            seen: HashSet::new(),
            capacity,
        }
    }

    pub fn check_and_record(&mut self, key: impl Into<String>) -> Result<(), E2eError> {
        let key = key.into();
        if self.seen.contains(&key) {
            return Err(E2eError::Replay(0));
        }
        if self.seen.len() >= self.capacity {
            self.seen.clear();
        }
        self.seen.insert(key);
        Ok(())
    }
}
