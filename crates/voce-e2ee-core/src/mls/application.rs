//! Canonical, numeric-key application payload carried inside MLS messages.

use std::collections::BTreeMap;

use minicbor::{Decoder, Encoder};
use rand::{rngs::OsRng, RngCore};

use super::MlsError;

const MIN_BUCKET: usize = 256;
const MAX_BUCKET: usize = 1024 * 1024;

/// The semantic application operation. Its numeric representation is stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PayloadKind {
    Text = 1,
    Reply = 2,
    Edit = 3,
    Reaction = 4,
    File = 5,
    Image = 6,
    Voice = 7,
    Markdown = 8,
    Delete = 9,
    Revoke = 10,
    MembershipNotice = 11,
}

impl TryFrom<u8> for PayloadKind {
    type Error = MlsError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Text),
            2 => Ok(Self::Reply),
            3 => Ok(Self::Edit),
            4 => Ok(Self::Reaction),
            5 => Ok(Self::File),
            6 => Ok(Self::Image),
            7 => Ok(Self::Voice),
            8 => Ok(Self::Markdown),
            9 => Ok(Self::Delete),
            10 => Ok(Self::Revoke),
            11 => Ok(Self::MembershipNotice),
            _ => Err(MlsError("unknown application payload kind".into())),
        }
    }
}

/// Plaintext encrypted by MLS. Map keys are integers and metadata is ordered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationPayload {
    pub kind: PayloadKind,
    pub body: Vec<u8>,
    pub metadata: BTreeMap<u16, Vec<u8>>,
}

/// Descriptor encrypted inside a File/Image/Voice application payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentDescriptor {
    pub path: String,
    pub key: [u8; 32],
    pub nonce: [u8; 12],
    pub sha256: [u8; 32],
    pub mime: String,
    pub name: String,
    pub size: u64,
}

impl AttachmentDescriptor {
    pub fn encode(&self) -> Result<Vec<u8>, MlsError> {
        validate_attachment_text(&self.path, 1024, "path")?;
        validate_attachment_text(&self.mime, 255, "mime")?;
        validate_attachment_text(&self.name, 1024, "name")?;
        let mut output = Vec::new();
        let mut encoder = Encoder::new(&mut output);
        encoder.map(7).map_err(cbor_error)?;
        encoder.u8(0).map_err(cbor_error)?;
        encoder.str(&self.path).map_err(cbor_error)?;
        encoder.u8(1).map_err(cbor_error)?;
        encoder.bytes(&self.key).map_err(cbor_error)?;
        encoder.u8(2).map_err(cbor_error)?;
        encoder.bytes(&self.nonce).map_err(cbor_error)?;
        encoder.u8(3).map_err(cbor_error)?;
        encoder.bytes(&self.sha256).map_err(cbor_error)?;
        encoder.u8(4).map_err(cbor_error)?;
        encoder.str(&self.mime).map_err(cbor_error)?;
        encoder.u8(5).map_err(cbor_error)?;
        encoder.str(&self.name).map_err(cbor_error)?;
        encoder.u8(6).map_err(cbor_error)?;
        encoder.u64(self.size).map_err(cbor_error)?;
        Ok(output)
    }

    pub fn decode(input: &[u8]) -> Result<Self, MlsError> {
        let mut decoder = Decoder::new(input);
        if decoder.map().map_err(cbor_error)? != Some(7) {
            return Err(MlsError("attachment descriptor must be a fixed map".into()));
        }
        expect_key(&mut decoder, 0)?;
        let path = decoder.str().map_err(cbor_error)?.to_owned();
        expect_key(&mut decoder, 1)?;
        let key = fixed_bytes::<32>(&mut decoder, "key")?;
        expect_key(&mut decoder, 2)?;
        let nonce = fixed_bytes::<12>(&mut decoder, "nonce")?;
        expect_key(&mut decoder, 3)?;
        let sha256 = fixed_bytes::<32>(&mut decoder, "sha256")?;
        expect_key(&mut decoder, 4)?;
        let mime = decoder.str().map_err(cbor_error)?.to_owned();
        expect_key(&mut decoder, 5)?;
        let name = decoder.str().map_err(cbor_error)?.to_owned();
        expect_key(&mut decoder, 6)?;
        let size = decoder.u64().map_err(cbor_error)?;
        if decoder.position() != input.len() {
            return Err(MlsError("trailing attachment descriptor data".into()));
        }
        validate_attachment_text(&path, 1024, "path")?;
        validate_attachment_text(&mime, 255, "mime")?;
        validate_attachment_text(&name, 1024, "name")?;
        Ok(Self {
            path,
            key,
            nonce,
            sha256,
            mime,
            name,
            size,
        })
    }
}

fn fixed_bytes<const N: usize>(
    decoder: &mut Decoder<'_>,
    field: &str,
) -> Result<[u8; N], MlsError> {
    decoder
        .bytes()
        .map_err(cbor_error)?
        .try_into()
        .map_err(|_| MlsError(format!("invalid attachment {field} length")))
}

fn validate_attachment_text(value: &str, maximum: usize, field: &str) -> Result<(), MlsError> {
    if value.is_empty() || value.len() > maximum {
        return Err(MlsError(format!("invalid attachment {field}")));
    }
    Ok(())
}

impl ApplicationPayload {
    /// Encode canonical CBOR and obscure its exact length with random padding.
    pub fn encode_padded(&self) -> Result<Vec<u8>, MlsError> {
        let mut payload = Vec::new();
        let mut encoder = Encoder::new(&mut payload);
        encoder.map(3).map_err(cbor_error)?;
        encoder.u8(0).map_err(cbor_error)?;
        encoder.u8(self.kind as u8).map_err(cbor_error)?;
        encoder.u8(1).map_err(cbor_error)?;
        encoder.bytes(&self.body).map_err(cbor_error)?;
        encoder.u8(2).map_err(cbor_error)?;
        encoder
            .map(self.metadata.len() as u64)
            .map_err(cbor_error)?;
        for (key, value) in &self.metadata {
            encoder.u16(*key).map_err(cbor_error)?;
            encoder.bytes(value).map_err(cbor_error)?;
        }

        let required = payload
            .len()
            .checked_add(4)
            .ok_or_else(|| MlsError("application payload length overflow".into()))?;
        let bucket = required
            .max(MIN_BUCKET)
            .checked_next_power_of_two()
            .ok_or_else(|| MlsError("application payload length overflow".into()))?;
        if bucket > MAX_BUCKET {
            return Err(MlsError(
                "application payload exceeds maximum length".into(),
            ));
        }

        let mut output = Vec::with_capacity(bucket);
        output.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        output.extend_from_slice(&payload);
        let mut padding = vec![0_u8; bucket - output.len()];
        OsRng.fill_bytes(&mut padding);
        output.extend_from_slice(&padding);
        Ok(output)
    }

    /// Decode a strict canonical payload. Padding bytes are intentionally ignored.
    pub fn decode_padded(input: &[u8]) -> Result<Self, MlsError> {
        if input.len() < MIN_BUCKET || input.len() > MAX_BUCKET || !input.len().is_power_of_two() {
            return Err(MlsError("invalid application payload bucket".into()));
        }
        let encoded_len = u32::from_be_bytes(
            input[..4]
                .try_into()
                .map_err(|_| MlsError("missing application length".into()))?,
        ) as usize;
        if encoded_len == 0 || encoded_len > input.len() - 4 {
            return Err(MlsError("invalid application payload length".into()));
        }

        let mut decoder = Decoder::new(&input[4..4 + encoded_len]);
        if decoder.map().map_err(cbor_error)? != Some(3) {
            return Err(MlsError("application payload must be a fixed map".into()));
        }
        expect_key(&mut decoder, 0)?;
        let kind = PayloadKind::try_from(decoder.u8().map_err(cbor_error)?)?;
        expect_key(&mut decoder, 1)?;
        let body = decoder.bytes().map_err(cbor_error)?.to_vec();
        expect_key(&mut decoder, 2)?;
        let metadata_len = decoder
            .map()
            .map_err(cbor_error)?
            .ok_or_else(|| MlsError("indefinite metadata map is not canonical".into()))?;
        let mut metadata = BTreeMap::new();
        let mut previous = None;
        for _ in 0..metadata_len {
            let key = decoder.u16().map_err(cbor_error)?;
            if previous.is_some_and(|value| key <= value) {
                return Err(MlsError("metadata keys are not canonical".into()));
            }
            previous = Some(key);
            metadata.insert(key, decoder.bytes().map_err(cbor_error)?.to_vec());
        }
        if decoder.position() != encoded_len {
            return Err(MlsError("trailing canonical CBOR data".into()));
        }

        Ok(Self {
            kind,
            body,
            metadata,
        })
    }
}

fn expect_key(decoder: &mut Decoder<'_>, expected: u8) -> Result<(), MlsError> {
    let actual = decoder.u8().map_err(cbor_error)?;
    if actual != expected {
        return Err(MlsError("application keys are not canonical".into()));
    }
    Ok(())
}

fn cbor_error(error: impl core::fmt::Display) -> MlsError {
    MlsError(format!("invalid application CBOR: {error}"))
}
