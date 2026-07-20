use std::collections::BTreeMap;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::Deserialize;
use voce_e2ee_core::mls::application::{
    ApplicationPayload, AttachmentDescriptor, PayloadKind,
};

#[derive(Deserialize)]
struct ApplicationVector {
    contract: String,
    kind: u8,
    body_b64: String,
    metadata: BTreeMap<u16, String>,
    encoded_b64: String,
}

#[test]
fn canonical_numeric_cbor_roundtrips_without_branded_fields() {
    let payload = ApplicationPayload {
        kind: PayloadKind::Text,
        body: b"hello".to_vec(),
        metadata: BTreeMap::from([
            (1, b"text/plain".to_vec()),
            (2, 42_u64.to_be_bytes().to_vec()),
        ]),
    };

    let encoded = payload.encode_padded().expect("encode");
    assert!(encoded.len().is_power_of_two());
    assert!(encoded.len() >= 256);
    for forbidden in [
        b"ver".as_slice(),
        b"chat".as_slice(),
        b"vocechat".as_slice(),
    ] {
        assert!(!encoded
            .windows(forbidden.len())
            .any(|window| window == forbidden));
    }

    assert_eq!(
        ApplicationPayload::decode_padded(&encoded).expect("decode"),
        payload
    );
}

#[test]
fn malformed_lengths_and_unknown_kinds_are_rejected() {
    assert!(ApplicationPayload::decode_padded(&[0, 0, 0, 10, 1]).is_err());
    assert!(ApplicationPayload::decode_padded(&[0; 256]).is_err());
}

#[test]
fn v2_application_kind_numbers_are_stable() {
    assert_eq!(PayloadKind::Text as u8, 1);
    assert_eq!(PayloadKind::Reply as u8, 2);
    assert_eq!(PayloadKind::Edit as u8, 3);
    assert_eq!(PayloadKind::Reaction as u8, 4);
    assert_eq!(PayloadKind::File as u8, 5);
    assert_eq!(PayloadKind::Image as u8, 6);
    assert_eq!(PayloadKind::Voice as u8, 7);
    assert_eq!(PayloadKind::Markdown as u8, 8);
    assert_eq!(PayloadKind::Delete as u8, 9);
    assert_eq!(PayloadKind::Revoke as u8, 10);
    assert_eq!(PayloadKind::MembershipNotice as u8, 11);
}

#[test]
fn v2_markdown_payload_round_trips_with_padding() {
    let payload = ApplicationPayload {
        kind: PayloadKind::Markdown,
        body: b"**encrypted markdown**".to_vec(),
        metadata: [(1_u16, b"text/markdown".to_vec())].into_iter().collect(),
    };
    let encoded = payload.encode_padded().unwrap();
    assert_eq!(encoded.len(), 256);
    assert_eq!(
        ApplicationPayload::decode_padded(&encoded).unwrap(),
        payload
    );
}

#[test]
fn v2_text_vector_is_stable() {
    let vector: ApplicationVector =
        serde_json::from_str(include_str!("../testdata/e2ee-v2-text-vector.json")).unwrap();
    assert_eq!(vector.contract, "vocechat-e2ee-v2-application");

    let encoded = B64.decode(vector.encoded_b64).unwrap();
    assert_eq!(encoded.len(), 256);
    let decoded = ApplicationPayload::decode_padded(&encoded).unwrap();
    assert_eq!(decoded.kind as u8, vector.kind);
    assert_eq!(decoded.body, B64.decode(vector.body_b64).unwrap());
    assert_eq!(
        decoded.metadata,
        vector
            .metadata
            .into_iter()
            .map(|(key, value)| (key, B64.decode(value).unwrap()))
            .collect()
    );

    let randomized = decoded.encode_padded().unwrap();
    assert_eq!(
        ApplicationPayload::decode_padded(&randomized).unwrap(),
        decoded
    );
}

#[test]
fn encrypted_attachment_descriptor_round_trips_canonically() {
    let descriptor = AttachmentDescriptor {
        path: "2026/07/opaque.bin".into(),
        key: [3_u8; 32],
        nonce: [4_u8; 12],
        sha256: [5_u8; 32],
        mime: "application/pdf".into(),
        name: "report.pdf".into(),
        size: 1234,
    };
    let encoded = descriptor.encode().unwrap();
    assert_eq!(AttachmentDescriptor::decode(&encoded).unwrap(), descriptor);
}

#[test]
fn encrypted_attachment_descriptor_rejects_tampered_key_material() {
    let descriptor = AttachmentDescriptor {
        path: "opaque.bin".into(),
        key: [3_u8; 32],
        nonce: [4_u8; 12],
        sha256: [5_u8; 32],
        mime: "application/octet-stream".into(),
        name: "opaque.bin".into(),
        size: 7,
    };
    let mut encoded = descriptor.encode().unwrap();
    let key = encoded
        .windows(32)
        .position(|window| window == [3_u8; 32])
        .expect("encoded key");
    encoded[key] ^= 1;
    assert_ne!(AttachmentDescriptor::decode(&encoded).unwrap(), descriptor);

    let truncated = &encoded[..encoded.len() - 1];
    assert!(AttachmentDescriptor::decode(truncated).is_err());
}
