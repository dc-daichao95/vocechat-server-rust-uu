use std::collections::BTreeMap;

use voce_e2ee_core::mls::application::{ApplicationPayload, PayloadKind};

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
