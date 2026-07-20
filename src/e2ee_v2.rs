use std::{collections::HashMap, fmt};

use serde_json::Value;
use sqlx::SqlitePool;

pub const CONTENT_TYPE: &str = "application/vnd.vocechat.e2ee.v2";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Protocol {
    Dr,
    Mls,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireClass {
    DrEnvelope,
    MlsHandshake,
    MlsApplication,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MlsHandshakeKind {
    Commit,
    Welcome,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutingProperties {
    pub protocol: Protocol,
    pub wire_class: WireClass,
    pub sender_device_id: String,
    pub recipient_device_id: Option<String>,
    pub local_id: String,
    pub mls_epoch: Option<u64>,
    pub mls_generation: Option<u32>,
    pub mls_handshake_kind: Option<MlsHandshakeKind>,
    pub mls_commit_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum E2eV2Error {
    InvalidProperty(&'static str),
    ProtocolMismatch,
    DeviceMismatch,
}

impl fmt::Display for E2eV2Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProperty(property) => {
                write!(formatter, "missing or invalid E2EE v2 property: {property}")
            }
            Self::ProtocolMismatch => formatter.write_str("wire_class does not match protocol"),
            Self::DeviceMismatch => formatter.write_str("E2E_DEVICE_MISMATCH"),
        }
    }
}

pub fn validate_authenticated_sender(
    properties: &HashMap<String, Value>,
    authenticated_device: &str,
) -> Result<RoutingProperties, E2eV2Error> {
    let route = validate_properties(properties)?;
    if route.sender_device_id != authenticated_device {
        return Err(E2eV2Error::DeviceMismatch);
    }
    Ok(route)
}

pub fn validate_authenticated_device(
    provided_device: &str,
    authenticated_device: &str,
) -> Result<(), E2eV2Error> {
    if provided_device != authenticated_device {
        return Err(E2eV2Error::DeviceMismatch);
    }
    Ok(())
}

impl std::error::Error for E2eV2Error {}

#[derive(Debug)]
pub enum MlsSequenceError {
    Conflict,
    Database(sqlx::Error),
}

fn sequence_database_error(error: sqlx::Error) -> MlsSequenceError {
    if error
        .as_database_error()
        .and_then(|error| error.code())
        .map(|code| code == "1555" || code == "2067")
        .unwrap_or(false)
    {
        MlsSequenceError::Conflict
    } else {
        MlsSequenceError::Database(error)
    }
}

pub async fn reserve_mls_sequence(
    pool: &SqlitePool,
    gid: i64,
    sender_uid: i64,
    route: &RoutingProperties,
) -> Result<(), MlsSequenceError> {
    if route.protocol != Protocol::Mls {
        return Err(MlsSequenceError::Conflict);
    }
    let epoch = i64::try_from(route.mls_epoch.ok_or(MlsSequenceError::Conflict)?)
        .map_err(|_| MlsSequenceError::Conflict)?;
    let generation = i64::from(route.mls_generation.ok_or(MlsSequenceError::Conflict)?);
    let mut tx = pool.begin().await.map_err(MlsSequenceError::Database)?;

    match (route.wire_class, route.mls_handshake_kind) {
        (WireClass::MlsHandshake, Some(MlsHandshakeKind::Commit)) => {
            let current = sqlx::query_scalar::<_, Option<i64>>(
                "select max(epoch) from e2e_v2_mls_commit where gid = ?",
            )
            .bind(gid)
            .fetch_one(&mut *tx)
            .await
            .map_err(MlsSequenceError::Database)?
            .unwrap_or(0);
            if epoch != current + 1 {
                return Err(MlsSequenceError::Conflict);
            }
            sqlx::query(
                "insert into e2e_v2_mls_commit (gid, epoch, commit_id, sender_uid, sender_device_id) values (?, ?, ?, ?, ?)",
            )
            .bind(gid)
            .bind(epoch)
            .bind(route.mls_commit_id.as_deref().ok_or(MlsSequenceError::Conflict)?)
            .bind(sender_uid)
            .bind(&route.sender_device_id)
            .execute(&mut *tx)
            .await
            .map_err(sequence_database_error)?;
        }
        (WireClass::MlsHandshake, Some(MlsHandshakeKind::Welcome)) => {
            let commit_id = route.mls_commit_id.as_deref().ok_or(MlsSequenceError::Conflict)?;
            let exists = sqlx::query_scalar::<_, i64>(
                "select count(*) from e2e_v2_mls_commit where gid = ? and epoch = ? and commit_id = ?",
            )
            .bind(gid)
            .bind(epoch)
            .bind(commit_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(MlsSequenceError::Database)?;
            if exists != 1 {
                return Err(MlsSequenceError::Conflict);
            }
            sqlx::query(
                "insert into e2e_v2_mls_welcome (gid, epoch, commit_id, sender_uid, sender_device_id) values (?, ?, ?, ?, ?)",
            )
            .bind(gid)
            .bind(epoch)
            .bind(commit_id)
            .bind(sender_uid)
            .bind(&route.sender_device_id)
            .execute(&mut *tx)
            .await
            .map_err(sequence_database_error)?;
        }
        (WireClass::MlsApplication, None) => {
            let current_epoch = sqlx::query_scalar::<_, Option<i64>>(
                "select max(epoch) from e2e_v2_mls_commit where gid = ?",
            )
            .bind(gid)
            .fetch_one(&mut *tx)
            .await
            .map_err(MlsSequenceError::Database)?
            .unwrap_or(0);
            if epoch != current_epoch {
                return Err(MlsSequenceError::Conflict);
            }
            let last_generation = sqlx::query_scalar::<_, Option<i64>>(
                "select max(generation) from e2e_v2_mls_application where gid = ? and epoch = ? and sender_uid = ? and sender_device_id = ?",
            )
            .bind(gid)
            .bind(epoch)
            .bind(sender_uid)
            .bind(&route.sender_device_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(MlsSequenceError::Database)?;
            let expected = last_generation.map(|value| value + 1).unwrap_or(0);
            if generation != expected {
                return Err(MlsSequenceError::Conflict);
            }
            sqlx::query(
                "insert into e2e_v2_mls_application (gid, epoch, sender_uid, sender_device_id, generation) values (?, ?, ?, ?, ?)",
            )
            .bind(gid)
            .bind(epoch)
            .bind(sender_uid)
            .bind(&route.sender_device_id)
            .bind(generation)
            .execute(&mut *tx)
            .await
            .map_err(sequence_database_error)?;
        }
        _ => return Err(MlsSequenceError::Conflict),
    }

    tx.commit().await.map_err(MlsSequenceError::Database)
}

pub fn validate_properties(
    properties: &HashMap<String, Value>,
) -> Result<RoutingProperties, E2eV2Error> {
    if properties.get("e2e_version").and_then(Value::as_u64) != Some(2) {
        return Err(E2eV2Error::InvalidProperty("e2e_version"));
    }

    let protocol = match properties.get("protocol").and_then(Value::as_str) {
        Some("dr") => Protocol::Dr,
        Some("mls") => Protocol::Mls,
        _ => return Err(E2eV2Error::InvalidProperty("protocol")),
    };
    let wire_class = match properties.get("wire_class").and_then(Value::as_str) {
        Some("dr_envelope") => WireClass::DrEnvelope,
        Some("mls_handshake") => WireClass::MlsHandshake,
        Some("mls_application") => WireClass::MlsApplication,
        _ => return Err(E2eV2Error::InvalidProperty("wire_class")),
    };
    if !matches!(
        (protocol, wire_class),
        (Protocol::Dr, WireClass::DrEnvelope)
            | (
                Protocol::Mls,
                WireClass::MlsHandshake | WireClass::MlsApplication
            )
    ) {
        return Err(E2eV2Error::ProtocolMismatch);
    }

    let required_string = |key: &'static str| {
        properties
            .get(key)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .ok_or(E2eV2Error::InvalidProperty(key))
    };
    let sender_device_id = required_string("sender_device_id")?;
    let local_id = required_string("local_id")?;
    let recipient_device_id = match properties.get("recipient_device_id") {
        Some(value) => Some(
            value
                .as_str()
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .ok_or(E2eV2Error::InvalidProperty("recipient_device_id"))?,
        ),
        None => None,
    };
    let mls_epoch = properties.get("mls_epoch").and_then(Value::as_u64);
    let mls_generation = properties
        .get("mls_generation")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok());
    let mls_handshake_kind = match properties.get("mls_handshake_kind") {
        Some(Value::String(value)) if value == "commit" => Some(MlsHandshakeKind::Commit),
        Some(Value::String(value)) if value == "welcome" => Some(MlsHandshakeKind::Welcome),
        Some(_) => return Err(E2eV2Error::InvalidProperty("mls_handshake_kind")),
        None => None,
    };
    let mls_commit_id = match properties.get("mls_commit_id") {
        Some(value) => Some(
            value
                .as_str()
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .ok_or(E2eV2Error::InvalidProperty("mls_commit_id"))?,
        ),
        None => None,
    };

    match (protocol, wire_class) {
        (Protocol::Dr, WireClass::DrEnvelope) if recipient_device_id.is_none() => {
            return Err(E2eV2Error::InvalidProperty("recipient_device_id"));
        }
        (Protocol::Dr, WireClass::DrEnvelope)
            if mls_epoch.is_some()
                || mls_generation.is_some()
                || mls_handshake_kind.is_some()
                || mls_commit_id.is_some() =>
        {
            return Err(E2eV2Error::ProtocolMismatch);
        }
        (Protocol::Mls, _) if recipient_device_id.is_some() => {
            return Err(E2eV2Error::ProtocolMismatch);
        }
        (Protocol::Mls, _) if mls_epoch.is_none() => {
            return Err(E2eV2Error::InvalidProperty("mls_epoch"));
        }
        (Protocol::Mls, _) if mls_generation.is_none() => {
            return Err(E2eV2Error::InvalidProperty("mls_generation"));
        }
        (Protocol::Mls, WireClass::MlsHandshake)
            if mls_handshake_kind.is_none() || mls_commit_id.is_none() =>
        {
            return Err(E2eV2Error::InvalidProperty("mls_handshake_kind"));
        }
        (Protocol::Mls, WireClass::MlsHandshake) if mls_generation != Some(0) => {
            return Err(E2eV2Error::InvalidProperty("mls_generation"));
        }
        (Protocol::Mls, WireClass::MlsApplication)
            if mls_handshake_kind.is_some() || mls_commit_id.is_some() =>
        {
            return Err(E2eV2Error::ProtocolMismatch);
        }
        _ => {}
    }

    Ok(RoutingProperties {
        protocol,
        wire_class,
        sender_device_id,
        recipient_device_id,
        local_id,
        mls_epoch,
        mls_generation,
        mls_handshake_kind,
        mls_commit_id,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde_json::{json, Value};

    use super::{validate_properties, Protocol, WireClass, CONTENT_TYPE};

    fn props(value: Value) -> HashMap<String, Value> {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn accepts_dr_envelope() {
        assert_eq!(CONTENT_TYPE, "application/vnd.vocechat.e2ee.v2");
        let route = validate_properties(&props(json!({
            "e2e_version": 2,
            "protocol": "dr",
            "wire_class": "dr_envelope",
            "sender_device_id": "device-a",
            "recipient_device_id": "device-b",
            "local_id": "018f8dd2-c87e-7b40-bf45-4df46c08e591"
        })))
        .unwrap();
        assert_eq!(route.protocol, Protocol::Dr);
        assert_eq!(route.wire_class, WireClass::DrEnvelope);
    }

    #[test]
    fn accepts_mls_routes() {
        for wire_class in ["mls_handshake", "mls_application"] {
            let mut value = json!({
                "e2e_version": 2,
                "protocol": "mls",
                "wire_class": wire_class,
                "sender_device_id": "device-a",
                "local_id": "018f8dd2-c87e-7b40-bf45-4df46c08e591",
                "mls_epoch": 7,
                "mls_generation": 3
            });
            if wire_class == "mls_handshake" {
                value["mls_generation"] = json!(0);
                value["mls_handshake_kind"] = json!("commit");
                value["mls_commit_id"] = json!("commit-7");
            }
            let route = validate_properties(&props(value))
            .unwrap();
            assert_eq!(route.protocol, Protocol::Mls);
            assert_eq!(route.mls_epoch, Some(7));
        }
    }

    #[test]
    fn rejects_protocol_class_mismatch_and_missing_ids() {
        for value in [
            json!({"e2e_version":2,"protocol":"dr","wire_class":"mls_application","sender_device_id":"a","local_id":"c"}),
            json!({"e2e_version":2,"protocol":"mls","wire_class":"mls_application","sender_device_id":"","local_id":"c","mls_epoch":0,"mls_generation":0}),
            json!({"e2e_version":1,"protocol":"dr","wire_class":"dr_envelope","sender_device_id":"a","local_id":"c"}),
        ] {
            assert!(validate_properties(&props(value)).is_err());
        }
    }

    #[test]
    fn rejects_missing_protocol_specific_fields_and_invalid_numbers() {
        for value in [
            json!({"e2e_version":2,"protocol":"dr","wire_class":"dr_envelope","sender_device_id":"a","local_id":"c"}),
            json!({"e2e_version":2,"protocol":"mls","wire_class":"mls_application","sender_device_id":"a","local_id":"c","mls_epoch":0}),
            json!({"e2e_version":2,"protocol":"mls","wire_class":"mls_application","sender_device_id":"a","local_id":"c","mls_epoch":-1,"mls_generation":0}),
            json!({"e2e_version":2,"protocol":"mls","wire_class":"mls_application","sender_device_id":"a","local_id":"c","mls_epoch":0,"mls_generation":4294967296_u64}),
        ] {
            assert!(validate_properties(&props(value)).is_err());
        }
    }

    #[test]
    fn mls_handshake_requires_kind_and_commit_id() {
        let missing_kind = props(json!({
            "e2e_version": 2,
            "protocol": "mls",
            "wire_class": "mls_handshake",
            "sender_device_id": "device-a",
            "local_id": "local-commit-1",
            "mls_epoch": 8,
            "mls_generation": 0
        }));
        assert!(validate_properties(&missing_kind).is_err());

        for kind in ["commit", "welcome"] {
            let route = validate_properties(&props(json!({
                "e2e_version": 2,
                "protocol": "mls",
                "wire_class": "mls_handshake",
                "mls_handshake_kind": kind,
                "mls_commit_id": "commit-018f8dd2",
                "sender_device_id": "device-a",
                "local_id": format!("local-{kind}-1"),
                "mls_epoch": 8,
                "mls_generation": 0
            })))
            .unwrap();
            assert_eq!(route.mls_commit_id.as_deref(), Some("commit-018f8dd2"));
        }
    }
}
