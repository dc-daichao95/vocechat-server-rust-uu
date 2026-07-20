//! Stateless JSON-control commands shared by C FFI and WASM bindings.

use std::collections::BTreeMap;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde_json::{json, Map, Value};

use super::application::{ApplicationPayload, AttachmentDescriptor, PayloadKind};
use super::{MlsClient, MlsError, MlsGroupState, MlsKeyPackage, MlsProcessed, MlsWelcome};

const MAX_IDENTITY: usize = 255;
const MAX_GROUP_ID: usize = 255;
const MAX_KEY_PACKAGE: usize = 64 * 1024;
const MAX_STATE: usize = 4 * 1024 * 1024;
const MAX_WELCOME: usize = 4 * 1024 * 1024;
const MAX_APPLICATION: usize = 1024 * 1024;
const MAX_PRIVATE_MESSAGE: usize = 2 * 1024 * 1024;

pub fn dispatch(method: &str, args: &Value) -> Result<Value, MlsError> {
    match method {
        "mls_device_generate" => device_generate(args),
        "mls_key_package" => key_package(args),
        "mls_group_create" => group_create(args),
        "mls_group_add" => group_add(args),
        "mls_group_add_many" => group_add_many(args),
        "mls_group_members" => group_members(args),
        "mls_group_info" => group_info(args),
        "mls_group_remove" => group_remove(args),
        "mls_group_join" => group_join(args),
        "mls_application_encode" => application_encode(args),
        "mls_application_decode" => application_decode(args),
        "e2ee_attachment_encode" => attachment_encode(args),
        "e2ee_attachment_decode" => attachment_decode(args),
        "mls_encrypt" => encrypt(args),
        "mls_decrypt" => decrypt(args),
        _ => Err(MlsError("unknown MLS command".into())),
    }
}

fn attachment_encode(args: &Value) -> Result<Value, MlsError> {
    let fixed = |key: &str, length: usize| -> Result<Vec<u8>, MlsError> {
        let value = decode(args, key, length)?;
        if value.len() != length {
            return Err(MlsError(format!("invalid {key} length")));
        }
        Ok(value)
    };
    let descriptor = AttachmentDescriptor {
        path: required_string(args, "path")?,
        key: fixed("key_b64", 32)?.try_into().unwrap(),
        nonce: fixed("nonce_b64", 12)?.try_into().unwrap(),
        sha256: fixed("sha256_b64", 32)?.try_into().unwrap(),
        mime: required_string(args, "mime")?,
        name: required_string(args, "name")?,
        size: args
            .get("size")
            .and_then(Value::as_u64)
            .ok_or_else(|| MlsError("invalid attachment size".into()))?,
    };
    Ok(json!({"descriptor_b64": B64.encode(descriptor.encode()?)}))
}

fn attachment_decode(args: &Value) -> Result<Value, MlsError> {
    let descriptor = AttachmentDescriptor::decode(&decode(
        args,
        "descriptor_b64",
        MAX_APPLICATION,
    )?)?;
    Ok(json!({
        "path": descriptor.path,
        "key_b64": B64.encode(descriptor.key),
        "nonce_b64": B64.encode(descriptor.nonce),
        "sha256_b64": B64.encode(descriptor.sha256),
        "mime": descriptor.mime,
        "name": descriptor.name,
        "size": descriptor.size,
    }))
}

fn required_string(args: &Value, key: &str) -> Result<String, MlsError> {
    args.get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| MlsError(format!("missing {key}")))
}

fn group_info(args: &Value) -> Result<Value, MlsError> {
    let state = decode(args, "group_state_b64", MAX_STATE)?;
    let group = MlsGroupState::restore(&state)?;
    Ok(json!({"epoch": group.epoch()}))
}

fn device_generate(args: &Value) -> Result<Value, MlsError> {
    let identity = decode(args, "identity_b64", MAX_IDENTITY)?;
    if identity.is_empty() {
        return Err(MlsError("identity must not be empty".into()));
    }
    let client = MlsClient::generate(&identity)?;
    Ok(json!({"device_state_b64": B64.encode(client.snapshot()?)}))
}

fn key_package(args: &Value) -> Result<Value, MlsError> {
    let state = decode(args, "device_state_b64", MAX_STATE)?;
    let mut client = MlsClient::restore(&state)?;
    let package = client.key_package()?;
    Ok(json!({
        "device_state_b64": B64.encode(client.snapshot()?),
        "key_package_b64": B64.encode(package.to_bytes()?),
    }))
}

fn group_create(args: &Value) -> Result<Value, MlsError> {
    let state = decode(args, "device_state_b64", MAX_STATE)?;
    let group_id = decode(args, "group_id_b64", MAX_GROUP_ID)?;
    if group_id.is_empty() {
        return Err(MlsError("group identifier must not be empty".into()));
    }
    let group = MlsClient::restore(&state)?.create_group(&group_id)?;
    Ok(json!({"group_state_b64": B64.encode(group.snapshot()?)}))
}

fn group_add(args: &Value) -> Result<Value, MlsError> {
    let state = decode(args, "group_state_b64", MAX_STATE)?;
    let package = decode(args, "key_package_b64", MAX_KEY_PACKAGE)?;
    let mut group = MlsGroupState::restore(&state)?;
    let admission = group.add_members_with_commit(vec![MlsKeyPackage::from_bytes(&package)?])?;
    let commit = MlsGroupState::admission_commit(&admission).to_vec();
    let welcome = MlsGroupState::admission_welcome(admission);
    Ok(json!({
        "group_state_b64": B64.encode(group.snapshot()?),
        "commit_b64": B64.encode(commit),
        "welcome_b64": B64.encode(welcome.to_bytes()?),
    }))
}

fn group_add_many(args: &Value) -> Result<Value, MlsError> {
    let state = decode(args, "group_state_b64", MAX_STATE)?;
    let packages = args
        .get("key_packages_b64")
        .and_then(Value::as_array)
        .ok_or_else(|| MlsError("key_packages_b64 must be an array".into()))?;
    if packages.is_empty() || packages.len() > 1024 {
        return Err(MlsError("invalid KeyPackage count".into()));
    }
    let packages = packages
        .iter()
        .map(|value| {
            let value = value
                .as_str()
                .ok_or_else(|| MlsError("KeyPackage must be base64".into()))?;
            let bytes = B64
                .decode(value)
                .map_err(|_| MlsError("invalid KeyPackage base64".into()))?;
            if bytes.len() > MAX_KEY_PACKAGE {
                return Err(MlsError("KeyPackage exceeds maximum length".into()));
            }
            MlsKeyPackage::from_bytes(&bytes)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut group = MlsGroupState::restore(&state)?;
    let admission = group.add_members_with_commit(packages)?;
    let commit = MlsGroupState::admission_commit(&admission).to_vec();
    let welcome = MlsGroupState::admission_welcome(admission);
    Ok(json!({
        "group_state_b64": B64.encode(group.snapshot()?),
        "commit_b64": B64.encode(commit),
        "welcome_b64": B64.encode(welcome.to_bytes()?),
    }))
}

fn group_join(args: &Value) -> Result<Value, MlsError> {
    let state = decode(args, "device_state_b64", MAX_STATE)?;
    let welcome = decode(args, "welcome_b64", MAX_WELCOME)?;
    let group = MlsClient::restore(&state)?.join_group(&MlsWelcome::from_bytes(&welcome)?)?;
    Ok(json!({"group_state_b64": B64.encode(group.snapshot()?)}))
}

fn group_members(args: &Value) -> Result<Value, MlsError> {
    let state = decode(args, "group_state_b64", MAX_STATE)?;
    let group = MlsGroupState::restore(&state)?;
    Ok(json!({
        "identities_b64": group
            .member_identities()
            .into_iter()
            .map(|identity| B64.encode(identity))
            .collect::<Vec<_>>(),
    }))
}

fn group_remove(args: &Value) -> Result<Value, MlsError> {
    let state = decode(args, "group_state_b64", MAX_STATE)?;
    let identities = args
        .get("identities_b64")
        .and_then(Value::as_array)
        .ok_or_else(|| MlsError("identities_b64 must be an array".into()))?;
    if identities.is_empty() || identities.len() > 1024 {
        return Err(MlsError("invalid identity count".into()));
    }
    let identities = identities
        .iter()
        .map(|value| {
            let value = value
                .as_str()
                .ok_or_else(|| MlsError("identity must be base64".into()))?;
            let identity = B64
                .decode(value)
                .map_err(|_| MlsError("invalid identity base64".into()))?;
            if identity.is_empty() || identity.len() > MAX_IDENTITY {
                return Err(MlsError("invalid identity length".into()));
            }
            Ok(identity)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut group = MlsGroupState::restore(&state)?;
    let commit = group.remove_identities(&identities)?;
    Ok(json!({
        "group_state_b64": B64.encode(group.snapshot()?),
        "commit_b64": B64.encode(commit),
    }))
}

fn application_encode(args: &Value) -> Result<Value, MlsError> {
    let kind_value = args
        .get("kind")
        .and_then(Value::as_u64)
        .and_then(|value| u8::try_from(value).ok())
        .ok_or_else(|| MlsError("invalid application kind".into()))?;
    let body = decode(args, "body_b64", MAX_APPLICATION)?;
    let mut metadata = BTreeMap::new();
    if let Some(values) = args.get("metadata") {
        let values = values
            .as_object()
            .ok_or_else(|| MlsError("metadata must be an object".into()))?;
        if values.len() > 32 {
            return Err(MlsError("too many metadata entries".into()));
        }
        for (key, value) in values {
            let key = key
                .parse::<u16>()
                .map_err(|_| MlsError("metadata keys must be u16 integers".into()))?;
            let value = value
                .as_str()
                .ok_or_else(|| MlsError("metadata values must be base64 strings".into()))?;
            let value = B64
                .decode(value)
                .map_err(|_| MlsError("invalid metadata base64".into()))?;
            if value.len() > 64 * 1024 {
                return Err(MlsError("metadata value is too large".into()));
            }
            metadata.insert(key, value);
        }
    }
    let payload = ApplicationPayload {
        kind: PayloadKind::try_from(kind_value)?,
        body,
        metadata,
    };
    Ok(json!({"plaintext_b64": B64.encode(payload.encode_padded()?)}))
}

fn application_decode(args: &Value) -> Result<Value, MlsError> {
    let plaintext = decode(args, "plaintext_b64", MAX_APPLICATION)?;
    let payload = ApplicationPayload::decode_padded(&plaintext)?;
    let metadata: Map<String, Value> = payload
        .metadata
        .into_iter()
        .map(|(key, value)| (key.to_string(), json!(B64.encode(value))))
        .collect();
    Ok(json!({
        "kind": payload.kind as u8,
        "body_b64": B64.encode(payload.body),
        "metadata": metadata,
    }))
}

fn encrypt(args: &Value) -> Result<Value, MlsError> {
    let state = decode(args, "group_state_b64", MAX_STATE)?;
    let plaintext = decode(args, "plaintext_b64", MAX_APPLICATION)?;
    ApplicationPayload::decode_padded(&plaintext)?;
    let mut group = MlsGroupState::restore(&state)?;
    let private_message = group.encrypt_application(&plaintext)?;
    Ok(json!({
        "group_state_b64": B64.encode(group.snapshot()?),
        "private_message_b64": B64.encode(private_message),
    }))
}

fn decrypt(args: &Value) -> Result<Value, MlsError> {
    let state = decode(args, "group_state_b64", MAX_STATE)?;
    let private_message = decode(args, "private_message_b64", MAX_PRIVATE_MESSAGE)?;
    let mut group = MlsGroupState::restore(&state)?;
    match group.process_message(&private_message)? {
        MlsProcessed::Application(plaintext) => {
            ApplicationPayload::decode_padded(&plaintext)?;
            Ok(json!({
                "event": "application",
                "group_state_b64": B64.encode(group.snapshot()?),
                "plaintext_b64": B64.encode(plaintext),
            }))
        }
        MlsProcessed::Commit => Ok(json!({
            "event": "commit",
            "group_state_b64": B64.encode(group.snapshot()?),
        })),
    }
}

fn decode(args: &Value, key: &str, maximum: usize) -> Result<Vec<u8>, MlsError> {
    let value = args
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| MlsError(format!("missing {key}")))?;
    let decoded = B64
        .decode(value)
        .map_err(|_| MlsError(format!("invalid base64 in {key}")))?;
    if decoded.len() > maximum {
        return Err(MlsError(format!("{key} exceeds maximum length")));
    }
    Ok(decoded)
}
