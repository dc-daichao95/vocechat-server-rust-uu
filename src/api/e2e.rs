use std::sync::Arc;

use poem::{error::InternalServerError, http::StatusCode, web::Data, Error, Result};
use poem_openapi::{
    param::{Path, Query},
    payload::Json,
    Object, OpenApi,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    api::{tags::ApiTags, token::Token, DateTime, LoginConfig},
    state::BroadcastEvent,
    State,
};

fn dm_pair(a: i64, b: i64) -> (i64, i64) {
    if a < b {
        (a, b)
    } else {
        (b, a)
    }
}

async fn e2e_protocol_ver(state: &State) -> i32 {
    state
        .get_dynamic_config_instance::<LoginConfig>()
        .await
        .map(|c| c.e2e_protocol_ver)
        .unwrap_or(1)
}

/// Published identity key for one device
#[derive(Debug, Object, Serialize, Deserialize, Clone)]
pub struct E2eIdentity {
    pub uid: i64,
    pub device_id: String,
    /// Base64url or hex-encoded public identity key (client-defined encoding)
    pub identity_key_pub: String,
    pub signed_prekey_pub: Option<String>,
    pub signed_prekey_sig: Option<String>,
    pub updated_at: DateTime,
}

#[derive(Debug, Object)]
struct PutE2eIdentityRequest {
    device_id: String,
    identity_key_pub: String,
    signed_prekey_pub: Option<String>,
    signed_prekey_sig: Option<String>,
}

#[derive(Debug, Object)]
struct E2ePrekeyItem {
    key_id: i32,
    public_key: String,
}

#[derive(Debug, Object)]
struct PutE2ePrekeysRequest {
    device_id: String,
    keys: Vec<E2ePrekeyItem>,
}

#[derive(Debug, Object)]
struct E2ePrekeyBundle {
    uid: i64,
    device_id: String,
    identity_key_pub: String,
    signed_prekey_pub: Option<String>,
    signed_prekey_sig: Option<String>,
    /// One unused one-time prekey if available
    one_time_prekey: Option<E2ePrekeyItem>,
}

#[derive(Debug, Object)]
struct PutE2eBackupRequest {
    /// Encrypted backup container version. Generation-2 clients use version 2.
    version: i32,
    /// Opaque passphrase-encrypted blob (base64)
    blob_base64: String,
}

#[derive(Debug, Object)]
struct E2eBackupResponse {
    version: i32,
    size_bytes: i64,
    updated_by_device: String,
    blob_base64: String,
    updated_at: DateTime,
}

#[derive(Debug, Object)]
struct E2eDmSetting {
    peer_uid: i64,
    e2e_enabled: bool,
}

#[derive(Debug, Object)]
struct PutE2eDmSettingRequest {
    peer_uid: i64,
    e2e_enabled: bool,
}

/// A deferred DM (`protocol=dr-pending`) still awaiting a recipient-device
/// key envelope.
#[derive(Debug, Object, Serialize, Deserialize, Clone)]
struct E2ePendingDmMessage {
    mid: i64,
    created_at: DateTime,
}

#[derive(Debug, Object)]
struct AppendPendingEnvelopeRequest {
    recipient_uid: i64,
    device_id: String,
    /// Opaque per-device key envelope (client-defined encoding).
    envelope: String,
}

#[derive(Debug, Object)]
struct PendingEnvelopeAck {
    mid: i64,
    recipient_uid: i64,
    device_id: String,
    /// True once at least one current recipient device has an envelope.
    completed: bool,
}

/// Public E2E capability advertised to clients (no admin token required).
#[derive(Debug, Object, Serialize, Deserialize, Clone)]
struct E2eProtocolInfo {
    e2e_available: bool,
    e2e_default_on: bool,
    /// `1` = v1; `2` = v2 required for new encrypted sends
    e2e_protocol_ver: i32,
}

pub struct ApiE2e;

#[OpenApi(prefix_path = "/user/e2e", tag = "ApiTags::User")]
impl ApiE2e {
    /// Upload or rotate this user's identity public key for a device.
    #[oai(path = "/identity", method = "put")]
    async fn put_identity(
        &self,
        state: Data<&State>,
        token: Token,
        req: Json<PutE2eIdentityRequest>,
    ) -> Result<Json<E2eIdentity>> {
        crate::e2ee_v2::validate_authenticated_device(&req.device_id, &token.device)
            .map_err(|error| Error::from_string(error.to_string(), StatusCode::BAD_REQUEST))?;
        if req.device_id.is_empty() || req.identity_key_pub.is_empty() {
            return Err(Error::from_status(StatusCode::BAD_REQUEST));
        }
        if e2e_protocol_ver(&state).await >= 2 {
            let spk = req.signed_prekey_pub.as_deref().unwrap_or("").trim();
            let sig = req.signed_prekey_sig.as_deref().unwrap_or("").trim();
            if spk.is_empty() || sig.is_empty() {
                return Err(Error::from_string(
                    "E2E_SIGNED_PREKEY_REQUIRED",
                    StatusCode::BAD_REQUEST,
                ));
            }
        }
        let now = DateTime::now();
        sqlx::query(
            r#"
            insert into e2e_identity (uid, device_id, identity_key_pub, signed_prekey_pub, signed_prekey_sig, updated_at)
            values (?, ?, ?, ?, ?, ?)
            on conflict(uid, device_id) do update set
              identity_key_pub = excluded.identity_key_pub,
              signed_prekey_pub = excluded.signed_prekey_pub,
              signed_prekey_sig = excluded.signed_prekey_sig,
              updated_at = excluded.updated_at
            "#,
        )
        .bind(token.uid)
        .bind(&req.device_id)
        .bind(&req.identity_key_pub)
        .bind(&req.signed_prekey_pub)
        .bind(&req.signed_prekey_sig)
        .bind(now)
        .execute(&state.db_pool)
        .await
        .map_err(InternalServerError)?;

        // Notify senders with an incomplete deferred DM addressed to this uid
        // so their online devices can catch up and append envelopes.
        let waiting_senders = sqlx::query_scalar::<_, i64>(
            "select distinct sender_uid from e2e_pending_message where target_uid = ? and completed_at is null",
        )
        .bind(token.uid)
        .fetch_all(&state.db_pool)
        .await
        .map_err(InternalServerError)?;
        if !waiting_senders.is_empty() {
            let _ = state.event_sender.send(Arc::new(BroadcastEvent::E2eIdentityChanged {
                targets: waiting_senders.into_iter().collect(),
                uid: token.uid,
                device_id: req.device_id.clone(),
                updated_at: now,
            }));
        }

        Ok(Json(E2eIdentity {
            uid: token.uid,
            device_id: req.0.device_id,
            identity_key_pub: req.0.identity_key_pub,
            signed_prekey_pub: req.0.signed_prekey_pub,
            signed_prekey_sig: req.0.signed_prekey_sig,
            updated_at: now,
        }))
    }

    /// Advertise E2E protocol version / defaults (any authenticated user).
    #[oai(path = "/protocol", method = "get")]
    async fn get_protocol(
        &self,
        state: Data<&State>,
        _token: Token,
    ) -> Result<Json<E2eProtocolInfo>> {
        let cfg = state
            .get_dynamic_config_instance::<LoginConfig>()
            .await
            .map(|c| (*c).clone())
            .unwrap_or_default();
        Ok(Json(E2eProtocolInfo {
            e2e_available: cfg.e2e_available,
            e2e_default_on: cfg.e2e_default_on,
            e2e_protocol_ver: cfg.e2e_protocol_ver,
        }))
    }

    /// List identity public keys for a user (all devices).
    #[oai(path = "/identity/:uid", method = "get")]
    async fn get_identity(
        &self,
        state: Data<&State>,
        _token: Token,
        uid: Path<i64>,
    ) -> Result<Json<Vec<E2eIdentity>>> {
        let rows = sqlx::query_as::<
            _,
            (
                i64,
                String,
                String,
                Option<String>,
                Option<String>,
                DateTime,
            ),
        >(
            "select uid, device_id, identity_key_pub, signed_prekey_pub, signed_prekey_sig, updated_at from e2e_identity where uid = ?",
        )
        .bind(uid.0)
        .fetch_all(&state.db_pool)
        .await
        .map_err(InternalServerError)?;

        Ok(Json(
            rows.into_iter()
                .map(
                    |(
                        uid,
                        device_id,
                        identity_key_pub,
                        signed_prekey_pub,
                        signed_prekey_sig,
                        updated_at,
                    )| E2eIdentity {
                        uid,
                        device_id,
                        identity_key_pub,
                        signed_prekey_pub,
                        signed_prekey_sig,
                        updated_at,
                    },
                )
                .collect(),
        ))
    }

    /// Replace one-time prekeys for a device (upload batch).
    #[oai(path = "/prekeys", method = "put")]
    async fn put_prekeys(
        &self,
        state: Data<&State>,
        token: Token,
        req: Json<PutE2ePrekeysRequest>,
    ) -> Result<()> {
        crate::e2ee_v2::validate_authenticated_device(&req.device_id, &token.device)
            .map_err(|error| Error::from_string(error.to_string(), StatusCode::BAD_REQUEST))?;
        if req.device_id.is_empty() {
            return Err(Error::from_status(StatusCode::BAD_REQUEST));
        }
        let mut tx = state.db_pool.begin().await.map_err(InternalServerError)?;
        sqlx::query("delete from e2e_prekey where uid = ? and device_id = ? and consumed = false")
            .bind(token.uid)
            .bind(&req.device_id)
            .execute(&mut tx)
            .await
            .map_err(InternalServerError)?;
        for key in &req.keys {
            sqlx::query(
                "insert into e2e_prekey (uid, device_id, key_id, public_key, consumed) values (?, ?, ?, ?, false)",
            )
            .bind(token.uid)
            .bind(&req.device_id)
            .bind(key.key_id)
            .bind(&key.public_key)
            .execute(&mut tx)
            .await
            .map_err(InternalServerError)?;
        }
        tx.commit().await.map_err(InternalServerError)?;
        Ok(())
    }

    /// Fetch a prekey bundle for starting a session with uid (consumes one OTP if present).
    #[oai(path = "/bundle/:uid", method = "get")]
    async fn get_bundle(
        &self,
        state: Data<&State>,
        _token: Token,
        uid: Path<i64>,
        device_id: Query<Option<String>>,
    ) -> Result<Json<E2ePrekeyBundle>> {
        let identity = if let Some(device_id) = device_id.0.as_ref() {
            sqlx::query_as::<_, (String, String, Option<String>, Option<String>)>(
                "select device_id, identity_key_pub, signed_prekey_pub, signed_prekey_sig from e2e_identity where uid = ? and device_id = ?",
            )
            .bind(uid.0)
            .bind(device_id)
            .fetch_optional(&state.db_pool)
            .await
            .map_err(InternalServerError)?
        } else {
            sqlx::query_as::<_, (String, String, Option<String>, Option<String>)>(
                "select device_id, identity_key_pub, signed_prekey_pub, signed_prekey_sig from e2e_identity where uid = ? order by updated_at desc limit 1",
            )
            .bind(uid.0)
            .fetch_optional(&state.db_pool)
            .await
            .map_err(InternalServerError)?
        };

        let (device_id, identity_key_pub, signed_prekey_pub, signed_prekey_sig) =
            identity.ok_or_else(|| Error::from_status(StatusCode::NOT_FOUND))?;

        if e2e_protocol_ver(&state).await >= 2 {
            let spk_ok = signed_prekey_pub
                .as_deref()
                .map(|s| !s.trim().is_empty())
                .unwrap_or(false);
            let sig_ok = signed_prekey_sig
                .as_deref()
                .map(|s| !s.trim().is_empty())
                .unwrap_or(false);
            if !spk_ok || !sig_ok {
                return Err(Error::from_string(
                    "E2E_SIGNED_PREKEY_REQUIRED",
                    StatusCode::CONFLICT,
                ));
            }
        }

        let otp = sqlx::query_as::<_, (i64, i32, String)>(
            "select id, key_id, public_key from e2e_prekey where uid = ? and device_id = ? and consumed = false order by id asc limit 1",
        )
        .bind(uid.0)
        .bind(&device_id)
        .fetch_optional(&state.db_pool)
        .await
        .map_err(InternalServerError)?;

        let one_time_prekey = if let Some((id, key_id, public_key)) = otp {
            sqlx::query("update e2e_prekey set consumed = true where id = ?")
                .bind(id)
                .execute(&state.db_pool)
                .await
                .map_err(InternalServerError)?;
            Some(E2ePrekeyItem { key_id, public_key })
        } else {
            None
        };

        Ok(Json(E2ePrekeyBundle {
            uid: uid.0,
            device_id,
            identity_key_pub,
            signed_prekey_pub,
            signed_prekey_sig,
            one_time_prekey,
        }))
    }

    /// Upload passphrase-encrypted identity backup (opaque).
    #[oai(path = "/backup", method = "put")]
    async fn put_backup(
        &self,
        state: Data<&State>,
        token: Token,
        req: Json<PutE2eBackupRequest>,
    ) -> Result<()> {
        let raw = base64::decode(req.blob_base64.trim())
            .map_err(|_| Error::from_status(StatusCode::BAD_REQUEST))?;
        if req.version != 2 || raw.len() < 32 || raw.len() > 8 * 1024 * 1024 {
            return Err(Error::from_status(StatusCode::BAD_REQUEST));
        }
        let now = DateTime::now();
        if let Some((updated_at,)) = sqlx::query_as::<_, (DateTime,)>(
            "select updated_at from e2e_backup where uid = ?",
        )
        .bind(token.uid)
        .fetch_optional(&state.db_pool)
        .await
        .map_err(InternalServerError)?
        {
            if (now.0 - updated_at.0).num_seconds() < 1 {
                return Err(Error::from_status(StatusCode::TOO_MANY_REQUESTS));
            }
        }
        sqlx::query(
            r#"
            insert into e2e_backup
              (uid, version, size_bytes, updated_by_device, blob, updated_at)
            values (?, ?, ?, ?, ?, ?)
            on conflict(uid) do update set
              version = excluded.version,
              size_bytes = excluded.size_bytes,
              updated_by_device = excluded.updated_by_device,
              blob = excluded.blob,
              updated_at = excluded.updated_at
            "#,
        )
        .bind(token.uid)
        .bind(req.version)
        .bind(raw.len() as i64)
        .bind(&token.device)
        .bind(raw)
        .bind(now)
        .execute(&state.db_pool)
        .await
        .map_err(InternalServerError)?;
        Ok(())
    }

    /// Download own encrypted backup blob.
    #[oai(path = "/backup", method = "get")]
    async fn get_backup(
        &self,
        state: Data<&State>,
        token: Token,
    ) -> Result<Json<E2eBackupResponse>> {
        let row = sqlx::query_as::<_, (i32, i64, String, Vec<u8>, DateTime)>(
            "select version, size_bytes, updated_by_device, blob, updated_at from e2e_backup where uid = ?",
        )
        .bind(token.uid)
        .fetch_optional(&state.db_pool)
        .await
        .map_err(InternalServerError)?
        .ok_or_else(|| Error::from_status(StatusCode::NOT_FOUND))?;

        Ok(Json(E2eBackupResponse {
            version: row.0,
            size_bytes: row.1,
            updated_by_device: row.2,
            blob_base64: base64::encode(&row.3),
            updated_at: row.4,
        }))
    }

    /// Revoke the account's opaque encrypted backup.
    #[oai(path = "/backup", method = "delete")]
    async fn delete_backup(&self, state: Data<&State>, token: Token) -> Result<()> {
        sqlx::query("delete from e2e_backup where uid = ?")
            .bind(token.uid)
            .execute(&state.db_pool)
            .await
            .map_err(InternalServerError)?;
        Ok(())
    }

    /// Get DM E2E setting with peer.
    #[oai(path = "/dm/:peer_uid", method = "get")]
    async fn get_dm_setting(
        &self,
        state: Data<&State>,
        token: Token,
        peer_uid: Path<i64>,
    ) -> Result<Json<E2eDmSetting>> {
        let (lo, hi) = dm_pair(token.uid, peer_uid.0);
        let enabled = sqlx::query_as::<_, (bool,)>(
            "select e2e_enabled from e2e_dm_setting where uid_low = ? and uid_high = ?",
        )
        .bind(lo)
        .bind(hi)
        .fetch_optional(&state.db_pool)
        .await
        .map_err(InternalServerError)?
        .map(|r| r.0)
        .unwrap_or(true);

        Ok(Json(E2eDmSetting {
            peer_uid: peer_uid.0,
            e2e_enabled: enabled,
        }))
    }

    /// Set DM E2E setting with peer (either party may enable/disable).
    #[oai(path = "/dm", method = "put")]
    async fn put_dm_setting(
        &self,
        state: Data<&State>,
        token: Token,
        req: Json<PutE2eDmSettingRequest>,
    ) -> Result<Json<E2eDmSetting>> {
        if req.peer_uid == token.uid {
            return Err(Error::from_status(StatusCode::BAD_REQUEST));
        }
        {
            let cache = state.cache.read().await;
            if !cache.users.contains_key(&req.peer_uid) {
                return Err(Error::from_status(StatusCode::NOT_FOUND));
            }
        }
        let (lo, hi) = dm_pair(token.uid, req.peer_uid);
        let now = DateTime::now();
        sqlx::query(
            r#"
            insert into e2e_dm_setting (uid_low, uid_high, e2e_enabled, updated_at)
            values (?, ?, ?, ?)
            on conflict(uid_low, uid_high) do update set
              e2e_enabled = excluded.e2e_enabled,
              updated_at = excluded.updated_at
            "#,
        )
        .bind(lo)
        .bind(hi)
        .bind(req.e2e_enabled)
        .bind(now)
        .execute(&state.db_pool)
        .await
        .map_err(InternalServerError)?;

        Ok(Json(E2eDmSetting {
            peer_uid: req.0.peer_uid,
            e2e_enabled: req.0.e2e_enabled,
        }))
    }

    /// List this user's deferred (`dr-pending`) DM sends to `uid` that are
    /// still awaiting a recipient-device key envelope.
    #[oai(path = "/pending/:uid", method = "get")]
    async fn get_pending(
        &self,
        state: Data<&State>,
        token: Token,
        uid: Path<i64>,
    ) -> Result<Json<Vec<E2ePendingDmMessage>>> {
        let rows = sqlx::query_as::<_, (i64, DateTime)>(
            r#"
            select mid, created_at from e2e_pending_message
            where sender_uid = ? and target_uid = ? and completed_at is null
            order by mid asc
            "#,
        )
        .bind(token.uid)
        .bind(uid.0)
        .fetch_all(&state.db_pool)
        .await
        .map_err(InternalServerError)?;

        Ok(Json(
            rows.into_iter()
                .map(|(mid, created_at)| E2ePendingDmMessage { mid, created_at })
                .collect(),
        ))
    }

    /// Append a per-device key envelope to a deferred DM. Only the original
    /// sender may call this. `recipient_uid` must equal the original DM
    /// target and `device_id` must be a published identity for that user.
    #[oai(path = "/pending/:mid/envelope", method = "post")]
    async fn post_pending_envelope(
        &self,
        state: Data<&State>,
        token: Token,
        mid: Path<i64>,
        req: Json<AppendPendingEnvelopeRequest>,
    ) -> Result<Json<PendingEnvelopeAck>> {
        if req.device_id.is_empty() || req.envelope.is_empty() {
            return Err(Error::from_status(StatusCode::BAD_REQUEST));
        }

        let (sender_uid, target_uid) = sqlx::query_as::<_, (i64, i64)>(
            "select sender_uid, target_uid from e2e_pending_message where mid = ?",
        )
        .bind(mid.0)
        .fetch_optional(&state.db_pool)
        .await
        .map_err(InternalServerError)?
        .ok_or_else(|| Error::from_status(StatusCode::NOT_FOUND))?;

        if sender_uid != token.uid {
            return Err(Error::from_string(
                "E2E_PENDING_FORBIDDEN",
                StatusCode::FORBIDDEN,
            ));
        }
        if req.recipient_uid != target_uid {
            return Err(Error::from_string(
                "E2E_PENDING_WRONG_RECIPIENT",
                StatusCode::BAD_REQUEST,
            ));
        }

        let device_exists = sqlx::query_scalar::<_, i64>(
            "select count(*) from e2e_identity where uid = ? and device_id = ?",
        )
        .bind(req.recipient_uid)
        .bind(&req.device_id)
        .fetch_one(&state.db_pool)
        .await
        .map_err(InternalServerError)?;
        if device_exists == 0 {
            return Err(Error::from_string(
                "E2E_PENDING_UNKNOWN_DEVICE",
                StatusCode::BAD_REQUEST,
            ));
        }

        let now = DateTime::now();
        let mut tx = state.db_pool.begin().await.map_err(InternalServerError)?;
        sqlx::query(
            r#"
            insert into e2e_pending_envelope (mid, recipient_uid, device_id, envelope, created_at)
            values (?, ?, ?, ?, ?)
            on conflict(mid, recipient_uid, device_id) do update set
              envelope = excluded.envelope,
              created_at = excluded.created_at
            "#,
        )
        .bind(mid.0)
        .bind(req.recipient_uid)
        .bind(&req.device_id)
        .bind(&req.envelope)
        .bind(now)
        .execute(&mut tx)
        .await
        .map_err(InternalServerError)?;

        sqlx::query(
            "update e2e_pending_message set completed_at = ? where mid = ? and completed_at is null",
        )
        .bind(now)
        .bind(mid.0)
        .execute(&mut tx)
        .await
        .map_err(InternalServerError)?;
        tx.commit().await.map_err(InternalServerError)?;

        let _ = state.event_sender.send(Arc::new(BroadcastEvent::E2ePendingEnvelopeAdded {
            targets: [sender_uid, req.recipient_uid].into_iter().collect(),
            mid: mid.0,
            recipient_uid: req.recipient_uid,
            device_id: req.device_id.clone(),
        }));

        Ok(Json(PendingEnvelopeAck {
            mid: mid.0,
            recipient_uid: req.0.recipient_uid,
            device_id: req.0.device_id,
            completed: true,
        }))
    }
}

/// Build webhook-safe body for E2E chat messages (no plaintext content).
pub fn redact_e2e_chat_message_json(message: &crate::api::ChatMessage) -> Option<String> {
    use crate::api::message::{MessageDetail, MessageNormal, MessageReply};
    use poem_openapi::types::ToJSON;

    let is_e2e = match &message.payload.detail {
        MessageDetail::Normal(MessageNormal { content, .. })
        | MessageDetail::Reply(MessageReply { content, .. }) => {
            content.content_type == crate::e2ee_v2::CONTENT_TYPE
                || content
                    .properties
                    .as_ref()
                    .and_then(|p| p.get("e2e"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
        }
        _ => false,
    };
    if !is_e2e {
        return None;
    }

    // `ChatMessage` flattens its `payload` fields (mid, from_uid, target,
    // detail, ...) into one JSON object; there is no nested "payload" key.
    let mut v: Value = serde_json::from_str(&message.to_json_string()).unwrap_or_else(|_| {
        json!({
            "mid": message.mid,
            "e2e": true,
            "detail": { "type": "e2e_opaque" }
        })
    });
    if let Some(detail) = v.get_mut("detail") {
        *detail = json!({ "type": "e2e_opaque" });
    }
    v["e2e"] = Value::Bool(true);
    Some(v.to_string())
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use crate::{
        api::{redact_e2e_chat_message_json, DateTime},
        test_harness::TestServer,
    };

    #[tokio::test]
    async fn test_e2e_identity_roundtrip() {
        let server = TestServer::new().await;
        let admin = server.login_admin().await;
        let uid = server.create_user(&admin, "e2e_user@voce.chat").await;
        let token = server
            .login_with_device("e2e_user@voce.chat", "web:test")
            .await;

        let resp = server
            .put("/api/user/e2e/identity")
            .header("X-API-Key", &token)
            .body_json(&json!({
                "device_id": "web:test",
                "identity_key_pub": "pk_test_abc",
                "signed_prekey_pub": "spk_test_abc",
                "signed_prekey_sig": "sig_test_abc"
            }))
            .send()
            .await;
        resp.assert_status_is_ok();

        let resp = server
            .get(format!("/api/user/e2e/identity/{}", uid))
            .header("X-API-Key", &admin)
            .send()
            .await;
        resp.assert_status_is_ok();
        let body = resp.json().await;
        let arr = body.value().array();
        assert_eq!(arr.len(), 1);
        assert_eq!(
            arr.get(0).object().get("identity_key_pub").string(),
            "pk_test_abc"
        );
    }

    #[tokio::test]
    async fn test_e2e_identity_rejects_another_device_id() {
        let server = TestServer::new().await;
        let admin = server.login_admin().await;
        server.create_user(&admin, "e2e_spoof@voce.chat").await;
        let token = server
            .login_with_device("e2e_spoof@voce.chat", "device-real")
            .await;

        let resp = server
            .put("/api/user/e2e/identity")
            .header("X-API-Key", &token)
            .body_json(&json!({
                "device_id": "device-other",
                "identity_key_pub": "pk",
                "signed_prekey_pub": "spk",
                "signed_prekey_sig": "sig"
            }))
            .send()
            .await;

        resp.assert_status(poem::http::StatusCode::BAD_REQUEST);
        resp.assert_text("E2E_DEVICE_MISMATCH").await;
    }

    #[tokio::test]
    async fn test_e2e_protocol_requires_v2() {
        let server = TestServer::new().await;
        let admin = server.login_admin().await;
        let _uid = server.create_user(&admin, "e2e_link@voce.chat").await;
        let token = server.login("e2e_link@voce.chat").await;

        let resp = server
            .get("/api/user/e2e/protocol")
            .header("X-API-Key", &token)
            .send()
            .await;
        resp.assert_status_is_ok();
        let body = resp.json().await;
        assert_eq!(body.value().object().get("e2e_protocol_ver").i64(), 2);

    }

    #[tokio::test]
    async fn test_e2e_backup_replace_and_revoke() {
        let server = TestServer::new().await;
        let admin = server.login_admin().await;
        server.create_user(&admin, "e2e_backup@voce.chat").await;
        let token = server
            .login_with_device("e2e_backup@voce.chat", "backup-device")
            .await;

        for byte in [7_u8, 9_u8] {
            server
                .put("/api/user/e2e/backup")
                .header("X-API-Key", &token)
                .body_json(&json!({
                    "version": 2,
                    "blob_base64": base64::encode(vec![byte; 64]),
                }))
                .send()
                .await
                .assert_status_is_ok();
            tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        }

        let response = server
            .get("/api/user/e2e/backup")
            .header("X-API-Key", &token)
            .send()
            .await;
        response.assert_status_is_ok();
        let body = response.json().await;
        assert_eq!(body.value().object().get("version").i64(), 2);
        assert_eq!(body.value().object().get("size_bytes").i64(), 64);
        assert_eq!(
            body.value().object().get("updated_by_device").string(),
            "backup-device"
        );
        assert_eq!(
            body.value().object().get("blob_base64").string(),
            base64::encode(vec![9_u8; 64])
        );

        server
            .delete("/api/user/e2e/backup")
            .header("X-API-Key", &token)
            .send()
            .await
            .assert_status_is_ok();
        server
            .get("/api/user/e2e/backup")
            .header("X-API-Key", &token)
            .send()
            .await
            .assert_status(poem::http::StatusCode::NOT_FOUND);
    }

    fn dr_pending_properties(sender_device_id: &str, local_id: &str) -> Value {
        json!({
            "e2e_version": 2,
            "protocol": "dr-pending",
            "wire_class": "dr_envelope",
            "sender_device_id": sender_device_id,
            "local_id": local_id,
        })
    }

    async fn send_pending_dm(
        server: &crate::test_harness::TestServer,
        sender_token: &str,
        sender_device_id: &str,
        target_uid: i64,
        local_id: &str,
    ) -> i64 {
        let resp = server
            .post(format!("/api/user/{target_uid}/send"))
            .header("X-API-Key", sender_token)
            .header(
                "X-Properties",
                base64::encode(
                    serde_json::to_string(&dr_pending_properties(sender_device_id, local_id))
                        .unwrap(),
                ),
            )
            .content_type(crate::e2ee_v2::CONTENT_TYPE)
            .body("opaque-pending-envelope")
            .send()
            .await;
        resp.assert_status_is_ok();
        resp.json().await.value().i64()
    }

    async fn put_identity(
        server: &crate::test_harness::TestServer,
        token: &str,
        device_id: &str,
    ) {
        server
            .put("/api/user/e2e/identity")
            .header("X-API-Key", token)
            .body_json(&json!({
                "device_id": device_id,
                "identity_key_pub": format!("pk_{device_id}"),
                "signed_prekey_pub": format!("spk_{device_id}"),
                "signed_prekey_sig": format!("sig_{device_id}"),
            }))
            .send()
            .await
            .assert_status_is_ok();
    }

    #[tokio::test]
    async fn test_pending_dm_rejects_group_target() {
        use poem::http::StatusCode;

        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;
        let gid = {
            let resp = server
                .post("/api/group")
                .header("X-API-Key", &admin_token)
                .body_json(&json!({"name": "g1", "description": "", "is_public": true, "members": []}))
                .send()
                .await;
            resp.assert_status_is_ok();
            resp.json().await.value().object().get("gid").i64()
        };

        let resp = server
            .post(format!("/api/group/{gid}/send"))
            .header("X-API-Key", &admin_token)
            .header(
                "X-Properties",
                base64::encode(
                    serde_json::to_string(&dr_pending_properties("device-admin", "l1")).unwrap(),
                ),
            )
            .content_type(crate::e2ee_v2::CONTENT_TYPE)
            .body("opaque")
            .send()
            .await;
        resp.assert_status(StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_pending_dm_send_lists_and_completes_on_envelope_append() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin_with_device("device-admin").await;
        let uid1 = server.create_user(&admin_token, "pending1@voce.chat").await;
        let token1 = server.login_with_device("pending1@voce.chat", "device-1").await;

        let mid = send_pending_dm(&server, &admin_token, "device-admin", uid1, "local-pending-1").await;

        let resp = server
            .get(format!("/api/user/e2e/pending/{uid1}"))
            .header("X-API-Key", &admin_token)
            .send()
            .await;
        resp.assert_status_is_ok();
        let body = resp.json().await;
        let arr = body.value().array();
        assert!(arr.iter().any(|row| row.object().get("mid").i64() == mid));

        put_identity(&server, &token1, "device-1").await;

        let resp = server
            .post(format!("/api/user/e2e/pending/{mid}/envelope"))
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "recipient_uid": uid1,
                "device_id": "device-1",
                "envelope": "wrapped-content-key",
            }))
            .send()
            .await;
        resp.assert_status_is_ok();
        let body = resp.json().await;
        assert!(body.value().object().get("completed").bool());

        let resp = server
            .get(format!("/api/user/e2e/pending/{uid1}"))
            .header("X-API-Key", &admin_token)
            .send()
            .await;
        resp.assert_status_is_ok();
        let body = resp.json().await;
        assert!(!body.value().array().iter().any(|row| row.object().get("mid").i64() == mid));
    }

    #[tokio::test]
    async fn test_pending_envelope_rejects_wrong_sender() {
        use poem::http::StatusCode;

        let server = TestServer::new().await;
        let admin_token = server.login_admin_with_device("device-admin").await;
        let uid1 = server.create_user(&admin_token, "pending2@voce.chat").await;
        let token1 = server.login_with_device("pending2@voce.chat", "device-1").await;
        let _uid_other = server.create_user(&admin_token, "pending2b@voce.chat").await;
        let token_other = server.login_with_device("pending2b@voce.chat", "device-2").await;

        let mid = send_pending_dm(&server, &admin_token, "device-admin", uid1, "local-pending-2").await;
        put_identity(&server, &token1, "device-1").await;

        let resp = server
            .post(format!("/api/user/e2e/pending/{mid}/envelope"))
            .header("X-API-Key", &token_other)
            .body_json(&json!({
                "recipient_uid": uid1,
                "device_id": "device-1",
                "envelope": "wrapped-content-key",
            }))
            .send()
            .await;
        resp.assert_status(StatusCode::FORBIDDEN);
        resp.assert_text("E2E_PENDING_FORBIDDEN").await;
    }

    #[tokio::test]
    async fn test_pending_envelope_rejects_wrong_recipient() {
        use poem::http::StatusCode;

        let server = TestServer::new().await;
        let admin_token = server.login_admin_with_device("device-admin").await;
        let uid1 = server.create_user(&admin_token, "pending3@voce.chat").await;
        let uid2 = server.create_user(&admin_token, "pending3b@voce.chat").await;

        let mid = send_pending_dm(&server, &admin_token, "device-admin", uid1, "local-pending-3").await;

        let resp = server
            .post(format!("/api/user/e2e/pending/{mid}/envelope"))
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "recipient_uid": uid2,
                "device_id": "device-x",
                "envelope": "wrapped-content-key",
            }))
            .send()
            .await;
        resp.assert_status(StatusCode::BAD_REQUEST);
        resp.assert_text("E2E_PENDING_WRONG_RECIPIENT").await;
    }

    #[tokio::test]
    async fn test_pending_envelope_rejects_unknown_device() {
        use poem::http::StatusCode;

        let server = TestServer::new().await;
        let admin_token = server.login_admin_with_device("device-admin").await;
        let uid1 = server.create_user(&admin_token, "pending4@voce.chat").await;

        let mid = send_pending_dm(&server, &admin_token, "device-admin", uid1, "local-pending-4").await;

        let resp = server
            .post(format!("/api/user/e2e/pending/{mid}/envelope"))
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "recipient_uid": uid1,
                "device_id": "device-ghost",
                "envelope": "wrapped-content-key",
            }))
            .send()
            .await;
        resp.assert_status(StatusCode::BAD_REQUEST);
        resp.assert_text("E2E_PENDING_UNKNOWN_DEVICE").await;
    }

    #[tokio::test]
    async fn test_pending_envelope_not_found() {
        use poem::http::StatusCode;

        let server = TestServer::new().await;
        let admin_token = server.login_admin().await;

        let resp = server
            .post("/api/user/e2e/pending/9999999/envelope")
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "recipient_uid": 1,
                "device_id": "device-x",
                "envelope": "wrapped-content-key",
            }))
            .send()
            .await;
        resp.assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_pending_envelope_append_is_idempotent() {
        let server = TestServer::new().await;
        let admin_token = server.login_admin_with_device("device-admin").await;
        let uid1 = server.create_user(&admin_token, "pending5@voce.chat").await;
        let token1 = server.login_with_device("pending5@voce.chat", "device-1").await;
        put_identity(&server, &token1, "device-1").await;

        let mid = send_pending_dm(&server, &admin_token, "device-admin", uid1, "local-pending-5").await;

        for _ in 0..2 {
            let resp = server
                .post(format!("/api/user/e2e/pending/{mid}/envelope"))
                .header("X-API-Key", &admin_token)
                .body_json(&json!({
                    "recipient_uid": uid1,
                    "device_id": "device-1",
                    "envelope": "wrapped-content-key",
                }))
                .send()
                .await;
            resp.assert_status_is_ok();
        }

        let count: i64 = sqlx::query_scalar(
            "select count(*) from e2e_pending_envelope where mid = ? and recipient_uid = ? and device_id = ?",
        )
        .bind(mid)
        .bind(uid1)
        .bind("device-1")
        .fetch_one(&server.state().db_pool)
        .await
        .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_identity_publish_emits_event_to_waiting_sender() {
        use futures_util::StreamExt;

        let server = TestServer::new().await;
        let admin_token = server.login_admin_with_device("device-admin").await;
        let uid1 = server.create_user(&admin_token, "pending6@voce.chat").await;
        let token1 = server.login_with_device("pending6@voce.chat", "device-1").await;

        let _mid = send_pending_dm(&server, &admin_token, "device-admin", uid1, "local-pending-6").await;

        let mut events = server
            .subscribe_events(&admin_token, Some(&["e2e_identity_changed"]))
            .await;

        put_identity(&server, &token1, "device-1").await;

        let event = events.next().await.unwrap();
        let event = event.value().object();
        event.get("uid").assert_i64(uid1);
        event.get("device_id").assert_string("device-1");
    }

    #[tokio::test]
    async fn test_pending_envelope_added_emits_event_to_sender_and_recipient() {
        use futures_util::StreamExt;

        let server = TestServer::new().await;
        let admin_token = server.login_admin_with_device("device-admin").await;
        let uid1 = server.create_user(&admin_token, "pending7@voce.chat").await;
        let token1 = server.login_with_device("pending7@voce.chat", "device-1").await;
        put_identity(&server, &token1, "device-1").await;

        let mid = send_pending_dm(&server, &admin_token, "device-admin", uid1, "local-pending-7").await;

        let sender_events = server
            .subscribe_events(&admin_token, Some(&["e2e_pending_envelope_added"]))
            .await;
        let recipient_events = server
            .subscribe_events(&token1, Some(&["e2e_pending_envelope_added"]))
            .await;

        server
            .post(format!("/api/user/e2e/pending/{mid}/envelope"))
            .header("X-API-Key", &admin_token)
            .body_json(&json!({
                "recipient_uid": uid1,
                "device_id": "device-1",
                "envelope": "wrapped-content-key",
            }))
            .send()
            .await
            .assert_status_is_ok();

        for mut events in [sender_events, recipient_events] {
            let event = events.next().await.unwrap();
            let event = event.value().object();
            event.get("mid").assert_i64(mid);
            event.get("recipient_uid").assert_i64(uid1);
            event.get("device_id").assert_string("device-1");
        }
    }

    #[test]
    fn test_pending_dm_message_webhook_redaction_stays_opaque() {
        use crate::api::message::{
            ChatMessagePayload, MessageDetail, MessageNormal, MessageTarget, MessageTargetUser,
        };

        let payload = ChatMessagePayload {
            from_uid: 1,
            created_at: DateTime::now(),
            target: MessageTarget::User(MessageTargetUser { uid: 2 }),
            detail: MessageDetail::Normal(MessageNormal {
                content: crate::api::message::ChatMessageContent {
                    properties: Some(
                        serde_json::from_value(dr_pending_properties("device-a", "local-1"))
                            .unwrap(),
                    ),
                    content_type: crate::e2ee_v2::CONTENT_TYPE.to_owned(),
                    content: "opaque-ciphertext".to_owned(),
                },
                expires_in: None,
            }),
        };
        let message = crate::api::ChatMessage { mid: 42, payload };

        let redacted = redact_e2e_chat_message_json(&message).expect("should redact e2e message");
        let value: Value = serde_json::from_str(&redacted).unwrap();
        assert_eq!(value["e2e"], json!(true));
        assert_eq!(value["detail"], json!({"type": "e2e_opaque"}));
        assert!(!redacted.contains("opaque-ciphertext"));
    }
}
