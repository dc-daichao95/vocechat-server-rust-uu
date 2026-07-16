use poem::{
    error::InternalServerError,
    http::StatusCode,
    web::Data,
    Error, Result,
};
use poem_openapi::{
    param::{Path, Query},
    payload::Json,
    Object, OpenApi,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    api::{tags::ApiTags, token::Token, DateTime},
    State,
};

fn dm_pair(a: i64, b: i64) -> (i64, i64) {
    if a < b {
        (a, b)
    } else {
        (b, a)
    }
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
    /// Opaque passphrase-encrypted blob (base64)
    blob_base64: String,
}

#[derive(Debug, Object)]
struct E2eBackupResponse {
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
        if req.device_id.is_empty() || req.identity_key_pub.is_empty() {
            return Err(Error::from_status(StatusCode::BAD_REQUEST));
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

        Ok(Json(E2eIdentity {
            uid: token.uid,
            device_id: req.0.device_id,
            identity_key_pub: req.0.identity_key_pub,
            signed_prekey_pub: req.0.signed_prekey_pub,
            signed_prekey_sig: req.0.signed_prekey_sig,
            updated_at: now,
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
        let raw = base64::decode(req.blob_base64.trim()).map_err(|_| {
            Error::from_status(StatusCode::BAD_REQUEST)
        })?;
        if raw.is_empty() || raw.len() > 2 * 1024 * 1024 {
            return Err(Error::from_status(StatusCode::BAD_REQUEST));
        }
        let now = DateTime::now();
        sqlx::query(
            r#"
            insert into e2e_backup (uid, blob, updated_at) values (?, ?, ?)
            on conflict(uid) do update set blob = excluded.blob, updated_at = excluded.updated_at
            "#,
        )
        .bind(token.uid)
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
        let row = sqlx::query_as::<_, (Vec<u8>, DateTime)>(
            "select blob, updated_at from e2e_backup where uid = ?",
        )
        .bind(token.uid)
        .fetch_optional(&state.db_pool)
        .await
        .map_err(InternalServerError)?
        .ok_or_else(|| Error::from_status(StatusCode::NOT_FOUND))?;

        Ok(Json(E2eBackupResponse {
            blob_base64: base64::encode(&row.0),
            updated_at: row.1,
        }))
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
}

/// Build webhook-safe body for E2E chat messages (no plaintext content).
pub fn redact_e2e_chat_message_json(message: &crate::api::ChatMessage) -> Option<String> {
    use crate::api::message::{MessageDetail, MessageNormal, MessageReply};
    use poem_openapi::types::ToJSON;

    let is_e2e = match &message.payload.detail {
        MessageDetail::Normal(MessageNormal { content, .. })
        | MessageDetail::Reply(MessageReply { content, .. }) => {
            content.content_type == "vocechat/e2e"
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

    let mut v: Value = serde_json::from_str(&message.to_json_string()).unwrap_or_else(|_| {
        json!({
            "mid": message.mid,
            "e2e": true,
            "detail": { "type": "e2e_opaque" }
        })
    });
    if let Some(payload) = v.get_mut("payload") {
        if let Some(detail) = payload.get_mut("detail") {
            *detail = json!({ "type": "e2e_opaque" });
        }
    }
    v["e2e"] = Value::Bool(true);
    Some(v.to_string())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::test_harness::TestServer;

    #[tokio::test]
    async fn test_e2e_identity_roundtrip() {
        let server = TestServer::new().await;
        let admin = server.login_admin().await;
        let uid = server.create_user(&admin, "e2e_user@voce.chat").await;
        let token = server.login(&format!("e2e_user@voce.chat")).await;

        let resp = server
            .put("/api/user/e2e/identity")
            .header("X-API-Key", &token)
            .body_json(&json!({
                "device_id": "web:test",
                "identity_key_pub": "pk_test_abc",
                "signed_prekey_pub": null,
                "signed_prekey_sig": null
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
}
