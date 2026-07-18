use poem::{error::InternalServerError, http::StatusCode, Error, Result};
use sqlx::SqlitePool;
use uuid::Uuid;

const MAX_CREDENTIAL: usize = 64 * 1024;
const MAX_KEY_PACKAGE: usize = 64 * 1024;
const MAX_ARTIFACT: usize = 2 * 1024 * 1024;
const MAX_BATCH_BYTES: usize = 8 * 1024 * 1024;

pub fn validate_device_id(device_id: &str) -> Result<()> {
    if device_id.is_empty()
        || device_id.len() > 128
        || !device_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(Error::from_status(StatusCode::BAD_REQUEST));
    }
    Ok(())
}

pub fn validate_blob(blob: &[u8], maximum: usize) -> Result<()> {
    if blob.is_empty() || blob.len() > maximum {
        return Err(Error::from_status(StatusCode::PAYLOAD_TOO_LARGE));
    }
    Ok(())
}

pub async fn put_credential(
    db: &SqlitePool,
    uid: i64,
    device_id: &str,
    credential: &[u8],
) -> Result<()> {
    validate_device_id(device_id)?;
    validate_blob(credential, MAX_CREDENTIAL)?;
    sqlx::query(
        "insert into mls_device (uid, device_id, credential, updated_at) values (?, ?, ?, current_timestamp) \
         on conflict(uid, device_id) do update set credential = excluded.credential, updated_at = current_timestamp",
    )
    .bind(uid)
    .bind(device_id)
    .bind(credential)
    .execute(db)
    .await
    .map_err(InternalServerError)?;
    Ok(())
}

pub async fn publish_key_package(
    db: &SqlitePool,
    uid: i64,
    device_id: &str,
    package: &[u8],
) -> Result<()> {
    validate_device_id(device_id)?;
    validate_blob(package, MAX_KEY_PACKAGE)?;
    let result =
        sqlx::query("insert into mls_key_package (uid, device_id, package) values (?, ?, ?)")
            .bind(uid)
            .bind(device_id)
            .bind(package)
            .execute(db)
            .await;
    match result {
        Ok(_) => Ok(()),
        Err(sqlx::Error::Database(error)) if is_foreign_key_violation(error.as_ref()) => {
            Err(Error::from_status(StatusCode::CONFLICT))
        }
        Err(error) => Err(InternalServerError(error)),
    }
}

pub async fn consume_key_package(db: &SqlitePool, uid: i64, device_id: &str) -> Result<Vec<u8>> {
    validate_device_id(device_id)?;
    let mut tx = db.begin().await.map_err(InternalServerError)?;
    let row = sqlx::query_as::<_, (i64, Vec<u8>)>(
        "select id, package from mls_key_package \
         where uid = ? and device_id = ? and consumed_at is null order by id limit 1",
    )
    .bind(uid)
    .bind(device_id)
    .fetch_optional(&mut tx)
    .await
    .map_err(InternalServerError)?
    .ok_or_else(|| Error::from_status(StatusCode::NOT_FOUND))?;
    sqlx::query("update mls_key_package set consumed_at = current_timestamp where id = ?")
        .bind(row.0)
        .execute(&mut tx)
        .await
        .map_err(InternalServerError)?;
    tx.commit().await.map_err(InternalServerError)?;
    Ok(row.1)
}

pub async fn authorize_group(db: &SqlitePool, uid: i64, gid: i64) -> Result<()> {
    let allowed = sqlx::query_scalar::<_, bool>(
        "select exists(\
           select 1 from `group` g where g.gid = ? and \
             (g.owner = ? or exists(\
                select 1 from group_user gu where gu.gid = g.gid and gu.uid = ?\
             ))\
         )",
    )
    .bind(gid)
    .bind(uid)
    .bind(uid)
    .fetch_one(db)
    .await
    .map_err(InternalServerError)?;
    if !allowed {
        return Err(Error::from_status(StatusCode::FORBIDDEN));
    }
    Ok(())
}

pub async fn route_for_group(db: &SqlitePool, uid: i64, gid: i64) -> Result<String> {
    authorize_group(db, uid, gid).await?;
    if let Some(token) =
        sqlx::query_scalar::<_, String>("select token from mls_route where gid = ?")
            .bind(gid)
            .fetch_optional(db)
            .await
            .map_err(InternalServerError)?
    {
        return Ok(token);
    }
    let token = Uuid::new_v4().to_simple().to_string();
    sqlx::query("insert into mls_route (token, gid) values (?, ?) on conflict(gid) do nothing")
        .bind(&token)
        .bind(gid)
        .execute(db)
        .await
        .map_err(InternalServerError)?;
    sqlx::query_scalar("select token from mls_route where gid = ?")
        .bind(gid)
        .fetch_one(db)
        .await
        .map_err(InternalServerError)
}

async fn authorize_route(db: &SqlitePool, uid: i64, token: &str) -> Result<()> {
    let gid = sqlx::query_scalar::<_, i64>("select gid from mls_route where token = ?")
        .bind(token)
        .fetch_optional(db)
        .await
        .map_err(InternalServerError)?
        .ok_or_else(|| Error::from_status(StatusCode::NOT_FOUND))?;
    authorize_group(db, uid, gid).await
}

/// Returns 1 when this device owns the initialization lease, 2 when the route
/// already has an MLS group, and 0 while another device owns the lease.
pub async fn claim_initialization(
    db: &SqlitePool,
    uid: i64,
    device_id: &str,
    token: &str,
) -> Result<u8> {
    validate_device_id(device_id)?;
    authorize_route(db, uid, token).await?;
    let mut tx = db.begin().await.map_err(InternalServerError)?;
    sqlx::query(
        "update mls_route set initializer_uid = ?, initializer_device = ?, \
         initializer_lease = datetime('now', '+30 seconds') \
         where token = ? and initialized = false and (initializer_uid is null \
           or initializer_lease < current_timestamp \
           or (initializer_uid = ? and initializer_device = ?))",
    )
    .bind(uid)
    .bind(device_id)
    .bind(token)
    .bind(uid)
    .bind(device_id)
    .execute(&mut tx)
    .await
    .map_err(InternalServerError)?;
    let row = sqlx::query_as::<_, (bool, Option<i64>, Option<String>)>(
        "select initialized, initializer_uid, initializer_device from mls_route where token = ?",
    )
    .bind(token)
    .fetch_one(&mut tx)
    .await
    .map_err(InternalServerError)?;
    tx.commit().await.map_err(InternalServerError)?;
    if row.0 {
        Ok(2)
    } else if row.1 == Some(uid) && row.2.as_deref() == Some(device_id) {
        Ok(1)
    } else {
        Ok(0)
    }
}

pub async fn mark_initialized(
    db: &SqlitePool,
    uid: i64,
    device_id: &str,
    token: &str,
) -> Result<()> {
    validate_device_id(device_id)?;
    authorize_route(db, uid, token).await?;
    let done = sqlx::query(
        "update mls_route set initialized = true, initializer_lease = null \
         where token = ? and initializer_uid = ? and initializer_device = ? and initialized = false",
    )
    .bind(token)
    .bind(uid)
    .bind(device_id)
    .execute(db)
    .await
    .map_err(InternalServerError)?;
    if done.rows_affected() == 1 {
        Ok(())
    } else {
        Err(Error::from_status(StatusCode::CONFLICT))
    }
}

pub async fn append_artifact(
    db: &SqlitePool,
    uid: i64,
    device_id: &str,
    token: &str,
    payload: &[u8],
) -> Result<i64> {
    validate_device_id(device_id)?;
    validate_blob(payload, MAX_ARTIFACT)?;
    authorize_route(db, uid, token).await?;
    let result = sqlx::query(
        "insert into mls_artifact (route_token, sender_uid, device_id, payload) values (?, ?, ?, ?)",
    )
    .bind(token)
    .bind(uid)
    .bind(device_id)
    .bind(payload)
    .execute(db)
    .await;
    match result {
        Ok(done) => Ok(done.last_insert_rowid()),
        Err(sqlx::Error::Database(error)) if is_foreign_key_violation(error.as_ref()) => {
            Err(Error::from_status(StatusCode::CONFLICT))
        }
        Err(error) => Err(InternalServerError(error)),
    }
}

fn is_foreign_key_violation(error: &dyn sqlx::error::DatabaseError) -> bool {
    error.message().contains("FOREIGN KEY constraint failed")
}

pub async fn read_artifacts(db: &SqlitePool, uid: i64, token: &str, after: i64) -> Result<Vec<u8>> {
    authorize_route(db, uid, token).await?;
    let rows = sqlx::query_as::<_, (i64, Vec<u8>)>(
        "select sequence, payload from mls_artifact where route_token = ? and sequence > ? order by sequence limit 256",
    )
    .bind(token)
    .bind(after.max(0))
    .fetch_all(db)
    .await
    .map_err(InternalServerError)?;
    let mut output = Vec::new();
    for (sequence, payload) in rows {
        let required = 12usize.saturating_add(payload.len());
        if output.len().saturating_add(required) > MAX_BATCH_BYTES {
            break;
        }
        output.extend_from_slice(&(sequence as u64).to_be_bytes());
        output.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        output.extend_from_slice(&payload);
    }
    Ok(output)
}
