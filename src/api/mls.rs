use poem::{error::InternalServerError, http::StatusCode, web::Data, Error, Result};
use poem_openapi::{
    param::{Path, Query},
    payload::{Binary, Json},
    Object, OpenApi,
};

use crate::{
    api::{tags::ApiTags, token::Token},
    mls_delivery, State,
};

#[derive(Object)]
struct MlsDeviceList {
    device_ids: Vec<String>,
}

pub struct ApiMls;

#[OpenApi(prefix_path = "/user/mls", tag = "ApiTags::User")]
impl ApiMls {
    #[oai(path = "/device/:device_id/credential", method = "put")]
    async fn put_credential(
        &self,
        state: Data<&State>,
        token: Token,
        device_id: Path<String>,
        body: Binary<Vec<u8>>,
    ) -> Result<()> {
        mls_delivery::put_credential(&state.db_pool, token.uid, &device_id, &body).await
    }

    #[oai(path = "/device/:uid/:device_id/credential", method = "get")]
    async fn get_credential(
        &self,
        state: Data<&State>,
        _token: Token,
        uid: Path<i64>,
        device_id: Path<String>,
    ) -> Result<Binary<Vec<u8>>> {
        mls_delivery::validate_device_id(&device_id)?;
        let credential = sqlx::query_scalar::<_, Vec<u8>>(
            "select credential from mls_device where uid = ? and device_id = ?",
        )
        .bind(uid.0)
        .bind(&device_id.0)
        .fetch_optional(&state.db_pool)
        .await
        .map_err(InternalServerError)?
        .ok_or_else(|| Error::from_status(StatusCode::NOT_FOUND))?;
        Ok(Binary(credential))
    }

    #[oai(path = "/devices/:uid", method = "get")]
    async fn list_devices(
        &self,
        state: Data<&State>,
        _token: Token,
        uid: Path<i64>,
    ) -> Result<Json<MlsDeviceList>> {
        let device_ids = sqlx::query_scalar::<_, String>(
            "select device_id from mls_device where uid = ? order by device_id",
        )
        .bind(uid.0)
        .fetch_all(&state.db_pool)
        .await
        .map_err(InternalServerError)?;
        Ok(Json(MlsDeviceList { device_ids }))
    }

    #[oai(path = "/device/:device_id/key-package", method = "post")]
    async fn publish_key_package(
        &self,
        state: Data<&State>,
        token: Token,
        device_id: Path<String>,
        body: Binary<Vec<u8>>,
    ) -> Result<()> {
        mls_delivery::publish_key_package(&state.db_pool, token.uid, &device_id, &body).await
    }

    #[oai(path = "/device/:uid/:device_id/key-package", method = "get")]
    async fn consume_key_package(
        &self,
        state: Data<&State>,
        _token: Token,
        uid: Path<i64>,
        device_id: Path<String>,
    ) -> Result<Binary<Vec<u8>>> {
        Ok(Binary(
            mls_delivery::consume_key_package(&state.db_pool, uid.0, &device_id).await?,
        ))
    }

    #[oai(path = "/group/:gid/route", method = "put")]
    async fn group_route(
        &self,
        state: Data<&State>,
        token: Token,
        gid: Path<i64>,
    ) -> Result<Binary<Vec<u8>>> {
        let route = mls_delivery::route_for_group(&state.db_pool, token.uid, gid.0).await?;
        Ok(Binary(route.into_bytes()))
    }

    #[oai(path = "/route/:route/:device_id", method = "post")]
    async fn append_artifact(
        &self,
        state: Data<&State>,
        token: Token,
        route: Path<String>,
        device_id: Path<String>,
        body: Binary<Vec<u8>>,
    ) -> Result<Binary<Vec<u8>>> {
        validate_route(&route)?;
        let sequence =
            mls_delivery::append_artifact(&state.db_pool, token.uid, &device_id, &route, &body)
                .await?;
        Ok(Binary((sequence as u64).to_be_bytes().to_vec()))
    }

    #[oai(path = "/route/:route/:device_id/claim", method = "post")]
    async fn claim_initialization(
        &self,
        state: Data<&State>,
        token: Token,
        route: Path<String>,
        device_id: Path<String>,
    ) -> Result<Binary<Vec<u8>>> {
        validate_route(&route)?;
        let status =
            mls_delivery::claim_initialization(&state.db_pool, token.uid, &device_id, &route)
                .await?;
        Ok(Binary(vec![status]))
    }

    #[oai(path = "/route/:route/:device_id/initialized", method = "post")]
    async fn mark_initialized(
        &self,
        state: Data<&State>,
        token: Token,
        route: Path<String>,
        device_id: Path<String>,
    ) -> Result<()> {
        validate_route(&route)?;
        mls_delivery::mark_initialized(&state.db_pool, token.uid, &device_id, &route).await
    }

    #[oai(path = "/route/:route", method = "get")]
    async fn read_artifacts(
        &self,
        state: Data<&State>,
        token: Token,
        route: Path<String>,
        #[oai(default)] after: Query<i64>,
    ) -> Result<Binary<Vec<u8>>> {
        validate_route(&route)?;
        Ok(Binary(
            mls_delivery::read_artifacts(&state.db_pool, token.uid, &route, after.0).await?,
        ))
    }
}

fn validate_route(route: &str) -> Result<()> {
    if route.len() != 32 || !route.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::from_status(StatusCode::BAD_REQUEST));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::test_harness::TestServer;

    #[tokio::test]
    async fn opaque_binary_delivery_roundtrip() {
        let server = TestServer::new().await;
        let token = server.login_admin().await;
        let user = server.parse_token(&token).await;

        let put = server
            .put("/api/user/mls/device/phone/credential")
            .header("X-API-Key", &token)
            .content_type("application/octet-stream")
            .body(b"public credential".to_vec())
            .send()
            .await;
        put.assert_status_is_ok();

        let publish = server
            .post("/api/user/mls/device/phone/key-package")
            .header("X-API-Key", &token)
            .content_type("application/octet-stream")
            .body(b"opaque package".to_vec())
            .send()
            .await;
        publish.assert_status_is_ok();
        server
            .get(format!(
                "/api/user/mls/device/{}/phone/key-package",
                user.uid
            ))
            .header("X-API-Key", &token)
            .send()
            .await
            .assert_bytes(b"opaque package")
            .await;

        let group = sqlx::query(
            "insert into `group` (name, owner, is_public) values ('mls-test', ?, false)",
        )
        .bind(user.uid)
        .execute(&server.state().db_pool)
        .await
        .unwrap();
        let gid = group.last_insert_rowid();
        let route_response = server
            .put(format!("/api/user/mls/group/{gid}/route"))
            .header("X-API-Key", &token)
            .content_type("application/octet-stream")
            .send()
            .await;
        route_response.assert_status_is_ok();
        let route = String::from_utf8(
            route_response
                .0
                .into_body()
                .into_vec()
                .await
                .expect("route bytes"),
        )
        .unwrap();
        assert_eq!(route.len(), 32);

        server
            .post(format!("/api/user/mls/route/{route}/phone/claim"))
            .header("X-API-Key", &token)
            .send()
            .await
            .assert_bytes(&[1])
            .await;
        server
            .post(format!("/api/user/mls/route/{route}/phone/initialized"))
            .header("X-API-Key", &token)
            .send()
            .await
            .assert_status_is_ok();
        server
            .post(format!("/api/user/mls/route/{route}/phone/claim"))
            .header("X-API-Key", &token)
            .send()
            .await
            .assert_bytes(&[2])
            .await;

        let append = server
            .post(format!("/api/user/mls/route/{route}/phone"))
            .header("X-API-Key", &token)
            .content_type("application/octet-stream")
            .body(b"opaque private message".to_vec())
            .send()
            .await;
        append.assert_status_is_ok();
        let batch = server
            .get(format!("/api/user/mls/route/{route}?after=0"))
            .header("X-API-Key", &token)
            .send()
            .await;
        batch.assert_status_is_ok();
        let bytes = batch.0.into_body().into_vec().await.unwrap();
        assert_eq!(&bytes[12..], b"opaque private message");
        assert_eq!(u32::from_be_bytes(bytes[8..12].try_into().unwrap()), 22);
    }

    #[tokio::test]
    async fn rejects_invalid_device_and_unauthorized_route() {
        let server = TestServer::new().await;
        let token = server.login_admin().await;
        let response = server
            .put("/api/user/mls/device/../credential")
            .header("X-API-Key", &token)
            .content_type("application/octet-stream")
            .body(b"x".to_vec())
            .send()
            .await;
        assert!(!response.0.status().is_success());

        let outsider_uid = server.create_user(&token, "outsider@voce.chat").await;
        let outsider = server.login("outsider@voce.chat").await;
        let group = sqlx::query(
            "insert into `group` (name, owner, is_public) values ('public-mls-test', 1, true)",
        )
        .execute(&server.state().db_pool)
        .await
        .unwrap();
        let gid = group.last_insert_rowid();
        let response = server
            .put(format!("/api/user/mls/group/{gid}/route"))
            .header("X-API-Key", &outsider)
            .body_json(&json!({ "uid": outsider_uid }))
            .send()
            .await;
        response.assert_status(poem::http::StatusCode::FORBIDDEN);
    }
}
