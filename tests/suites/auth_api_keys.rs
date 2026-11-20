//! Personal API keys: issuance, bearer authentication, revoke, expiry, shape
//! refusal and per-route scope enforcement.

use crate::common::{self, TestApp};

use mokosh_server::utils::crypto::verify_password_call_count;
use mokosh_test::mokosh_test;
use reqwest::StatusCode;
use serde_json::{json, Value};
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

/// Boot, sign the seeded admin in, and return `(app, session token)`.
async fn app_with_session(pool: PgPool) -> (TestApp, String) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;
    (app, token)
}

/// Mint a key through the API; returns the raw create response body.
async fn create_key(app: &TestApp, session: &str, body: Value) -> Value {
    let resp = app
        .client
        .post(app.url("/api/v1/auth/me/api-keys"))
        .bearer_auth(session)
        .json(&body)
        .send()
        .await
        .expect("send create api key");
    assert_eq!(resp.status(), StatusCode::OK, "create api key");
    resp.json().await.expect("create api key JSON")
}

async fn get_status(app: &TestApp, path: &str, bearer: &str) -> StatusCode {
    app.client
        .get(app.url(path))
        .bearer_auth(bearer)
        .send()
        .await
        .expect("send GET")
        .status()
}

async fn last_used_at(app: &TestApp, key_id: Uuid) -> Option<chrono::DateTime<chrono::Utc>> {
    sqlx::query_scalar("SELECT last_used_at FROM api_keys WHERE id = $1")
        .bind(key_id)
        .fetch_one(&app.pool)
        .await
        .expect("read last_used_at")
}

#[mokosh_test]
async fn plaintext_key_is_returned_once_and_never_listed(pool: PgPool) {
    let (app, session) = app_with_session(pool).await;
    let created = create_key(&app, &session, json!({ "name": "ci" })).await;

    let raw = created["key"].as_str().expect("create returns the key");
    assert_eq!(raw.len(), 44);
    assert!(raw.starts_with("psa_"));
    assert!(raw[4..].bytes().all(|b| b.is_ascii_alphanumeric()));
    assert_eq!(created["scopes"], json!(["*"]));

    let list = app
        .client
        .get(app.url("/api/v1/auth/me/api-keys"))
        .bearer_auth(&session)
        .send()
        .await
        .expect("send list");
    assert_eq!(list.status(), StatusCode::OK);
    let text = list.text().await.expect("list body");
    assert!(!text.contains(raw), "the list leaked the plaintext key");
    assert!(!text.contains("key_hash"), "the list leaked the key hash");
    let body: Value = serde_json::from_str(&text).expect("list JSON");
    let item = &body["data"][0];
    assert_eq!(item["key_prefix"], created["key_prefix"]);
    assert!(item.get("key").is_none());
    assert!(item["revoked_at"].is_null());
}

#[mokosh_test]
async fn a_valid_key_authenticates_and_stamps_last_used_at(pool: PgPool) {
    let (app, session) = app_with_session(pool).await;
    let created = create_key(&app, &session, json!({ "name": "ci" })).await;
    let raw = created["key"].as_str().unwrap();
    let key_id: Uuid = created["id"].as_str().unwrap().parse().unwrap();
    assert!(last_used_at(&app, key_id).await.is_none());

    assert_eq!(
        get_status(&app, "/api/v1/auth/me", raw).await,
        StatusCode::OK
    );

    // The stamp is written off the request path, so poll for it.
    let mut stamped = None;
    for _ in 0..50 {
        stamped = last_used_at(&app, key_id).await;
        if stamped.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let first = stamped.expect("last_used_at was never stamped");

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        get_status(&app, "/api/v1/auth/me", raw).await,
        StatusCode::OK
    );
    let mut advanced = false;
    for _ in 0..50 {
        if last_used_at(&app, key_id).await.is_some_and(|t| t > first) {
            advanced = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(advanced, "last_used_at did not advance on a second use");
}

#[mokosh_test]
async fn a_revoked_key_is_refused_and_stays_listed(pool: PgPool) {
    let (app, session) = app_with_session(pool).await;
    let created = create_key(&app, &session, json!({ "name": "ci" })).await;
    let raw = created["key"].as_str().unwrap();
    let id = created["id"].as_str().unwrap();
    assert_eq!(
        get_status(&app, "/api/v1/auth/me", raw).await,
        StatusCode::OK
    );

    let revoke = app
        .client
        .delete(app.url(&format!("/api/v1/auth/me/api-keys/{id}")))
        .bearer_auth(&session)
        .send()
        .await
        .expect("send revoke");
    assert!(revoke.status().is_success(), "revoke: {}", revoke.status());

    assert_eq!(
        get_status(&app, "/api/v1/auth/me", raw).await,
        StatusCode::UNAUTHORIZED
    );

    let list: Value = app
        .client
        .get(app.url("/api/v1/auth/me/api-keys"))
        .bearer_auth(&session)
        .send()
        .await
        .expect("send list")
        .json()
        .await
        .expect("list JSON");
    assert!(!list["data"][0]["revoked_at"].is_null());

    // Unknown id is a 404, not a silent success.
    let missing = app
        .client
        .delete(app.url(&format!("/api/v1/auth/me/api-keys/{}", Uuid::new_v4())))
        .bearer_auth(&session)
        .send()
        .await
        .expect("send revoke missing");
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
}

#[mokosh_test]
async fn an_expired_key_is_refused(pool: PgPool) {
    let (app, session) = app_with_session(pool).await;
    let created = create_key(&app, &session, json!({ "name": "ci" })).await;
    let raw = created["key"].as_str().unwrap();
    let key_id: Uuid = created["id"].as_str().unwrap().parse().unwrap();
    assert_eq!(
        get_status(&app, "/api/v1/auth/me", raw).await,
        StatusCode::OK
    );

    sqlx::query("UPDATE api_keys SET expires_at = NOW() - INTERVAL '1 minute' WHERE id = $1")
        .bind(key_id)
        .execute(&app.pool)
        .await
        .expect("expire key");

    assert_eq!(
        get_status(&app, "/api/v1/auth/me", raw).await,
        StatusCode::UNAUTHORIZED
    );
}

#[mokosh_test]
async fn a_malformed_key_is_refused_before_any_hash_comparison(pool: PgPool) {
    let (app, session) = app_with_session(pool).await;
    let created = create_key(&app, &session, json!({ "name": "ci" })).await;
    let raw = created["key"].as_str().unwrap();
    let wrong_len = format!("{raw}x");
    let non_alnum = format!("psa_{}", "-".repeat(40));
    let wrong_prefix = format!("xsa_{}", &raw[4..]);

    let before = verify_password_call_count();
    for bad in [
        "psa_xyz",
        "psa_",
        wrong_len.as_str(),
        non_alnum.as_str(),
        wrong_prefix.as_str(),
    ] {
        assert_eq!(
            get_status(&app, "/api/v1/auth/me", bad).await,
            StatusCode::UNAUTHORIZED,
            "bearer {bad:?}"
        );
    }
    assert_eq!(
        verify_password_call_count(),
        before,
        "a malformed key reached a hash comparison"
    );
}

#[mokosh_test]
async fn a_narrow_scope_key_is_refused_outside_its_scope_with_403(pool: PgPool) {
    let (app, session) = app_with_session(pool).await;
    let narrow = create_key(
        &app,
        &session,
        json!({ "name": "reader", "scopes": ["invoices:read"] }),
    )
    .await;
    let narrow = narrow["key"].as_str().unwrap();

    // Inside the scope.
    assert_eq!(
        get_status(&app, "/api/v1/invoices", narrow).await,
        StatusCode::OK
    );
    // Outside it: authenticated (not 401), but forbidden.
    assert_eq!(
        get_status(&app, "/api/v1/auth/users", narrow).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        get_status(&app, "/api/v1/tickets", narrow).await,
        StatusCode::FORBIDDEN
    );

    // A resource wildcard and the default `*` both cover the route.
    let wild = create_key(
        &app,
        &session,
        json!({ "name": "wild", "scopes": ["users:*"] }),
    )
    .await;
    assert_eq!(
        get_status(&app, "/api/v1/auth/users", wild["key"].as_str().unwrap()).await,
        StatusCode::OK
    );
    let full = create_key(&app, &session, json!({ "name": "full" })).await;
    assert_eq!(
        get_status(&app, "/api/v1/auth/users", full["key"].as_str().unwrap()).await,
        StatusCode::OK
    );
}
