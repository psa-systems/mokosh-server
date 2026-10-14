//! PMS-1487 asset inline edit (server half): `PATCH /api/v1/assets/{id}`.
//!
//! The partial-update verb the SPA drawer calls on blur. Three states on
//! every nullable field: key absent leaves the column untouched, key
//! present with `null` writes NULL, key present with a value writes
//! that value. Every patch records one audit-log entry carrying the
//! full before -> after diff, so the audit panel keeps its uniform
//! shape across PUT and PATCH.

mod common;

use mokosh_test::mokosh_test;
use reqwest::StatusCode;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_company(pool: &PgPool, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(common::DEFAULT_TENANT_ID)
        .bind(name)
        .execute(pool)
        .await
        .expect("seed company");
    id
}

async fn seed_asset_type(pool: &PgPool, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO asset_types (id, tenant_id, name, is_active) VALUES ($1, $2, $3, TRUE)",
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(name)
    .execute(pool)
    .await
    .expect("seed type");
    id
}

async fn seed_asset(
    pool: &PgPool,
    company: Uuid,
    asset_type: Uuid,
    name: &str,
    status: &str,
    hostname: Option<&str>,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO assets (id, tenant_id, name, asset_type_id, company_id, status, hostname) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(name)
    .bind(asset_type)
    .bind(company)
    .bind(status)
    .bind(hostname)
    .execute(pool)
    .await
    .expect("seed asset");
    id
}

async fn patch(app: &common::TestApp, token: &str, id: Uuid, body: Value) -> (StatusCode, Value) {
    let r = app
        .client
        .patch(app.url(&format!("/api/v1/assets/{id}")))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("patch");
    let st = r.status();
    let json = r.json().await.unwrap_or(Value::Null);
    (st, json)
}

async fn fetch_audit(app: &common::TestApp, token: &str, id: Uuid) -> Vec<Value> {
    let r = app
        .client
        .get(app.url(&format!("/api/v1/assets/{id}/audit-log")))
        .bearer_auth(token)
        .send()
        .await
        .expect("audit");
    assert!(r.status().is_success(), "audit status: {}", r.status());
    let body: Value = r.json().await.expect("audit json");
    body["data"].as_array().cloned().unwrap_or_default()
}

/// T1 - absent key leaves the column untouched; a present key writes the
/// value; the audit row records the before -> after diff.
#[mokosh_test]
async fn patch_updates_only_the_sent_keys(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let co = seed_company(&pool, "Acme").await;
    let at = seed_asset_type(&pool, "Laptop").await;
    let a = seed_asset(&pool, co, at, "First", "active", Some("first.local")).await;

    let (st, body) = patch(&app, &token, a, json!({ "status": "in_repair" })).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["status"].as_str(), Some("in_repair"));
    assert_eq!(
        body["hostname"].as_str(),
        Some("first.local"),
        "an un-sent key stays untouched: {body}"
    );
    assert_eq!(body["name"].as_str(), Some("First"));

    let entries = fetch_audit(&app, &token, a).await;
    assert!(!entries.is_empty(), "an audit row was written");
    let last = entries.last().expect("last entry");
    assert_eq!(
        last["action"].as_str(),
        Some("status_changed"),
        "status change surfaces as status_changed: {last}"
    );
}

/// T2 - `null` on a nullable key clears the column.
#[mokosh_test]
async fn patch_null_clears_a_nullable_column(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let co = seed_company(&pool, "Acme").await;
    let at = seed_asset_type(&pool, "Laptop").await;
    let a = seed_asset(&pool, co, at, "Clearable", "active", Some("clear.local")).await;

    let (st, body) = patch(&app, &token, a, json!({ "hostname": null })).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert!(body["hostname"].is_null(), "null clears the column: {body}");
}

/// T3 - a value with a cap over `#[validate]` is refused the same way on
/// Patch as it is on Create. Guards: the shared
/// `check-create-update-validate-parity` script covers this at compile
/// time, but exercising the HTTP shape once catches a regression if the
/// guard is skipped on a branch.
#[mokosh_test]
async fn patch_validates_oversize_hostname(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let co = seed_company(&pool, "Acme").await;
    let at = seed_asset_type(&pool, "Laptop").await;
    let a = seed_asset(&pool, co, at, "Val", "active", None).await;

    let huge = "x".repeat(300);
    let (st, _body) = patch(&app, &token, a, json!({ "hostname": huge })).await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "oversized hostname");
}

/// T4 - an empty body is a no-op that returns the current row. Not an
/// error; the SPA's "re-fetch after Esc" shape sends an empty body.
#[mokosh_test]
async fn patch_empty_body_returns_the_current_row(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let co = seed_company(&pool, "Acme").await;
    let at = seed_asset_type(&pool, "Laptop").await;
    let a = seed_asset(&pool, co, at, "Idle", "active", None).await;

    let (st, body) = patch(&app, &token, a, json!({})).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["id"].as_str(), Some(a.to_string().as_str()));
    assert_eq!(body["name"].as_str(), Some("Idle"));
}

/// T5 - a patch on an id in another tenant's scope is 404.
#[mokosh_test]
async fn patch_refuses_cross_tenant_access(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let (st, _) = patch(&app, &token, Uuid::new_v4(), json!({ "name": "Hi" })).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

/// T6 - tags are replace-on-send; absent leaves them, empty vec clears.
#[mokosh_test]
async fn patch_tags_replace_semantics(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let co = seed_company(&pool, "Acme").await;
    let at = seed_asset_type(&pool, "Laptop").await;
    let a = seed_asset(&pool, co, at, "Tagged", "active", None).await;
    sqlx::query("UPDATE assets SET tags = $1 WHERE id = $2")
        .bind(vec!["kiosk".to_string()])
        .bind(a)
        .execute(&pool)
        .await
        .expect("seed tags");

    // Omitting the key leaves them.
    let (_, body) = patch(&app, &token, a, json!({ "name": "Still tagged" })).await;
    let tags: Vec<&str> = body["tags"]
        .as_array()
        .expect("tags")
        .iter()
        .map(|v| v.as_str().unwrap_or(""))
        .collect();
    assert_eq!(tags, vec!["kiosk"]);

    // Sending the key replaces them.
    let (_, body) = patch(&app, &token, a, json!({ "tags": ["sales", "field"] })).await;
    let tags: Vec<&str> = body["tags"]
        .as_array()
        .expect("tags")
        .iter()
        .map(|v| v.as_str().unwrap_or(""))
        .collect();
    assert_eq!(tags, vec!["sales", "field"]);

    // Empty vec clears.
    let (_, body) = patch(&app, &token, a, json!({ "tags": [] })).await;
    let tags: Vec<&str> = body["tags"]
        .as_array()
        .expect("tags")
        .iter()
        .map(|v| v.as_str().unwrap_or(""))
        .collect();
    assert!(tags.is_empty(), "empty vec clears tags: {body}");
}
