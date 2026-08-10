//! PMS-729 phase 2 H10: portal auth events land in the shared
//! `audit_log` table under `entity_type = 'portal_contact'`.
//!
//! Each test drives one auth event through the HTTP surface and then
//! asserts the row shape on `audit_log`. The audit writes are
//! best-effort (never fail the auth flow), so this suite is the safety
//! net that catches a wire that stopped emitting them.

mod common;

use sqlx::PgPool;
use uuid::Uuid;

const PORTAL_PASSWORD: &str = "portal-password-12345";

async fn seed_portal_contact(pool: &PgPool, email: &str) -> Uuid {
    let company = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, 'Acme Co')")
        .bind(company)
        .bind(common::DEFAULT_TENANT_ID)
        .execute(pool)
        .await
        .expect("seed company");
    let hash =
        mokosh_server::utils::crypto::hash_password(PORTAL_PASSWORD).expect("hash portal password");
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO contacts (
            id, tenant_id, company_id, first_name, last_name, email,
            is_portal_user, portal_password_hash
        )
        VALUES ($1, $2, $3, 'Portal', 'Contact', $4, TRUE, $5)
        "#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company)
    .bind(email)
    .bind(&hash)
    .execute(pool)
    .await
    .expect("seed portal contact");
    id
}

/// Fetch every audit row this test seeded for a specific contact +
/// event subtype pair. Portal audit rows carry `event_type=portal_contact`
/// and the subtype in `new_values.event`.
async fn portal_audit_rows(
    pool: &PgPool,
    contact_id: Uuid,
    subtype: &str,
) -> Vec<(String, Option<Uuid>, Option<serde_json::Value>)> {
    sqlx::query_as(
        r#"
        SELECT action, entity_id, new_values
        FROM audit_log
        WHERE entity_type = 'portal_contact'
          AND entity_id = $1
          AND new_values ->> 'event' = $2
        ORDER BY timestamp ASC
        "#,
    )
    .bind(contact_id)
    .bind(subtype)
    .fetch_all(pool)
    .await
    .expect("select audit rows")
}

// AC (H10): a successful portal login writes an audit row with action
// `login`, subtype `portal.login`, and the contact id as `entity_id`.
#[sqlx::test]
async fn login_success_writes_audit_row(pool: PgPool) {
    let contact = seed_portal_contact(&pool, "user@example.com").await;
    let app = common::boot(pool.clone()).await;

    let resp = app
        .client
        .post(app.url("/api/v1/portal/auth/login"))
        .json(&serde_json::json!({
            "tenant_slug": "default",
            "email": "user@example.com",
            "password": PORTAL_PASSWORD,
        }))
        .send()
        .await
        .expect("login");
    assert!(resp.status().is_success());

    let rows = portal_audit_rows(&pool, contact, "portal.login").await;
    assert_eq!(rows.len(), 1, "one login audit row");
    let (action, entity_id, new_values) = &rows[0];
    assert_eq!(action, "login");
    assert_eq!(*entity_id, Some(contact));
    let nv = new_values.as_ref().expect("new_values present");
    assert_eq!(nv["event"].as_str(), Some("portal.login"));
}

// AC (H10): a failed login (wrong password) writes a distinct subtype
// so a brute-force run is visible in the audit log.
#[sqlx::test]
async fn login_failure_writes_audit_row(pool: PgPool) {
    let contact = seed_portal_contact(&pool, "user@example.com").await;
    let app = common::boot(pool.clone()).await;

    let resp = app
        .client
        .post(app.url("/api/v1/portal/auth/login"))
        .json(&serde_json::json!({
            "tenant_slug": "default",
            "email": "user@example.com",
            "password": "wrong-password",
        }))
        .send()
        .await
        .expect("login");
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    let rows = portal_audit_rows(&pool, contact, "portal.login_failed").await;
    assert_eq!(rows.len(), 1, "one login_failed audit row");
    assert_eq!(rows[0].0, "login");
}

// AC (H10): logout writes an audit row with action `logout` and the
// subtype `portal.logout`.
#[sqlx::test]
async fn logout_writes_audit_row(pool: PgPool) {
    let contact = seed_portal_contact(&pool, "user@example.com").await;
    let app = common::boot(pool.clone()).await;

    let login = app
        .client
        .post(app.url("/api/v1/portal/auth/login"))
        .json(&serde_json::json!({
            "tenant_slug": "default",
            "email": "user@example.com",
            "password": PORTAL_PASSWORD,
        }))
        .send()
        .await
        .expect("login");
    let body: serde_json::Value = login.json().await.unwrap();
    let refresh_token = body["refresh_token"].as_str().unwrap().to_string();

    let out = app
        .client
        .post(app.url("/api/v1/portal/auth/logout"))
        .json(&serde_json::json!({ "refresh_token": refresh_token }))
        .send()
        .await
        .expect("logout");
    assert_eq!(out.status(), reqwest::StatusCode::NO_CONTENT);

    let rows = portal_audit_rows(&pool, contact, "portal.logout").await;
    assert_eq!(rows.len(), 1, "one logout audit row");
    assert_eq!(rows[0].0, "logout");
}

// AC (H10): a successful password reset writes an audit row with
// action `update` and subtype `portal.password_reset`.
#[sqlx::test]
async fn password_reset_writes_audit_row(pool: PgPool) {
    let contact = seed_portal_contact(&pool, "user@example.com").await;
    let app = common::boot(pool.clone()).await;

    // Insert a valid reset-token row directly with a known secret.
    let secret = "reset-secret-abcdefghij";
    let hash = mokosh_server::utils::crypto::hash_password(secret).expect("hash");
    let token_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO portal_password_reset_tokens
            (id, tenant_id, contact_id, token_hash, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(token_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(contact)
    .bind(&hash)
    .bind(chrono::Utc::now() + chrono::Duration::minutes(30))
    .execute(&pool)
    .await
    .expect("insert");

    let resp = app
        .client
        .post(app.url("/api/v1/portal/auth/reset-password"))
        .json(&serde_json::json!({
            "token": format!("{token_id}.{secret}"),
            "password": "Kq7$mZ2n#PxR9wLf",
        }))
        .send()
        .await
        .expect("reset");
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);

    let rows = portal_audit_rows(&pool, contact, "portal.password_reset").await;
    assert_eq!(rows.len(), 1, "one password_reset audit row");
    assert_eq!(rows[0].0, "update");
}

// AC (H10): a successful password change writes an audit row with
// action `update` and subtype `portal.password_changed`.
#[sqlx::test]
async fn password_change_writes_audit_row(pool: PgPool) {
    let contact = seed_portal_contact(&pool, "user@example.com").await;
    let app = common::boot(pool.clone()).await;

    let login = app
        .client
        .post(app.url("/api/v1/portal/auth/login"))
        .json(&serde_json::json!({
            "tenant_slug": "default",
            "email": "user@example.com",
            "password": PORTAL_PASSWORD,
        }))
        .send()
        .await
        .expect("login");
    let access_token = login.json::<serde_json::Value>().await.unwrap()["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    let resp = app
        .client
        .put(app.url("/api/v1/portal/auth/me/password"))
        .bearer_auth(&access_token)
        .json(&serde_json::json!({
            "current_password": PORTAL_PASSWORD,
            "new_password": "Kq7$mZ2n#PxR9wLf",
        }))
        .send()
        .await
        .expect("change");
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);

    let rows = portal_audit_rows(&pool, contact, "portal.password_changed").await;
    assert_eq!(rows.len(), 1, "one password_changed audit row");
    assert_eq!(rows[0].0, "update");
}
