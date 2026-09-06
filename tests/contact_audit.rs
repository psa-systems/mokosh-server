//! PMS-1089: contact-plane auth events land in the shared `audit_log`
//! under `entity_type = 'portal_contact'`, the contact in `entity_id`
//! and the subtype in `new_values.event`. The writes are best-effort
//! (they never fail the auth flow), so this suite is what catches a
//! wire that stopped emitting them.

mod common;

use sqlx::PgPool;
use uuid::Uuid;

const STRONG: &str = "Xy9#pQ4v!Lm2wRt7";

async fn seed_portal_contact(pool: &PgPool, email: &str) -> common::PortalContact {
    let company = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, $3)")
        .bind(company)
        .bind(common::DEFAULT_TENANT_ID)
        .bind(format!("{email} Co"))
        .execute(pool)
        .await
        .expect("seed company");
    common::seed_portal_contact(pool, company, email, &[]).await
}

type AuditRow = (
    String,
    Option<Uuid>,
    Option<serde_json::Value>,
    Option<String>,
    Option<String>,
);

async fn rows(pool: &PgPool, contact_id: Uuid, subtype: &str) -> Vec<AuditRow> {
    sqlx::query_as(
        "SELECT action, entity_id, new_values, ip_address, user_agent FROM audit_log \
         WHERE entity_type = 'portal_contact' AND entity_id = $1 \
           AND new_values ->> 'event' = $2 \
         ORDER BY timestamp ASC",
    )
    .bind(contact_id)
    .bind(subtype)
    .fetch_all(pool)
    .await
    .expect("select audit rows")
}

async fn assert_one(pool: &PgPool, contact_id: Uuid, subtype: &str, action: &str) -> AuditRow {
    let found = rows(pool, contact_id, subtype).await;
    assert_eq!(found.len(), 1, "one {subtype} row, got {found:?}");
    assert_eq!(found[0].0, action, "{subtype} action");
    assert_eq!(found[0].1, Some(contact_id));
    assert!(found[0].2.as_ref().unwrap()["event"].as_str() == Some(subtype));
    found[0].clone()
}

async fn login_with(
    app: &common::TestApp,
    contact: &common::PortalContact,
    extra: serde_json::Value,
) -> reqwest::Response {
    let mut body = serde_json::json!({
        "slug": contact.slug,
        "email": contact.email,
        "password": common::CONTACT_PASSWORD,
    });
    for (k, v) in extra.as_object().unwrap() {
        body[k] = v.clone();
    }
    app.client
        .post(app.url("/api/v1/contact/auth/login"))
        .header("User-Agent", "audit-suite/1.0")
        .json(&body)
        .send()
        .await
        .expect("login")
}

async fn authed(
    app: &common::TestApp,
    method: reqwest::Method,
    token: &str,
    path: &str,
    body: serde_json::Value,
) -> reqwest::Response {
    app.client
        .request(method, app.url(path))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("send")
}

// Login success and failure each write their own subtype, with the
// client address and user agent on the row.
#[sqlx::test]
async fn login_success_and_failure_write_rows(pool: PgPool) {
    let contact = seed_portal_contact(&pool, "login@example.com").await;
    let app = common::boot(pool.clone()).await;

    let ok = login_with(&app, &contact, serde_json::json!({})).await;
    assert_eq!(ok.status(), reqwest::StatusCode::OK);
    let row = assert_one(&pool, contact.id, "portal.login", "login").await;
    assert!(row.3.is_some(), "ip recorded");
    assert_eq!(row.4.as_deref(), Some("audit-suite/1.0"));

    let bad = login_with(&app, &contact, serde_json::json!({ "password": "wrong" })).await;
    assert_eq!(bad.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_one(&pool, contact.id, "portal.login_failed", "login").await;
    assert_eq!(rows(&pool, contact.id, "portal.login").await.len(), 1);
}

// A wrong second factor is its own subtype; the pre-signal writes none.
#[sqlx::test]
async fn a_wrong_second_factor_writes_mfa_failed(pool: PgPool) {
    let contact = seed_portal_contact(&pool, "mfa@example.com").await;
    let secret = mokosh_server::utils::totp::generate_secret();
    sqlx::query(
        "UPDATE contacts SET portal_mfa_enabled = TRUE, portal_mfa_secret = $1 WHERE id = $2",
    )
    .bind(mokosh_server::utils::totp::base32_encode(&secret))
    .bind(contact.id)
    .execute(&pool)
    .await
    .unwrap();
    let app = common::boot(pool.clone()).await;

    let pre = login_with(&app, &contact, serde_json::json!({})).await;
    assert_eq!(pre.status(), reqwest::StatusCode::OK);
    assert!(rows(&pool, contact.id, "portal.login").await.is_empty());
    assert!(rows(&pool, contact.id, "portal.mfa_failed")
        .await
        .is_empty());

    let wrong = login_with(&app, &contact, serde_json::json!({ "mfa_code": "000000" })).await;
    assert_eq!(wrong.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_one(&pool, contact.id, "portal.mfa_failed", "login").await;

    let code = mokosh_server::utils::totp::code_at(&secret, chrono::Utc::now());
    let ok = login_with(&app, &contact, serde_json::json!({ "mfa_code": code })).await;
    assert_eq!(ok.status(), reqwest::StatusCode::OK);
    assert_one(&pool, contact.id, "portal.login", "login").await;
}

// Logout and a replayed refresh both write, as logout actions.
#[sqlx::test]
async fn logout_and_replay_write_rows(pool: PgPool) {
    let contact = seed_portal_contact(&pool, "sessions@example.com").await;
    let app = common::boot(pool.clone()).await;
    let body = common::contact_login(&app, &contact).await;
    let rt_1 = body["refresh_token"].as_str().unwrap().to_string();

    let rotated = app
        .client
        .post(app.url("/api/v1/contact/auth/refresh"))
        .json(&serde_json::json!({ "refresh_token": rt_1 }))
        .send()
        .await
        .unwrap();
    assert!(rotated.status().is_success());
    let replay = app
        .client
        .post(app.url("/api/v1/contact/auth/refresh"))
        .json(&serde_json::json!({ "refresh_token": rt_1 }))
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_one(
        &pool,
        contact.id,
        "portal.refresh_replay_detected",
        "logout",
    )
    .await;

    let body = common::contact_login(&app, &contact).await;
    let rt = body["refresh_token"].as_str().unwrap().to_string();
    let out = app
        .client
        .post(app.url("/api/v1/contact/auth/logout"))
        .header("User-Agent", "audit-suite/1.0")
        .json(&serde_json::json!({ "refresh_token": rt }))
        .send()
        .await
        .unwrap();
    assert_eq!(out.status(), reqwest::StatusCode::NO_CONTENT);
    let row = assert_one(&pool, contact.id, "portal.logout", "logout").await;
    assert_eq!(row.4.as_deref(), Some("audit-suite/1.0"));

    // A logout with a forged secret revokes nothing and writes nothing.
    let (id, _) = rt.split_once('.').unwrap();
    let forged = app
        .client
        .post(app.url("/api/v1/contact/auth/logout"))
        .json(&serde_json::json!({ "refresh_token": format!("{id}.nope-nope-nope") }))
        .send()
        .await
        .unwrap();
    assert_eq!(forged.status(), reqwest::StatusCode::NO_CONTENT);
    assert_eq!(rows(&pool, contact.id, "portal.logout").await.len(), 1);
}

// Reset through a token, and change while signed in, each write.
#[sqlx::test]
async fn password_reset_and_change_write_rows(pool: PgPool) {
    let contact = seed_portal_contact(&pool, "pw@example.com").await;
    let app = common::boot(pool.clone()).await;

    let secret = "reset-secret-abcdefghij";
    let hash = mokosh_server::utils::crypto::hash_password(secret).unwrap();
    let token_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO portal_setup_tokens (id, tenant_id, contact_id, token_hash, expires_at) \
         VALUES ($1, $2, $3, $4, NOW() + INTERVAL '30 minutes')",
    )
    .bind(token_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(contact.id)
    .bind(&hash)
    .execute(&pool)
    .await
    .unwrap();
    let reset = app
        .client
        .post(app.url("/api/v1/contact/auth/reset-password"))
        .json(
            &serde_json::json!({ "token": format!("{}.{secret}", contact.id), "password": STRONG }),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(reset.status(), reqwest::StatusCode::NO_CONTENT);
    assert_one(&pool, contact.id, "portal.password_reset", "update").await;
    assert!(rows(&pool, contact.id, "portal.setup_password")
        .await
        .is_empty());

    let body = common::contact_login_response(&app, &contact, STRONG).await;
    assert_eq!(body.status(), reqwest::StatusCode::OK);
    let token = body.json::<serde_json::Value>().await.unwrap()["access_token"]
        .as_str()
        .unwrap()
        .to_string();
    let changed = authed(
        &app,
        reqwest::Method::PUT,
        &token,
        "/api/v1/contact/auth/me/password",
        serde_json::json!({ "current_password": STRONG, "new_password": "Kq7$mZ2n#PxR9wLf" }),
    )
    .await;
    assert_eq!(changed.status(), reqwest::StatusCode::NO_CONTENT);
    assert_one(&pool, contact.id, "portal.password_changed", "update").await;

    // A refused change writes nothing.
    let refused = authed(
        &app,
        reqwest::Method::PUT,
        &token,
        "/api/v1/contact/auth/me/password",
        serde_json::json!({ "current_password": "wrong", "new_password": STRONG }),
    )
    .await;
    assert_eq!(refused.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(
        rows(&pool, contact.id, "portal.password_changed")
            .await
            .len(),
        1
    );
}

// The three MFA transitions each write.
#[sqlx::test]
async fn mfa_setup_enable_disable_write_rows(pool: PgPool) {
    let contact = seed_portal_contact(&pool, "totp@example.com").await;
    let app = common::boot(pool.clone()).await;
    let token = common::contact_token(&app, &contact).await;

    let setup = authed(
        &app,
        reqwest::Method::POST,
        &token,
        "/api/v1/contact/auth/me/mfa/setup",
        serde_json::json!({ "current_password": common::CONTACT_PASSWORD }),
    )
    .await;
    assert_eq!(setup.status(), reqwest::StatusCode::OK);
    let setup: serde_json::Value = setup.json().await.unwrap();
    assert_one(&pool, contact.id, "portal.mfa_setup_started", "update").await;

    let secret =
        mokosh_server::utils::totp::base32_decode(setup["secret"].as_str().unwrap()).unwrap();
    let code = mokosh_server::utils::totp::code_at(&secret, chrono::Utc::now());
    let enable = authed(
        &app,
        reqwest::Method::POST,
        &token,
        "/api/v1/contact/auth/me/mfa/enable",
        serde_json::json!({ "code": code, "current_password": common::CONTACT_PASSWORD }),
    )
    .await;
    assert_eq!(enable.status(), reqwest::StatusCode::OK);
    assert_one(&pool, contact.id, "portal.mfa_enabled", "update").await;

    let code = mokosh_server::utils::totp::code_at(&secret, chrono::Utc::now());
    let disable = authed(
        &app,
        reqwest::Method::POST,
        &token,
        "/api/v1/contact/auth/me/mfa/disable",
        serde_json::json!({ "current_password": common::CONTACT_PASSWORD, "code": code }),
    )
    .await;
    assert_eq!(disable.status(), reqwest::StatusCode::NO_CONTENT);
    assert_one(&pool, contact.id, "portal.mfa_disabled", "update").await;
}
