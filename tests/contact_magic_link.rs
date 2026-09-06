//! mokosh-contact-login prompt 009: magic-link edge cases.
//!
//! Complements the happy-path magic-link test in `contact_auth.rs` +
//! `contact_e2e.rs` by pinning each hostile / degenerate input the
//! `/contact/auth/set-password` endpoint could receive: fresh redeem,
//! replayed link, expired link, malformed token, weak password. The
//! set-password path is the single entry point through which a fresh
//! portal account acquires a credential, so every failure mode of
//! `setup_password` needs an HTTP-layer pin.

mod common;

use reqwest::StatusCode;
use sqlx::PgPool;
use uuid::Uuid;

/// Seed a Company + Contact + granted portal access under
/// `DEFAULT_TENANT_ID` and return `(company_id, contact_id,
/// portal_slug, setup_token)` so a test can drive the set-password
/// endpoint directly. Mirrors the private helper in
/// `tests/contact_auth.rs`; each integration-test crate compiles its
/// own copy of `common/`, so duplication over a shared helper is the
/// idiom for a small per-file utility.
async fn seed_portal_contact(pool: &PgPool, email: &str) -> (Uuid, Uuid, String, String) {
    let company_id = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, 'ML P009 Co')")
        .bind(company_id)
        .bind(common::DEFAULT_TENANT_ID)
        .execute(pool)
        .await
        .expect("seed company");
    let contact_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contacts (id, tenant_id, company_id, first_name, last_name, email) \
         VALUES ($1, $2, $3, 'Magic', 'Link', $4)",
    )
    .bind(contact_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .bind(email)
    .execute(pool)
    .await
    .expect("seed contact");

    let db = mokosh_server::Database::from_pool(pool.clone());
    let contact_svc = mokosh_server::modules::contacts::ContactService::new(db);
    let role_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM portal_roles WHERE tenant_id = $1 AND name = 'Support Contact'",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(pool)
    .await
    .expect("read Support Contact role");
    let outcome = contact_svc
        .grant_portal_access(
            mokosh_server::modules::auth::TenantId::from_trusted(common::DEFAULT_TENANT_ID),
            contact_id,
            &[role_id],
            &mokosh_server::modules::audit::AuditCtx::system(common::DEFAULT_TENANT_ID),
        )
        .await
        .expect("grant_portal_access");
    let prefix = format!("/portal/{}/set-password?token=", outcome.portal_slug);
    let token = outcome
        .setup_link
        .split(&prefix)
        .nth(1)
        .expect("token in setup_link")
        .to_string();
    (company_id, contact_id, outcome.portal_slug, token)
}

/// Fresh magic link redeems to 204 and the resulting password logs in.
/// Sanity floor for every other test in this file: without this working
/// the rest of the assertions are meaningless.
#[sqlx::test]
async fn fresh_link_redeems_and_enables_login(pool: PgPool) {
    let (_company_id, _contact_id, slug, token) =
        seed_portal_contact(&pool, "fresh@ml.example").await;
    let app = common::boot(pool.clone()).await;
    let strong = "Kq7$mZ2n#PxR9wLf";

    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/set-password"))
        .json(&serde_json::json!({ "token": token, "password": strong }))
        .send()
        .await
        .expect("set-password");
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "prompt 009: fresh magic link must redeem to 204",
    );

    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/login"))
        .json(&serde_json::json!({
            "slug": slug,
            "email": "fresh@ml.example",
            "password": strong,
        }))
        .send()
        .await
        .expect("login");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "prompt 009: freshly redeemed credentials must log in",
    );
    let cookie_header = resp
        .headers()
        .get("set-cookie")
        .expect("Set-Cookie header")
        .to_str()
        .expect("cookie text");
    assert!(
        cookie_header.contains("mokosh:contact_token="),
        "prompt 009: login must Set-Cookie for the contact-plane refresh, got {cookie_header}",
    );
}

/// A magic link is single-use. After a successful redeem, replaying
/// the exact same token must be rejected. The `setup_password`
/// implementation returns `AppError::Gone` in that branch, which the
/// HTTP layer maps to 410. Pinning the observed status keeps a future
/// refactor that quietly downgrades this to 400 caught.
#[sqlx::test]
async fn replayed_link_is_rejected(pool: PgPool) {
    let (_company_id, _contact_id, _slug, token) =
        seed_portal_contact(&pool, "replay@ml.example").await;
    let app = common::boot(pool.clone()).await;
    let strong = "Kq7$mZ2n#PxR9wLf";

    let first = app
        .client
        .post(app.url("/api/v1/contact/auth/set-password"))
        .json(&serde_json::json!({ "token": token, "password": strong }))
        .send()
        .await
        .expect("first redeem");
    assert_eq!(
        first.status(),
        StatusCode::NO_CONTENT,
        "prompt 009: first redeem must 204",
    );

    let second = app
        .client
        .post(app.url("/api/v1/contact/auth/set-password"))
        .json(&serde_json::json!({ "token": token, "password": strong }))
        .send()
        .await
        .expect("replayed redeem");
    // The service returns `AppError::Gone`; the wire status is 410.
    // Some implementations flatten already-used to 400 - we pin the
    // actual behaviour so a future change to that branch is caught.
    assert_eq!(
        second.status(),
        StatusCode::GONE,
        "prompt 009: replayed magic link must be rejected (single-use); \
         observed status pinned so a downgrade is caught",
    );
}

/// A magic link with an `expires_at` in the past must be rejected.
/// Roll the row back with a direct SQL update so we don't need to
/// wait real wall-clock time. The service reads `expires_at <= NOW`
/// under the same code path that rejects malformed tokens, and both
/// surface as 400.
#[sqlx::test]
async fn expired_link_is_rejected(pool: PgPool) {
    let (_company_id, contact_id, _slug, token) =
        seed_portal_contact(&pool, "expired@ml.example").await;
    let app = common::boot(pool.clone()).await;

    sqlx::query(
        "UPDATE portal_setup_tokens SET expires_at = NOW() - INTERVAL '1 second' \
         WHERE contact_id = $1 AND used_at IS NULL",
    )
    .bind(contact_id)
    .execute(&pool)
    .await
    .expect("expire token");

    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/set-password"))
        .json(&serde_json::json!({
            "token": token,
            "password": "Kq7$mZ2n#PxR9wLf",
        }))
        .send()
        .await
        .expect("expired redeem");
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "prompt 009: expired magic link must be rejected with 400",
    );
}

/// A syntactically malformed token (not `{uuid}.{secret}`) must be
/// rejected at the parser gate. `parse_contact_bound_token` returns
/// `None` for a non-UUID first segment; `setup_password` maps that
/// to `AppError::BadRequest`.
#[sqlx::test]
async fn malformed_token_is_rejected(pool: PgPool) {
    let _ = seed_portal_contact(&pool, "malformed@ml.example").await;
    let app = common::boot(pool.clone()).await;

    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/set-password"))
        .json(&serde_json::json!({
            "token": "not-a-uuid.blah",
            "password": "Kq7$mZ2n#PxR9wLf",
        }))
        .send()
        .await
        .expect("malformed redeem");
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "prompt 009: malformed token must be rejected with 400 at the parser gate",
    );
}

/// Weak-password rejection must come back with an `error.message`
/// that literally mentions "password" so the SPA (learned from
/// MAPPS-560) can render a policy hint instead of a generic error
/// toast. `PasswordPolicyError::UserMessage` maps to
/// `AppError::BadRequest(m)`; the response envelope wraps that as
/// `{"error":{"code":"BAD_REQUEST","message":"Password is too easy to guess. ..."}}`.
///
/// `aaaaaaaaaaaa` passes the 12-char length gate but scores as
/// trivially guessable under zxcvbn, so the score branch is the one
/// that fires (see `password_policy::rejects_weak_zxcvbn_score`).
#[sqlx::test]
async fn weak_password_rejected_with_password_message(pool: PgPool) {
    let (_company_id, _contact_id, _slug, token) =
        seed_portal_contact(&pool, "weak@ml.example").await;
    let app = common::boot(pool.clone()).await;

    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/set-password"))
        .json(&serde_json::json!({
            "token": token,
            "password": "aaaaaaaaaaaa",
        }))
        .send()
        .await
        .expect("weak-password redeem");
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "prompt 009: weak password must be rejected with 400",
    );
    let body: serde_json::Value = resp.json().await.expect("error body JSON");
    let message = body["error"]["message"]
        .as_str()
        .expect("error.message string")
        .to_lowercase();
    assert!(
        message.contains("password"),
        "prompt 009: weak-password message must literally mention 'password' so the \
         SPA can render a policy hint (MAPPS-560), got: {message}",
    );
}
