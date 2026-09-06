//! Post-PMS-729 code-review findings 1-4: regression tests, on the
//! contact plane since PMS-1025 (ported in PMS-1031).
//!
//! Every test here documents a specific finding the /code-review pass
//! surfaced. Cross-reference the finding numbering in
//! `docs/mokosh-client-login/implementation-notes.md`.
//!
//! Findings #1 and #3 pin the second factor: enrolment at
//! `POST /contact/auth/me/mfa/setup` behind the current password, and a
//! wrong TOTP ticking `portal_failed_login_count`. Both were dropped by
//! the PMS-1031 port because the contact plane had neither; PMS-1063
//! restored them, and `tests/contact_mfa.rs` carries the full lifecycle.

mod common;

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

// ---- Finding #4: case-insensitive email lookup --------------------------

/// A contact stored with mixed-case email must authenticate against a
/// canonical-cased login attempt. Before the fix, the DB compared
/// bytes and returned Unauthorized for `alice@example.com` vs
/// `Alice@Example.com`.
#[sqlx::test]
async fn login_matches_email_case_insensitively(pool: PgPool) {
    let _ = common::seed_admin(&pool).await;
    let company = seed_company(&pool, "Case Co").await;
    let mut contact = common::seed_portal_contact(&pool, company, "Alice@Example.com", &[]).await;
    let app = common::boot(pool.clone()).await;

    contact.email = "alice@example.com".to_string();
    let resp = common::contact_login_response(&app, &contact, common::CONTACT_PASSWORD).await;
    assert!(
        resp.status().is_success(),
        "case-insensitive email lookup regressed: {}",
        resp.status()
    );
}

// ---- Finding #2: refresh principal gate ---------------------------------

/// Deactivating the contact (`is_portal_user = FALSE`) must invalidate
/// live refresh tokens on the next presentation. Before the fix, the
/// refresh SELECT filtered only (id, tenant_id) and rotation continued
/// after portal access was revoked.
#[sqlx::test]
async fn refresh_rejects_a_deactivated_contact(pool: PgPool) {
    let _ = common::seed_admin(&pool).await;
    let company = seed_company(&pool, "Deact Co").await;
    let contact = common::seed_portal_contact(&pool, company, "deact@example.com", &[]).await;
    let app = common::boot(pool.clone()).await;

    let login = common::contact_login(&app, &contact).await;
    let refresh = login["refresh_token"].as_str().unwrap().to_string();

    // Revoke portal access on the row.
    sqlx::query("UPDATE contacts SET is_portal_user = FALSE WHERE id = $1")
        .bind(contact.id)
        .execute(&pool)
        .await
        .expect("deactivate");

    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/refresh"))
        .json(&serde_json::json!({"refresh_token": refresh}))
        .send()
        .await
        .expect("refresh");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "refresh should reject a deactivated contact"
    );
}

// ---- Finding #3: MFA setup requires the current password ---------------

/// A stolen access token must not be enough to enrol an attacker's
/// authenticator: setup with no body, or the wrong password, must not
/// stage a secret; the right password does.
#[sqlx::test]
async fn mfa_setup_rejects_missing_current_password(pool: PgPool) {
    let _ = common::seed_admin(&pool).await;
    let company = seed_company(&pool, "Setup Co").await;
    let contact = common::seed_portal_contact(&pool, company, "setup@example.com", &[]).await;
    let app = common::boot(pool.clone()).await;
    let token = common::contact_token(&app, &contact).await;

    let empty = app
        .client
        .post(app.url("/api/v1/contact/auth/me/mfa/setup"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("empty");
    assert!(
        empty.status().is_client_error(),
        "empty body should be rejected: {}",
        empty.status()
    );

    let wrong = app
        .client
        .post(app.url("/api/v1/contact/auth/me/mfa/setup"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "current_password": "not-the-password" }))
        .send()
        .await
        .expect("wrong");
    assert_eq!(
        wrong.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "wrong current_password must not enrol"
    );
    let staged: Option<String> =
        sqlx::query_scalar("SELECT portal_mfa_secret FROM contacts WHERE id = $1")
            .bind(contact.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(staged.is_none(), "nothing staged by the refused calls");

    let ok = app
        .client
        .post(app.url("/api/v1/contact/auth/me/mfa/setup"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "current_password": common::CONTACT_PASSWORD }))
        .send()
        .await
        .expect("ok");
    assert!(ok.status().is_success(), "correct password should enrol");
}

// ---- Finding #1: MFA failure arms the persistent lockout counter --------

/// Password correct, TOTP wrong: the persistent `portal_failed_login_count`
/// must tick so PMS-501's DB-backed lockout arms across replicas rather
/// than leaving the second factor throttled only by an in-memory limiter.
#[sqlx::test]
async fn mfa_failure_ticks_persistent_failed_login_counter(pool: PgPool) {
    let _ = common::seed_admin(&pool).await;
    let company = seed_company(&pool, "MFAFail Co").await;
    let contact = common::seed_portal_contact(&pool, company, "mfafail@example.com", &[]).await;
    let secret = mokosh_server::utils::totp::generate_secret();
    let secret_b32 = mokosh_server::utils::totp::base32_encode(&secret);
    sqlx::query(
        "UPDATE contacts SET portal_mfa_enabled = TRUE, portal_mfa_secret = $1 WHERE id = $2",
    )
    .bind(&secret_b32)
    .bind(contact.id)
    .execute(&pool)
    .await
    .expect("enable mfa");
    let app = common::boot(pool.clone()).await;

    let before: i32 =
        sqlx::query_scalar("SELECT portal_failed_login_count FROM contacts WHERE id = $1")
            .bind(contact.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(before, 0);

    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/login"))
        .json(&serde_json::json!({
            "slug": contact.slug,
            "email": contact.email,
            "password": common::CONTACT_PASSWORD,
            "mfa_code": "000000",
        }))
        .send()
        .await
        .expect("mfa login");
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    let after: i32 =
        sqlx::query_scalar("SELECT portal_failed_login_count FROM contacts WHERE id = $1")
            .bind(contact.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        after > before,
        "portal_failed_login_count must tick on MFA failure: before={before}, after={after}"
    );
}
