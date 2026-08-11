//! Post-PMS-729 code-review findings 1-4: regression tests.
//!
//! Every test here documents a specific finding the /code-review pass
//! surfaced. Cross-reference the finding numbering in
//! `docs/mokosh-client-login/implementation-notes.md`.

mod common;

use sqlx::PgPool;
use uuid::Uuid;

const PORTAL_PASSWORD: &str = "portal-password-12345";

async fn seed_portal_contact(pool: &PgPool, company_id: Uuid, email: &str) -> Uuid {
    let hash = mokosh_server::utils::crypto::hash_password(PORTAL_PASSWORD).expect("hash password");
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO contacts (
            id, tenant_id, company_id, first_name, last_name, email,
            is_portal_user, portal_password_hash
        )
        VALUES ($1, $2, $3, 'Port', 'Al', $4, TRUE, $5)
        "#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .bind(email)
    .bind(&hash)
    .execute(pool)
    .await
    .expect("seed portal contact");
    id
}

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
    let _ = seed_portal_contact(&pool, company, "Alice@Example.com").await;
    let app = common::boot(pool.clone()).await;
    let resp = app
        .client
        .post(app.url("/api/v1/portal/auth/login"))
        .json(&serde_json::json!({
            "tenant_slug": "default",
            "email": "alice@example.com",
            "password": PORTAL_PASSWORD,
        }))
        .send()
        .await
        .expect("login");
    assert!(
        resp.status().is_success(),
        "case-insensitive email lookup regressed: {}",
        resp.status()
    );
}

// ---- Finding #2: refresh_access_token principal gate --------------------

/// Deactivating the contact (`is_portal_user = FALSE`) must invalidate
/// live refresh tokens on the next presentation. Before the fix, the
/// refresh SELECT filtered only (id, tenant_id) and rotation continued
/// after portal access was revoked.
#[sqlx::test]
async fn refresh_rejects_a_deactivated_contact(pool: PgPool) {
    let _ = common::seed_admin(&pool).await;
    let company = seed_company(&pool, "Deact Co").await;
    let contact = seed_portal_contact(&pool, company, "deact@example.com").await;
    let app = common::boot(pool.clone()).await;

    let login = app
        .client
        .post(app.url("/api/v1/portal/auth/login"))
        .json(&serde_json::json!({
            "tenant_slug": "default",
            "email": "deact@example.com",
            "password": PORTAL_PASSWORD,
        }))
        .send()
        .await
        .expect("login")
        .json::<serde_json::Value>()
        .await
        .unwrap();
    let refresh = login["refresh_token"].as_str().unwrap().to_string();

    // Revoke portal access on the row.
    sqlx::query("UPDATE contacts SET is_portal_user = FALSE WHERE id = $1")
        .bind(contact)
        .execute(&pool)
        .await
        .expect("deactivate");

    let resp = app
        .client
        .post(app.url("/api/v1/portal/auth/refresh"))
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

// ---- Finding #3: MFA setup + enable require current password ------------

#[sqlx::test]
async fn mfa_setup_rejects_missing_current_password(pool: PgPool) {
    let _ = common::seed_admin(&pool).await;
    let company = seed_company(&pool, "Setup Co").await;
    let _ = seed_portal_contact(&pool, company, "setup@example.com").await;
    let app = common::boot(pool.clone()).await;

    let token = app
        .client
        .post(app.url("/api/v1/portal/auth/login"))
        .json(&serde_json::json!({
            "tenant_slug": "default",
            "email": "setup@example.com",
            "password": PORTAL_PASSWORD,
        }))
        .send()
        .await
        .expect("login")
        .json::<serde_json::Value>()
        .await
        .unwrap()["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    // No body at all: bad request or unauthorized - either way the
    // setup MUST NOT succeed.
    let empty = app
        .client
        .post(app.url("/api/v1/portal/auth/me/mfa/setup"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("empty");
    assert!(
        empty.status().is_client_error(),
        "empty body should be rejected: {}",
        empty.status()
    );

    // Wrong password: 401.
    let wrong = app
        .client
        .post(app.url("/api/v1/portal/auth/me/mfa/setup"))
        .bearer_auth(&token)
        .json(&serde_json::json!({"current_password": "not-the-password"}))
        .send()
        .await
        .expect("wrong");
    assert_eq!(
        wrong.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "wrong current_password must not enroll: {}",
        wrong.status()
    );

    // Right password: 200.
    let ok = app
        .client
        .post(app.url("/api/v1/portal/auth/me/mfa/setup"))
        .bearer_auth(&token)
        .json(&serde_json::json!({"current_password": PORTAL_PASSWORD}))
        .send()
        .await
        .expect("ok");
    assert!(ok.status().is_success(), "correct password should enroll");
}

// ---- Finding #1: MFA failure arms the persistent lockout counter --------

/// Bad TOTP + password-correct combos must tick the persistent
/// `portal_failed_login_count` so PMS-501's DB-backed lockout arms
/// across replicas. Before the fix, the only throttle was the 5/min
/// in-memory limiter, which a multi-replica attacker bypasses.
#[sqlx::test]
async fn mfa_failure_ticks_persistent_failed_login_counter(pool: PgPool) {
    let _ = common::seed_admin(&pool).await;
    let company = seed_company(&pool, "MFAFail Co").await;
    let contact = seed_portal_contact(&pool, company, "mfafail@example.com").await;

    // Enable MFA on the row directly.
    let secret = mokosh_server::utils::totp::generate_secret();
    let secret_b32 = mokosh_server::utils::totp::base32_encode(&secret);
    sqlx::query(
        "UPDATE contacts SET portal_mfa_enabled = TRUE, portal_mfa_secret = $1 WHERE id = $2",
    )
    .bind(&secret_b32)
    .bind(contact)
    .execute(&pool)
    .await
    .expect("enable mfa");

    let app = common::boot(pool.clone()).await;

    let before: i32 =
        sqlx::query_scalar("SELECT portal_failed_login_count FROM contacts WHERE id = $1")
            .bind(contact)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(before, 0);

    // Password correct, TOTP wrong.
    let resp = app
        .client
        .post(app.url("/api/v1/portal/auth/login"))
        .json(&serde_json::json!({
            "tenant_slug": "default",
            "email": "mfafail@example.com",
            "password": PORTAL_PASSWORD,
            "mfa_code": "000000",
        }))
        .send()
        .await
        .expect("mfa login");
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    let after: i32 =
        sqlx::query_scalar("SELECT portal_failed_login_count FROM contacts WHERE id = $1")
            .bind(contact)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        after > before,
        "portal_failed_login_count must tick on MFA failure: before={before}, after={after}"
    );
}
