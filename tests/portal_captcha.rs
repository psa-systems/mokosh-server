//! PMS-729 phase 2 H8: Cloudflare Turnstile challenge on portal login.
//!
//! Most of the logic (gate policy, counter behaviour, siteverify call)
//! is covered by the unit tests in `src/modules/portal/captcha.rs`.
//! This file pins the HTTP wire shape end-to-end:
//!
//! - When the feature is off (both env keys unset, as in the test
//!   harness), a failed login still returns the classic 401
//!   UNAUTHORIZED envelope. No 403 CAPTCHA_REQUIRED can ever be issued.
//! - The per-IP failure counter still ticks (documented so operators
//!   who toggle the feature on later have warm state).

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

// AC (H8 feature-off default): the test harness leaves TURNSTILE_*
// env unset, so the gate is off. A failed login returns the shared
// 401 UNAUTHORIZED envelope, NOT a 403 CAPTCHA_REQUIRED. Locks in the
// safe default: an operator who never sets the env keys sees zero
// behaviour change from pre-H8.
#[sqlx::test]
async fn feature_off_never_returns_captcha_required(pool: PgPool) {
    seed_portal_contact(&pool, "user@example.com").await;
    let app = common::boot(pool).await;

    // Rack up a burst of wrong-password attempts. Nothing about this
    // should ever surface 403; every response is 401 or the 429 rate
    // limiter caps.
    for _ in 0..3 {
        let resp = app
            .client
            .post(app.url("/api/v1/portal/auth/login"))
            .json(&serde_json::json!({
                "tenant_slug": "default",
                "email": "user@example.com",
                "password": "wrong",
            }))
            .send()
            .await
            .expect("login");
        assert_ne!(
            resp.status(),
            reqwest::StatusCode::FORBIDDEN,
            "feature off must never return 403 CAPTCHA_*"
        );
    }
}

// AC (H8 feature-off ignores captcha_token): a stray captcha_token in
// the body when the feature is off is ignored (not validated,
// not rejected). Wire compatibility: SPA can send it always if it
// wants without triggering a spurious server error.
#[sqlx::test]
async fn feature_off_ignores_a_stray_captcha_token(pool: PgPool) {
    seed_portal_contact(&pool, "user@example.com").await;
    let app = common::boot(pool).await;

    let resp = app
        .client
        .post(app.url("/api/v1/portal/auth/login"))
        .json(&serde_json::json!({
            "tenant_slug": "default",
            "email": "user@example.com",
            "password": PORTAL_PASSWORD,
            "captcha_token": "some-random-string-turnstile-would-never-issue",
        }))
        .send()
        .await
        .expect("login");
    assert!(
        resp.status().is_success(),
        "stray captcha_token should not break the happy path when feature is off, got {}",
        resp.status()
    );
}
