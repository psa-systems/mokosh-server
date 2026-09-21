//! PMS-1297: the contact plane's unauthenticated credential routes are
//! throttled, set/reset share one budget, and a new reset token supersedes
//! the earlier ones.

mod common;

use chrono::{Duration, Utc};
use mokosh_server::utils::crypto::{hash_password, sha256_hex};
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_contact(pool: &PgPool) -> common::PortalContact {
    let company = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, 'Acme Co')")
        .bind(company)
        .bind(common::DEFAULT_TENANT_ID)
        .execute(pool)
        .await
        .expect("seed company");
    common::seed_portal_contact(pool, company, "user@example.com", &[]).await
}

async fn post(app: &common::TestApp, path: &str, body: serde_json::Value) -> reqwest::Response {
    app.client
        .post(app.url(path))
        .json(&body)
        .send()
        .await
        .expect("send")
}

#[sqlx::test]
async fn set_and_reset_password_share_one_budget(pool: PgPool) {
    let contact = seed_contact(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = format!("{}.no-such-secret", contact.id);
    let body = serde_json::json!({ "token": token, "password": "Xy9#pQ4v!Lm2wRt7" });

    // Account quota is 3 per minute: spend it across BOTH routes.
    for path in [
        "/api/v1/contact/auth/set-password",
        "/api/v1/contact/auth/reset-password",
        "/api/v1/contact/auth/set-password",
    ] {
        let r = post(&app, path, body.clone()).await;
        assert_ne!(r.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
    }
    let r = post(&app, "/api/v1/contact/auth/reset-password", body).await;
    assert_eq!(r.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
    assert!(r.headers().contains_key("retry-after"));
}

#[sqlx::test]
async fn forgot_password_spends_quota_for_known_and_unknown_email(pool: PgPool) {
    let contact = seed_contact(&pool).await;
    let app = common::boot(pool.clone()).await;
    for email in [contact.email.as_str(), "nobody@example.com"] {
        let body = serde_json::json!({ "slug": contact.slug, "email": email });
        for _ in 0..3 {
            let r = post(&app, "/api/v1/contact/auth/forgot-password", body.clone()).await;
            assert_eq!(r.status(), reqwest::StatusCode::NO_CONTENT);
        }
        let r = post(&app, "/api/v1/contact/auth/forgot-password", body).await;
        assert_eq!(
            r.status(),
            reqwest::StatusCode::TOO_MANY_REQUESTS,
            "{email}"
        );
        assert!(r.headers().contains_key("retry-after"));
    }
}

#[sqlx::test]
async fn a_second_reset_token_invalidates_the_first(pool: PgPool) {
    let contact = seed_contact(&pool).await;
    let app = common::boot(pool.clone()).await;
    let secret = "first-secret-value-abcdef";
    sqlx::query(
        "INSERT INTO portal_setup_tokens (tenant_id, contact_id, token_hash, lookup_hash, expires_at) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(contact.id)
    .bind(hash_password(secret).await.unwrap())
    .bind(sha256_hex(secret))
    .bind(Utc::now() + Duration::hours(1))
    .execute(&pool)
    .await
    .unwrap();

    let r = post(
        &app,
        "/api/v1/contact/auth/forgot-password",
        serde_json::json!({ "slug": contact.slug, "email": contact.email }),
    )
    .await;
    assert_eq!(r.status(), reqwest::StatusCode::NO_CONTENT);

    let r = post(
        &app,
        "/api/v1/contact/auth/reset-password",
        serde_json::json!({
            "token": format!("{}.{secret}", contact.id),
            "password": "Xy9#pQ4v!Lm2wRt7",
        }),
    )
    .await;
    assert!(
        r.status().is_client_error(),
        "the superseded token must fail"
    );
}
