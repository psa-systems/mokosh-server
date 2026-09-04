//! Post-PMS-729 code-review findings 1-4: regression tests, on the
//! contact plane since PMS-1025 (ported in PMS-1031).
//!
//! Every test here documents a specific finding the /code-review pass
//! surfaced. Cross-reference the finding numbering in
//! `docs/mokosh-client-login/implementation-notes.md`.
//!
//! Findings #1 and #3 pinned the retired portal's MFA: enrolment at
//! `POST /portal/auth/me/mfa/setup` behind the current password, and a
//! wrong TOTP ticking `portal_failed_login_count`. The contact plane has
//! no enrolment route and `ContactAuthService::login` does not read
//! `mfa_code` (its parameter is `_mfa_code`), so neither case can be
//! expressed against it; both are PMS-1063, not behaviour to pin here.

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
