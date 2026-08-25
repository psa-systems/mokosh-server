//! mokosh-contact-login prompt 010 (PMS-918): the grant-portal-access
//! email now carries two links, not one:
//!   - Primary CTA: `/portal/pick?token=...` magic-link intent
//!   - Secondary: `/portal/{slug}/set-password?token=...`
//!
//! Pins the two-block shape: without this test a future template
//! rewrite that drops either URL would go undetected.

mod common;

use sqlx::PgPool;
use uuid::Uuid;

async fn seed_company_row(pool: &PgPool, name: &str) -> Uuid {
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

async fn seed_contact_row(pool: &PgPool, company_id: Uuid, email: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contacts (id, tenant_id, company_id, first_name, last_name, email) \
         VALUES ($1, $2, $3, 'Test', 'Contact', $4)",
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .bind(email)
    .execute(pool)
    .await
    .expect("seed contact");
    id
}

/// mokosh-contact-login prompt 010: the auth.portal_grant email
/// carries BOTH the magic-link URL and the set-password URL, so the
/// recipient can pick whichever they prefer.
#[sqlx::test]
async fn grant_email_now_carries_both_magic_link_and_set_password_urls(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let company_id = seed_company_row(&pool, "Grant Email Co").await;
    let contact_id = seed_contact_row(&pool, company_id, "granted@mcl.example").await;

    // Pick Support Contact role (any built-in is fine; the email
    // shape is role-agnostic).
    let support_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM portal_roles WHERE tenant_id = $1 AND name = 'Support Contact'",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("Support role");

    let resp = app
        .client
        .post(app.url(&format!(
            "/api/v1/contacts/contacts/{contact_id}/grant-portal-access"
        )))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "role_ids": [support_id] }))
        .send()
        .await
        .expect("grant");
    assert!(
        resp.status().is_success(),
        "grant returned {}",
        resp.status()
    );
    let outcome: serde_json::Value = resp.json().await.expect("outcome JSON");
    let portal_slug = outcome["portal_slug"].as_str().expect("portal_slug");

    // The queued auth.portal_grant email body must carry both URLs.
    let body: String = sqlx::query_scalar(
        "SELECT body FROM notifications \
         WHERE tenant_id = $1 AND recipient = $2 AND channel_type = 'email'",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind("granted@mcl.example")
    .fetch_one(&pool)
    .await
    .expect("read email body");

    assert!(
        body.contains("/portal/pick?token="),
        "prompt 010: grant email must carry the magic-link URL, got: {body}"
    );
    let expected_setup_prefix = format!("/portal/{portal_slug}/set-password?token=");
    assert!(
        body.contains(&expected_setup_prefix),
        "prompt 010: grant email must carry the set-password URL, got: {body}"
    );

    // Both tokens landed in the DB: one setup token + one login
    // intent for the same contact's email.
    let setup_tokens: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM portal_setup_tokens \
         WHERE contact_id = $1 AND used_at IS NULL",
    )
    .bind(contact_id)
    .fetch_one(&pool)
    .await
    .expect("count setup tokens");
    assert_eq!(
        setup_tokens, 1,
        "prompt 010: exactly one unredeemed setup token"
    );

    let intents: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM portal_login_intents \
         WHERE tenant_id = $1 AND LOWER(email) = LOWER($2) AND used_at IS NULL",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind("granted@mcl.example")
    .fetch_one(&pool)
    .await
    .expect("count login intents");
    assert_eq!(
        intents, 1,
        "prompt 010: exactly one unredeemed magic-link intent"
    );
}
