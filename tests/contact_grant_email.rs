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

/// Regression pin for the "Welcome to Default / no slug" bug: creating
/// a contact with `is_portal_user: true` used to route through the wrong
/// email path (`send_setup_email` -> `auth.welcome` template with a
/// slug-less `/portal/set-password?token=...` URL that the SPA router
/// 404'd on). The fix delegates to `send_grant_email` so the same
/// well-formed URL + template that the explicit `/grant-portal-access`
/// path already sent shows up here too. Without this pin, a future
/// refactor that re-splits the two paths could silently re-open the bug.
#[sqlx::test]
async fn create_contact_with_is_portal_user_true_dispatches_portal_grant_email_with_slug(
    pool: PgPool,
) {
    let (_admin_id, admin_email, admin_password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &admin_email, &admin_password).await;

    let company_id = seed_company_row(&pool, "Create-With-Portal Co").await;

    let resp = app
        .client
        .post(app.url("/api/v1/contacts/contacts"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "company_id": company_id,
            "first_name": "Fresh",
            "last_name": "Contact",
            "email": "fresh@mcl.example",
            "contact_type": "primary",
            // `CreateContactRequest.create_portal_access` (not
            // `is_portal_user`) is the create-time signal to mint a
            // setup token; the update path uses `is_portal_user`
            // (below) - two DTOs, two field names.
            "create_portal_access": true,
        }))
        .send()
        .await
        .expect("create contact");
    assert!(
        resp.status().is_success(),
        "create contact returned {}",
        resp.status()
    );

    let body: String = sqlx::query_scalar(
        "SELECT body FROM notifications \
         WHERE tenant_id = $1 AND recipient = $2 AND channel_type = 'email'",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind("fresh@mcl.example")
    .fetch_one(&pool)
    .await
    .expect("read email body");

    // The email MUST NOT contain the broken slug-less URL shape.
    assert!(
        !body.contains("/portal/set-password?token="),
        "regression: create_contact must not emit the slug-less URL that the SPA router 404s on, got: {body}"
    );
    // It MUST contain the well-formed `/portal/{slug}/set-password?token=` URL.
    let slug: String = sqlx::query_scalar(
        "SELECT portal_slug FROM companies WHERE id = $1 AND tenant_id = $2",
    )
    .bind(company_id)
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("read portal_slug");
    let expected_prefix = format!("/portal/{slug}/set-password?token=");
    assert!(
        body.contains(&expected_prefix),
        "create_contact grant email must carry /portal/{{slug}}/set-password URL, got: {body}"
    );

    // A portal_id must be assigned on the Company (prompt 011) so the
    // recipient can dictate it over the phone.
    let portal_id: Option<i64> = sqlx::query_scalar(
        "SELECT portal_id FROM companies WHERE id = $1 AND tenant_id = $2",
    )
    .bind(company_id)
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("read portal_id");
    assert!(
        portal_id.is_some(),
        "create_contact with is_portal_user=true must ensure Company has a portal_id"
    );
}

/// Same regression pin for the update path: flipping an existing
/// contact's `is_portal_user` from false to true must also dispatch the
/// correct grant email with the slug in the URL. The prior path routed
/// through `send_setup_email` which produced the same broken URL.
#[sqlx::test]
async fn update_contact_flipping_is_portal_user_true_dispatches_portal_grant_email_with_slug(
    pool: PgPool,
) {
    let (_admin_id, admin_email, admin_password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &admin_email, &admin_password).await;

    let company_id = seed_company_row(&pool, "Update-Flip Co").await;
    let contact_id = seed_contact_row(&pool, company_id, "flipped@mcl.example").await;

    let resp = app
        .client
        .put(app.url(&format!("/api/v1/contacts/contacts/{contact_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "is_portal_user": true,
        }))
        .send()
        .await
        .expect("update contact");
    assert!(
        resp.status().is_success(),
        "update contact returned {}",
        resp.status()
    );

    let body: String = sqlx::query_scalar(
        "SELECT body FROM notifications \
         WHERE tenant_id = $1 AND recipient = $2 AND channel_type = 'email'",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind("flipped@mcl.example")
    .fetch_one(&pool)
    .await
    .expect("read email body");

    assert!(
        !body.contains("/portal/set-password?token="),
        "regression: update_contact must not emit the slug-less URL, got: {body}"
    );
    let slug: String = sqlx::query_scalar(
        "SELECT portal_slug FROM companies WHERE id = $1 AND tenant_id = $2",
    )
    .bind(company_id)
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("read portal_slug");
    let expected_prefix = format!("/portal/{slug}/set-password?token=");
    assert!(
        body.contains(&expected_prefix),
        "update_contact grant email must carry /portal/{{slug}}/set-password URL, got: {body}"
    );
}
