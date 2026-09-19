//! PMS-1222: the contact-portal middleware must re-check, on every
//! request, the same conditions `ContactAuthService::login` checks
//! before it mints a token - not just once at token issuance.
//!
//! Before this fix, `portal_contact_middleware` only re-checked the
//! owning tenant's status; a contact whose portal access was revoked
//! at the contact level (`is_portal_user = FALSE`) mid-session kept
//! full access for the life of the 15-minute access token, because
//! the middleware built `ContactSession` straight from the JWT claims.

mod common;

use reqwest::StatusCode;
use sqlx::PgPool;
use uuid::Uuid;

/// Seed a Company + Contact, grant portal access, and log in for a
/// real access token (the token has to come from the production
/// login path so it carries a genuine `contact_id` claim).
async fn seed_portal_contact(pool: &PgPool, email: &str) -> (Uuid, String, String) {
    let company_id = Uuid::new_v4();
    let slug = format!("ac-{}", &Uuid::new_v4().simple().to_string()[..12]);
    sqlx::query("INSERT INTO companies (id, tenant_id, name, portal_slug) VALUES ($1, $2, $3, $4)")
        .bind(company_id)
        .bind(common::DEFAULT_TENANT_ID)
        .bind("Access Check Co")
        .bind(&slug)
        .execute(pool)
        .await
        .expect("seed company");

    let contact_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contacts (id, tenant_id, company_id, first_name, last_name, email) \
         VALUES ($1, $2, $3, 'Access', 'Check', $4)",
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
    let roles: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM portal_roles WHERE tenant_id = $1 AND name = 'Support Contact'",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_all(pool)
    .await
    .expect("read Support role");
    let role_ids: Vec<Uuid> = roles.into_iter().map(|(id,)| id).collect();
    let outcome = contact_svc
        .grant_portal_access(
            mokosh_server::modules::auth::TenantId::from_trusted(common::DEFAULT_TENANT_ID),
            contact_id,
            &role_ids,
            &mokosh_server::modules::audit::AuditCtx::system(common::DEFAULT_TENANT_ID),
        )
        .await
        .expect("grant_portal_access");

    let prefix = format!("/portal/{}/set-password?token=", outcome.portal_slug);
    let setup_token = outcome
        .setup_link
        .split(&prefix)
        .nth(1)
        .expect("token in setup_link")
        .to_string();
    (contact_id, slug, setup_token)
}

async fn me_status(app: &common::TestApp, token: &str) -> StatusCode {
    app.client
        .get(app.url("/api/v1/contact/auth/me"))
        .bearer_auth(token)
        .send()
        .await
        .expect("contact reads /auth/me")
        .status()
}

/// Revoking `is_portal_user` mid-session - the exact scenario PMS-1222
/// names ("their own portal access is revoked at the contact level
/// rather than the session level") - must reject the very next
/// request on the still-live, unexpired access token.
#[sqlx::test]
async fn revoking_portal_access_rejects_the_next_request(pool: PgPool) {
    let (contact_id, company_slug, setup_token) =
        seed_portal_contact(&pool, "revoke-access@pms1222.example").await;
    let app = common::boot(pool.clone()).await;

    let password = "Kq7$mZ2n#PxR9wLf";
    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/set-password"))
        .json(&serde_json::json!({ "token": setup_token, "password": password }))
        .send()
        .await
        .expect("set-password");
    assert_eq!(resp.status(), StatusCode::NO_CONTENT, "set-password 204");

    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/login"))
        .json(&serde_json::json!({
            "slug": company_slug,
            "email": "revoke-access@pms1222.example",
            "password": password,
        }))
        .send()
        .await
        .expect("contact login");
    assert_eq!(resp.status(), StatusCode::OK, "contact login 200");
    let body: serde_json::Value = resp.json().await.expect("login JSON");
    let token = body["access_token"]
        .as_str()
        .expect("access_token in login response")
        .to_string();

    assert_eq!(
        me_status(&app, &token).await,
        StatusCode::OK,
        "the fresh token must authenticate before any revoke"
    );

    // Revoke portal access at the contact level, out from under the
    // still-live token, exactly the way `ContactService::revoke_portal_access`
    // does in production.
    sqlx::query("UPDATE contacts SET is_portal_user = FALSE, updated_at = NOW() WHERE id = $1")
        .bind(contact_id)
        .execute(&pool)
        .await
        .expect("revoke is_portal_user");

    assert_eq!(
        me_status(&app, &token).await,
        StatusCode::UNAUTHORIZED,
        "PMS-1222: revoking portal access at the contact level must reject the very next \
         request on the same token, not after the 15-minute access-token TTL"
    );
}
