//! PMS-1500: id-scoped accept/decline for the grantee inbox. The
//! inbox returns rows without the plaintext accept token (by design,
//! the plaintext is only ever handed back once on the create response),
//! so the SPA's `TenantSwitcher` needs a path that acts on `id` + an
//! authenticated caller. These tests pin the four cases the id-scoped
//! handlers must satisfy: the grantee accepts, a foreign caller cannot,
//! an expired invitation 410s, and a double accept 409s.

mod common;

use mokosh_test::mokosh_test;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use mokosh_server::modules::auth::grant_invitations::{GrantInvitationsService, DEFAULT_TTL};

async fn seed_tenant(pool: &PgPool, slug: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, status, kind) \
         VALUES ($1, $2, $3, 'active', 'org')",
    )
    .bind(id)
    .bind(format!("Tenant {slug}"))
    .bind(slug)
    .execute(pool)
    .await
    .expect("seed tenant");
    id
}

async fn seed_bunyip_user(
    pool: &PgPool,
    tenant_id: Uuid,
    bunyip_user_id: Uuid,
    email: &str,
    password: &str,
) -> Uuid {
    let password_hash = mokosh_server::utils::crypto::hash_password(password)
        .await
        .expect("hash password");
    let user_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, tenant_id, email, password_hash, \
             first_name, last_name, role, status, email_verified_at, bunyip_user_id) \
         VALUES ($1, $2, $3, $4, 'Test', 'User', 'admin', 'active', NOW(), $5)",
    )
    .bind(user_id)
    .bind(tenant_id)
    .bind(email)
    .bind(&password_hash)
    .bind(bunyip_user_id)
    .execute(pool)
    .await
    .expect("seed user");
    user_id
}

async fn create_invitation(
    pool: &PgPool,
    tenant_id: Uuid,
    inviter: Uuid,
    invitee_bunyip: Option<Uuid>,
    invitee_email: &str,
) -> Uuid {
    let created = GrantInvitationsService::create(
        pool,
        tenant_id,
        inviter,
        invitee_bunyip,
        invitee_email,
        "admin",
        DEFAULT_TTL,
    )
    .await
    .expect("create invitation");
    created.invitation.id
}

#[mokosh_test]
async fn authenticated_grantee_accepts_their_own_invitation_by_id(pool: PgPool) {
    let owner_tenant = seed_tenant(&pool, "pms1500-owner").await;
    let grantee_tenant = seed_tenant(&pool, "pms1500-grantee").await;
    let inviter = Uuid::new_v4();
    let grantee_bunyip = Uuid::new_v4();
    seed_bunyip_user(
        &pool,
        grantee_tenant,
        grantee_bunyip,
        "grantee-id@example.com",
        "pw-pms1500-01",
    )
    .await;
    let invitation_id =
        create_invitation(&pool, owner_tenant, inviter, Some(grantee_bunyip), "grantee-id@example.com").await;

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, "grantee-id@example.com", "pw-pms1500-01").await;

    let resp = app
        .client
        .post(app.url(&format!(
            "/api/v1/my-grants/invitations/{invitation_id}/accept"
        )))
        .bearer_auth(&token)
        .send()
        .await
        .expect("accept by id");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: Value = resp.json().await.expect("body");
    assert_eq!(body["status"].as_str(), Some("accepted"));
    assert_eq!(body["tenant_slug"].as_str(), Some("pms1500-owner"));
}

#[mokosh_test]
async fn a_different_user_cannot_accept_someone_elses_invitation(pool: PgPool) {
    let owner_tenant = seed_tenant(&pool, "pms1500-foreign-owner").await;
    let user_tenant = seed_tenant(&pool, "pms1500-foreign-user").await;
    let inviter = Uuid::new_v4();
    let intended_grantee = Uuid::new_v4();
    let foreign_user = Uuid::new_v4();
    seed_bunyip_user(
        &pool,
        user_tenant,
        foreign_user,
        "foreign@example.com",
        "pw-pms1500-02",
    )
    .await;
    let invitation_id = create_invitation(
        &pool,
        owner_tenant,
        inviter,
        Some(intended_grantee),
        "intended@example.com",
    )
    .await;

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, "foreign@example.com", "pw-pms1500-02").await;

    let resp = app
        .client
        .post(app.url(&format!(
            "/api/v1/my-grants/invitations/{invitation_id}/accept"
        )))
        .bearer_auth(&token)
        .send()
        .await
        .expect("foreign accept");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::NOT_FOUND,
        "a foreign caller must see 404, not 403 - the invitation's existence is not information the caller is entitled to"
    );
}

#[mokosh_test]
async fn an_expired_invitation_410s_on_the_id_path(pool: PgPool) {
    let owner_tenant = seed_tenant(&pool, "pms1500-expired-owner").await;
    let grantee_tenant = seed_tenant(&pool, "pms1500-expired-grantee").await;
    let inviter = Uuid::new_v4();
    let grantee_bunyip = Uuid::new_v4();
    seed_bunyip_user(
        &pool,
        grantee_tenant,
        grantee_bunyip,
        "expired-grantee@example.com",
        "pw-pms1500-03",
    )
    .await;
    let invitation_id = create_invitation(
        &pool,
        owner_tenant,
        inviter,
        Some(grantee_bunyip),
        "expired-grantee@example.com",
    )
    .await;
    // Backdate `expires_at` so the next accept is past it.
    sqlx::query("UPDATE mokosh_grant_invitations SET expires_at = NOW() - INTERVAL '1 hour' WHERE id = $1")
        .bind(invitation_id)
        .execute(&pool)
        .await
        .expect("backdate expiry");

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, "expired-grantee@example.com", "pw-pms1500-03").await;

    let resp = app
        .client
        .post(app.url(&format!(
            "/api/v1/my-grants/invitations/{invitation_id}/accept"
        )))
        .bearer_auth(&token)
        .send()
        .await
        .expect("expired accept");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::GONE,
        "an expired invitation must 410 on both the by-token and the id paths"
    );
}

#[mokosh_test]
async fn a_declined_invitation_cannot_be_re_accepted(pool: PgPool) {
    let owner_tenant = seed_tenant(&pool, "pms1500-double-owner").await;
    let grantee_tenant = seed_tenant(&pool, "pms1500-double-grantee").await;
    let inviter = Uuid::new_v4();
    let grantee_bunyip = Uuid::new_v4();
    seed_bunyip_user(
        &pool,
        grantee_tenant,
        grantee_bunyip,
        "double-grantee@example.com",
        "pw-pms1500-04",
    )
    .await;
    let invitation_id = create_invitation(
        &pool,
        owner_tenant,
        inviter,
        Some(grantee_bunyip),
        "double-grantee@example.com",
    )
    .await;

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, "double-grantee@example.com", "pw-pms1500-04").await;

    let decline = app
        .client
        .post(app.url(&format!(
            "/api/v1/my-grants/invitations/{invitation_id}/decline"
        )))
        .bearer_auth(&token)
        .send()
        .await
        .expect("decline");
    assert_eq!(decline.status(), reqwest::StatusCode::OK);

    let accept = app
        .client
        .post(app.url(&format!(
            "/api/v1/my-grants/invitations/{invitation_id}/accept"
        )))
        .bearer_auth(&token)
        .send()
        .await
        .expect("re-accept");
    assert_eq!(
        accept.status(),
        reqwest::StatusCode::CONFLICT,
        "a declined invitation cannot be re-accepted on either path"
    );
}
