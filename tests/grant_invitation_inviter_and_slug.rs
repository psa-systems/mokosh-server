//! PMS-1499: `InvitationMetadata` carries the inviter display name,
//! and every `InvitationResponse` shape carries the granted tenant's
//! slug. Both are resolved server-side with one join each; a lookup
//! that cannot find the inviter / tenant row leaves the field `None`.

mod common;

use mokosh_test::mokosh_test;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

/// Seed a user row with a known `bunyip_user_id` + display name so the
/// by-token GET resolves the inviter.
async fn seed_bunyip_user(
    pool: &PgPool,
    tenant_id: Uuid,
    bunyip_user_id: Uuid,
    first: &str,
    last: &str,
    email: &str,
) {
    sqlx::query(
        "INSERT INTO users (id, tenant_id, email, password_hash, \
             first_name, last_name, role, status, email_verified_at, bunyip_user_id) \
         VALUES ($1, $2, $3, 'x', $4, $5, 'admin', 'active', NOW(), $6)",
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(email)
    .bind(first)
    .bind(last)
    .bind(bunyip_user_id)
    .execute(pool)
    .await
    .expect("seed bunyip-linked user");
}

async fn seed_tenant_with_slug(pool: &PgPool, slug: &str, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, status, kind) \
         VALUES ($1, $2, $3, 'active', 'org')",
    )
    .bind(id)
    .bind(name)
    .bind(slug)
    .execute(pool)
    .await
    .expect("seed tenant");
    id
}

/// Insert a grant-invitation row by hand, bypassing the create handler
/// (the handler fetches a bunyip-side user by email, which this test
/// does not want to stub). Returns the plaintext accept token.
async fn insert_invitation(
    pool: &PgPool,
    tenant_id: Uuid,
    inviter_bunyip_user_id: Uuid,
    invitee_email: &str,
) -> (Uuid, String) {
    use mokosh_server::modules::auth::grant_invitations::{GrantInvitationsService, DEFAULT_TTL};
    let created = GrantInvitationsService::create(
        pool,
        tenant_id,
        inviter_bunyip_user_id,
        None,
        invitee_email,
        "admin",
        DEFAULT_TTL,
    )
    .await
    .expect("create invitation row");
    (created.invitation.id, created.accept_token)
}

#[mokosh_test]
async fn by_token_response_carries_inviter_name_when_user_resolves(pool: PgPool) {
    let tenant_id = seed_tenant_with_slug(&pool, "acme-pms1499", "Acme PMS-1499").await;
    let inviter_bunyip = Uuid::new_v4();
    seed_bunyip_user(
        &pool,
        tenant_id,
        inviter_bunyip,
        "Alice",
        "Carter",
        "alice@acme.test",
    )
    .await;
    let (_id, token) = insert_invitation(&pool, tenant_id, inviter_bunyip, "bob@example.com").await;

    let app = common::boot(pool.clone()).await;
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/grants/invitations/by-token/{token}")))
        .send()
        .await
        .expect("by-token GET");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: Value = resp.json().await.expect("body");
    assert_eq!(body["mokosh_account_slug"].as_str(), Some("acme-pms1499"));
    assert_eq!(body["inviter_name"].as_str(), Some("Alice Carter"));
}

#[mokosh_test]
async fn by_token_response_omits_inviter_name_when_lookup_misses(pool: PgPool) {
    let tenant_id = seed_tenant_with_slug(&pool, "acme-noinviter", "Acme No-Inviter").await;
    let inviter_bunyip = Uuid::new_v4(); // never seeded on `users`
    let (_id, token) = insert_invitation(&pool, tenant_id, inviter_bunyip, "bob@example.com").await;

    let app = common::boot(pool.clone()).await;
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/grants/invitations/by-token/{token}")))
        .send()
        .await
        .expect("by-token GET");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: Value = resp.json().await.expect("body");
    // The field is `skip_serializing_if = "Option::is_none"`, so an
    // unresolved inviter means the key is absent, not null.
    assert!(
        body.get("inviter_name").is_none(),
        "unresolved inviter must omit the key, not emit null: {body}"
    );
    // The tenant slug is still present.
    assert_eq!(body["mokosh_account_slug"].as_str(), Some("acme-noinviter"));
}

#[mokosh_test]
async fn owner_outbox_rows_carry_tenant_slug(pool: PgPool) {
    let (admin_bunyip, admin_email, admin_pw) = common::seed_admin(&pool).await;
    // The admin's own tenant: look its slug up for the assertion.
    let admin_tenant: Uuid = sqlx::query_scalar("SELECT tenant_id FROM users WHERE id = $1")
        .bind(admin_bunyip)
        .fetch_one(&pool)
        .await
        .expect("admin tenant_id");
    let slug: String = sqlx::query_scalar("SELECT slug FROM tenants WHERE id = $1")
        .bind(admin_tenant)
        .fetch_one(&pool)
        .await
        .expect("admin tenant slug");
    // Insert an invitation row by hand (bypasses the directory stub).
    insert_invitation(&pool, admin_tenant, admin_bunyip, "pms1499@example.com").await;

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &admin_email, &admin_pw).await;
    let resp = app
        .client
        .get(app.url("/api/v1/grants/invitations"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list outbox");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let rows: Vec<Value> = resp.json().await.expect("rows");
    assert_eq!(
        rows.len(),
        1,
        "exactly one invitation seeded for this tenant"
    );
    assert_eq!(
        rows[0]["tenant_slug"].as_str(),
        Some(slug.as_str()),
        "owner outbox row must carry tenant_slug per PMS-1499"
    );
}

#[mokosh_test]
async fn create_response_carries_tenant_slug(pool: PgPool) {
    let (_admin_bunyip, admin_email, admin_pw) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &admin_email, &admin_pw).await;

    let resp = app
        .client
        .post(app.url("/api/v1/grants/invitations"))
        .bearer_auth(&token)
        .json(&json!({
            "invitee_email": "pms1499-create@example.com",
            "role": "admin",
        }))
        .send()
        .await
        .expect("create invitation");
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);
    let body: Value = resp.json().await.expect("body");
    assert!(
        body["tenant_slug"].as_str().is_some(),
        "create response must carry tenant_slug per PMS-1499: {body}"
    );
}
