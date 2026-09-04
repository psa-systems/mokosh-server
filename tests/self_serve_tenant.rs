//! MAPPS-493 (MAPPS-474 phase 4): self-serve tenant creation.
//!
//! The phase-3 `needs_setup` login branch hands the SPA a short-lived
//! identity_token when the identity holds zero memberships. This test
//! suite pins the `/api/v1/tenants/self-serve` handler that redeems it:
//! creates a fresh org with the identity as admin and returns a full
//! scoped session.

mod common;

use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

async fn insert_identity_no_membership(pool: &PgPool, email: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash =
        mokosh_server::utils::crypto::hash_password("test-password-12345").expect("hash test pw");
    sqlx::query(
        "INSERT INTO identities \
         (id, email, password_hash, first_name, last_name, status, email_verified_at) \
         VALUES ($1, $2, $3, 'First', 'Last', 'active', NOW())",
    )
    .bind(id)
    .bind(email)
    .bind(&hash)
    .execute(pool)
    .await
    .expect("insert identity");
    id
}

async fn identity_token_via_login(app: &common::TestApp, email: &str, password: &str) -> String {
    let resp = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .json(&serde_json::json!({ "email": email, "password": password }))
        .send()
        .await
        .expect("send login");
    let body: Value = resp.json().await.expect("login json");
    body["identity_token"]
        .as_str()
        .expect("identity_token in needs_setup response")
        .to_string()
}

async fn post_self_serve(app: &common::TestApp, body: Value) -> reqwest::Response {
    app.client
        .post(app.url("/api/v1/tenants/self-serve"))
        .json(&body)
        .send()
        .await
        .expect("send self-serve")
}

#[sqlx::test]
async fn self_serve_creates_tenant_and_returns_full_session(pool: PgPool) {
    insert_identity_no_membership(&pool, "founder@example.com").await;
    let app = common::boot(pool).await;
    let identity_token =
        identity_token_via_login(&app, "founder@example.com", "test-password-12345").await;

    let resp = post_self_serve(
        &app,
        serde_json::json!({
            "identity_token": identity_token,
            "tenant_name": "Founder Co",
        }),
    )
    .await;
    assert!(
        resp.status().is_success(),
        "self-serve expected 2xx, got {}",
        resp.status()
    );
    let body: Value = resp.json().await.expect("json");

    assert!(!body["access_token"].as_str().unwrap().is_empty());
    assert!(!body["refresh_token"].as_str().unwrap().is_empty());
    assert!(body["user"].is_object());
    assert_eq!(
        body["user"]["email"].as_str().unwrap(),
        "founder@example.com"
    );
    assert_eq!(body["user"]["role"].as_str().unwrap(), "admin");
    assert_eq!(body["needs_selection"], false);
    assert_eq!(body["needs_setup"], false);
}

#[sqlx::test]
async fn self_serve_refuses_when_identity_already_has_membership(pool: PgPool) {
    // The seeded admin identity already holds the default-tenant
    // membership. A stale needs_setup identity_token (or a caller who
    // forged one for a placed identity) must be refused with 409.
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;

    // Get an identity_token by triggering the picker branch. seed_admin has
    // exactly one membership so a plain login auto-scopes; the picker branch
    // needs multiple memberships. Instead, mint the token directly via the
    // (already tested) select-tenant path proxy: log in with a second
    // membership to force picker mode.
    let other_tenant = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, kind, status) \
         VALUES ($1, 'Other', 'other-p4', 'org', 'active')",
    )
    .bind(other_tenant)
    .execute(&app.pool)
    .await
    .expect("insert 2nd tenant");
    let hash = mokosh_server::utils::crypto::hash_password(&password).expect("hash pw");
    sqlx::query(
        "INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, role, status, email_verified_at) \
         VALUES ($1, $2, $3, $4, 'First', 'Last', 'admin', 'active', NOW())",
    )
    .bind(uuid::Uuid::new_v4())
    .bind(other_tenant)
    .bind(&email)
    .bind(&hash)
    .execute(&app.pool)
    .await
    .expect("insert 2nd user");
    let identity_token = identity_token_via_login(&app, &email, &password).await;

    let resp = post_self_serve(
        &app,
        serde_json::json!({
            "identity_token": identity_token,
            "tenant_name": "Should Be Rejected",
        }),
    )
    .await;
    assert_eq!(resp.status(), reqwest::StatusCode::CONFLICT);
}

#[sqlx::test]
async fn self_serve_rejects_expired_or_wrong_type_token(pool: PgPool) {
    let app = common::boot(pool).await;

    let resp = post_self_serve(
        &app,
        serde_json::json!({
            "identity_token": "not-a-real-jwt",
            "tenant_name": "Whatever",
        }),
    )
    .await;
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[sqlx::test]
async fn self_serve_slug_collision_returns_409(pool: PgPool) {
    // Seed a tenant that already owns the slug "founder-co", then run
    // self-serve with a name that slugifies to the same value.
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, kind, status) \
         VALUES ($1, 'Existing', 'founder-co', 'org', 'active')",
    )
    .bind(uuid::Uuid::new_v4())
    .execute(&pool)
    .await
    .expect("seed existing tenant");
    insert_identity_no_membership(&pool, "founder@example.com").await;
    let app = common::boot(pool).await;
    let identity_token =
        identity_token_via_login(&app, "founder@example.com", "test-password-12345").await;

    let resp = post_self_serve(
        &app,
        serde_json::json!({
            "identity_token": identity_token,
            "tenant_name": "Founder Co",
        }),
    )
    .await;
    assert_eq!(resp.status(), reqwest::StatusCode::CONFLICT);
}

#[sqlx::test]
async fn self_serve_accepts_explicit_slug_and_uses_it(pool: PgPool) {
    insert_identity_no_membership(&pool, "founder@example.com").await;
    let app = common::boot(pool).await;
    let identity_token =
        identity_token_via_login(&app, "founder@example.com", "test-password-12345").await;

    let resp = post_self_serve(
        &app,
        serde_json::json!({
            "identity_token": identity_token,
            "tenant_name": "Founder Co",
            "tenant_slug": "custom-slug-mapps493",
        }),
    )
    .await;
    assert!(
        resp.status().is_success(),
        "expected 2xx, got {}",
        resp.status()
    );

    // Confirm the tenant landed with the explicit slug.
    let slug: String = sqlx::query_scalar("SELECT slug FROM tenants WHERE lower(name) = lower($1)")
        .bind("Founder Co")
        .fetch_one(&app.pool)
        .await
        .expect("read slug");
    assert_eq!(slug, "custom-slug-mapps493");
}

#[sqlx::test]
async fn self_serve_membership_appears_immediately(pool: PgPool) {
    // After a self-serve create, calling /auth/memberships with the fresh
    // session token must return the new tenant right away (no re-login).
    insert_identity_no_membership(&pool, "founder@example.com").await;
    let app = common::boot(pool).await;
    let identity_token =
        identity_token_via_login(&app, "founder@example.com", "test-password-12345").await;

    let create_resp: Value = post_self_serve(
        &app,
        serde_json::json!({
            "identity_token": identity_token,
            "tenant_name": "Founder Co",
        }),
    )
    .await
    .json()
    .await
    .expect("json");
    let access = create_resp["access_token"].as_str().unwrap().to_string();

    let memberships: Vec<Value> = app
        .client
        .get(app.url("/api/v1/auth/memberships"))
        .bearer_auth(&access)
        .send()
        .await
        .expect("send /memberships")
        .json()
        .await
        .expect("json");
    assert_eq!(memberships.len(), 1);
    assert_eq!(memberships[0]["is_active"].as_bool(), Some(true));
    assert_eq!(memberships[0]["role"].as_str().unwrap(), "admin");
}
