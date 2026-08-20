//! MAPPS-492 (MAPPS-474 phase 3): email-only login + tenant picker.
//!
//! - Login with no tenant hint auto-scopes when the identity has one
//!   membership.
//! - Same call returns `needs_selection` + identity_token when the
//!   identity has more than one, and `needs_setup` when zero.
//! - The `/auth/select-tenant` handler consumes the identity_token +
//!   chosen tenant_id and returns a full session, plus the expected
//!   400/404/401 error surface.

mod common;

use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

async fn insert_tenant(pool: &PgPool, name: &str, slug: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, kind, status) \
         VALUES ($1, $2, $3, 'org', 'active')",
    )
    .bind(id)
    .bind(name)
    .bind(slug)
    .execute(pool)
    .await
    .expect("insert tenant");
    id
}

async fn insert_user_row(pool: &PgPool, tenant_id: Uuid, email: &str, role: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash =
        mokosh_server::utils::crypto::hash_password("test-password-12345").expect("hash test pw");
    sqlx::query(
        "INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, role, status, email_verified_at) \
         VALUES ($1, $2, $3, $4, 'First', 'Last', $5, 'active', NOW())",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(email)
    .bind(&hash)
    .bind(role)
    .execute(pool)
    .await
    .expect("insert user");
    id
}

async fn insert_identity_no_membership(pool: &PgPool, email: &str) -> Uuid {
    // The dual-write trigger only fires from `users`. Insert directly
    // into `identities` to model the zero-membership case (the phase-4
    // create-org flow will attach one).
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

async fn post_login(app: &common::TestApp, body: Value) -> reqwest::Response {
    app.client
        .post(app.url("/api/v1/auth/login"))
        .json(&body)
        .send()
        .await
        .expect("send login")
}

async fn post_select_tenant(app: &common::TestApp, body: Value) -> reqwest::Response {
    app.client
        .post(app.url("/api/v1/auth/select-tenant"))
        .json(&body)
        .send()
        .await
        .expect("send select-tenant")
}

#[sqlx::test]
async fn email_only_login_with_single_membership_auto_scopes(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;

    let resp = post_login(
        &app,
        serde_json::json!({ "email": email, "password": password }),
    )
    .await;
    assert!(
        resp.status().is_success(),
        "login expected 2xx, got {}",
        resp.status()
    );
    let body: Value = resp.json().await.expect("json");

    assert!(!body["access_token"].as_str().unwrap().is_empty());
    assert!(!body["refresh_token"].as_str().unwrap().is_empty());
    assert_eq!(
        body["needs_selection"], false,
        "single membership auto-scopes"
    );
    assert_eq!(body["needs_setup"], false);
    assert!(body["identity_token"].is_null());
    assert!(body["user"].is_object(), "user profile returned");
}

#[sqlx::test]
async fn email_only_login_with_multiple_memberships_returns_picker(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let other_tenant = insert_tenant(&pool, "Second Tenant", "second-mapps492").await;
    insert_user_row(&pool, other_tenant, &email, "manager").await;
    let app = common::boot(pool).await;

    let resp = post_login(
        &app,
        serde_json::json!({ "email": email, "password": password }),
    )
    .await;
    assert!(
        resp.status().is_success(),
        "login expected 2xx, got {}",
        resp.status()
    );
    let body: Value = resp.json().await.expect("json");

    assert_eq!(body["needs_selection"], true);
    assert_eq!(body["needs_setup"], false);
    assert!(body["access_token"].as_str().unwrap().is_empty());
    assert!(body["refresh_token"].as_str().unwrap().is_empty());
    assert!(body["identity_token"].as_str().is_some());
    let mems = body["memberships"].as_array().expect("memberships array");
    assert_eq!(mems.len(), 2);
    assert!(body["user"].is_null());
}

#[sqlx::test]
async fn email_only_login_with_zero_memberships_returns_needs_setup(pool: PgPool) {
    insert_identity_no_membership(&pool, "orphan@example.com").await;
    let app = common::boot(pool).await;

    let resp = post_login(
        &app,
        serde_json::json!({
            "email": "orphan@example.com",
            "password": "test-password-12345",
        }),
    )
    .await;
    assert!(
        resp.status().is_success(),
        "login expected 2xx, got {}",
        resp.status()
    );
    let body: Value = resp.json().await.expect("json");

    assert_eq!(body["needs_setup"], true);
    assert_eq!(body["needs_selection"], false);
    assert!(body["identity_token"].as_str().is_some());
    assert!(body["access_token"].as_str().unwrap().is_empty());
    assert!(body["memberships"].is_null());
    assert!(body["user"].is_null());
}

#[sqlx::test]
async fn email_only_login_with_wrong_password_returns_401(pool: PgPool) {
    let (_admin_id, email, _password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;

    let resp = post_login(
        &app,
        serde_json::json!({ "email": email, "password": "wrong-password" }),
    )
    .await;
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[sqlx::test]
async fn select_tenant_with_valid_identity_token_returns_session(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let other_tenant = insert_tenant(&pool, "Second Tenant", "second-mapps492").await;
    insert_user_row(&pool, other_tenant, &email, "manager").await;
    let app = common::boot(pool).await;

    // Step 1: get identity_token via picker branch.
    let login: Value = post_login(
        &app,
        serde_json::json!({ "email": email, "password": password }),
    )
    .await
    .json()
    .await
    .expect("login json");
    let identity_token = login["identity_token"]
        .as_str()
        .expect("identity_token")
        .to_string();

    // Step 2: pick the second tenant.
    let resp = post_select_tenant(
        &app,
        serde_json::json!({
            "identity_token": identity_token,
            "tenant_id": other_tenant.to_string(),
        }),
    )
    .await;
    assert!(
        resp.status().is_success(),
        "select-tenant expected 2xx, got {}",
        resp.status()
    );
    let body: Value = resp.json().await.expect("json");

    assert!(!body["access_token"].as_str().unwrap().is_empty());
    assert_eq!(
        body["user"]["tenant_id"].as_str().unwrap(),
        other_tenant.to_string()
    );
    assert_eq!(body["needs_selection"], false);
    assert_eq!(body["needs_setup"], false);
}

#[sqlx::test]
async fn select_tenant_with_wrong_tenant_returns_404(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    // Force a picker branch so we get an identity_token.
    let other_tenant = insert_tenant(&pool, "Second Tenant", "second-mapps492").await;
    insert_user_row(&pool, other_tenant, &email, "manager").await;
    let app = common::boot(pool).await;

    let login: Value = post_login(
        &app,
        serde_json::json!({ "email": email, "password": password }),
    )
    .await
    .json()
    .await
    .expect("json");
    let identity_token = login["identity_token"].as_str().unwrap().to_string();

    let stranger_tenant = Uuid::new_v4();
    let resp = post_select_tenant(
        &app,
        serde_json::json!({
            "identity_token": identity_token,
            "tenant_id": stranger_tenant.to_string(),
        }),
    )
    .await;
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
}

#[sqlx::test]
async fn select_tenant_with_bogus_token_returns_401(pool: PgPool) {
    let app = common::boot(pool).await;
    let resp = post_select_tenant(
        &app,
        serde_json::json!({
            "identity_token": "not-a-real-jwt",
            "tenant_id": Uuid::new_v4().to_string(),
        }),
    )
    .await;
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[sqlx::test]
async fn tenant_hint_login_still_works_unchanged(pool: PgPool) {
    // Existing shape: caller supplies tenant_slug -> tenant-hint path
    // runs, identity-first is not entered. Guards the compat contract
    // of MAPPS-492 (see phase-3 spec: existing tests keep passing).
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;

    let resp = post_login(
        &app,
        serde_json::json!({
            "email": email,
            "password": password,
            "tenant_slug": "default",
        }),
    )
    .await;
    assert!(resp.status().is_success());
    let body: Value = resp.json().await.expect("json");
    assert!(!body["access_token"].as_str().unwrap().is_empty());
}
