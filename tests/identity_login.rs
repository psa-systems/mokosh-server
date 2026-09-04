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

/// MAPPS-497 item 4 (PMS-502 identity extension): a TOTP step, once
/// accepted by the identity-first branch, cannot be replayed against
/// the same identity within its ~60s window. The second POST with the
/// same code must 401, matching how the tenant-hint MFA branch has
/// enforced anti-replay since PMS-502.
#[sqlx::test]
async fn identity_first_mfa_burns_totp_step(pool: PgPool) {
    // Seed a fresh identity with MFA enabled and a known secret so we
    // can compute a valid TOTP code deterministically via the same
    // helpers the server uses.
    let secret_bytes = [0x11u8; 20];
    let secret_b32 = mokosh_server::utils::totp::base32_encode(&secret_bytes);
    let identity_id = uuid::Uuid::new_v4();
    let email = "mfa-replay@example.com";
    let password = "test-password-12345";
    let hash = mokosh_server::utils::crypto::hash_password(password).expect("hash pw");
    sqlx::query(
        "INSERT INTO identities \
         (id, email, password_hash, first_name, last_name, status, email_verified_at, \
          mfa_enabled, mfa_secret) \
         VALUES ($1, $2, $3, 'First', 'Last', 'active', NOW(), TRUE, $4)",
    )
    .bind(identity_id)
    .bind(email)
    .bind(&hash)
    .bind(&secret_b32)
    .execute(&pool)
    .await
    .expect("insert identity");
    // Attach the identity to the default tenant so the login auto-scopes.
    let user_id = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, role, status, email_verified_at, mfa_enabled, mfa_secret) \
         VALUES ($1, $2, $3, $4, 'First', 'Last', 'technician', 'active', NOW(), TRUE, $5)",
    )
    .bind(user_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(email)
    .bind(&hash)
    .bind(&secret_b32)
    .execute(&pool)
    .await
    .expect("insert user");
    let app = common::boot(pool).await;

    let code = mokosh_server::utils::totp::code_at(&secret_bytes, chrono::Utc::now());

    // First attempt with the code: 2xx (auto-scoped session).
    let resp1 = post_login(
        &app,
        serde_json::json!({ "email": email, "password": password, "mfa_code": code }),
    )
    .await;
    assert!(
        resp1.status().is_success(),
        "first MFA attempt should succeed, got {}",
        resp1.status()
    );

    // Second attempt with the SAME code: must 401 (replay).
    let resp2 = post_login(
        &app,
        serde_json::json!({ "email": email, "password": password, "mfa_code": code }),
    )
    .await;
    assert_eq!(
        resp2.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "replay of the same TOTP code must be rejected"
    );
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

// MAPPS-551: identity-first login verifies against each membership's
// users.password_hash, not identities.password_hash. An identity with
// TWO memberships whose users rows carry DIFFERENT password hashes must
// auto-scope to the tenant whose users row password matches the caller's
// input, without a picker step and without asking the identity plane.
#[sqlx::test]
async fn identity_first_finds_the_matching_membership_when_hashes_diverged(pool: PgPool) {
    let email = "diverged@example.com".to_string();
    let password_a = "TENANT-A-PW-12345".to_string();
    let password_b = "TENANT-B-PW-67890".to_string();
    let hash_a = mokosh_server::utils::crypto::hash_password(&password_a).expect("hash A");
    let hash_b = mokosh_server::utils::crypto::hash_password(&password_b).expect("hash B");

    let tenant_a = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, kind, status) \
         VALUES ($1, 'A', 'a-mapps551', 'org', 'active')",
    )
    .bind(tenant_a)
    .execute(&pool)
    .await
    .expect("insert tenant a");
    let user_a = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, role, status, email_verified_at) \
         VALUES ($1, $2, $3, $4, 'A', 'Admin', 'admin', 'active', NOW())",
    )
    .bind(user_a)
    .bind(tenant_a)
    .bind(&email)
    .bind(&hash_a)
    .execute(&pool)
    .await
    .expect("insert user a");

    let tenant_b = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, kind, status) \
         VALUES ($1, 'B', 'b-mapps551', 'org', 'active')",
    )
    .bind(tenant_b)
    .execute(&pool)
    .await
    .expect("insert tenant b");
    let user_b = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, role, status, email_verified_at) \
         VALUES ($1, $2, $3, $4, 'B', 'Admin', 'admin', 'active', NOW())",
    )
    .bind(user_b)
    .bind(tenant_b)
    .bind(&email)
    .bind(&hash_b)
    .execute(&pool)
    .await
    .expect("insert user b");

    let app = common::boot(pool).await;

    // Login with password A: auto-scope to tenant A.
    let resp_a = post_login(
        &app,
        serde_json::json!({ "email": email, "password": password_a }),
    )
    .await;
    assert!(resp_a.status().is_success(), "got {}", resp_a.status());
    let body_a: Value = resp_a.json().await.expect("json a");
    assert_eq!(body_a["needs_selection"], false, "auto-scope to tenant A");
    assert_eq!(body_a["needs_setup"], false);
    assert_eq!(
        body_a["user"]["tenant_id"].as_str().unwrap(),
        tenant_a.to_string(),
        "MAPPS-551: password A auto-scoped to tenant A"
    );

    // Login with password B: auto-scope to tenant B.
    let resp_b = post_login(
        &app,
        serde_json::json!({ "email": email, "password": password_b }),
    )
    .await;
    assert!(resp_b.status().is_success(), "got {}", resp_b.status());
    let body_b: Value = resp_b.json().await.expect("json b");
    assert_eq!(
        body_b["user"]["tenant_id"].as_str().unwrap(),
        tenant_b.to_string(),
        "MAPPS-551: password B auto-scoped to tenant B"
    );
}
