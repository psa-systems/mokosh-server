//! MAPPS-494 (MAPPS-474 phase 5): in-app tenant switcher server side.
//!
//! - `POST /api/v1/auth/switch-tenant/:tenant_id` re-mints a session
//!   for another tenant the identity holds a membership in.
//! - `POST /api/v1/tenants/additional` lets an authenticated caller
//!   create a new organization + become its admin.

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

async fn insert_user_row(
    pool: &PgPool,
    tenant_id: Uuid,
    email: &str,
    password: &str,
    role: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    let hash = mokosh_server::utils::crypto::hash_password(password).expect("hash pw");
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

/// Log the seeded admin in and return an access token scoped to the
/// default tenant. Uses the tenant-hint path so the token maps to the
/// default tenant regardless of any additional memberships the identity
/// may hold (which would otherwise force the picker branch).
async fn login_via_default_tenant(app: &common::TestApp, email: &str, password: &str) -> String {
    let resp = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .json(&serde_json::json!({
            "email": email,
            "password": password,
            "tenant_slug": "default",
        }))
        .send()
        .await
        .expect("send login");
    assert!(
        resp.status().is_success(),
        "login expected 2xx, got {}",
        resp.status()
    );
    let body: Value = resp.json().await.expect("json");
    body["access_token"]
        .as_str()
        .expect("access_token")
        .to_string()
}

#[sqlx::test]
async fn switch_tenant_returns_new_session_scoped_to_the_target(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let other_tenant = insert_tenant(&pool, "Other Co", "other-mapps494").await;
    insert_user_row(&pool, other_tenant, &email, &password, "manager").await;
    let app = common::boot(pool).await;
    let bearer = login_via_default_tenant(&app, &email, &password).await;

    let resp = app
        .client
        .post(app.url(&format!("/api/v1/auth/switch-tenant/{other_tenant}")))
        .bearer_auth(&bearer)
        .send()
        .await
        .expect("send switch");
    assert!(
        resp.status().is_success(),
        "switch expected 2xx, got {}",
        resp.status()
    );
    let body: Value = resp.json().await.expect("json");

    assert!(!body["access_token"].as_str().unwrap().is_empty());
    assert_eq!(
        body["user"]["tenant_id"].as_str().unwrap(),
        other_tenant.to_string()
    );
    assert_eq!(body["user"]["role"].as_str().unwrap(), "manager");
    assert_eq!(body["needs_selection"], false);
    assert_eq!(body["needs_setup"], false);
}

#[sqlx::test]
async fn switch_tenant_to_stranger_tenant_returns_404(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let bearer = login_via_default_tenant(&app, &email, &password).await;

    let stranger = Uuid::new_v4();
    let resp = app
        .client
        .post(app.url(&format!("/api/v1/auth/switch-tenant/{stranger}")))
        .bearer_auth(&bearer)
        .send()
        .await
        .expect("send switch");
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
}

#[sqlx::test]
async fn switch_tenant_without_bearer_returns_401(pool: PgPool) {
    let app = common::boot(pool).await;
    let target = Uuid::new_v4();
    let resp = app
        .client
        .post(app.url(&format!("/api/v1/auth/switch-tenant/{target}")))
        .send()
        .await
        .expect("send switch");
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[sqlx::test]
async fn additional_tenant_creates_new_org_with_caller_as_admin(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let bearer = login_via_default_tenant(&app, &email, &password).await;

    let resp = app
        .client
        .post(app.url("/api/v1/tenants/additional"))
        .bearer_auth(&bearer)
        .json(&serde_json::json!({
            "tenant_name": "Second Org",
        }))
        .send()
        .await
        .expect("send additional");
    assert!(
        resp.status().is_success(),
        "additional expected 2xx, got {}",
        resp.status()
    );
    let body: Value = resp.json().await.expect("json");
    let new_tenant_id: Uuid = body["id"].as_str().unwrap().parse().expect("uuid");

    // Confirm membership appears immediately via /auth/memberships (both
    // the default tenant and the new one).
    let memberships: Vec<Value> = app
        .client
        .get(app.url("/api/v1/auth/memberships"))
        .bearer_auth(&bearer)
        .send()
        .await
        .expect("send memberships")
        .json()
        .await
        .expect("json");
    assert_eq!(memberships.len(), 2);
    let has_new = memberships.iter().any(|m| {
        m["tenant_id"].as_str().unwrap() == new_tenant_id.to_string() && m["role"] == "admin"
    });
    assert!(has_new, "new tenant appears as admin membership");
}

#[sqlx::test]
async fn additional_tenant_without_bearer_returns_401(pool: PgPool) {
    let app = common::boot(pool).await;
    let resp = app
        .client
        .post(app.url("/api/v1/tenants/additional"))
        .json(&serde_json::json!({ "tenant_name": "Anywhere" }))
        .send()
        .await
        .expect("send additional");
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[sqlx::test]
async fn additional_tenant_slug_collision_returns_409(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    insert_tenant(&pool, "Existing", "second-org-taken").await;
    let app = common::boot(pool).await;
    let bearer = login_via_default_tenant(&app, &email, &password).await;

    let resp = app
        .client
        .post(app.url("/api/v1/tenants/additional"))
        .bearer_auth(&bearer)
        .json(&serde_json::json!({
            "tenant_name": "Anywhere",
            "tenant_slug": "second-org-taken",
        }))
        .send()
        .await
        .expect("send additional");
    assert_eq!(resp.status(), reqwest::StatusCode::CONFLICT);
}

#[sqlx::test]
async fn switch_then_switch_back_yields_two_working_sessions(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let other_tenant = insert_tenant(&pool, "Other Co", "other-mapps494").await;
    insert_user_row(&pool, other_tenant, &email, &password, "admin").await;
    let app = common::boot(pool).await;
    let bearer_default = login_via_default_tenant(&app, &email, &password).await;

    // Switch to other tenant.
    let switch1: Value = app
        .client
        .post(app.url(&format!("/api/v1/auth/switch-tenant/{other_tenant}")))
        .bearer_auth(&bearer_default)
        .send()
        .await
        .expect("send switch")
        .json()
        .await
        .expect("json");
    let bearer_other = switch1["access_token"].as_str().unwrap().to_string();

    // Switch back to default.
    let switch2: Value = app
        .client
        .post(app.url(&format!(
            "/api/v1/auth/switch-tenant/{}",
            common::DEFAULT_TENANT_ID
        )))
        .bearer_auth(&bearer_other)
        .send()
        .await
        .expect("send switch back")
        .json()
        .await
        .expect("json");
    let bearer_default_again = switch2["access_token"].as_str().unwrap().to_string();

    // The `user` field on the switch response IS a CurrentUser, which
    // carries tenant_id. Confirms the second switch scoped to the
    // default tenant and returned a working bearer.
    assert_eq!(
        switch2["user"]["tenant_id"].as_str().unwrap(),
        common::DEFAULT_TENANT_ID.to_string()
    );
    // And the second bearer authorizes a /memberships call (arbitrary
    // authenticated endpoint) - proves the token verifies.
    let resp = app
        .client
        .get(app.url("/api/v1/auth/memberships"))
        .bearer_auth(&bearer_default_again)
        .send()
        .await
        .expect("send /memberships");
    assert!(resp.status().is_success(), "second bearer authorizes");
}
