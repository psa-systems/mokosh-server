//! MAPPS-491 (MAPPS-474 phase 2): `GET /api/v1/auth/memberships` +
//! JwtClaims.mid + AuthState identity-plane enrichment.
//!
//! Covers the wire path the client's `use_memberships_loader`
//! (mokosh-apps/src/hooks/auth.rs:299) already calls, plus the
//! legacy-token fallback path (a pre-phase-2 token with no `mid`
//! claim still resolves the active membership via
//! `(email, tenant_id)` lookup so no rolling-deploy 401 storm).

mod common;

use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use mokosh_types::auth::JwtClaims;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

const TEST_JWT_SECRET: &str = "test-jwt-secret-that-is-clearly-not-for-prod";

/// Mint a legacy-shape access token (no `mid` claim) using the same HS256
/// secret the test router boots with. Simulates a token issued before
/// phase 2 lands.
fn mint_legacy_access_token(
    user_id: Uuid,
    tenant_id: Uuid,
    email: &str,
    session_id: Uuid,
) -> String {
    let now = Utc::now();
    let claims = JwtClaims {
        sub: user_id,
        tid: tenant_id,
        email: email.to_string(),
        role: mokosh_types::auth::UserRole::SuperAdmin,
        iat: now.timestamp(),
        nbf: now.timestamp(),
        exp: (now + Duration::hours(1)).timestamp(),
        iss: String::new(),
        aud: String::new(),
        typ: "access".to_string(),
        sid: session_id,
        mid: None,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(TEST_JWT_SECRET.as_bytes()),
    )
    .expect("mint legacy JWT")
}

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
    .expect("insert tenants row");
    id
}

async fn insert_user_row(pool: &PgPool, tenant_id: Uuid, email: &str, role: &str) -> Uuid {
    let id = Uuid::new_v4();
    let password_hash = mokosh_server::utils::crypto::hash_password("test-password-12345")
        .expect("hash test password");
    sqlx::query(
        "INSERT INTO users \
         (id, tenant_id, email, password_hash, first_name, last_name, role, status, email_verified_at) \
         VALUES ($1, $2, $3, $4, 'First', 'Last', $5, 'active', NOW())",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(email)
    .bind(&password_hash)
    .bind(role)
    .execute(pool)
    .await
    .expect("insert user row");
    id
}

#[sqlx::test]
async fn me_memberships_returns_the_admin_membership(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let body: Vec<Value> = app
        .client
        .get(app.url("/api/v1/auth/memberships"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send /memberships")
        .json()
        .await
        .expect("/memberships json");

    assert_eq!(body.len(), 1, "one seeded membership expected");
    let m = &body[0];
    assert_eq!(
        m["tenant_id"].as_str().unwrap(),
        common::DEFAULT_TENANT_ID.to_string()
    );
    assert_eq!(m["role"].as_str().unwrap(), "super_admin");
    assert_eq!(m["status"].as_str().unwrap(), "active");
    assert_eq!(
        m["is_active"].as_bool(),
        Some(true),
        "current tenant flagged"
    );
    assert!(m["tenant_name"].as_str().is_some());
    assert!(m["tenant_slug"].as_str().is_some());
}

#[sqlx::test]
async fn me_memberships_returns_every_active_membership_for_the_identity(pool: PgPool) {
    // Same email in two tenants -> phase-1 trigger collapses to one
    // identity with two memberships. /memberships must return both.
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let other_tenant = insert_tenant(&pool, "Second Tenant", "second-mapps491").await;
    insert_user_row(&pool, other_tenant, &email, "manager").await;

    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let body: Vec<Value> = app
        .client
        .get(app.url("/api/v1/auth/memberships"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send /memberships")
        .json()
        .await
        .expect("/memberships json");

    assert_eq!(body.len(), 2, "identity has two memberships");
    let tenants: Vec<&str> = body
        .iter()
        .map(|m| m["tenant_id"].as_str().unwrap())
        .collect();
    let default_str = common::DEFAULT_TENANT_ID.to_string();
    let other_str = other_tenant.to_string();
    assert!(tenants.contains(&default_str.as_str()));
    assert!(tenants.contains(&other_str.as_str()));

    // Exactly one membership is flagged active: the one matching the
    // session's tenant scope (default tenant, because login used
    // tenant_slug="default").
    let active_count = body.iter().filter(|m| m["is_active"] == true).count();
    assert_eq!(active_count, 1);
    let active_tenant = body.iter().find(|m| m["is_active"] == true).unwrap();
    assert_eq!(active_tenant["tenant_id"].as_str().unwrap(), default_str);
}

#[sqlx::test]
async fn legacy_token_without_mid_still_authorizes_and_resolves_membership(pool: PgPool) {
    // Simulates a rolling deploy: a token minted before phase 2 (no
    // `mid` claim) must still authenticate. The middleware's enrich
    // pass fills the active membership via (email, tenant_id) lookup.
    let (admin_id, email, _password) = common::seed_admin(&pool).await;

    // Need a real session row: `ensure_user_and_tenant_active` accepts
    // any decoded access token whose sub + tid resolve, but the enrich
    // pass needs the identity/membership rows populated (phase-1
    // migration handles that).
    let app = common::boot(pool).await;
    let session_id = Uuid::new_v4();
    let legacy_token =
        mint_legacy_access_token(admin_id, common::DEFAULT_TENANT_ID, &email, session_id);

    let resp = app
        .client
        .get(app.url("/api/v1/auth/memberships"))
        .bearer_auth(&legacy_token)
        .send()
        .await
        .expect("send /memberships");
    assert!(
        resp.status().is_success(),
        "legacy token should authorize, got {}",
        resp.status()
    );
    let body: Vec<Value> = resp.json().await.expect("/memberships json");
    assert_eq!(body.len(), 1);
    assert_eq!(body[0]["is_active"].as_bool(), Some(true));
    assert_eq!(body[0]["role"].as_str().unwrap(), "super_admin");
}
