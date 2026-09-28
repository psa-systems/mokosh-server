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
use mokosh_test::mokosh_test;
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

/// Insert the `user_sessions` row a hand-minted access token names in its
/// `sid`, mirroring the columns `AuthService::login` writes.
async fn insert_session_row(pool: &PgPool, session_id: Uuid, tenant_id: Uuid, user_id: Uuid) {
    sqlx::query(
        "INSERT INTO user_sessions (id, tenant_id, user_id, token_hash, expires_at) \
         VALUES ($1, $2, $3, 'legacy-token-test-hash', NOW() + INTERVAL '1 hour')",
    )
    .bind(session_id)
    .bind(tenant_id)
    .bind(user_id)
    .execute(pool)
    .await
    .expect("insert user_sessions row");
}

async fn insert_user_row(pool: &PgPool, tenant_id: Uuid, email: &str, role: &str) -> Uuid {
    let id = Uuid::new_v4();
    let password_hash = mokosh_server::utils::crypto::hash_password("test-password-12345")
        .await
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

#[mokosh_test]
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

#[mokosh_test]
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

#[mokosh_test]
async fn legacy_token_without_mid_still_authorizes_and_resolves_membership(pool: PgPool) {
    // Simulates a rolling deploy: a token minted before phase 2 (no
    // `mid` claim) must still authenticate. The middleware's enrich
    // pass fills the active membership via (email, tenant_id) lookup.
    let (admin_id, email, _password) = common::seed_admin(&pool).await;

    let app = common::boot(pool).await;
    let session_id = Uuid::new_v4();
    let legacy_token =
        mint_legacy_access_token(admin_id, common::DEFAULT_TENANT_ID, &email, session_id);

    // MAPPS-531: `ensure_user_and_tenant_active` refuses an access token whose
    // `sid` names no live `user_sessions` row, which is what makes a legacy
    // sign-out revoke the access token and not only the refresh. The legacy
    // claim shape is no exception, so assert that first: with no session row
    // the token is refused 403 even though sub + tid resolve.
    let refused = app
        .client
        .get(app.url("/api/v1/auth/memberships"))
        .bearer_auth(&legacy_token)
        .send()
        .await
        .expect("send /memberships with no session row");
    assert_eq!(
        refused.status(),
        reqwest::StatusCode::FORBIDDEN,
        "legacy token naming no session row must be refused"
    );

    // Seed the row the token names. MAPPS-531 requires it; the enrich pass
    // then fills the active membership from (email, tenant_id) because the
    // token carries no `mid` claim.
    insert_session_row(&app.pool, session_id, common::DEFAULT_TENANT_ID, admin_id).await;

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

/// PMS-1393: a seat that came from a grant carries the grant id, and the id is
/// the one `DELETE /api/v1/my-grants/{id}` accepts.
///
/// PMS-1210 shipped that endpoint keyed on `mokosh_bunyip_grants.id` and shipped
/// nothing on the wire that carried it, so this asserts the two halves agree
/// rather than asserting a field exists: the id the memberships list hands a
/// client is fed straight back as the path parameter, and the endpoint answers
/// 204 instead of the 404 it gives for an id that is not the caller's.
#[mokosh_test]
async fn a_granted_seat_carries_the_grant_id_the_leave_endpoint_accepts(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let granted_tenant = insert_tenant(&pool, "Granted Tenant", "granted-pms1393").await;
    let granted_user = insert_user_row(&pool, granted_tenant, &email, "manager").await;

    // The grant is keyed on (Bunyip sub, tenant SLUG), so the placement row in
    // the granted tenant has to name the same sub the caller's own row does:
    // migration 226 pinned `(bunyip_user_id, tenant_id)` unique precisely so one
    // human's placements across tenants share a sub.
    let sub = Uuid::new_v4();
    sqlx::query("UPDATE users SET bunyip_user_id = $1 WHERE id = ANY($2)")
        .bind(sub)
        .bind(vec![admin_id, granted_user])
        .execute(&pool)
        .await
        .expect("stamp the Bunyip sub on both placements");
    let grant_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO mokosh_bunyip_grants \
         (id, grantee_bunyip_user_id, owner_bunyip_user_id, mokosh_account_id, role) \
         VALUES ($1, $2, $3, 'granted-pms1393', 'manager')",
    )
    .bind(grant_id)
    .bind(sub)
    .bind(Uuid::new_v4())
    .execute(&pool)
    .await
    .expect("insert the grant row");

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
    assert_eq!(body.len(), 2, "own seat plus the granted one: {body:?}");

    let granted = body
        .iter()
        .find(|m| m["tenant_id"].as_str() == Some(granted_tenant.to_string().as_str()))
        .expect("the granted seat");
    assert_eq!(
        granted["mokosh_bunyip_grant_id"].as_str(),
        Some(grant_id.to_string().as_str()),
        "the granted seat names its grant"
    );
    let own = body
        .iter()
        .find(|m| m["tenant_id"].as_str() == Some(common::DEFAULT_TENANT_ID.to_string().as_str()))
        .expect("the own seat");
    assert!(
        own["mokosh_bunyip_grant_id"].is_null(),
        "a seat held in its own right has no grant to leave: {own:?}"
    );

    // The whole point: the id travels from the list into the endpoint.
    let left = app
        .client
        .delete(app.url(&format!(
            "/api/v1/my-grants/{}",
            granted["mokosh_bunyip_grant_id"].as_str().unwrap()
        )))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send the leave request");
    assert_eq!(
        left.status(),
        reqwest::StatusCode::NO_CONTENT,
        "the id the list handed us is the id the leave endpoint keys on"
    );
}

/// PMS-1393: a revoked grant reads as no grant.
///
/// The column is nullable and the join requires `revoked_at IS NULL`, so a seat
/// whose grant is already gone offers no id. Without that, a client would render
/// Leave for a grant revoked days ago and the endpoint would answer 204 for
/// nothing, which reads to the person as having just left.
#[mokosh_test]
async fn a_revoked_grant_leaves_no_id_on_the_membership(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let sub = Uuid::new_v4();
    sqlx::query("UPDATE users SET bunyip_user_id = $1 WHERE id = $2")
        .bind(sub)
        .bind(admin_id)
        .execute(&pool)
        .await
        .expect("stamp the Bunyip sub");
    // A revoked row carries no role, which the table's own CHECK enforces.
    sqlx::query(
        "INSERT INTO mokosh_bunyip_grants \
         (grantee_bunyip_user_id, owner_bunyip_user_id, mokosh_account_id, role, revoked_at) \
         VALUES ($1, $2, 'default', NULL, NOW())",
    )
    .bind(sub)
    .bind(Uuid::new_v4())
    .execute(&pool)
    .await
    .expect("insert the revoked grant");

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
    assert_eq!(body.len(), 1);
    assert!(
        body[0]["mokosh_bunyip_grant_id"].is_null(),
        "a revoked grant is not something to leave: {:?}",
        body[0]
    );
}
