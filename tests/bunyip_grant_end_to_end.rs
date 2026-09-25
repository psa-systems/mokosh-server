//! BUNYIP-674 option B: end-to-end grant token pin.
//!
//! Boots the real router with the bunyip Resource-Server verifier
//! mounted against a stub OP (Ed25519 JWKS + `/userinfo`, matching
//! the shape `tests/bunyip_principal_gate.rs` uses), seeds an active
//! `mokosh_bunyip_grants` mirror row, mints a grant-scoped `at+jwt`
//! carrying the three `mokosh_grant_*` extras, and asserts:
//!
//! - `GET /api/v1/auth/me` answers 200 for a first-sight grantee,
//!   JIT-provisions the placement row in the granted tenant, and
//!   the response's `tenant_id` and `role` are the grant's rather
//!   than the caller's own tenant.
//! - A subsequent revoke through `MokoshBunyipGrantService::upsert`
//!   plus a cache clear turns the same request into 403 within the
//!   parent BUNYIP-674 stale-window budget.
//! - A re-grant after revoke reinstates the tombstoned users row on
//!   the next request without minting a fresh mokosh-side `users.id`
//!   (any FK dependent on the row survives the revoke/re-grant cycle).
//!
//! The stub OP signs with the RFC 8032 section 7.1 TEST 1 key
//! vector, so no key-generation dependency is needed. The mint
//! helper here is a superset of `bunyip_principal_gate::StubOp::mint`
//! that also emits the grant extras; a normal login token still
//! comes through with them absent.

mod common;

use axum::{routing::get, Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use mokosh_test::mokosh_test;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use mokosh_server::modules::auth::mokosh_bunyip_grants::{
    clear_cache_for_tests, MokoshBunyipGrantService,
};
use mokosh_server::modules::auth::oidc_rs::{Verifier, VerifierConfig};

/// RFC 8032 7.1 TEST 1 secret seed.
const ED25519_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];
const ED25519_PUBLIC: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];
const PKCS8_V1_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

const KID: &str = "stub-op-key";
const AUDIENCE: &str = "https://mokosh.test";

fn pkcs8_der() -> Vec<u8> {
    let mut der = PKCS8_V1_PREFIX.to_vec();
    der.extend_from_slice(&ED25519_SEED);
    der
}

struct StubOp {
    issuer: String,
}

/// One grant's worth of `mokosh_grant_*` claim extras. `mint` folds
/// them onto the token JSON only when Some is passed, so a
/// null-carrying grant claim never accidentally leaks onto a plain
/// login token.
#[derive(Clone)]
struct GrantExtras {
    grant_id: Uuid,
    role: String,
    account_slug: String,
}

impl StubOp {
    async fn spawn(sub: Uuid, email: &str) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind stub OP");
        let issuer = format!("http://{}", listener.local_addr().expect("local_addr"));

        let discovery = json!({
            "issuer": issuer,
            "jwks_uri": format!("{issuer}/jwks.json"),
            "userinfo_endpoint": format!("{issuer}/userinfo"),
        });
        let jwks = json!({
            "keys": [{
                "kty": "OKP",
                "use": "sig",
                "kid": KID,
                "crv": "Ed25519",
                "x": URL_SAFE_NO_PAD.encode(ED25519_PUBLIC),
            }]
        });
        // A grantee has a Bunyip identity but no Mokosh account of
        // their own in the target tenant; userinfo carries the same
        // (sub, email, first, last) shape regardless of which
        // tenant Mokosh ends up placing them in.
        let userinfo = json!({
            "sub": sub.to_string(),
            "email": email,
            "email_verified": true,
            "given_name": "Guest",
            "family_name": "Person",
        });

        let router = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(move || async move { Json(discovery) }),
            )
            .route("/jwks.json", get(move || async move { Json(jwks) }))
            .route("/userinfo", get(move || async move { Json(userinfo) }));

        tokio::spawn(async move {
            axum::serve(listener, router).await.expect("stub OP serve");
        });

        Self { issuer }
    }

    fn verifier(&self) -> Verifier {
        Verifier::new(VerifierConfig {
            issuer: self.issuer.clone(),
            audience: AUDIENCE.to_string(),
            jwks_cache_ttl_secs: 600,
            leeway_seconds: 30,
        })
    }

    /// Mint an at+jwt carrying an optional grant claim set. `grant`
    /// is `Some` when the token is a grant-scoped mint (this is what
    /// Bunyip's `mint_grant_access_token` produces) and `None` for
    /// a normal login token.
    fn mint(&self, sub: Uuid, bunyip_role: &str, grant: Option<&GrantExtras>) -> String {
        let now = Utc::now().timestamp();
        let mut claims = json!({
            "iss": self.issuer,
            "sub": sub.to_string(),
            "aud": AUDIENCE,
            "client_id": "mokosh",
            "scope": "openid profile",
            "exp": now + 3600,
            "iat": now,
            "bunyip_role": bunyip_role,
        });
        if let Some(g) = grant {
            let obj = claims.as_object_mut().expect("claims is an object");
            obj.insert("mokosh_grant_id".to_string(), json!(g.grant_id.to_string()));
            obj.insert("mokosh_grant_role".to_string(), json!(g.role));
            obj.insert("mokosh_grant_account_id".to_string(), json!(g.account_slug));
        }
        let mut header = Header::new(Algorithm::EdDSA);
        header.typ = Some("at+jwt".to_string());
        header.kid = Some(KID.to_string());
        jsonwebtoken::encode(&header, &claims, &EncodingKey::from_ed_der(&pkcs8_der()))
            .expect("mint at+jwt")
    }
}

/// Seed a tenant row directly (not through `TenantService::create`),
/// so this file has no dependency on the owner-provisioning path.
async fn seed_tenant(pool: &PgPool, slug: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, status, kind) VALUES ($1, $2, $3, 'active', 'org')",
    )
    .bind(id)
    .bind(format!("Tenant {slug}"))
    .bind(slug)
    .execute(pool)
    .await
    .expect("seed tenant");
    id
}

async fn get_me(app: &common::TestApp, token: &str) -> (reqwest::StatusCode, serde_json::Value) {
    let resp = app
        .client
        .get(app.url("/api/v1/auth/me"))
        .bearer_auth(token)
        .send()
        .await
        .expect("GET /auth/me");
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or(json!({}));
    (status, body)
}

/// BUNYIP-674 option B end-to-end: an active grant + a grant token
/// mint together JIT-provision a placement row in the granted
/// tenant, `GET /auth/me` answers scoped to that tenant at the
/// grant's role, and the row is keyed on (bunyip_user_id, tenant_id)
/// so a subsequent revoke tombstones it while the caller's own
/// tenant (if any) is untouched.
#[mokosh_test]
async fn a_granted_token_places_the_grantee_in_the_granted_tenant(pool: PgPool) {
    clear_cache_for_tests();

    let owner_sub = Uuid::new_v4();
    let grantee_sub = Uuid::new_v4();
    let granted_slug = "acme";
    let granted_tenant = seed_tenant(&pool, granted_slug).await;

    // Seed the grantee's OWN tenant so the (bunyip_user_id,
    // tenant_id) axis has two rows to distinguish. Not strictly
    // required for the endpoint to answer (the grant path never
    // reads the caller's own tenant), but it makes the "wrong
    // tenant" failure mode observable rather than absent.
    let grantee_own_tenant = seed_tenant(&pool, "grantee-own").await;
    sqlx::query(
        "INSERT INTO users (id, tenant_id, bunyip_user_id, email, first_name, last_name, \
         role, status, email_verified_at) \
         VALUES ($1, $2, $1, 'grantee@example.com', 'Guest', 'Person', 'admin', 'active', NOW())",
    )
    .bind(grantee_sub)
    .bind(grantee_own_tenant)
    .execute(&pool)
    .await
    .expect("seed grantee's own tenant placement");

    // Seed the active mirror row: Bunyip has issued the grant and
    // fired the `granted` webhook.
    MokoshBunyipGrantService::upsert(
        &pool,
        Uuid::new_v4(),
        owner_sub,
        grantee_sub,
        granted_slug,
        Some("manager"),
        Utc::now(),
        None,
    )
    .await
    .expect("seed active grant mirror");

    let op = StubOp::spawn(grantee_sub, "grantee@example.com").await;
    let app = common::boot_with_bunyip(pool.clone(), op.verifier()).await;

    let grant_extras = GrantExtras {
        grant_id: Uuid::new_v4(),
        role: "manager".to_string(),
        account_slug: granted_slug.to_string(),
    };
    let token = op.mint(grantee_sub, "subscriber", Some(&grant_extras));

    let (status, body) = get_me(&app, &token).await;
    assert!(
        status.is_success(),
        "grant-scoped GET /auth/me returned {status}, body: {body}"
    );

    // `UserResponse` does not carry `tenant_id`, so the placement
    // proof comes from `id` and `role`. The grant path mints a
    // FRESH users.id (not the sub, which would collide with the
    // grantee's own tenant row on the PK) and stamps the grant's
    // role, so `id != sub AND role == "manager"` is the wire proof
    // that the grantee path served this request.
    let response_id = body
        .get("id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
        .expect("response carries id");
    assert_ne!(
        response_id, grantee_sub,
        "grantee placement's id is fresh, not the sub (that would collide with their own tenant's row)"
    );
    assert_eq!(
        body.get("role").and_then(|v| v.as_str()),
        Some("manager"),
        "grant's role is what the placement row carries; body was {body}"
    );

    // Direct-DB pin that the placement lives IN THE GRANTED TENANT.
    // The tenant scope is what /auth/me implicitly answered under
    // (the handler reads by `user.tenant_id`), so a row with the
    // response's id AND the granted tenant's id is the load-bearing
    // check; the wire body cannot say which tenant on its own.
    let placement: (Uuid, String) = sqlx::query_as(
        "SELECT id, role FROM users \
         WHERE bunyip_user_id = $1 AND tenant_id = $2 AND deleted_at IS NULL",
    )
    .bind(grantee_sub)
    .bind(granted_tenant)
    .fetch_one(&pool)
    .await
    .expect("JIT users row present in granted tenant");
    assert_eq!(placement.0, response_id);
    assert_eq!(placement.1, "manager");

    // The caller's OWN tenant placement is untouched.
    let own_row: (Uuid, String) = sqlx::query_as("SELECT tenant_id, role FROM users WHERE id = $1")
        .bind(grantee_sub)
        .fetch_one(&pool)
        .await
        .expect("own-tenant row untouched");
    assert_eq!(own_row.0, grantee_own_tenant);
    assert_eq!(own_row.1, "admin");
}

/// A revoke through the mirror + a cache clear turns the same grant
/// token into 403 on the very next request. The parent BUNYIP-674
/// ticket promises this happens within the 30-second stale-window
/// budget; the cache clear here is what makes the test deterministic
/// on the same clock cycle.
#[mokosh_test]
async fn a_revoked_grant_refuses_the_next_request(pool: PgPool) {
    clear_cache_for_tests();

    let owner_sub = Uuid::new_v4();
    let grantee_sub = Uuid::new_v4();
    let granted_slug = "acme";
    let _granted_tenant = seed_tenant(&pool, granted_slug).await;

    let grant_id = Uuid::new_v4();
    MokoshBunyipGrantService::upsert(
        &pool,
        grant_id,
        owner_sub,
        grantee_sub,
        granted_slug,
        Some("technician"),
        Utc::now(),
        None,
    )
    .await
    .unwrap();

    let op = StubOp::spawn(grantee_sub, "grantee@example.com").await;
    let app = common::boot_with_bunyip(pool.clone(), op.verifier()).await;
    let extras = GrantExtras {
        grant_id,
        role: "technician".to_string(),
        account_slug: granted_slug.to_string(),
    };
    let token = op.mint(grantee_sub, "subscriber", Some(&extras));

    // Warm the placement first: an active grant works.
    let (before, _) = get_me(&app, &token).await;
    assert!(before.is_success(), "active grant answers /auth/me");

    // Revoke on the mirror + clear the process-wide cache so the
    // next request re-reads the row.
    MokoshBunyipGrantService::upsert(
        &pool,
        grant_id,
        owner_sub,
        grantee_sub,
        granted_slug,
        None,
        Utc::now(),
        Some(Utc::now()),
    )
    .await
    .unwrap();
    clear_cache_for_tests();

    let (after, body) = get_me(&app, &token).await;
    assert_eq!(
        after,
        reqwest::StatusCode::FORBIDDEN,
        "revoked grant must return 403, got {after}, body: {body}"
    );
}

/// BUNYIP-674 option B phase 3: a revoke tombstones the placement
/// row and a follow-up re-grant reinstates the SAME row (the fresh
/// id from the first grant, not a second fresh id), so any FK on the
/// row survives the cycle. This is the belt-and-braces path the
/// receiver's `revoked` branch adds on top of the mirror gate.
#[mokosh_test]
async fn a_regrant_after_revoke_reinstates_the_same_row(pool: PgPool) {
    clear_cache_for_tests();

    let owner_sub = Uuid::new_v4();
    let grantee_sub = Uuid::new_v4();
    let granted_slug = "acme";
    let granted_tenant = seed_tenant(&pool, granted_slug).await;

    let grant_id = Uuid::new_v4();
    MokoshBunyipGrantService::upsert(
        &pool,
        grant_id,
        owner_sub,
        grantee_sub,
        granted_slug,
        Some("manager"),
        Utc::now(),
        None,
    )
    .await
    .unwrap();

    let op = StubOp::spawn(grantee_sub, "grantee@example.com").await;
    let app = common::boot_with_bunyip(pool.clone(), op.verifier()).await;
    let extras = GrantExtras {
        grant_id,
        role: "manager".to_string(),
        account_slug: granted_slug.to_string(),
    };
    let token = op.mint(grantee_sub, "subscriber", Some(&extras));

    // First request warms the placement.
    let (status, _) = get_me(&app, &token).await;
    assert!(status.is_success());
    let first_row: (Uuid,) =
        sqlx::query_as("SELECT id FROM users WHERE bunyip_user_id = $1 AND tenant_id = $2")
            .bind(grantee_sub)
            .bind(granted_tenant)
            .fetch_one(&pool)
            .await
            .unwrap();

    // Revoke + tombstone via a fresh receiver-shaped upsert AND the
    // production receiver's explicit `UPDATE users SET deleted_at`
    // (which the webhook receiver does after the mirror upsert). We
    // reproduce that write here so this test does not rely on the
    // HTTP path to the webhook.
    MokoshBunyipGrantService::upsert(
        &pool,
        grant_id,
        owner_sub,
        grantee_sub,
        granted_slug,
        None,
        Utc::now(),
        Some(Utc::now()),
    )
    .await
    .unwrap();
    sqlx::query(
        "UPDATE users SET deleted_at = COALESCE(deleted_at, NOW()) \
         WHERE bunyip_user_id = $1 \
           AND tenant_id = (SELECT id FROM tenants WHERE slug = $2)",
    )
    .bind(grantee_sub)
    .bind(granted_slug)
    .execute(&pool)
    .await
    .unwrap();
    clear_cache_for_tests();

    // Re-grant with a DIFFERENT role. On next request the placement
    // reinstates with the new role, keeping the same users.id.
    MokoshBunyipGrantService::upsert(
        &pool,
        Uuid::new_v4(), // Bunyip mints a new grant id on re-grant
        owner_sub,
        grantee_sub,
        granted_slug,
        Some("finance"),
        Utc::now(),
        None,
    )
    .await
    .unwrap();
    clear_cache_for_tests();
    let regrant = GrantExtras {
        grant_id: Uuid::new_v4(),
        role: "finance".to_string(),
        account_slug: granted_slug.to_string(),
    };
    let regrant_token = op.mint(grantee_sub, "subscriber", Some(&regrant));

    let (status, body) = get_me(&app, &regrant_token).await;
    assert!(
        status.is_success(),
        "re-grant token answers /auth/me, status: {status}, body: {body}"
    );
    let reinstated_row: (Uuid, String, Option<chrono::DateTime<Utc>>) = sqlx::query_as(
        "SELECT id, role, deleted_at FROM users \
         WHERE bunyip_user_id = $1 AND tenant_id = $2",
    )
    .bind(grantee_sub)
    .bind(granted_tenant)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        reinstated_row.0, first_row.0,
        "the same users.id survives the revoke -> re-grant cycle"
    );
    assert_eq!(reinstated_row.1, "finance");
    assert!(
        reinstated_row.2.is_none(),
        "the tombstone is cleared by the re-grant's JIT upsert"
    );
}
