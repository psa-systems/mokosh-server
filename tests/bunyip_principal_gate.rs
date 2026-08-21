//! PMS-698: the user-status / tenant-active gate must fire on BOTH auth paths.
//!
//! `auth_middleware` runs the bunyip Resource-Server branch first and the
//! legacy HS256 branch as a fallback. Before PMS-698 only the legacy branch
//! ran `ensure_user_and_tenant_active`, so deactivating a user or suspending a
//! tenant was a no-op for the path the SPA actually uses. These tests boot the
//! real router with the bunyip verifier mounted against a stub OP (Ed25519
//! JWKS + userinfo) and assert both branches reject the same fixture.
//!
//! The stub OP signs with the RFC 8032 section 7.1 TEST 1 key vector, so no
//! key-generation dependency is needed: the seed and its public key are fixed
//! constants and the PKCS#8 v1 wrapper is a constant prefix.

mod common;

use axum::{routing::get, Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use mokosh_server::modules::auth::oidc_rs::{Verifier, VerifierConfig};

/// RFC 8032 7.1 TEST 1 secret seed.
const ED25519_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];
/// The matching public key from the same vector.
const ED25519_PUBLIC: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];
/// PKCS#8 v1 (`OneAsymmetricKey`) header for a bare Ed25519 seed. jsonwebtoken
/// signs via ring's `from_pkcs8_maybe_unchecked`, which accepts the v1 form.
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

/// A stub bunyip OP: discovery doc, JWKS, and a `/userinfo` that echoes the
/// single (sub, email) pair it was spawned with.
struct StubOp {
    issuer: String,
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
        let userinfo = json!({
            "sub": sub.to_string(),
            "email": email,
            "email_verified": true,
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

    /// Mint an `at+jwt` the mokosh RS branch will accept.
    fn mint(&self, sub: Uuid, bunyip_role: &str) -> String {
        let now = chrono::Utc::now().timestamp();
        let claims = json!({
            "iss": self.issuer,
            "sub": sub.to_string(),
            "aud": AUDIENCE,
            "client_id": "mokosh",
            "scope": "openid profile",
            "exp": now + 3600,
            "iat": now,
            "bunyip_role": bunyip_role,
        });
        let mut header = Header::new(Algorithm::EdDSA);
        header.typ = Some("at+jwt".to_string());
        header.kid = Some(KID.to_string());
        jsonwebtoken::encode(&header, &claims, &EncodingKey::from_ed_der(&pkcs8_der()))
            .expect("mint at+jwt")
    }
}

async fn tickets_status(app: &common::TestApp, token: &str) -> reqwest::StatusCode {
    app.client
        .get(app.url("/api/v1/tickets"))
        .bearer_auth(token)
        .send()
        .await
        .expect("GET /tickets")
        .status()
}

/// AC3: after `POST /tenants/{id}/suspend` a previously working bunyip bearer
/// gets a non-2xx on `GET /api/v1/tickets`. The legacy bearer for the same
/// tenant is asserted alongside it so the two paths are pinned together.
///
/// MAPPS-519 note: this test used to seed its principal via
/// `common::seed_admin`, which parks a `users.role='super_admin'` row in
/// `DEFAULT_TENANT_ID`. Pre-519 the bunyip `admin` claim promoted to
/// `SuperAdmin`, `is_stuck_in_default` exempted `super_admin`, and both
/// bearers stayed pinned to DEFAULT so suspending DEFAULT rejected both.
/// Post-519 the claim mints tenant `Admin`, which then gets re-homed off
/// the shared default tenant into a personal one on the next bunyip
/// placement, so suspending DEFAULT is no longer enough. The fixture
/// switches to `common::seed_tenant_with_admin`, which puts the caller
/// in a purpose-built non-default tenant from the start; re-home never
/// fires (the caller is already in a real tenant), both bearers stay
/// pinned to that tenant, and suspending that tenant rejects both.
/// Platform-admin credentials for `/platform/login` still come from
/// `common::seed_admin`'s `platform_admins` seed.
#[sqlx::test]
async fn suspended_tenant_rejects_both_auth_paths(pool: PgPool) {
    // Platform-plane admin: exists in `platform_admins` so
    // `platform_login` returns a valid bearer for `/suspend`.
    let (_pa_id, pa_email, pa_password) = common::seed_admin(&pool).await;

    // Tenant-plane principal: a `users` row in a fresh non-default
    // tenant so the bunyip re-home never fires and both bearers stay
    // pinned to the same tenant across the test.
    let (tenant_id, admin_id, email, password) =
        common::seed_tenant_with_admin(&pool, "mapps-519-suspend-probe").await;

    let op = StubOp::spawn(admin_id, &email).await;
    let app = common::boot_with_bunyip(pool.clone(), op.verifier()).await;

    let bunyip = op.mint(admin_id, "admin");
    // MAPPS-519: the seeded tenant is not the default one, so
    // `common::login` (which hardcodes `tenant_slug="default"`) 401s.
    // POST `/auth/login` with the seeded slug directly.
    let legacy = {
        let resp = app
            .client
            .post(app.url("/api/v1/auth/login"))
            .json(&serde_json::json!({
                "email": email,
                "password": password,
                "tenant_slug": "mapps-519-suspend-probe",
            }))
            .send()
            .await
            .expect("send /auth/login request");
        assert!(
            resp.status().is_success(),
            "legacy login for the seeded tenant admin expected 2xx, got {}",
            resp.status()
        );
        let body: serde_json::Value = resp.json().await.expect("/auth/login JSON body");
        body["access_token"]
            .as_str()
            .expect("login response has access_token")
            .to_string()
    };

    assert!(
        tickets_status(&app, &bunyip).await.is_success(),
        "bunyip bearer works before the suspension"
    );
    assert!(
        tickets_status(&app, &legacy).await.is_success(),
        "legacy bearer works before the suspension"
    );

    // MAPPS-518: /tenants/{id}/suspend is gated on `RequirePlatformAdmin`
    // (the bunyip bearer's tenant scope no longer grants it). Use the
    // platform-plane bearer minted by `seed_admin` + `/platform/login` to
    // drive the suspension of the seeded tenant.
    let platform = common::platform_login(&app, &pa_email, &pa_password).await;
    let resp = app
        .client
        .post(app.url(&format!("/api/v1/tenants/{}/suspend", tenant_id)))
        .bearer_auth(&platform)
        .send()
        .await
        .expect("POST /tenants/{id}/suspend");
    assert!(
        resp.status().is_success(),
        "suspend returned {}",
        resp.status()
    );

    assert!(
        !tickets_status(&app, &bunyip).await.is_success(),
        "bunyip bearer must be rejected once the tenant is suspended"
    );
    assert!(
        !tickets_status(&app, &legacy).await.is_success(),
        "legacy bearer must be rejected once the tenant is suspended"
    );
}

/// AC4 + AC5: the same fixture (one users row flipped to `inactive`) is
/// rejected on BOTH branches of `auth_middleware`, which is what the shared
/// `AuthService::ensure_principal_usable` buys.
#[sqlx::test]
async fn inactive_user_rejects_both_auth_paths(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let op = StubOp::spawn(admin_id, &email).await;
    let app = common::boot_with_bunyip(pool.clone(), op.verifier()).await;

    let bunyip = op.mint(admin_id, "admin");
    let legacy = common::login(&app, &email, &password).await;

    assert!(
        tickets_status(&app, &bunyip).await.is_success(),
        "bunyip bearer works while the user is active"
    );
    assert!(
        tickets_status(&app, &legacy).await.is_success(),
        "legacy bearer works while the user is active"
    );

    sqlx::query("UPDATE users SET status = 'inactive' WHERE id = $1")
        .bind(admin_id)
        .execute(&pool)
        .await
        .expect("deactivate user");

    assert!(
        !tickets_status(&app, &bunyip).await.is_success(),
        "bunyip bearer must be rejected once the user is inactive"
    );
    assert!(
        !tickets_status(&app, &legacy).await.is_success(),
        "legacy bearer must be rejected once the user is inactive"
    );
}
