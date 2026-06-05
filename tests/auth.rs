//! Integration tests for the legacy HS256 auth module.
//!
//! Covers:
//! - PMS-124 F10 acceptance: login + /me happy path.
//! - PMS-4 AC1: paginated, filterable `list_users` (with the F9 oversize-q
//!   regression pin) + admin gate.
//! - PMS-4 AC2: layered `(ip, email)` rate limit, 429 + `Retry-After`.
//! - PMS-4 AC3: MFA TOTP challenge + recovery-code single-use.
//! - PMS-4 AC6: cross-tenant `GET /users/{id}` returns 404 (pins the
//!   surgical `tenant_id` WHERE-clause fixes in service.rs).
//! - Negative pin: wrong password returns 401.

mod common;

use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test]
async fn login_then_me_happy_path(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;

    let token = common::login(&app, &email, &password).await;

    let me = app
        .client
        .get(app.url("/api/v1/auth/me"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send /me request");
    assert_eq!(
        me.status(),
        reqwest::StatusCode::OK,
        "/me should authenticate via the login bearer token"
    );

    let body: serde_json::Value = me.json().await.expect("/me body is JSON");
    assert_eq!(
        body["email"].as_str(),
        Some(email.as_str()),
        "/me must reflect the seeded admin email"
    );
    assert_eq!(
        body["id"].as_str(),
        Some(admin_id.to_string().as_str()),
        "/me must reflect the seeded admin id"
    );
}

// ============================================================================
// PMS-4 AC1: list_users pagination + filter
// ============================================================================

/// Seed 1 admin + 14 technicians (15 users total in tenant) and assert
/// the pagination envelope at `page=2&per_page=10` returns exactly 5.
#[sqlx::test]
async fn list_users_pagination_happy_path(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    for i in 0..14 {
        let e = format!("tech-{i:02}@example.com");
        common::seed_user(&pool, &e, "technician").await;
    }
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let resp = app
        .client
        .get(app.url("/api/v1/auth/users?page=2&per_page=10"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send list users page 2");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("list users JSON");
    let data = body["data"].as_array().expect("list response has data");
    assert_eq!(data.len(), 5, "page 2 of 10 over 15 users = 5");
    assert_eq!(body["meta"]["page"].as_i64(), Some(2));
    assert_eq!(body["meta"]["total"].as_i64(), Some(15));
    assert_eq!(body["meta"]["per_page"].as_i64(), Some(10));
}

/// Pin the new `ListUsersFilter` struct: `role` narrows to the
/// requested role; combined `q` + `role` narrows to the intersection.
/// The seeded admin (super_admin) is excluded from any
/// `role=technician` / `role=manager` result.
#[sqlx::test]
async fn list_users_filter_by_role_and_q(pool: PgPool) {
    let (_admin_id, admin_email, password) = common::seed_admin(&pool).await;
    for i in 0..3 {
        let e = format!("pms4test-tech-{i}@example.com");
        common::seed_user(&pool, &e, "technician").await;
    }
    for i in 0..2 {
        let e = format!("pms4test-mgr-{i}@example.com");
        common::seed_user(&pool, &e, "manager").await;
    }
    let app = common::boot(pool).await;
    let token = common::login(&app, &admin_email, &password).await;

    let resp = app
        .client
        .get(app.url("/api/v1/auth/users?role=manager&per_page=50"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send list users filtered by role");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("filter response JSON");
    let data = body["data"].as_array().expect("data array");
    assert_eq!(data.len(), 2, "exactly two managers seeded");

    let resp2 = app
        .client
        .get(app.url("/api/v1/auth/users?q=pms4test&role=technician&per_page=50"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send list users filtered by q + role");
    assert_eq!(resp2.status(), reqwest::StatusCode::OK);
    let body2: serde_json::Value = resp2.json().await.expect("filter2 response JSON");
    let data2 = body2["data"].as_array().expect("data array");
    assert_eq!(data2.len(), 3, "three technicians match pms4test");
}

/// F9 regression pin: `q` is capped at 200 chars in `ListUsersFilter`;
/// a 201-char `q` is rejected with 422 by the route's
/// `filter.validate()?` call.
#[sqlx::test]
async fn list_users_filter_validation_rejects_oversize_q(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let huge_q = "a".repeat(201);
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/auth/users?q={huge_q}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send list users oversize q");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "oversize q must fail validation with 422"
    );
}

/// A logged-in non-admin (`technician`) cannot list users. PMS-4 AC1
/// admin/manager gate pin.
#[sqlx::test]
async fn list_users_requires_admin(pool: PgPool) {
    let (_uid, email, password) =
        common::seed_user(&pool, "techguy@example.com", "technician").await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let resp = app
        .client
        .get(app.url("/api/v1/auth/users"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send list users as non-admin");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::FORBIDDEN,
        "technician must not be able to list users"
    );
}

// ============================================================================
// PMS-4 AC3: MFA challenge + recovery code single-use
// ============================================================================

/// End-to-end TOTP challenge: enroll, enable, log in without code
/// (expect `mfa_required: true`), then log in with the TOTP code.
#[sqlx::test]
async fn mfa_challenge_happy_path(pool: PgPool) {
    let (_uid, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let setup: serde_json::Value = app
        .client
        .post(app.url("/api/v1/auth/me/mfa/setup"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send mfa setup")
        .json()
        .await
        .expect("mfa setup JSON");
    let secret_b32 = setup["secret"].as_str().expect("secret in mfa setup");
    let secret = mokosh_auth_crypto::totp::base32_decode(secret_b32).expect("decode mfa secret");
    let code_now = mokosh_auth_crypto::totp::code_at(&secret, Utc::now());

    let enable_resp = app
        .client
        .post(app.url("/api/v1/auth/me/mfa/enable"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "code": code_now }))
        .send()
        .await
        .expect("send mfa enable");
    assert!(
        enable_resp.status().is_success(),
        "enable mfa should succeed, got {}",
        enable_resp.status()
    );
    let enable_json: serde_json::Value = enable_resp.json().await.expect("enable JSON");
    let recovery = enable_json["recovery_codes"]
        .as_array()
        .expect("recovery_codes returned");
    assert_eq!(recovery.len(), 10, "exactly 10 recovery codes");

    // Login WITHOUT mfa_code: expect 200 with mfa_required: true and
    // empty access_token.
    let resp = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .json(&serde_json::json!({ "email": email, "password": password }))
        .send()
        .await
        .expect("send login without mfa");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("mfa-required JSON");
    assert_eq!(body["mfa_required"].as_bool(), Some(true));
    assert_eq!(body["access_token"].as_str(), Some(""));

    // Submit a fresh TOTP code (recomputed because the 30-second step
    // may have rolled over between calls).
    let code_now = mokosh_auth_crypto::totp::code_at(&secret, Utc::now());
    let resp2 = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .json(&serde_json::json!({
            "email": email,
            "password": password,
            "mfa_code": code_now,
        }))
        .send()
        .await
        .expect("send login with mfa_code");
    assert_eq!(resp2.status(), reqwest::StatusCode::OK);
    let body2: serde_json::Value = resp2.json().await.expect("mfa-success JSON");
    assert_eq!(body2["mfa_required"].as_bool(), Some(false));
    assert!(
        !body2["access_token"].as_str().unwrap_or("").is_empty(),
        "access_token populated after TOTP verify"
    );
}

/// PMS-4 AC3: a recovery code can be used to log in instead of a TOTP
/// code, and each code works exactly once.
#[sqlx::test]
async fn mfa_recovery_code_login_single_use(pool: PgPool) {
    let (_uid, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let setup: serde_json::Value = app
        .client
        .post(app.url("/api/v1/auth/me/mfa/setup"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send mfa setup")
        .json()
        .await
        .expect("mfa setup JSON");
    let secret_b32 = setup["secret"].as_str().expect("secret");
    let secret = mokosh_auth_crypto::totp::base32_decode(secret_b32).expect("decode mfa secret");
    let code_now = mokosh_auth_crypto::totp::code_at(&secret, Utc::now());

    let enable_json: serde_json::Value = app
        .client
        .post(app.url("/api/v1/auth/me/mfa/enable"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "code": code_now }))
        .send()
        .await
        .expect("send mfa enable")
        .json()
        .await
        .expect("enable JSON");
    let recovery: Vec<String> = enable_json["recovery_codes"]
        .as_array()
        .expect("recovery_codes")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(recovery.len() >= 2, "need at least 2 codes for this test");
    let first = recovery[0].clone();
    let second = recovery[1].clone();

    // First use of the first recovery code: success.
    let r1 = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .json(&serde_json::json!({
            "email": email,
            "password": password,
            "recovery_code": first,
        }))
        .send()
        .await
        .expect("send recovery login 1");
    assert_eq!(
        r1.status(),
        reqwest::StatusCode::OK,
        "first recovery code must succeed"
    );
    let b1: serde_json::Value = r1.json().await.expect("r1 JSON");
    assert!(!b1["access_token"].as_str().unwrap_or("").is_empty());

    // Replay of the SAME code: 401.
    let r2 = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .json(&serde_json::json!({
            "email": email,
            "password": password,
            "recovery_code": first,
        }))
        .send()
        .await
        .expect("send recovery login replay");
    assert_eq!(
        r2.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "re-using the same recovery code must fail"
    );

    // A different code from the batch still works.
    let r3 = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .json(&serde_json::json!({
            "email": email,
            "password": password,
            "recovery_code": second,
        }))
        .send()
        .await
        .expect("send recovery login with second code");
    assert_eq!(
        r3.status(),
        reqwest::StatusCode::OK,
        "second recovery code is independent"
    );
}

// ============================================================================
// Negative pins + AC2 rate limit
// ============================================================================

/// Wrong password yields 401 (not 200, not 404). Negative pin for the
/// login happy path.
#[sqlx::test]
async fn login_wrong_password_returns_401(pool: PgPool) {
    let (_uid, email, _password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;

    let resp = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .json(&serde_json::json!({
            "email": email,
            "password": "definitely-not-the-password",
        }))
        .send()
        .await
        .expect("send wrong-password login");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "wrong password must 401"
    );
}

/// PMS-4 AC2: per-email rate limit (5/min). Hammering the same email
/// with the wrong password 5+ times trips the limiter and returns 429
/// with a populated `Retry-After` header.
///
/// Each `#[sqlx::test]` boots a fresh `LoginLimiter` instance because
/// `boot(pool)` builds a new `AuthRouterState` per test, so this test
/// starts with empty buckets and does not need a serial guard.
#[sqlx::test]
async fn login_rate_limit_triggers_429(pool: PgPool) {
    let (_uid, email, _password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;

    let bad = serde_json::json!({
        "email": email,
        "password": "wrong-password",
    });

    // First 5 attempts: 401 (within quota).
    for i in 0..5 {
        let resp = app
            .client
            .post(app.url("/api/v1/auth/login"))
            .json(&bad)
            .send()
            .await
            .expect("send bad login");
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::UNAUTHORIZED,
            "attempt {i} should be 401 (within quota)"
        );
    }

    // 6th attempt: 429 with Retry-After.
    let resp = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .json(&bad)
        .send()
        .await
        .expect("send over-quota login");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::TOO_MANY_REQUESTS,
        "6th attempt must trip the per-email rate limit"
    );
    let retry_after = resp
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .expect("Retry-After header present on 429")
        .to_str()
        .expect("Retry-After is ASCII");
    let secs: u64 = retry_after
        .parse()
        .expect("Retry-After parses as positive integer");
    assert!(secs >= 1, "Retry-After must be at least 1 second");

    let body: serde_json::Value = resp.json().await.expect("rate-limit body is JSON");
    assert_eq!(body["error"].as_str(), Some("rate_limited"));
    assert!(body["retry_after_seconds"].as_u64().unwrap_or(0) >= 1);
}

// ============================================================================
// PMS-4 AC6: tenant isolation pin
// ============================================================================

/// Seed two tenants. Tenant A's admin attempts to GET tenant B's user
/// by id. Pre-fix the service-level SELECT returned the row (cross-
/// tenant leak); post-fix the WHERE binds `tenant_id` so the route
/// returns 404. Pins all four A.6 surgical fixes at the route level.
#[sqlx::test]
async fn tenant_isolation_get_user_by_id_returns_404(pool: PgPool) {
    let (_admin_a, email_a, password_a) = common::seed_admin(&pool).await;
    let (_tenant_b_id, user_b_id, _email_b, _password_b) =
        common::seed_tenant_with_admin(&pool, "pms4-tenant-b").await;

    let app = common::boot(pool).await;
    let token_a = common::login(&app, &email_a, &password_a).await;

    let resp = app
        .client
        .get(app.url(&format!("/api/v1/auth/users/{user_b_id}")))
        .bearer_auth(&token_a)
        .send()
        .await
        .expect("send cross-tenant get user");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::NOT_FOUND,
        "tenant A must not be able to read tenant B's user; got {}",
        resp.status()
    );

    // Silence the unused-binding warning while keeping the id visible
    // in the assertion above.
    let _: Uuid = user_b_id;
}

// ============================================================================
// PMS-138: subdomain-driven `LoginRequest::tenant_id` hint
// ============================================================================

/// Insert a user under an arbitrary `(tenant_id, email)` with a known
/// password. Used by the PMS-138 tests to set up the multi-tenant
/// colliding-email scenario that the seeded helpers can't express on
/// their own (they hard-code the default tenant or generate a unique
/// per-tenant email).
async fn insert_user_in_tenant(
    pool: &PgPool,
    tenant_id: Uuid,
    email: &str,
    password: &str,
    role: &str,
) -> Uuid {
    let password_hash = mokosh_server::utils::crypto::hash_password(password)
        .expect("hash PMS-138 colliding user password");
    let user_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO users (
            id, tenant_id, email, password_hash,
            first_name, last_name, role, status, email_verified_at
        )
        VALUES ($1, $2, $3, $4, 'Colliding', 'User', $5, 'active', NOW())
        "#,
    )
    .bind(user_id)
    .bind(tenant_id)
    .bind(email)
    .bind(&password_hash)
    .bind(role)
    .execute(pool)
    .await
    .expect("insert PMS-138 colliding user");
    user_id
}

/// PMS-138 multi-tenant resolution: with the same email under two
/// tenants the `tenant_id` hint must steer the lookup to the user in
/// the named tenant. Pre-PMS-138 the email-only lookup returned the
/// oldest-created row regardless of which tenant the caller intended.
#[sqlx::test]
async fn login_with_tenant_hint_resolves_to_correct_tenant(pool: PgPool) {
    let colliding_email = "colliding@example.com";
    let password_a = "password-tenant-a";
    let password_b = "password-tenant-b";

    let user_a_id = insert_user_in_tenant(
        &pool,
        common::DEFAULT_TENANT_ID,
        colliding_email,
        password_a,
        "admin",
    )
    .await;
    let (tenant_b_id, _admin_b_id, _admin_b_email, _admin_b_password) =
        common::seed_tenant_with_admin(&pool, "pms138-tenant-b").await;
    let user_b_id =
        insert_user_in_tenant(&pool, tenant_b_id, colliding_email, password_b, "admin").await;

    let app = common::boot(pool).await;

    // Hint -> tenant B. Must authenticate as B's user.
    let resp_b = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .json(&serde_json::json!({
            "email": colliding_email,
            "password": password_b,
            "tenant_id": tenant_b_id,
        }))
        .send()
        .await
        .expect("send login (tenant B hint)");
    assert_eq!(
        resp_b.status(),
        reqwest::StatusCode::OK,
        "tenant B login must succeed with the B-tenant hint"
    );
    let body_b: serde_json::Value = resp_b.json().await.expect("login B body");
    assert_eq!(
        body_b["user"]["id"].as_str(),
        Some(user_b_id.to_string().as_str()),
        "tenant-B hint must resolve to tenant B's user"
    );
    assert_eq!(
        body_b["user"]["tenant_id"].as_str(),
        Some(tenant_b_id.to_string().as_str()),
        "tenant-B hint must return tenant B in user.tenant_id"
    );

    // Hint -> default tenant. Must authenticate as A's user.
    let resp_a = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .json(&serde_json::json!({
            "email": colliding_email,
            "password": password_a,
            "tenant_id": common::DEFAULT_TENANT_ID,
        }))
        .send()
        .await
        .expect("send login (default-tenant hint)");
    assert_eq!(
        resp_a.status(),
        reqwest::StatusCode::OK,
        "tenant A login must succeed with the default-tenant hint"
    );
    let body_a: serde_json::Value = resp_a.json().await.expect("login A body");
    assert_eq!(
        body_a["user"]["id"].as_str(),
        Some(user_a_id.to_string().as_str()),
        "default-tenant hint must resolve to the default-tenant user"
    );
}

/// PMS-138 backward compat: clients that omit `tenant_id` continue to
/// land in the default tenant, so single-tenant deployments and any
/// existing SPA that has not yet been updated keep working.
#[sqlx::test]
async fn login_omitting_tenant_id_falls_back_to_default(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;

    let resp = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .json(&serde_json::json!({
            "email": email,
            "password": password,
        }))
        .send()
        .await
        .expect("send login (no tenant_id)");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "login must succeed when tenant_id is omitted (default-tenant fallback)"
    );
    let body: serde_json::Value = resp.json().await.expect("login body");
    assert_eq!(
        body["user"]["tenant_id"].as_str(),
        Some(common::DEFAULT_TENANT_ID.to_string().as_str()),
        "omitted tenant_id must resolve to the default tenant"
    );
}

/// PMS-138 wrong-hint pin: a hint that names a tenant where the email
/// does not exist must return 401, never accidentally cross-
/// authenticate against a different tenant's user.
#[sqlx::test]
async fn login_wrong_tenant_hint_returns_401(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let (tenant_c_id, _admin_c_id, _admin_c_email, _admin_c_password) =
        common::seed_tenant_with_admin(&pool, "pms138-tenant-c").await;

    let app = common::boot(pool).await;

    let resp = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .json(&serde_json::json!({
            "email": email,
            "password": password,
            "tenant_id": tenant_c_id,
        }))
        .send()
        .await
        .expect("send login (wrong-tenant hint)");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "wrong tenant_id hint must 401, never cross-authenticate"
    );
}

/// PMS-138 forgot-password sibling fix: with the same email under two
/// tenants the `tenant_id` hint on `/api/v1/auth/forgot-password` must
/// route the reset token to the user in the named tenant.
#[sqlx::test]
async fn forgot_password_with_tenant_hint_targets_correct_user(pool: PgPool) {
    let colliding_email = "colliding@example.com";
    let _user_a_id = insert_user_in_tenant(
        &pool,
        common::DEFAULT_TENANT_ID,
        colliding_email,
        "password-tenant-a",
        "admin",
    )
    .await;
    let (tenant_b_id, _admin_b_id, _admin_b_email, _admin_b_password) =
        common::seed_tenant_with_admin(&pool, "pms138-tenant-b-forgot").await;
    let user_b_id = insert_user_in_tenant(
        &pool,
        tenant_b_id,
        colliding_email,
        "password-tenant-b",
        "admin",
    )
    .await;

    let app = common::boot(pool).await;

    let resp = app
        .client
        .post(app.url("/api/v1/auth/forgot-password"))
        .json(&serde_json::json!({
            "email": colliding_email,
            "tenant_id": tenant_b_id,
        }))
        .send()
        .await
        .expect("send forgot-password (tenant B hint)");
    assert!(
        resp.status().is_success(),
        "forgot-password with tenant hint must 2xx; got {}",
        resp.status()
    );

    let (token_user_id, token_tenant_id): (Uuid, Uuid) =
        sqlx::query_as("SELECT user_id, tenant_id FROM password_reset_tokens WHERE tenant_id = $1")
            .bind(tenant_b_id)
            .fetch_one(&app.pool)
            .await
            .expect("read tenant B reset token");
    assert_eq!(
        token_user_id, user_b_id,
        "reset token must target tenant B's user, not the default-tenant collider"
    );
    assert_eq!(
        token_tenant_id, tenant_b_id,
        "reset token row must be scoped to tenant B"
    );

    let default_tenant_token_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM password_reset_tokens WHERE tenant_id = $1")
            .bind(common::DEFAULT_TENANT_ID)
            .fetch_one(&app.pool)
            .await
            .expect("count default-tenant reset tokens");
    assert_eq!(
        default_tenant_token_count, 0,
        "no reset token should have been issued for the default-tenant collider"
    );
}
