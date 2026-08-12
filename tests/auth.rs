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
//! - PMS-693: concurrent failed second-factor codes each increment the
//!   persistent attempt counter, and one TOTP step is spendable exactly once.
//! - PMS-694: a failed recovery code advances the same lockout counter a
//!   failed TOTP code does, and an accepted one clears it.

mod common;

use std::sync::Arc;

use chrono::{Duration, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use mokosh_server::modules::auth::{
    mfa_lock_seconds_sql, mfa_lockout_until, AuthService, LoginRequest,
};
use mokosh_server::utils::error::AppError;
use mokosh_server::utils::pagination::PaginationParams;
use mokosh_server::Database;

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
// MAPPS-348: tombstoned user gets 410 Gone (ACCOUNT_DELETED), not 401
// ============================================================================

/// MAPPS-348: after the Bunyip account_deleted webhook has soft-deleted the
/// user row, an authenticated request bearing the pre-tombstone JWT must
/// come back as 410 Gone with `code: ACCOUNT_DELETED`, not the generic 401.
/// Distinguishes "your account has been deleted" from "your session expired
/// (please refresh)" so the SPA can render its terminal modal instead of
/// falling into a token-refresh loop.
#[sqlx::test]
async fn tombstoned_user_gets_410_account_deleted_on_me(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    // Sanity: /me works while the user is active.
    let me = app
        .client
        .get(app.url("/api/v1/auth/me"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send /me pre-tombstone");
    assert_eq!(me.status(), reqwest::StatusCode::OK);

    // Simulate the Bunyip account_deleted webhook: soft-delete the row.
    // This is the same terminal state PMS-591 leaves the row in.
    sqlx::query("UPDATE users SET deleted_at = NOW() WHERE id = $1")
        .bind(admin_id)
        .execute(&pool)
        .await
        .expect("tombstone the seeded user");

    let me_after = app
        .client
        .get(app.url("/api/v1/auth/me"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send /me post-tombstone");
    assert_eq!(
        me_after.status(),
        reqwest::StatusCode::GONE,
        "/me must return 410 Gone once the user row is tombstoned"
    );
    let body: serde_json::Value = me_after.json().await.expect("/me body is JSON");
    assert_eq!(
        body["error"]["code"].as_str(),
        Some("ACCOUNT_DELETED"),
        "410 response must carry the ACCOUNT_DELETED code so the SPA can catch it"
    );
}

// ============================================================================
// PMS-410: theme preferences round-trip on PUT/GET /me
// ============================================================================

/// PMS-410: `PUT /api/v1/auth/me` persists `theme_base_mode` +
/// `theme_accent_id`; `GET /me` reads them back; omitting one field on a
/// later PUT leaves it unchanged (conditional UPDATE builder); an invalid
/// `theme_base_mode` is rejected with 422 by the custom validator.
#[sqlx::test]
async fn update_me_theme_prefs_round_trip(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    // Defaults are NULL before any update.
    let me = app
        .client
        .get(app.url("/api/v1/auth/me"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send /me request");
    let body: serde_json::Value = me.json().await.expect("/me body is JSON");
    assert!(
        body["theme_base_mode"].is_null(),
        "theme_base_mode defaults to null when unset"
    );
    assert!(
        body["theme_accent_id"].is_null(),
        "theme_accent_id defaults to null when unset"
    );

    // PUT both fields; the response echoes the new values.
    let put = app
        .client
        .put(app.url("/api/v1/auth/me"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "theme_base_mode": "dark",
            "theme_accent_id": "ocean",
        }))
        .send()
        .await
        .expect("send PUT /me with theme prefs");
    assert_eq!(
        put.status(),
        reqwest::StatusCode::OK,
        "PUT /me with valid theme prefs should succeed"
    );
    let put_body: serde_json::Value = put.json().await.expect("PUT /me body is JSON");
    assert_eq!(put_body["theme_base_mode"].as_str(), Some("dark"));
    assert_eq!(put_body["theme_accent_id"].as_str(), Some("ocean"));

    // GET /me reads the persisted values back.
    let me2 = app
        .client
        .get(app.url("/api/v1/auth/me"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send /me request after update");
    let body2: serde_json::Value = me2.json().await.expect("/me body is JSON");
    assert_eq!(
        body2["theme_base_mode"].as_str(),
        Some("dark"),
        "/me must reflect the persisted theme_base_mode"
    );
    assert_eq!(
        body2["theme_accent_id"].as_str(),
        Some("ocean"),
        "/me must reflect the persisted theme_accent_id"
    );

    // PUT only one field: the omitted field must stay unchanged (the
    // conditional UPDATE builder only touches supplied fields).
    let put2 = app
        .client
        .put(app.url("/api/v1/auth/me"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "theme_base_mode": "light" }))
        .send()
        .await
        .expect("send PUT /me with one theme field");
    assert_eq!(put2.status(), reqwest::StatusCode::OK);
    let put2_body: serde_json::Value = put2.json().await.expect("PUT /me body is JSON");
    assert_eq!(
        put2_body["theme_base_mode"].as_str(),
        Some("light"),
        "theme_base_mode updates to the supplied value"
    );
    assert_eq!(
        put2_body["theme_accent_id"].as_str(),
        Some("ocean"),
        "theme_accent_id is unchanged when omitted from the PUT body"
    );

    // An invalid base mode is rejected with 422 by the custom validator.
    let bad = app
        .client
        .put(app.url("/api/v1/auth/me"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "theme_base_mode": "neon" }))
        .send()
        .await
        .expect("send PUT /me with invalid theme_base_mode");
    assert_eq!(
        bad.status(),
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "an invalid theme_base_mode must be rejected with 422"
    );
}

// ============================================================================
// PMS-512: profile identity fields are Bunyip-owned and no longer editable
// ============================================================================

/// PMS-512: `first_name`, `last_name`, and `phone` are gone from
/// `UpdateUserRequest`, so `PUT /api/v1/auth/me` cannot mutate them: the body
/// keys are ignored and the `users` row keeps the values Bunyip seeded. This
/// is the mechanical guard on the removal - re-adding any of the three fields
/// to the request type makes this test fail. `GET /me` still returns all
/// three for display.
#[sqlx::test]
async fn put_me_cannot_mutate_bunyip_owned_profile_fields(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    // `phone` has no seeder, so set it directly: it must survive the PUT too.
    sqlx::query("UPDATE users SET phone = '+15550100' WHERE id = $1")
        .bind(admin_id)
        .execute(&pool)
        .await
        .expect("seed phone");

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    // A PUT carrying all three fields plus one still-editable field. The
    // editable field proves the request was accepted and applied, so an
    // unchanged name is immutability rather than a rejected request.
    let put = app
        .client
        .put(app.url("/api/v1/auth/me"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "first_name": "Hacked",
            "last_name": "Name",
            "phone": "+19995550000",
            "theme_accent_id": "ocean",
        }))
        .send()
        .await
        .expect("send PUT /me with Bunyip-owned fields");
    assert_eq!(
        put.status(),
        reqwest::StatusCode::OK,
        "the unknown keys are ignored, not rejected"
    );
    let put_body: serde_json::Value = put.json().await.expect("PUT /me body is JSON");
    assert_eq!(
        put_body["theme_accent_id"].as_str(),
        Some("ocean"),
        "the editable field in the same body must have been applied"
    );

    let (first, last, phone): (String, String, Option<String>) =
        sqlx::query_as("SELECT first_name, last_name, phone FROM users WHERE id = $1")
            .bind(admin_id)
            .fetch_one(&pool)
            .await
            .expect("read user row");
    assert_eq!(
        first, "Test",
        "first_name is Bunyip-owned, not user-editable"
    );
    assert_eq!(
        last, "Admin",
        "last_name is Bunyip-owned, not user-editable"
    );
    assert_eq!(
        phone.as_deref(),
        Some("+15550100"),
        "phone is no longer user-editable"
    );

    // GET /me still surfaces all three for display.
    let me: serde_json::Value = app
        .client
        .get(app.url("/api/v1/auth/me"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send /me request")
        .json()
        .await
        .expect("/me body is JSON");
    assert_eq!(me["first_name"].as_str(), Some("Test"));
    assert_eq!(me["last_name"].as_str(), Some("Admin"));
    assert_eq!(me["phone"].as_str(), Some("+15550100"));
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
        common::seed_user(&pool, common::DEFAULT_TENANT_ID, &e, "technician").await;
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
        common::seed_user(&pool, common::DEFAULT_TENANT_ID, &e, "technician").await;
    }
    for i in 0..2 {
        let e = format!("pms4test-mgr-{i}@example.com");
        common::seed_user(&pool, common::DEFAULT_TENANT_ID, &e, "manager").await;
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
    let (_uid, email, password) = common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "techguy@example.com",
        "technician",
    )
    .await;
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
    let secret = mokosh_server::utils::totp::base32_decode(secret_b32).expect("decode mfa secret");

    // Compute the TOTP code immediately before sending (no awaits between
    // here and `.send()`) so the 30-second step cannot roll over in the
    // gap and push the code outside the server's +-1 step verify window.
    let code_now = mokosh_server::utils::totp::code_at(&secret, Utc::now());
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
    let code_now = mokosh_server::utils::totp::code_at(&secret, Utc::now());
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
    let secret = mokosh_server::utils::totp::base32_decode(secret_b32).expect("decode mfa secret");
    let code_now = mokosh_server::utils::totp::code_at(&secret, Utc::now());

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
// PMS-502: second-factor anti-replay + per-account attempt lockout
// ============================================================================

/// Enroll + enable TOTP MFA for the just-logged-in admin and return the
/// decoded shared secret. Mirrors the setup half of
/// `mfa_challenge_happy_path`.
async fn enroll_and_enable_mfa(app: &common::TestApp, token: &str) -> Vec<u8> {
    let setup: serde_json::Value = app
        .client
        .post(app.url("/api/v1/auth/me/mfa/setup"))
        .bearer_auth(token)
        .send()
        .await
        .expect("send mfa setup")
        .json()
        .await
        .expect("mfa setup JSON");
    let secret_b32 = setup["secret"].as_str().expect("secret in mfa setup");
    let secret = mokosh_server::utils::totp::base32_decode(secret_b32).expect("decode mfa secret");

    let code_now = mokosh_server::utils::totp::code_at(&secret, Utc::now());
    let enable_resp = app
        .client
        .post(app.url("/api/v1/auth/me/mfa/enable"))
        .bearer_auth(token)
        .json(&serde_json::json!({ "code": code_now }))
        .send()
        .await
        .expect("send mfa enable");
    assert!(
        enable_resp.status().is_success(),
        "enable mfa should succeed, got {}",
        enable_resp.status()
    );
    secret
}

/// PMS-502 anti-replay: a TOTP code accepted once cannot be replayed while
/// it is still inside its +/-1 verify window. The first login consumes the
/// code's step; a second login with the SAME code is rejected.
#[sqlx::test]
async fn mfa_totp_code_cannot_be_replayed(pool: PgPool) {
    let (_uid, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;
    let secret = enroll_and_enable_mfa(&app, &token).await;

    // Capture one code and use it to log in successfully.
    let code = mokosh_server::utils::totp::code_at(&secret, Utc::now());
    let ok = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .json(&serde_json::json!({
            "email": email,
            "password": password,
            "mfa_code": code,
        }))
        .send()
        .await
        .expect("send first mfa login");
    assert_eq!(
        ok.status(),
        reqwest::StatusCode::OK,
        "fresh TOTP code logs in"
    );

    // Replay the very same code: the step has been consumed, so even though
    // the code is still inside its +/-1 window the login must fail.
    let replay = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .json(&serde_json::json!({
            "email": email,
            "password": password,
            "mfa_code": code,
        }))
        .send()
        .await
        .expect("send replay mfa login");
    assert_eq!(
        replay.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "replaying an already-accepted TOTP code must fail"
    );
}

/// PMS-502 lockout: repeated wrong second-factor codes arm a persistent
/// per-account lockout (`users.mfa_locked_until`), independent of the
/// in-memory login limiter, that rejects further attempts with 429 even
/// when a correct code is finally supplied.
#[sqlx::test]
async fn mfa_failed_codes_lock_account(pool: PgPool) {
    let (uid, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;
    let secret = enroll_and_enable_mfa(&app, &token).await;

    // A code that is deliberately not the current valid one.
    let valid = mokosh_server::utils::totp::code_at(&secret, Utc::now());
    let bad = if valid == "000000" {
        "111111"
    } else {
        "000000"
    };

    // Three wrong codes crosses the threshold and arms the lockout.
    for i in 0..3 {
        let resp = app
            .client
            .post(app.url("/api/v1/auth/login"))
            .json(&serde_json::json!({
                "email": email,
                "password": password,
                "mfa_code": bad,
            }))
            .send()
            .await
            .expect("send bad mfa login");
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::UNAUTHORIZED,
            "wrong code attempt {i} returns 401"
        );
    }

    // The lockout is persisted on the user row (survives a restart / works
    // across replicas), not just held in the in-memory limiter.
    let (failed, locked_until): (i32, Option<chrono::DateTime<Utc>>) =
        sqlx::query_as("SELECT mfa_failed_attempts, mfa_locked_until FROM users WHERE id = $1")
            .bind(uid)
            .fetch_one(&app.pool)
            .await
            .expect("read mfa lockout state");
    assert!(
        failed >= 3,
        "failed-attempt counter persisted, got {failed}"
    );
    assert!(
        locked_until.is_some_and(|until| until > Utc::now()),
        "lockout window armed and in the future"
    );

    // Even a correct code is now rejected with 429 while the lockout holds.
    let fresh = mokosh_server::utils::totp::code_at(&secret, Utc::now());
    let locked = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .json(&serde_json::json!({
            "email": email,
            "password": password,
            "mfa_code": fresh,
        }))
        .send()
        .await
        .expect("send post-lock mfa login");
    assert_eq!(
        locked.status(),
        reqwest::StatusCode::TOO_MANY_REQUESTS,
        "a correct code is still rejected while the account is locked"
    );
}

// ============================================================================
// PMS-693: the attempt counter increments atomically, not from a stale read
// ============================================================================

/// Enable TOTP MFA for `user_id` straight on the row and return the shared
/// secret. The HTTP enrollment path is covered by `mfa_challenge_happy_path`;
/// the concurrency pins below call `AuthService::login` directly (the router's
/// 5/min per-email limiter would reject most of a 20-request burst before it
/// ever reached the MFA branch), so they seed the same end state in SQL.
async fn seed_mfa_enabled(pool: &PgPool, user_id: Uuid) -> Vec<u8> {
    let secret = mokosh_server::utils::totp::generate_secret();
    let secret_b32 = mokosh_server::utils::totp::base32_encode(&secret);
    sqlx::query("UPDATE users SET mfa_enabled = TRUE, mfa_secret = $1 WHERE id = $2")
        .bind(&secret_b32)
        .bind(user_id)
        .execute(pool)
        .await
        .expect("enable MFA on the seeded user");
    secret.to_vec()
}

fn login_request(email: &str, password: &str, mfa_code: &str) -> LoginRequest {
    serde_json::from_value(serde_json::json!({
        "email": email,
        "password": password,
        "mfa_code": mfa_code,
    }))
    .expect("build LoginRequest")
}

fn auth_service(pool: &PgPool) -> Arc<AuthService> {
    Arc::new(AuthService::new(
        Database::from_pool(pool.clone()),
        "test-secret".into(),
        vec![],
    ))
}

/// PMS-693: a burst of concurrent wrong second-factor codes must count every
/// one of them. Pre-fix each request read `mfa_failed_attempts` in its own
/// transaction, so all of them computed `0 + 1` and the column ended at 1 no
/// matter how many codes were guessed: the lockout never armed and the
/// attacker got a whole burst of guesses per round trip.
#[sqlx::test]
async fn concurrent_wrong_mfa_codes_all_count(pool: PgPool) {
    let (uid, email, password) = common::seed_admin(&pool).await;
    let secret = seed_mfa_enabled(&pool, uid).await;
    let auth = auth_service(&pool);

    // 21 distinct six-digit codes the verifier rejects (20 for the burst plus
    // one to probe the lockout afterwards).
    let codes: Vec<String> = (0..64)
        .map(|i| format!("{:06}", 100_000 + i))
        .filter(|c| mokosh_server::utils::totp::verify(&secret, c, Utc::now(), 1).is_none())
        .take(21)
        .collect();
    assert_eq!(codes.len(), 21, "need 21 codes that are all wrong");

    let mut handles = Vec::new();
    for code in &codes[..20] {
        let auth = Arc::clone(&auth);
        let req = login_request(&email, &password, code);
        handles.push(tokio::spawn(async move {
            auth.login(&req, None, None).await.is_ok()
        }));
    }
    for h in handles {
        assert!(
            !h.await.expect("login task joins"),
            "a wrong second-factor code must never log in"
        );
    }

    let failed: i32 = sqlx::query_scalar("SELECT mfa_failed_attempts FROM users WHERE id = $1")
        .bind(uid)
        .fetch_one(&pool)
        .await
        .expect("read mfa_failed_attempts");
    assert!(
        failed >= 20,
        "every concurrent failure is counted, got {failed}"
    );

    // The 21st attempt is refused by the armed lockout, not merely rejected
    // as a bad code.
    let err = auth
        .login(&login_request(&email, &password, &codes[20]), None, None)
        .await
        .expect_err("21st attempt must fail");
    assert!(
        matches!(err, AppError::RateLimited),
        "the lockout is armed, so the next attempt is rate-limited, got {err:?}"
    );
}

/// PMS-693 / PMS-502 anti-replay: two concurrent logins presenting the SAME
/// valid TOTP code must not both succeed. Pre-fix both compared the code's
/// step against a watermark read before either write, so both passed; the
/// advance is now a compare-and-set inside the UPDATE.
#[sqlx::test]
async fn concurrent_same_totp_code_accepted_once(pool: PgPool) {
    let (uid, email, password) = common::seed_admin(&pool).await;
    let secret = seed_mfa_enabled(&pool, uid).await;
    let auth = auth_service(&pool);

    // Compute the code immediately before spawning so the 30-second step
    // cannot roll past the verifier's +-1 window.
    let code = mokosh_server::utils::totp::code_at(&secret, Utc::now());
    let mut handles = Vec::new();
    for _ in 0..2 {
        let auth = Arc::clone(&auth);
        let req = login_request(&email, &password, &code);
        handles.push(tokio::spawn(async move {
            auth.login(&req, None, None).await.is_ok()
        }));
    }
    let mut wins = 0;
    for h in handles {
        if h.await.expect("login task joins") {
            wins += 1;
        }
    }
    assert_eq!(
        wins, 1,
        "exactly one of two concurrent logins with the same TOTP code succeeds"
    );
}

/// PMS-693: `register_failed_mfa` derives the lock window in SQL from the
/// post-increment counter, so that expression is a second copy of the schedule
/// `mfa_lockout_until` defines in Rust. Pin the two together across the whole
/// documented table (`1..=12` spans below-threshold, the doubling ramp and the
/// 3600s cap) so neither can drift.
#[sqlx::test]
async fn mfa_lock_seconds_sql_matches_rust_schedule(pool: PgPool) {
    let sql = format!("SELECT {}", mfa_lock_seconds_sql("$1::int"));
    let now = Utc::now();
    for n in 1..=12 {
        let sql_secs: Option<f64> = sqlx::query_scalar(&sql)
            .bind(n)
            .fetch_one(&pool)
            .await
            .expect("evaluate the SQL lockout schedule");
        let rust_secs = mfa_lockout_until(n, now).map(|until| (until - now).num_seconds());
        assert_eq!(
            sql_secs.map(|s| s as i64),
            rust_secs,
            "SQL and Rust lockout schedules disagree at failed_count = {n}"
        );
    }
}

// ============================================================================
// PMS-694: a failed recovery code counts against the same MFA lockout
// ============================================================================

fn recovery_login_request(email: &str, password: &str, recovery_code: &str) -> LoginRequest {
    serde_json::from_value(serde_json::json!({
        "email": email,
        "password": password,
        "recovery_code": recovery_code,
    }))
    .expect("build recovery LoginRequest")
}

/// PMS-694: guessing recovery codes must arm the PMS-502 lockout exactly like
/// guessing TOTP codes. Pre-fix the `!removed` branch returned `Unauthorized`
/// without touching `mfa_failed_attempts`, so an attacker holding the password
/// got unlimited second-factor guesses just by sending `recovery_code` instead
/// of `mfa_code` (and, since nothing else armed it, the lockout never applied
/// to the TOTP path either).
///
/// Calls `AuthService::login` directly for the same reason the PMS-693 pins do:
/// the router's 5/min per-email limiter would answer 429 on its own and mask
/// which gate refused the attempt.
#[sqlx::test]
async fn failed_recovery_codes_lock_account(pool: PgPool) {
    let (uid, email, password) = common::seed_admin(&pool).await;
    seed_mfa_enabled(&pool, uid).await;
    // A populated code set the guesses can miss against.
    sqlx::query("UPDATE users SET mfa_recovery_codes_hashes = $1 WHERE id = $2")
        .bind(vec!["a".repeat(64), "b".repeat(64)])
        .bind(uid)
        .execute(&pool)
        .await
        .expect("seed recovery code hashes");
    let auth = auth_service(&pool);

    // Three wrong recovery codes cross the threshold and arm the lockout.
    for i in 0..3 {
        let err = auth
            .login(
                &recovery_login_request(&email, &password, &format!("wrong-code-{i}")),
                None,
                None,
            )
            .await
            .expect_err("a wrong recovery code must never log in");
        assert!(
            matches!(err, AppError::Unauthorized),
            "wrong recovery code attempt {i} is a 401, got {err:?}"
        );
    }

    let (failed, locked_until): (i32, Option<chrono::DateTime<Utc>>) =
        sqlx::query_as("SELECT mfa_failed_attempts, mfa_locked_until FROM users WHERE id = $1")
            .bind(uid)
            .fetch_one(&pool)
            .await
            .expect("read mfa lockout state");
    assert_eq!(failed, 3, "every wrong recovery code is counted");
    assert!(
        locked_until.is_some_and(|until| until > Utc::now()),
        "lockout window armed and in the future"
    );

    // The 4th attempt is refused by the armed lockout, not merely rejected as
    // a bad code.
    let err = auth
        .login(
            &recovery_login_request(&email, &password, "wrong-code-3"),
            None,
            None,
        )
        .await
        .expect_err("4th attempt must fail");
    assert!(
        matches!(err, AppError::RateLimited),
        "the lockout is armed, so the next attempt is rate-limited, got {err:?}"
    );
}

/// PMS-694: the mirror image. A valid recovery code succeeds while failures
/// have accumulated below the threshold and clears the counter + lockout, so a
/// user who locked themselves out of TOTP is not still penalised afterwards.
/// It must NOT move `mfa_last_used_step`: a recovery code is not a TOTP step,
/// and dragging the anti-replay watermark forward would invalidate live codes.
#[sqlx::test]
async fn recovery_code_success_clears_mfa_counters(pool: PgPool) {
    let (uid, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    // Enroll + enable inline (rather than via `enroll_and_enable_mfa`) because
    // the plaintext recovery codes are returned exactly once, by `enable`.
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
    let secret = mokosh_server::utils::totp::base32_decode(secret_b32).expect("decode mfa secret");
    let code_now = mokosh_server::utils::totp::code_at(&secret, Utc::now());
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
    let recovery = enable_json["recovery_codes"][0]
        .as_str()
        .expect("a recovery code")
        .to_string();

    // Two failures already banked (still under the 3-failure threshold, so no
    // lockout is armed) plus a watermark the recovery code must not disturb.
    const WATERMARK: i64 = 12_345;
    sqlx::query("UPDATE users SET mfa_failed_attempts = 2, mfa_last_used_step = $1 WHERE id = $2")
        .bind(WATERMARK)
        .bind(uid)
        .execute(&pool)
        .await
        .expect("seed a partial failure count");

    let resp = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .json(&serde_json::json!({
            "email": email,
            "password": password,
            "recovery_code": recovery,
        }))
        .send()
        .await
        .expect("send recovery login");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "a valid recovery code still logs in with failures banked"
    );
    let body: serde_json::Value = resp.json().await.expect("recovery login JSON");
    assert!(
        !body["access_token"].as_str().unwrap_or("").is_empty(),
        "access_token populated after the recovery code is accepted"
    );

    let (failed, locked_until, step): (i32, Option<chrono::DateTime<Utc>>, Option<i64>) =
        sqlx::query_as(
            "SELECT mfa_failed_attempts, mfa_locked_until, mfa_last_used_step \
             FROM users WHERE id = $1",
        )
        .bind(uid)
        .fetch_one(&pool)
        .await
        .expect("read mfa state after the recovery login");
    assert_eq!(failed, 0, "the failure counter is cleared");
    assert!(locked_until.is_none(), "the lockout window is cleared");
    assert_eq!(
        step,
        Some(WATERMARK),
        "a recovery code must not advance the TOTP anti-replay watermark"
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
/// Each `#[sqlx::test]` boots a fresh `AuthRateLimiter` instance because
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

/// PMS-138 multi-tenant resolution: with the same email under two
/// tenants the `tenant_id` hint must steer the lookup to the user in
/// the named tenant. Pre-PMS-138 the email-only lookup returned the
/// oldest-created row regardless of which tenant the caller intended.
#[sqlx::test]
async fn login_with_tenant_hint_resolves_to_correct_tenant(pool: PgPool) {
    let colliding_email = "colliding@example.com";

    // Same email under two tenants, same uniform seed password. The
    // `tenant_id` hint (not the password) is what must disambiguate.
    let (user_a_id, _, password) =
        common::seed_user(&pool, common::DEFAULT_TENANT_ID, colliding_email, "admin").await;
    let (tenant_b_id, _admin_b_id, _admin_b_email, _admin_b_password) =
        common::seed_tenant_with_admin(&pool, "pms138-tenant-b").await;
    let (user_b_id, _, _) = common::seed_user(&pool, tenant_b_id, colliding_email, "admin").await;

    let app = common::boot(pool).await;

    // Hint -> tenant B. Must authenticate as B's user.
    let resp_b = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .json(&serde_json::json!({
            "email": colliding_email,
            "password": password,
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
            "password": password,
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

// ============================================================================
// MAPPS-396: tenant_slug hint (standalone SPA login form)
// ============================================================================

/// MAPPS-396: the standalone login form types a slug rather than a UUID,
/// so `tenant_slug: "acme"` on the login body must resolve to acme's
/// tenant_id server-side and authenticate the acme-tenant user.
#[sqlx::test]
async fn login_with_tenant_slug_resolves_to_correct_tenant(pool: PgPool) {
    let (tenant_id, user_id, email, password) =
        common::seed_tenant_with_admin(&pool, "acme-mapps396").await;

    let app = common::boot(pool).await;

    let resp = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .json(&serde_json::json!({
            "email": email,
            "password": password,
            "tenant_slug": "acme-mapps396",
        }))
        .send()
        .await
        .expect("send login (tenant_slug hint)");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "tenant_slug=acme-mapps396 must resolve to acme's tenant and authenticate"
    );
    let body: serde_json::Value = resp.json().await.expect("login body");
    assert_eq!(
        body["user"]["id"].as_str(),
        Some(user_id.to_string().as_str()),
        "tenant_slug hint must land on the acme-tenant user"
    );
    assert_eq!(
        body["user"]["tenant_id"].as_str(),
        Some(tenant_id.to_string().as_str()),
        "tenant_slug hint must return acme's tenant_id"
    );
}

/// MAPPS-396: `tenant_id` wins when both are set, so a host-derived
/// UUID hint is not silently overridden by a mistyped slug field.
#[sqlx::test]
async fn login_with_both_tenant_id_and_slug_prefers_id(pool: PgPool) {
    let (tenant_a_id, user_a_id, email_a, password_a) =
        common::seed_tenant_with_admin(&pool, "acme-both-a").await;
    let (_tenant_b_id, _user_b_id, _email_b, _password_b) =
        common::seed_tenant_with_admin(&pool, "beta-both-b").await;

    let app = common::boot(pool).await;

    let resp = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .json(&serde_json::json!({
            "email": email_a,
            "password": password_a,
            "tenant_id": tenant_a_id,
            "tenant_slug": "beta-both-b",
        }))
        .send()
        .await
        .expect("send login (both hints)");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "tenant_id must win over tenant_slug"
    );
    let body: serde_json::Value = resp.json().await.expect("login body");
    assert_eq!(
        body["user"]["id"].as_str(),
        Some(user_a_id.to_string().as_str()),
        "tenant_id must be the effective hint when both are set"
    );
}

/// MAPPS-396: an unknown slug must 401 (fail-closed), never
/// leak-through as "default tenant" and let the wrong user in.
#[sqlx::test]
async fn login_with_unknown_tenant_slug_401s(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;

    let resp = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .json(&serde_json::json!({
            "email": email,
            "password": password,
            "tenant_slug": "nope-does-not-exist",
        }))
        .send()
        .await
        .expect("send login (unknown slug)");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "unknown slug must 401 (fail-closed), never leak-through as default tenant"
    );
}

/// MAPPS-396: a slug that names a suspended tenant must 401 the same
/// way an unknown slug does, so the endpoint cannot be walked to
/// enumerate active-vs-suspended tenants.
#[sqlx::test]
async fn login_with_suspended_tenant_slug_401s(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;

    // Insert a suspended tenant directly - the seed helper only makes
    // active ones.
    sqlx::query(
        r#"
        INSERT INTO tenants (id, name, slug, status, kind)
        VALUES ($1, 'Suspended MSP', 'suspended-mapps396', 'suspended', 'org')
        "#,
    )
    .bind(uuid::Uuid::new_v4())
    .execute(&pool)
    .await
    .expect("seed suspended tenant");

    let app = common::boot(pool).await;

    let resp = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .json(&serde_json::json!({
            "email": email,
            "password": password,
            "tenant_slug": "suspended-mapps396",
        }))
        .send()
        .await
        .expect("send login (suspended slug)");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "suspended slug must 401 (matches unknown-slug shape so tenant status is not enumerable)"
    );
}

/// PMS-138 forgot-password sibling fix: with the same email under two
/// tenants the `tenant_id` hint on `/api/v1/auth/forgot-password` must
/// route the reset token to the user in the named tenant.
#[sqlx::test]
async fn forgot_password_with_tenant_hint_targets_correct_user(pool: PgPool) {
    let colliding_email = "colliding@example.com";
    let (_user_a_id, _, _) =
        common::seed_user(&pool, common::DEFAULT_TENANT_ID, colliding_email, "admin").await;
    let (tenant_b_id, _admin_b_id, _admin_b_email, _admin_b_password) =
        common::seed_tenant_with_admin(&pool, "pms138-tenant-b-forgot").await;
    let (user_b_id, _, _) = common::seed_user(&pool, tenant_b_id, colliding_email, "admin").await;

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

// ============================================================================
// PMS-260: cross-tenant leak fixes in the auth session methods
// ============================================================================

/// Insert an active (`expires_at` in the future) session row directly, so a
/// test can stand up the leak scenario the seed helpers cannot express: the
/// same `user_id` carrying sessions under more than one tenant. The
/// `user_sessions.tenant_id` / `user_id` FKs are independent (no composite
/// constraint), so a session can legally reference a tenant other than the
/// user's home tenant - which is exactly the leak PMS-260 closes.
fn build_pagination() -> PaginationParams {
    PaginationParams {
        page: 1,
        per_page: 25,
        sort: None,
        sort_dir: "desc".to_string(),
    }
}

async fn insert_active_session(
    pool: &PgPool,
    tenant_id: Uuid,
    user_id: Uuid,
    token_hash: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO user_sessions (id, tenant_id, user_id, token_hash, expires_at)
        VALUES ($1, $2, $3, $4, NOW() + INTERVAL '1 hour')
        "#,
    )
    .bind(id)
    .bind(tenant_id)
    .bind(user_id)
    .bind(token_hash)
    .execute(pool)
    .await
    .expect("insert active session");
    id
}

/// PMS-260: `get_user_sessions` must bind `tenant_id` so a `user_id` that
/// carries sessions under two tenants only ever enumerates the caller's-tenant
/// sessions. Pre-fix the `WHERE user_id = $1`-only query returned both rows.
#[sqlx::test]
async fn get_user_sessions_is_tenant_scoped(pool: PgPool) {
    let (user_id, _email, _password) = common::seed_admin(&pool).await;
    let (tenant_b_id, _b_uid, _b_email, _b_password) =
        common::seed_tenant_with_admin(&pool, "pms260-sessions-b").await;

    // Same user_id, two tenants: one session in the caller's (default) tenant,
    // one planted under tenant B.
    let session_a =
        insert_active_session(&pool, common::DEFAULT_TENANT_ID, user_id, "hash-a").await;
    let _session_b = insert_active_session(&pool, tenant_b_id, user_id, "hash-b").await;

    let auth = AuthService::new(
        Database::from_pool(pool.clone()),
        "test-secret".into(),
        vec![],
    );
    let (sessions, total) = auth
        .get_user_sessions(
            common::DEFAULT_TENANT_ID,
            user_id,
            Uuid::nil(),
            &build_pagination(),
        )
        .await
        .expect("get_user_sessions");

    assert_eq!(total, 1, "only the caller's-tenant session is counted");
    assert_eq!(sessions.len(), 1, "only the caller's-tenant session listed");
    assert_eq!(
        sessions[0].id, session_a,
        "the listed session is the one in the caller's tenant, not tenant B's"
    );
}

/// PMS-260: `logout_all` must bind `tenant_id` so it cannot delete sessions a
/// user holds under a different tenant. Pre-fix the `WHERE user_id = $1`-only
/// DELETE wiped both rows.
#[sqlx::test]
async fn logout_all_is_tenant_scoped(pool: PgPool) {
    let (user_id, _email, _password) = common::seed_admin(&pool).await;
    let (tenant_b_id, _b_uid, _b_email, _b_password) =
        common::seed_tenant_with_admin(&pool, "pms260-logout-b").await;

    insert_active_session(&pool, common::DEFAULT_TENANT_ID, user_id, "hash-a").await;
    let session_b = insert_active_session(&pool, tenant_b_id, user_id, "hash-b").await;

    let auth = AuthService::new(
        Database::from_pool(pool.clone()),
        "test-secret".into(),
        vec![],
    );
    auth.logout_all(common::DEFAULT_TENANT_ID, user_id)
        .await
        .expect("logout_all");

    let remaining: Vec<(Uuid, Uuid)> =
        sqlx::query_as("SELECT id, tenant_id FROM user_sessions WHERE user_id = $1")
            .bind(user_id)
            .fetch_all(&pool)
            .await
            .expect("read remaining sessions");
    assert_eq!(
        remaining.len(),
        1,
        "only the caller's-tenant session is deleted; tenant B's survives"
    );
    assert_eq!(
        remaining[0].0, session_b,
        "tenant B's session is the survivor"
    );
    assert_eq!(
        remaining[0].1, tenant_b_id,
        "survivor is scoped to tenant B"
    );
}

/// PMS-260: the two intentionally-cross-tenant login helpers
/// (`auth::find_user_placement`, `invitations::newest_pending_for`) read across
/// tenants by design and are only safe because the sole caller is the
/// pre-session bunyip login/placement path (`middleware::place_bunyip_user`).
/// This guard pins that invariant: no HTTP route handler (`*/routes.rs`) may
/// reference them, where an authenticated caller could probe other tenants.
#[test]
fn routes_do_not_reach_global_login_helpers() {
    const FORBIDDEN: [&str; 2] = ["find_user_placement", "newest_pending_for"];

    let modules_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/modules");

    fn collect_routes(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read_dir under src/modules") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                collect_routes(&path, out);
            } else if path.file_name().and_then(|n| n.to_str()) == Some("routes.rs") {
                out.push(path);
            }
        }
    }

    let mut route_files = Vec::new();
    collect_routes(&modules_dir, &mut route_files);
    assert!(
        !route_files.is_empty(),
        "expected at least one routes.rs under src/modules"
    );

    for file in &route_files {
        let src = std::fs::read_to_string(file).expect("read routes.rs");
        for needle in FORBIDDEN {
            assert!(
                !src.contains(needle),
                "{} references `{}`: a request handler must never call the \
                 cross-tenant login helper (PMS-260)",
                file.display(),
                needle
            );
        }
    }
}

// ============================================================================
// PMS-625: role ceiling holds on the UPDATE path, not just create
// ============================================================================

/// PMS-625: the admin `PUT /users/{id}` path must enforce the same PMS-503
/// role ceiling as `POST /users`. Without it a tenant `admin` (rank 2) could
/// elevate any user - including themselves via `PUT /users/{self}`, which is
/// NOT the role-sanitizing `/me` handler - to `super_admin` (rank 3), a
/// platform-level cross-tenant account. Pins that an above-ceiling role is
/// rejected with 403 while an at-or-below-ceiling change still succeeds.
#[sqlx::test]
async fn update_user_enforces_role_ceiling(pool: PgPool) {
    // Caller is a tenant admin (rank 2), NOT a super_admin.
    let (_admin_id, admin_email, admin_password) = common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "ceiling-admin@example.com",
        "admin",
    )
    .await;
    // Target the admin will try to elevate.
    let (target_id, _t_email, _t_pw) = common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "ceiling-target@example.com",
        "technician",
    )
    .await;

    let app = common::boot(pool).await;
    let token = common::login(&app, &admin_email, &admin_password).await;

    // Elevating the target to super_admin must be forbidden.
    let denied = app
        .client
        .put(app.url(&format!("/api/v1/auth/users/{target_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "role": "super_admin" }))
        .send()
        .await
        .expect("send PUT elevate-to-super_admin");
    assert_eq!(
        denied.status(),
        reqwest::StatusCode::FORBIDDEN,
        "an admin must not be able to grant super_admin via the update path"
    );

    // A within-ceiling change (technician -> manager) still succeeds.
    let allowed = app
        .client
        .put(app.url(&format!("/api/v1/auth/users/{target_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "role": "manager" }))
        .send()
        .await
        .expect("send PUT within-ceiling role change");
    assert_eq!(
        allowed.status(),
        reqwest::StatusCode::OK,
        "an at-or-below-ceiling role change must still be allowed"
    );
}

// ============================================================================
// PMS-659: password-reset flow verification (redeem, expiry, single-use,
// session revocation, no-enumeration). The emailed token is `{user_id}.{secret}`
// where only the Argon2 hash of `secret` is stored, so the secret cannot be read
// back from the row - these tests mint a row with a known secret to exercise the
// redeem half of the flow that the request-side tests cannot reach.
// ============================================================================

/// Insert a redeemable `password_reset_tokens` row for `user_id` with a known
/// secret and the given expiry, and return the emailed `{user_id}.{secret}`
/// token. Writes the Argon2 hash exactly as `request_password_reset` does.
async fn craft_reset_token(
    pool: &PgPool,
    tenant_id: Uuid,
    user_id: Uuid,
    expires_at: chrono::DateTime<Utc>,
) -> String {
    // A dotless secret so `{user_id}.{secret}` splits cleanly on the first dot.
    let secret = "pms659secretvaluewithoutanydots0";
    let token_hash =
        mokosh_server::utils::crypto::hash_password(secret).expect("hash the reset secret");
    sqlx::query(
        "INSERT INTO password_reset_tokens (tenant_id, user_id, token_hash, expires_at) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(tenant_id)
    .bind(user_id)
    .bind(&token_hash)
    .bind(expires_at)
    .execute(pool)
    .await
    .expect("insert crafted reset token");
    format!("{user_id}.{secret}")
}

/// AC1/AC2: a valid reset changes the password, marks the token used, and
/// revokes the user's sessions (`logout_all`). Confirms end to end that the old
/// password stops working and the new one logs in.
#[sqlx::test]
async fn reset_password_changes_password_and_revokes_sessions(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;

    // Log in to create a live session row, then confirm it exists.
    let _token = common::login(&app, &email, &password).await;
    let sessions_before: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM user_sessions WHERE user_id = $1")
            .bind(admin_id)
            .fetch_one(&app.pool)
            .await
            .expect("count sessions before reset");
    assert!(
        sessions_before >= 1,
        "logging in must create at least one session row"
    );

    let token = craft_reset_token(
        &app.pool,
        common::DEFAULT_TENANT_ID,
        admin_id,
        Utc::now() + Duration::hours(1),
    )
    .await;
    let new_password = "brand-new-password-123";
    let resp = app
        .client
        .post(app.url("/api/v1/auth/reset-password"))
        .json(&serde_json::json!({
            "token": token,
            "new_password": new_password,
            "confirm_password": new_password,
        }))
        .send()
        .await
        .expect("send reset-password");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "a valid reset token must succeed"
    );

    // Sessions revoked.
    let sessions_after: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM user_sessions WHERE user_id = $1")
            .bind(admin_id)
            .fetch_one(&app.pool)
            .await
            .expect("count sessions after reset");
    assert_eq!(
        sessions_after, 0,
        "a password reset must revoke all of the user's sessions"
    );

    // PMS-681: the reset stamps password_changed_at, which is what invalidates
    // every access token issued before it (the session delete above only
    // revokes refresh).
    let password_changed_at: Option<chrono::DateTime<Utc>> =
        sqlx::query_scalar("SELECT password_changed_at FROM users WHERE id = $1")
            .bind(admin_id)
            .fetch_one(&app.pool)
            .await
            .expect("read password_changed_at after reset");
    assert!(
        password_changed_at.is_some(),
        "reset must stamp password_changed_at so pre-reset access tokens are rejected"
    );

    // Token marked single-use.
    let used_at: Option<chrono::DateTime<Utc>> =
        sqlx::query_scalar("SELECT used_at FROM password_reset_tokens WHERE user_id = $1")
            .bind(admin_id)
            .fetch_one(&app.pool)
            .await
            .expect("read token used_at");
    assert!(
        used_at.is_some(),
        "the redeemed token must be stamped used_at"
    );

    // Old password rejected, new password accepted.
    let old_login = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .json(&serde_json::json!({ "email": email, "password": password }))
        .send()
        .await
        .expect("send old-password login");
    assert_eq!(
        old_login.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "the old password must no longer authenticate"
    );
    let new_session_token = common::login(&app, &email, new_password).await;
    assert!(
        !new_session_token.is_empty(),
        "the new password must authenticate"
    );
}

/// AC2: an expired token is rejected (the `expires_at > NOW()` guard).
#[sqlx::test]
async fn reset_password_rejects_expired_token(pool: PgPool) {
    let (admin_id, _email, _password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;

    let token = craft_reset_token(
        &app.pool,
        common::DEFAULT_TENANT_ID,
        admin_id,
        Utc::now() - Duration::hours(1),
    )
    .await;
    let resp = app
        .client
        .post(app.url("/api/v1/auth/reset-password"))
        .json(&serde_json::json!({
            "token": token,
            "new_password": "brand-new-password-123",
            "confirm_password": "brand-new-password-123",
        }))
        .send()
        .await
        .expect("send reset with expired token");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "an expired reset token must be rejected"
    );
}

/// AC2: a token is single-use (`used_at IS NULL` guard). The second redeem of
/// the same token fails.
#[sqlx::test]
async fn reset_password_token_is_single_use(pool: PgPool) {
    let (admin_id, _email, _password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;

    let token = craft_reset_token(
        &app.pool,
        common::DEFAULT_TENANT_ID,
        admin_id,
        Utc::now() + Duration::hours(1),
    )
    .await;
    let body = serde_json::json!({
        "token": token,
        "new_password": "brand-new-password-123",
        "confirm_password": "brand-new-password-123",
    });

    let first = app
        .client
        .post(app.url("/api/v1/auth/reset-password"))
        .json(&body)
        .send()
        .await
        .expect("first redeem");
    assert_eq!(
        first.status(),
        reqwest::StatusCode::OK,
        "the first redeem of a valid token succeeds"
    );

    let second = app
        .client
        .post(app.url("/api/v1/auth/reset-password"))
        .json(&body)
        .send()
        .await
        .expect("second redeem");
    assert_eq!(
        second.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "an already-used token must not be redeemable again"
    );
}

/// AC1: a malformed token, and a well-formed token whose secret does not match
/// the stored hash, are both rejected (no password change).
#[sqlx::test]
async fn reset_password_rejects_malformed_and_wrong_secret(pool: PgPool) {
    let (admin_id, _email, _password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;

    // A valid row exists, but the requests below present bad tokens.
    let _token = craft_reset_token(
        &app.pool,
        common::DEFAULT_TENANT_ID,
        admin_id,
        Utc::now() + Duration::hours(1),
    )
    .await;

    let malformed = app
        .client
        .post(app.url("/api/v1/auth/reset-password"))
        .json(&serde_json::json!({
            "token": "not-a-valid-token",
            "new_password": "brand-new-password-123",
            "confirm_password": "brand-new-password-123",
        }))
        .send()
        .await
        .expect("send malformed token");
    assert_eq!(
        malformed.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "a token without the user-bound shape must be rejected"
    );

    let wrong_secret = app
        .client
        .post(app.url("/api/v1/auth/reset-password"))
        .json(&serde_json::json!({
            "token": format!("{admin_id}.wrongsecretvaluethatwontmatch"),
            "new_password": "brand-new-password-123",
            "confirm_password": "brand-new-password-123",
        }))
        .send()
        .await
        .expect("send wrong-secret token");
    assert_eq!(
        wrong_secret.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "a token whose secret does not match the stored hash must be rejected"
    );
}

/// AC1: requesting a reset for an address that does not exist returns 2xx and
/// issues no token, so the endpoint never reveals whether an email is
/// registered (no user enumeration).
#[sqlx::test]
async fn forgot_password_unknown_email_issues_no_token(pool: PgPool) {
    // Seed an admin so the default tenant/config exists, then request a reset for
    // a different, unknown address.
    let (_admin_id, _email, _password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;

    let resp = app
        .client
        .post(app.url("/api/v1/auth/forgot-password"))
        .json(&serde_json::json!({ "email": "nobody-unknown-pms659@example.com" }))
        .send()
        .await
        .expect("send forgot-password for unknown email");
    assert!(
        resp.status().is_success(),
        "forgot-password must 2xx even for an unknown email; got {}",
        resp.status()
    );

    let token_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM password_reset_tokens")
        .fetch_one(&app.pool)
        .await
        .expect("count reset tokens");
    assert_eq!(
        token_count, 0,
        "no reset token may be issued for an unknown email"
    );
}

/// PMS-680: `/auth/forgot-password` is rate-limited per (IP, email) like login.
/// The 4th request for one email within a minute trips the 3/min per-email cap
/// with 429 + `Retry-After`, so a known address cannot be reset-email bombed.
/// The email need not belong to a real user: the limiter runs before the
/// (silent-success) lookup, so an unknown address is throttled the same.
#[sqlx::test]
async fn forgot_password_rate_limit_triggers_429(pool: PgPool) {
    let app = common::boot(pool).await;
    let body = serde_json::json!({ "email": "reset-flood-pms680@example.com" });

    // First 3 requests are within the per-email quota (silent success).
    for i in 0..3 {
        let resp = app
            .client
            .post(app.url("/api/v1/auth/forgot-password"))
            .json(&body)
            .send()
            .await
            .expect("send forgot-password within quota");
        assert!(
            resp.status().is_success(),
            "request {i} should be 2xx within quota; got {}",
            resp.status()
        );
    }

    // 4th request trips the per-email cap.
    let resp = app
        .client
        .post(app.url("/api/v1/auth/forgot-password"))
        .json(&body)
        .send()
        .await
        .expect("send over-quota forgot-password");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::TOO_MANY_REQUESTS,
        "the 4th reset request for one email must trip the rate limit"
    );

    let retry_after = resp
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .expect("Retry-After header present on 429")
        .to_str()
        .expect("Retry-After is ASCII");
    let secs: u64 = retry_after
        .parse()
        .expect("Retry-After parses as a positive integer");
    assert!(secs >= 1, "Retry-After must be at least 1 second");

    let json: serde_json::Value = resp.json().await.expect("rate-limit body is JSON");
    assert_eq!(json["error"].as_str(), Some("rate_limited"));
    assert!(json["retry_after_seconds"].as_u64().unwrap_or(0) >= 1);
}

// ============================================================================
// PMS-681: an access token issued before the last password change is rejected
// immediately (closes the up-to-1h stateless-JWT window after a reset/change).
// ============================================================================

/// PMS-681: an access token whose `iat` predates `users.password_changed_at` is
/// rejected (401) on its next request. Stamps password_changed_at 30s in the
/// future so the check is deterministic regardless of test timing.
#[sqlx::test]
async fn access_token_rejected_after_password_change(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    // Sanity: the token authenticates before any password change.
    let before = app
        .client
        .get(app.url("/api/v1/auth/me"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send /me before");
    assert_eq!(
        before.status(),
        reqwest::StatusCode::OK,
        "the token works before the password change"
    );

    // Stamp a password change strictly after the token was issued.
    sqlx::query(
        "UPDATE users SET password_changed_at = NOW() + INTERVAL '30 seconds' WHERE id = $1",
    )
    .bind(admin_id)
    .execute(&app.pool)
    .await
    .expect("stamp a future password_changed_at");

    // The same token is now rejected (the middleware maps the check failure to
    // an unauthenticated state, so the extractor returns 401).
    let after = app
        .client
        .get(app.url("/api/v1/auth/me"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send /me after");
    assert_eq!(
        after.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "a token issued before password_changed_at must be rejected"
    );
}

/// PMS-681: a self-service password change (PUT /me/password) revokes all
/// sessions and stamps password_changed_at, logging the user out everywhere.
#[sqlx::test]
async fn change_password_logs_out_everywhere(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let sessions_before: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM user_sessions WHERE user_id = $1")
            .bind(admin_id)
            .fetch_one(&app.pool)
            .await
            .expect("count sessions before change");
    assert!(sessions_before >= 1, "login creates a session");

    let new_password = "changed-password-123";
    let resp = app
        .client
        .put(app.url("/api/v1/auth/me/password"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "current_password": password,
            "new_password": new_password,
            "confirm_password": new_password,
        }))
        .send()
        .await
        .expect("send change-password");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "a valid password change succeeds"
    );

    let sessions_after: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM user_sessions WHERE user_id = $1")
            .bind(admin_id)
            .fetch_one(&app.pool)
            .await
            .expect("count sessions after change");
    assert_eq!(
        sessions_after, 0,
        "a self-service password change must revoke all sessions (log out everywhere)"
    );

    let pca: Option<chrono::DateTime<Utc>> =
        sqlx::query_scalar("SELECT password_changed_at FROM users WHERE id = $1")
            .bind(admin_id)
            .fetch_one(&app.pool)
            .await
            .expect("read password_changed_at after change");
    assert!(
        pca.is_some(),
        "a password change must stamp password_changed_at"
    );

    // The old password no longer authenticates; the new one does.
    let old = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .json(&serde_json::json!({ "email": email, "password": password }))
        .send()
        .await
        .expect("send old-password login");
    assert_eq!(
        old.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "the old password no longer works after the change"
    );
    let _new_token = common::login(&app, &email, new_password).await;
}
