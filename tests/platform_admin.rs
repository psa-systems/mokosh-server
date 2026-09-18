//! MAPPS-513 (MAPPS-474 stage A follow-up): platform super-admin
//! login + change-password + isolation from the tenant identity
//! plane.
//!
//! Covers:
//! - Backfill: after seed_admin, a platform_admins row exists for
//!   the super_admin user with the same password_hash.
//! - `POST /platform/login` returns a `typ="platform"` access token.
//! - `PUT /platform/me/password` writes ONLY platform_admins (not
//!   users, not identities).
//! - Cross-plane isolation: writing identities.password_hash (via
//!   MAPPS-499 change_password) does NOT touch platform_admins.
//! - PMS-1219: a stale identities.password_hash never authenticates
//!   the platform plane and never reverts a rotated platform hash.

mod common;

use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test]
async fn seed_admin_is_backfilled_into_platform_admins(pool: PgPool) {
    let (admin_id, email, _password) = common::seed_admin(&pool).await;
    // seed_admin inserts into users AFTER migration 132 already ran,
    // so the backfill missed it. Run it manually here to verify the
    // shape: super_admin users row -> platform_admins row.
    sqlx::query(
        "INSERT INTO platform_admins (id, email, password_hash, first_name, last_name, status) \
         SELECT id, email, password_hash, first_name, last_name, 'active' FROM users WHERE id = $1 \
         ON CONFLICT DO NOTHING",
    )
    .bind(admin_id)
    .execute(&pool)
    .await
    .expect("manual backfill");

    let row_email: Option<String> =
        sqlx::query_scalar("SELECT email FROM platform_admins WHERE lower(email) = lower($1)")
            .bind(&email)
            .fetch_optional(&pool)
            .await
            .expect("read platform_admin");
    assert_eq!(row_email.as_deref(), Some(email.as_str()));
}

#[sqlx::test]
async fn platform_login_returns_access_token(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    // Backfill this admin.
    let hash = mokosh_server::utils::crypto::hash_password(&password)
        .await
        .expect("hash pw");
    sqlx::query(
        "INSERT INTO platform_admins (email, password_hash, first_name, last_name, status) \
         VALUES ($1, $2, 'Test', 'Admin', 'active') ON CONFLICT DO NOTHING",
    )
    .bind(&email)
    .bind(&hash)
    .execute(&pool)
    .await
    .expect("insert platform admin");
    let app = common::boot(pool).await;

    let resp = app
        .client
        .post(app.url("/api/v1/platform/login"))
        .json(&serde_json::json!({ "email": email, "password": password }))
        .send()
        .await
        .expect("send platform login");
    assert!(
        resp.status().is_success(),
        "platform login expected 2xx, got {}",
        resp.status()
    );
    let body: Value = resp.json().await.expect("json");
    assert!(!body["access_token"].as_str().unwrap().is_empty());
    assert_eq!(body["admin"]["email"].as_str().unwrap(), email);
}

#[sqlx::test]
async fn platform_login_wrong_password_returns_401(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let hash = mokosh_server::utils::crypto::hash_password(&password)
        .await
        .expect("hash pw");
    sqlx::query(
        "INSERT INTO platform_admins (email, password_hash, first_name, last_name, status) \
         VALUES ($1, $2, 'Test', 'Admin', 'active') ON CONFLICT DO NOTHING",
    )
    .bind(&email)
    .bind(&hash)
    .execute(&pool)
    .await
    .expect("insert platform admin");
    let app = common::boot(pool).await;

    let resp = app
        .client
        .post(app.url("/api/v1/platform/login"))
        .json(&serde_json::json!({ "email": email, "password": "wrong-password" }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[sqlx::test]
async fn platform_change_password_isolates_from_identity_plane(pool: PgPool) {
    // Setup: super_admin users row (via seed_admin) + backfill platform_admins
    // with the same email/password. Login to /platform/login, change password.
    // Assert platform_admins.password_hash changed and identities.password_hash
    // did NOT (super-admin persona is isolated from the tenant identity plane).
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let hash = mokosh_server::utils::crypto::hash_password(&password)
        .await
        .expect("hash pw");
    sqlx::query(
        "INSERT INTO platform_admins (email, password_hash, first_name, last_name, status) \
         VALUES ($1, $2, 'Test', 'Admin', 'active') ON CONFLICT DO NOTHING",
    )
    .bind(&email)
    .bind(&hash)
    .execute(&pool)
    .await
    .expect("insert platform admin");
    let app = common::boot(pool).await;

    // Login to /platform/login.
    let login: Value = app
        .client
        .post(app.url("/api/v1/platform/login"))
        .json(&serde_json::json!({ "email": email, "password": password }))
        .send()
        .await
        .expect("login")
        .json()
        .await
        .expect("json");
    let token = login["access_token"].as_str().unwrap().to_string();

    let identity_hash_before: Option<String> =
        sqlx::query_scalar("SELECT password_hash FROM identities WHERE id = $1")
            .bind(admin_id)
            .fetch_one(&app.pool)
            .await
            .expect("read identity hash");

    let new_pw = "distinct-platform-pw-99";
    let resp = app
        .client
        .put(app.url("/api/v1/platform/me/password"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "current_password": password,
            "new_password": new_pw,
            "confirm_password": new_pw,
        }))
        .send()
        .await
        .expect("change pw");
    assert!(
        resp.status().is_success(),
        "change_password expected 2xx, got {}",
        resp.status()
    );

    let platform_hash_after: Option<String> = sqlx::query_scalar(
        "SELECT password_hash FROM platform_admins WHERE lower(email) = lower($1)",
    )
    .bind(&email)
    .fetch_one(&app.pool)
    .await
    .expect("read platform hash");
    let identity_hash_after: Option<String> =
        sqlx::query_scalar("SELECT password_hash FROM identities WHERE id = $1")
            .bind(admin_id)
            .fetch_one(&app.pool)
            .await
            .expect("read identity hash");

    // Platform hash changed.
    assert!(platform_hash_after.is_some());
    assert_ne!(
        platform_hash_after.as_deref(),
        Some(hash.as_str()),
        "platform_admins.password_hash was updated"
    );
    // Identity hash unchanged (still the seed_admin hash).
    assert_eq!(
        identity_hash_before, identity_hash_after,
        "identities.password_hash MUST NOT change when the platform password is set"
    );
    // Platform login with new password succeeds.
    let relog = app
        .client
        .post(app.url("/api/v1/platform/login"))
        .json(&serde_json::json!({ "email": email, "password": new_pw }))
        .send()
        .await
        .expect("relog");
    assert!(relog.status().is_success());
}

// PMS-1219: the MAPPS-550 identity-hash fallback is removed.
// `platform_admins.password_hash` is authoritative since migration
// 164 severed the mirror from `identities`, so a stale identity-plane
// hash must never authenticate the platform plane, and it must
// certainly never overwrite a hash the operator already rotated.
//
// Fixture: platform_admins row rotated to password B, with an
// identities row at the same email still holding the pre-rotation
// password A (drift in the direction that matters: the identity
// plane lags, not leads). Logging in with the stale identity
// password A must 401 and must NOT touch platform_admins.password_hash;
// logging in with the current platform password B must still succeed.
#[sqlx::test]
async fn platform_login_rejects_stale_identity_hash_after_rotation(pool: PgPool) {
    let email = "rotated@example.com".to_string();
    let password_old = "PLATFORM-OLD-STALE".to_string();
    let password_new = "PLATFORM-NEW-ROTATED".to_string();
    let hash_old = mokosh_server::utils::crypto::hash_password(&password_old)
        .await
        .expect("hash old");
    let hash_new = mokosh_server::utils::crypto::hash_password(&password_new)
        .await
        .expect("hash new");

    let admin_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO platform_admins (id, email, password_hash, first_name, last_name, status, email_verified_at) \
         VALUES ($1, $2, $3, 'Op', 'Rotated', 'active', NOW())",
    )
    .bind(admin_id)
    .bind(&email)
    .bind(&hash_new)
    .execute(&pool)
    .await
    .expect("insert rotated platform_admin");

    // identities row is a plane migration 164 stopped mirroring into;
    // it still holds the pre-rotation hash.
    let identity_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO identities (id, email, password_hash, first_name, last_name, status) \
         VALUES ($1, $2, $3, 'Op', 'Rotated', 'active')",
    )
    .bind(identity_id)
    .bind(&email)
    .bind(&hash_old)
    .execute(&pool)
    .await
    .expect("insert stale identity");

    let app = common::boot(pool.clone()).await;

    // The old, stale identity-plane password must NOT authenticate.
    let stale = app
        .client
        .post(app.url("/api/v1/platform/login"))
        .json(&serde_json::json!({ "email": email, "password": password_old }))
        .send()
        .await
        .expect("send login with stale identity password");
    assert_eq!(
        stale.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "PMS-1219: a stale identities.password_hash must not authenticate the platform plane"
    );

    // And it must not have reverted the rotated hash.
    let stored: String =
        sqlx::query_scalar("SELECT password_hash FROM platform_admins WHERE id = $1")
            .bind(admin_id)
            .fetch_one(&app.pool)
            .await
            .expect("re-read platform_admin");
    assert_eq!(
        stored, hash_new,
        "PMS-1219: a failed login must not change platform_admins.password_hash"
    );

    // The current, rotated platform password still works.
    let ok = app
        .client
        .post(app.url("/api/v1/platform/login"))
        .json(&serde_json::json!({ "email": email, "password": password_new }))
        .send()
        .await
        .expect("send login with rotated password");
    assert!(
        ok.status().is_success(),
        "the rotated platform password must still authenticate; got {}",
        ok.status()
    );
}

// A platform admin with no matching identities row still logs in
// normally and gets 401 on any other password (no crash on the
// missing-identity case, since there is no identity lookup at all
// anymore).
#[sqlx::test]
async fn platform_login_no_identity_row_still_works(pool: PgPool) {
    let email = "solo-platform@example.com".to_string();
    let password_a = "SOLO-A-12345".to_string();
    let hash_a = mokosh_server::utils::crypto::hash_password(&password_a)
        .await
        .expect("hash A");

    let admin_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO platform_admins (id, email, password_hash, first_name, last_name, status, email_verified_at) \
         VALUES ($1, $2, $3, 'Solo', 'Admin', 'active', NOW())",
    )
    .bind(admin_id)
    .bind(&email)
    .bind(&hash_a)
    .execute(&pool)
    .await
    .expect("insert lonely platform_admin");

    let app = common::boot(pool).await;

    // Correct password still succeeds.
    let ok = app
        .client
        .post(app.url("/api/v1/platform/login"))
        .json(&serde_json::json!({ "email": email, "password": password_a }))
        .send()
        .await
        .expect("send login");
    assert!(
        ok.status().is_success(),
        "MAPPS-550: no-identity-row path must still authenticate on match; got {}",
        ok.status()
    );

    // Wrong password still 401s (no false success from the missing-
    // identity fallback path).
    let bad = app
        .client
        .post(app.url("/api/v1/platform/login"))
        .json(&serde_json::json!({ "email": email, "password": "wrong-password-000" }))
        .send()
        .await
        .expect("send bad login");
    assert_eq!(bad.status(), reqwest::StatusCode::UNAUTHORIZED);
}
