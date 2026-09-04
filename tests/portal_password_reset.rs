//! PMS-729 phase 2 §5 H3: portal forgot-password + reset-password
//! + change-password HTTP wire tests.

mod common;

use sqlx::PgPool;
use uuid::Uuid;

const PORTAL_PASSWORD: &str = "portal-password-12345";

async fn seed_portal_contact(pool: &PgPool, email: &str) -> Uuid {
    let company = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, 'Acme Co')")
        .bind(company)
        .bind(common::DEFAULT_TENANT_ID)
        .execute(pool)
        .await
        .expect("seed company");
    let hash =
        mokosh_server::utils::crypto::hash_password(PORTAL_PASSWORD).expect("hash portal password");
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO contacts (
            id, tenant_id, company_id, first_name, last_name, email,
            is_portal_user, portal_password_hash
        )
        VALUES ($1, $2, $3, 'Portal', 'Contact', $4, TRUE, $5)
        "#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company)
    .bind(email)
    .bind(&hash)
    .execute(pool)
    .await
    .expect("seed portal contact");
    id
}

async fn forgot(app: &common::TestApp, email: &str) -> reqwest::Response {
    app.client
        .post(app.url("/api/v1/portal/auth/forgot-password"))
        .json(&serde_json::json!({
            "tenant_slug": "default",
            "email": email,
        }))
        .send()
        .await
        .expect("send forgot-password")
}

async fn reset(app: &common::TestApp, token: &str, password: &str) -> reqwest::Response {
    app.client
        .post(app.url("/api/v1/portal/auth/reset-password"))
        .json(&serde_json::json!({ "token": token, "password": password }))
        .send()
        .await
        .expect("send reset-password")
}

/// Look up the most recent reset-token row for a contact and return the
/// plaintext token to test with. Tests bypass the email dispatch (which
/// is disabled in `common::boot` because there is no notifications
/// dispatcher wired) and pull the row directly. `secret` is what the
/// service INSERT'd, hashed with a random Argon2 salt; the plaintext
/// can only come from the service return value.
async fn extract_last_reset_token(pool: &PgPool, contact_id: Uuid) -> Uuid {
    let (id,): (Uuid,) = sqlx::query_as(
        "SELECT id FROM portal_password_reset_tokens \
         WHERE contact_id = $1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(contact_id)
    .fetch_one(pool)
    .await
    .expect("select reset token id");
    id
}

// AC (H3 forgot): unknown email still returns 204. Enumeration-resistant.
#[sqlx::test]
async fn forgot_password_unknown_email_still_204(pool: PgPool) {
    let app = common::boot(pool).await;
    let resp = forgot(&app, "does-not-exist@example.com").await;
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);
}

// AC (H3 forgot): known email returns 204 AND inserts a row.
#[sqlx::test]
async fn forgot_password_known_email_204_and_writes_row(pool: PgPool) {
    let contact = seed_portal_contact(&pool, "user@example.com").await;
    let app = common::boot(pool.clone()).await;

    let before: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM portal_password_reset_tokens WHERE contact_id = $1",
    )
    .bind(contact)
    .fetch_one(&pool)
    .await
    .expect("count before");
    assert_eq!(before, 0);

    let resp = forgot(&app, "user@example.com").await;
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);

    let after: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM portal_password_reset_tokens WHERE contact_id = $1",
    )
    .bind(contact)
    .fetch_one(&pool)
    .await
    .expect("count after");
    assert_eq!(after, 1, "reset token row should exist");
}

// AC (H3 reset): a valid + unused + unexpired token with a strong
// password sets the hash and returns 204.
#[sqlx::test]
async fn reset_password_happy_path(pool: PgPool) {
    let contact = seed_portal_contact(&pool, "user@example.com").await;
    let app = common::boot(pool.clone()).await;

    // Insert a reset-token row directly with a known secret so the test
    // can present the plaintext. This bypasses forgot() so the secret
    // doesn't get lost in the mailer.
    let secret = "reset-secret-abcdefghij";
    let hash = mokosh_server::utils::crypto::hash_password(secret).expect("hash");
    let token_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO portal_password_reset_tokens
            (id, tenant_id, contact_id, token_hash, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(token_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(contact)
    .bind(&hash)
    .bind(chrono::Utc::now() + chrono::Duration::minutes(30))
    .execute(&pool)
    .await
    .expect("insert reset token");

    let token = format!("{token_id}.{secret}");
    let strong = "Kq7$mZ2n#PxR9wLf";
    let resp = reset(&app, &token, strong).await;
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);

    // Hash rotated.
    let new_hash: Option<String> =
        sqlx::query_scalar("SELECT portal_password_hash FROM contacts WHERE id = $1")
            .bind(contact)
            .fetch_one(&pool)
            .await
            .expect("select hash");
    assert!(new_hash.is_some(), "hash written after reset");
    // Password verify against the new value works.
    let verified =
        mokosh_server::utils::crypto::verify_password(strong, new_hash.as_ref().unwrap())
            .expect("verify");
    assert!(verified, "new password verifies");

    // Token marked used.
    let used_at: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT used_at FROM portal_password_reset_tokens WHERE id = $1")
            .bind(token_id)
            .fetch_one(&pool)
            .await
            .expect("select used_at");
    assert!(used_at.is_some(), "token marked used");
}

// AC (H3 reset): a replayed token returns 410 Gone. A weak password in
// the replay body does NOT change that: the token check wins.
#[sqlx::test]
async fn reset_password_replay_returns_410_regardless_of_password(pool: PgPool) {
    let contact = seed_portal_contact(&pool, "user@example.com").await;
    let app = common::boot(pool.clone()).await;

    let secret = "reset-secret-abcdefghij2";
    let hash = mokosh_server::utils::crypto::hash_password(secret).expect("hash");
    let token_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO portal_password_reset_tokens
            (id, tenant_id, contact_id, token_hash, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(token_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(contact)
    .bind(&hash)
    .bind(chrono::Utc::now() + chrono::Duration::minutes(30))
    .execute(&pool)
    .await
    .expect("insert");

    let token = format!("{token_id}.{secret}");
    let first = reset(&app, &token, "Kq7$mZ2n#PxR9wLf").await;
    assert_eq!(first.status(), reqwest::StatusCode::NO_CONTENT);

    // Replay with a weak password. Token status wins over policy.
    let replay = reset(&app, &token, "short").await;
    assert_eq!(replay.status(), reqwest::StatusCode::GONE);
}

// AC (H3 reset): an expired token is 400, distinct from replay.
#[sqlx::test]
async fn reset_password_expired_returns_400(pool: PgPool) {
    let contact = seed_portal_contact(&pool, "user@example.com").await;
    let app = common::boot(pool.clone()).await;

    let secret = "reset-secret-abcdefghij3";
    let hash = mokosh_server::utils::crypto::hash_password(secret).expect("hash");
    let token_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO portal_password_reset_tokens
            (id, tenant_id, contact_id, token_hash, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(token_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(contact)
    .bind(&hash)
    .bind(chrono::Utc::now() - chrono::Duration::hours(1))
    .execute(&pool)
    .await
    .expect("insert");

    let token = format!("{token_id}.{secret}");
    let resp = reset(&app, &token, "Kq7$mZ2n#PxR9wLf").await;
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

// AC (H3 reset): an unknown or malformed token is 400.
#[sqlx::test]
async fn reset_password_unknown_token_returns_400(pool: PgPool) {
    let app = common::boot(pool).await;

    // Unknown UUID + random secret.
    let unknown = format!("{}.random-secret", Uuid::new_v4());
    assert_eq!(
        reset(&app, &unknown, "Kq7$mZ2n#PxR9wLf").await.status(),
        reqwest::StatusCode::BAD_REQUEST
    );

    // Malformed (no dot).
    assert_eq!(
        reset(&app, "no-dot", "Kq7$mZ2n#PxR9wLf").await.status(),
        reqwest::StatusCode::BAD_REQUEST
    );
}

// AC (H3 reset + H5): a valid token + a weak password is 400 with the
// policy message. The token stays unused so the customer can retry.
#[sqlx::test]
async fn reset_password_weak_password_returns_400_and_token_unused(pool: PgPool) {
    let contact = seed_portal_contact(&pool, "user@example.com").await;
    let app = common::boot(pool.clone()).await;

    let secret = "reset-secret-abcdefghij4";
    let hash = mokosh_server::utils::crypto::hash_password(secret).expect("hash");
    let token_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO portal_password_reset_tokens
            (id, tenant_id, contact_id, token_hash, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(token_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(contact)
    .bind(&hash)
    .bind(chrono::Utc::now() + chrono::Duration::minutes(30))
    .execute(&pool)
    .await
    .expect("insert");

    let token = format!("{token_id}.{secret}");
    let resp = reset(&app, &token, "short").await;
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await.expect("400 body");
    let msg = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        msg.contains("at least 12") || msg.contains("well-known") || msg.contains("too easy"),
        "unexpected body: {body}"
    );

    // Token stays unused so the user can try again with a stronger one.
    let used_at: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT used_at FROM portal_password_reset_tokens WHERE id = $1")
            .bind(token_id)
            .fetch_one(&pool)
            .await
            .expect("select used_at");
    assert!(used_at.is_none(), "token stays unused after policy reject");
}

// AC (H3 reset): a successful reset revokes every live refresh token
// for the contact so a stolen refresh token cannot survive the reset.
#[sqlx::test]
async fn reset_password_revokes_all_live_refresh_tokens(pool: PgPool) {
    let contact = seed_portal_contact(&pool, "user@example.com").await;
    let app = common::boot(pool.clone()).await;

    // Log in to get a refresh token.
    let login = app
        .client
        .post(app.url("/api/v1/portal/auth/login"))
        .json(&serde_json::json!({
            "tenant_slug": "default",
            "email": "user@example.com",
            "password": PORTAL_PASSWORD,
        }))
        .send()
        .await
        .expect("login");
    let body: serde_json::Value = login.json().await.expect("login body");
    let refresh_token = body["refresh_token"].as_str().unwrap().to_string();

    // Insert a valid reset-token row directly.
    let secret = "reset-secret-abcdefghij5";
    let hash = mokosh_server::utils::crypto::hash_password(secret).expect("hash");
    let token_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO portal_password_reset_tokens
            (id, tenant_id, contact_id, token_hash, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(token_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(contact)
    .bind(&hash)
    .bind(chrono::Utc::now() + chrono::Duration::minutes(30))
    .execute(&pool)
    .await
    .expect("insert reset token");

    // Reset the password.
    let reset_resp = reset(&app, &format!("{token_id}.{secret}"), "Kq7$mZ2n#PxR9wLf").await;
    assert_eq!(reset_resp.status(), reqwest::StatusCode::NO_CONTENT);

    // Now the refresh token from BEFORE the reset should be dead.
    let refresh = app
        .client
        .post(app.url("/api/v1/portal/auth/refresh"))
        .json(&serde_json::json!({ "refresh_token": refresh_token }))
        .send()
        .await
        .expect("refresh after reset");
    assert_eq!(refresh.status(), reqwest::StatusCode::UNAUTHORIZED);
}

// AC (H3 change): change password with the correct current password
// works and the new password can log in.
#[sqlx::test]
async fn change_password_happy_path(pool: PgPool) {
    seed_portal_contact(&pool, "user@example.com").await;
    let app = common::boot(pool.clone()).await;

    // Log in to get an access token.
    let login = app
        .client
        .post(app.url("/api/v1/portal/auth/login"))
        .json(&serde_json::json!({
            "tenant_slug": "default",
            "email": "user@example.com",
            "password": PORTAL_PASSWORD,
        }))
        .send()
        .await
        .expect("login");
    let access_token = login.json::<serde_json::Value>().await.unwrap()["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    // Change password.
    let new_pw = "Kq7$mZ2n#PxR9wLf";
    let resp = app
        .client
        .put(app.url("/api/v1/portal/auth/me/password"))
        .bearer_auth(&access_token)
        .json(&serde_json::json!({
            "current_password": PORTAL_PASSWORD,
            "new_password": new_pw,
        }))
        .send()
        .await
        .expect("change password");
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);

    // Login with the OLD password now fails.
    let old_login = app
        .client
        .post(app.url("/api/v1/portal/auth/login"))
        .json(&serde_json::json!({
            "tenant_slug": "default",
            "email": "user@example.com",
            "password": PORTAL_PASSWORD,
        }))
        .send()
        .await
        .expect("old login");
    assert_eq!(old_login.status(), reqwest::StatusCode::UNAUTHORIZED);

    // Login with the NEW password works.
    let new_login = app
        .client
        .post(app.url("/api/v1/portal/auth/login"))
        .json(&serde_json::json!({
            "tenant_slug": "default",
            "email": "user@example.com",
            "password": new_pw,
        }))
        .send()
        .await
        .expect("new login");
    assert!(new_login.status().is_success());
}

// AC (H3 change): wrong current password returns 401.
#[sqlx::test]
async fn change_password_wrong_current_returns_401(pool: PgPool) {
    seed_portal_contact(&pool, "user@example.com").await;
    let app = common::boot(pool).await;

    let login = app
        .client
        .post(app.url("/api/v1/portal/auth/login"))
        .json(&serde_json::json!({
            "tenant_slug": "default",
            "email": "user@example.com",
            "password": PORTAL_PASSWORD,
        }))
        .send()
        .await
        .expect("login");
    let access_token = login.json::<serde_json::Value>().await.unwrap()["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    let resp = app
        .client
        .put(app.url("/api/v1/portal/auth/me/password"))
        .bearer_auth(&access_token)
        .json(&serde_json::json!({
            "current_password": "wrong",
            "new_password": "Kq7$mZ2n#PxR9wLf",
        }))
        .send()
        .await
        .expect("change password");
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

// AC (H3 change): weak new password returns 400 with a policy message.
#[sqlx::test]
async fn change_password_weak_new_returns_400(pool: PgPool) {
    seed_portal_contact(&pool, "user@example.com").await;
    let app = common::boot(pool).await;

    let login = app
        .client
        .post(app.url("/api/v1/portal/auth/login"))
        .json(&serde_json::json!({
            "tenant_slug": "default",
            "email": "user@example.com",
            "password": PORTAL_PASSWORD,
        }))
        .send()
        .await
        .expect("login");
    let access_token = login.json::<serde_json::Value>().await.unwrap()["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    let resp = app
        .client
        .put(app.url("/api/v1/portal/auth/me/password"))
        .bearer_auth(&access_token)
        .json(&serde_json::json!({
            "current_password": PORTAL_PASSWORD,
            "new_password": "short",
        }))
        .send()
        .await
        .expect("change password");
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

// AC (H3 change): unauthenticated (no bearer) returns 401. Guards the
// route from being called without a session.
#[sqlx::test]
async fn change_password_requires_auth(pool: PgPool) {
    seed_portal_contact(&pool, "user@example.com").await;
    let app = common::boot(pool).await;

    let resp = app
        .client
        .put(app.url("/api/v1/portal/auth/me/password"))
        .json(&serde_json::json!({
            "current_password": PORTAL_PASSWORD,
            "new_password": "Kq7$mZ2n#PxR9wLf",
        }))
        .send()
        .await
        .expect("change password");
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

// Sanity: the seed_portal_contact helper's `PORTAL_PASSWORD` is
// intentionally weak (documented; used only in test seed hashing) so
// the login path can verify it, but the setup/change path enforces
// the strong policy. Just leave a stub linking the two so a future
// reader sees the split without hunting.
#[allow(dead_code)]
fn note_test_password_is_seed_only() {
    let _ = extract_last_reset_token;
}
