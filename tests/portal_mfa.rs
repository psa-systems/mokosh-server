//! PMS-729 phase 2 §5 H4: portal MFA (TOTP + recovery codes) HTTP wire tests.
//!
//! Setup + enable + disable + login-with-mfa are covered here.
//! `src/utils/totp.rs` unit tests cover the TOTP primitive itself.

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

async fn login(
    app: &common::TestApp,
    email: &str,
    body_extra: serde_json::Value,
) -> reqwest::Response {
    let mut body = serde_json::json!({
        "tenant_slug": "default",
        "email": email,
        "password": PORTAL_PASSWORD,
    });
    if let Some(obj) = body.as_object_mut() {
        if let serde_json::Value::Object(extra) = body_extra {
            for (k, v) in extra {
                obj.insert(k, v);
            }
        }
    }
    app.client
        .post(app.url("/api/v1/portal/auth/login"))
        .json(&body)
        .send()
        .await
        .expect("send login")
}

/// Generate the current TOTP code for a base32 secret so tests can
/// exercise the login-with-mfa path without a real authenticator.
fn totp_now(secret_b32: &str) -> String {
    let secret = mokosh_server::utils::totp::base32_decode(secret_b32).expect("decode secret");
    mokosh_server::utils::totp::code_at(&secret, chrono::Utc::now())
}

// AC (H4 setup): setup returns a base32 secret + a provisioning URI.
// `portal_mfa_enabled` stays FALSE until `/enable` succeeds.
#[sqlx::test]
async fn mfa_setup_returns_secret_and_stays_disabled(pool: PgPool) {
    let contact = seed_portal_contact(&pool, "user@example.com").await;
    let app = common::boot(pool.clone()).await;
    let access_token = login(&app, "user@example.com", serde_json::Value::Null)
        .await
        .json::<serde_json::Value>()
        .await
        .unwrap()["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    let resp = app
        .client
        .post(app.url("/api/v1/portal/auth/me/mfa/setup"))
        .bearer_auth(&access_token)
        .json(&serde_json::json!({ "current_password": PORTAL_PASSWORD }))
        .send()
        .await
        .expect("setup");
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["secret"].as_str().unwrap().len() >= 16);
    assert!(body["provisioning_uri"]
        .as_str()
        .unwrap()
        .starts_with("otpauth://totp/"));

    // Row state: secret stored, enabled false.
    let (enabled, secret): (bool, Option<String>) =
        sqlx::query_as("SELECT portal_mfa_enabled, portal_mfa_secret FROM contacts WHERE id = $1")
            .bind(contact)
            .fetch_one(&pool)
            .await
            .expect("select row");
    assert!(!enabled, "setup does not flip enabled");
    assert!(secret.is_some(), "secret stored");
}

// AC (H4 enable): with a valid code, enable flips the flag and returns
// 10 recovery codes.
#[sqlx::test]
async fn mfa_enable_with_valid_code_flips_flag_and_returns_recovery_codes(pool: PgPool) {
    let contact = seed_portal_contact(&pool, "user@example.com").await;
    let app = common::boot(pool.clone()).await;
    let access_token = login(&app, "user@example.com", serde_json::Value::Null)
        .await
        .json::<serde_json::Value>()
        .await
        .unwrap()["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    // Setup first to mint the secret.
    let setup_resp: serde_json::Value = app
        .client
        .post(app.url("/api/v1/portal/auth/me/mfa/setup"))
        .bearer_auth(&access_token)
        .json(&serde_json::json!({ "current_password": PORTAL_PASSWORD }))
        .send()
        .await
        .expect("setup")
        .json()
        .await
        .unwrap();
    let secret = setup_resp["secret"].as_str().unwrap().to_string();

    // Enable with the current code.
    let code = totp_now(&secret);
    let enable_resp = app
        .client
        .post(app.url("/api/v1/portal/auth/me/mfa/enable"))
        .bearer_auth(&access_token)
        .json(&serde_json::json!({ "code": code, "current_password": PORTAL_PASSWORD }))
        .send()
        .await
        .expect("enable");
    assert!(enable_resp.status().is_success());
    let body: serde_json::Value = enable_resp.json().await.unwrap();
    let recovery: Vec<String> = body["recovery_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(recovery.len(), 10, "10 recovery codes minted");

    // Row state: enabled TRUE, hashes stored.
    let (enabled, hashes): (bool, Vec<String>) = sqlx::query_as(
        "SELECT portal_mfa_enabled, portal_mfa_recovery_codes_hashes FROM contacts WHERE id = $1",
    )
    .bind(contact)
    .fetch_one(&pool)
    .await
    .expect("select row");
    assert!(enabled, "flag flipped");
    assert_eq!(hashes.len(), 10, "10 hashes stored");
}

// AC (H4 enable): a wrong code returns 400 and does not flip the flag.
#[sqlx::test]
async fn mfa_enable_with_wrong_code_returns_400(pool: PgPool) {
    let contact = seed_portal_contact(&pool, "user@example.com").await;
    let app = common::boot(pool.clone()).await;
    let access_token = login(&app, "user@example.com", serde_json::Value::Null)
        .await
        .json::<serde_json::Value>()
        .await
        .unwrap()["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    // Setup first so a secret exists.
    let _: serde_json::Value = app
        .client
        .post(app.url("/api/v1/portal/auth/me/mfa/setup"))
        .bearer_auth(&access_token)
        .json(&serde_json::json!({ "current_password": PORTAL_PASSWORD }))
        .send()
        .await
        .expect("setup")
        .json()
        .await
        .unwrap();

    // Enable with 000000 - guaranteed wrong (probability 1/10^6 of
    // matching by chance, worth the risk in a test).
    let enable_resp = app
        .client
        .post(app.url("/api/v1/portal/auth/me/mfa/enable"))
        .bearer_auth(&access_token)
        .json(&serde_json::json!({ "code": "000000", "current_password": PORTAL_PASSWORD }))
        .send()
        .await
        .expect("enable");
    assert_eq!(enable_resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let (enabled,): (bool,) =
        sqlx::query_as("SELECT portal_mfa_enabled FROM contacts WHERE id = $1")
            .bind(contact)
            .fetch_one(&pool)
            .await
            .expect("select");
    assert!(!enabled, "flag stays FALSE on bad code");
}

// AC (H4 login mfa_required): a login without a code against an
// MFA-enabled contact returns 200 with `mfa_required: true`, no tokens.
#[sqlx::test]
async fn login_without_code_against_mfa_enabled_returns_mfa_required(pool: PgPool) {
    let contact = seed_portal_contact(&pool, "user@example.com").await;
    // Enable MFA directly in the DB with a known secret.
    let secret = mokosh_server::utils::totp::generate_secret();
    let secret_b32 = mokosh_server::utils::totp::base32_encode(&secret);
    sqlx::query(
        "UPDATE contacts SET portal_mfa_enabled = TRUE, portal_mfa_secret = $1 \
         WHERE id = $2",
    )
    .bind(&secret_b32)
    .bind(contact)
    .execute(&pool)
    .await
    .expect("enable mfa");
    let app = common::boot(pool.clone()).await;

    let resp = login(&app, "user@example.com", serde_json::Value::Null).await;
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["mfa_required"].as_bool(), Some(true));
    assert_eq!(body["access_token"].as_str().unwrap_or(""), "");
    assert_eq!(body["refresh_token"].as_str().unwrap_or(""), "");
    assert!(body.get("contact").is_none() || body["contact"].is_null());
}

// AC (H4 login mfa_code): retrying the login with a valid TOTP code
// completes and returns the full token set.
#[sqlx::test]
async fn login_with_valid_code_completes_mfa_flow(pool: PgPool) {
    let contact = seed_portal_contact(&pool, "user@example.com").await;
    let secret = mokosh_server::utils::totp::generate_secret();
    let secret_b32 = mokosh_server::utils::totp::base32_encode(&secret);
    sqlx::query(
        "UPDATE contacts SET portal_mfa_enabled = TRUE, portal_mfa_secret = $1 \
         WHERE id = $2",
    )
    .bind(&secret_b32)
    .bind(contact)
    .execute(&pool)
    .await
    .expect("enable mfa");
    let app = common::boot(pool.clone()).await;

    let code = totp_now(&secret_b32);
    let resp = login(
        &app,
        "user@example.com",
        serde_json::json!({ "mfa_code": code }),
    )
    .await;
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["mfa_required"].as_bool(), Some(false));
    assert!(body["access_token"].as_str().unwrap().len() > 20);
    assert!(body["refresh_token"].as_str().unwrap().len() > 20);
    assert!(body["contact"].is_object());
}

// AC (H4 login recovery_code): with a valid recovery code, login
// completes AND that code is consumed (cannot be reused).
#[sqlx::test]
async fn login_with_recovery_code_consumes_it(pool: PgPool) {
    let contact = seed_portal_contact(&pool, "user@example.com").await;
    // Enable MFA + set one known recovery code hash directly.
    let secret = mokosh_server::utils::totp::generate_secret();
    let secret_b32 = mokosh_server::utils::totp::base32_encode(&secret);
    // Use the same hashing helper the service uses. Only exposed via
    // the trait, so replicate the two-step hash-then-hex here.
    let raw_code = "ABCDE-12345";
    let hashed = mokosh_server::utils::recovery::hash_code(raw_code);
    let hex: String = hashed.iter().map(|b| format!("{b:02x}")).collect();
    sqlx::query(
        "UPDATE contacts \
         SET portal_mfa_enabled = TRUE, portal_mfa_secret = $1, \
             portal_mfa_recovery_codes_hashes = $2 \
         WHERE id = $3",
    )
    .bind(&secret_b32)
    .bind(vec![hex.clone()])
    .bind(contact)
    .execute(&pool)
    .await
    .expect("enable mfa + set recovery");
    let app = common::boot(pool.clone()).await;

    // First redeem: succeeds.
    let resp = login(
        &app,
        "user@example.com",
        serde_json::json!({ "recovery_code": raw_code }),
    )
    .await;
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["mfa_required"].as_bool(), Some(false));

    // Second redeem with the same code: 401 (consumed).
    let replay = login(
        &app,
        "user@example.com",
        serde_json::json!({ "recovery_code": raw_code }),
    )
    .await;
    assert_eq!(replay.status(), reqwest::StatusCode::UNAUTHORIZED);
}

// AC (H4 disable): disable with a valid password + code clears
// everything. Subsequent login is password-only again.
#[sqlx::test]
async fn mfa_disable_clears_state(pool: PgPool) {
    let contact = seed_portal_contact(&pool, "user@example.com").await;
    let secret = mokosh_server::utils::totp::generate_secret();
    let secret_b32 = mokosh_server::utils::totp::base32_encode(&secret);
    sqlx::query(
        "UPDATE contacts SET portal_mfa_enabled = TRUE, portal_mfa_secret = $1, \
                              portal_mfa_recovery_codes_hashes = ARRAY['deadbeef']::TEXT[] \
         WHERE id = $2",
    )
    .bind(&secret_b32)
    .bind(contact)
    .execute(&pool)
    .await
    .expect("enable mfa");
    let app = common::boot(pool.clone()).await;

    // Log in with the current MFA code to get an access token.
    let code = totp_now(&secret_b32);
    let login_body: serde_json::Value = login(
        &app,
        "user@example.com",
        serde_json::json!({ "mfa_code": code.clone() }),
    )
    .await
    .json()
    .await
    .unwrap();
    let access_token = login_body["access_token"].as_str().unwrap().to_string();

    // Disable requires current password + code.
    let resp = app
        .client
        .post(app.url("/api/v1/portal/auth/me/mfa/disable"))
        .bearer_auth(&access_token)
        .json(&serde_json::json!({
            "current_password": PORTAL_PASSWORD,
            "code": code,
        }))
        .send()
        .await
        .expect("disable");
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);

    // Row state cleared.
    let (enabled, secret, hashes): (bool, Option<String>, Vec<String>) = sqlx::query_as(
        "SELECT portal_mfa_enabled, portal_mfa_secret, portal_mfa_recovery_codes_hashes \
         FROM contacts WHERE id = $1",
    )
    .bind(contact)
    .fetch_one(&pool)
    .await
    .expect("select");
    assert!(!enabled);
    assert!(secret.is_none());
    assert!(hashes.is_empty());

    // Now a fresh password-only login succeeds.
    let post_disable = login(&app, "user@example.com", serde_json::Value::Null).await;
    assert!(post_disable.status().is_success());
    let body: serde_json::Value = post_disable.json().await.unwrap();
    assert_eq!(body["mfa_required"].as_bool(), Some(false));
    assert!(body["access_token"].as_str().unwrap().len() > 20);
}

// AC (H4 disable): wrong current password returns 401 and does NOT
// clear the state.
#[sqlx::test]
async fn mfa_disable_wrong_password_returns_401(pool: PgPool) {
    let contact = seed_portal_contact(&pool, "user@example.com").await;
    let secret = mokosh_server::utils::totp::generate_secret();
    let secret_b32 = mokosh_server::utils::totp::base32_encode(&secret);
    sqlx::query(
        "UPDATE contacts SET portal_mfa_enabled = TRUE, portal_mfa_secret = $1 \
         WHERE id = $2",
    )
    .bind(&secret_b32)
    .bind(contact)
    .execute(&pool)
    .await
    .expect("enable mfa");
    let app = common::boot(pool.clone()).await;

    let code = totp_now(&secret_b32);
    let login_body: serde_json::Value = login(
        &app,
        "user@example.com",
        serde_json::json!({ "mfa_code": code.clone() }),
    )
    .await
    .json()
    .await
    .unwrap();
    let access_token = login_body["access_token"].as_str().unwrap().to_string();

    let resp = app
        .client
        .post(app.url("/api/v1/portal/auth/me/mfa/disable"))
        .bearer_auth(&access_token)
        .json(&serde_json::json!({
            "current_password": "wrong",
            "code": code,
        }))
        .send()
        .await
        .expect("disable");
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    // Still enabled.
    let (enabled,): (bool,) =
        sqlx::query_as("SELECT portal_mfa_enabled FROM contacts WHERE id = $1")
            .bind(contact)
            .fetch_one(&pool)
            .await
            .expect("select");
    assert!(enabled);
}
