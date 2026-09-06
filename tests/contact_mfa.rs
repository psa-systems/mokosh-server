//! PMS-1063: a contact's second factor, end to end on the contact plane.
//!
//! Enrolment (`POST /contact/auth/me/mfa/setup` then `/enable`) stages a
//! secret and turns the flag on only after a live code verifies; the
//! password login then refuses the password alone (`mfa_required`),
//! ticks the lockout counter on a wrong code, signs in on a right one or
//! on a single-use recovery code, and `/disable` behind the password and
//! a code turns it back off. The secret is sealed at rest.

mod common;

use sqlx::PgPool;
use uuid::Uuid;

async fn seed_portal_contact(pool: &PgPool, email: &str) -> common::PortalContact {
    let company = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, 'Acme Co')")
        .bind(company)
        .bind(common::DEFAULT_TENANT_ID)
        .execute(pool)
        .await
        .expect("seed company");
    common::seed_portal_contact(pool, company, email, &[]).await
}

async fn login_with(
    app: &common::TestApp,
    contact: &common::PortalContact,
    extra: serde_json::Value,
) -> reqwest::Response {
    let mut body = serde_json::json!({
        "slug": contact.slug,
        "email": contact.email,
        "password": common::CONTACT_PASSWORD,
    });
    for (k, v) in extra.as_object().expect("object").iter() {
        body[k] = v.clone();
    }
    app.client
        .post(app.url("/api/v1/contact/auth/login"))
        .json(&body)
        .send()
        .await
        .expect("send login")
}

async fn post_json(
    app: &common::TestApp,
    token: &str,
    path: &str,
    body: serde_json::Value,
) -> reqwest::Response {
    app.client
        .post(app.url(path))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("send")
}

/// Enrol through the API and return the base32 secret plus the recovery
/// codes the enable step handed out.
async fn enrol(app: &common::TestApp, token: &str) -> (String, Vec<String>) {
    let setup = post_json(
        app,
        token,
        "/api/v1/contact/auth/me/mfa/setup",
        serde_json::json!({ "current_password": common::CONTACT_PASSWORD }),
    )
    .await;
    assert_eq!(setup.status(), reqwest::StatusCode::OK, "setup");
    let setup: serde_json::Value = setup.json().await.expect("setup body");
    let secret_b32 = setup["secret"].as_str().expect("secret").to_string();
    assert!(
        setup["provisioning_uri"]
            .as_str()
            .unwrap_or_default()
            .starts_with("otpauth://totp/"),
        "provisioning uri: {setup}"
    );
    let secret = mokosh_server::utils::totp::base32_decode(&secret_b32).expect("base32");
    let code = mokosh_server::utils::totp::code_at(&secret, chrono::Utc::now());
    let enable = post_json(
        app,
        token,
        "/api/v1/contact/auth/me/mfa/enable",
        serde_json::json!({ "code": code, "current_password": common::CONTACT_PASSWORD }),
    )
    .await;
    assert_eq!(enable.status(), reqwest::StatusCode::OK, "enable");
    let enable: serde_json::Value = enable.json().await.expect("enable body");
    let codes: Vec<String> = enable["recovery_codes"]
        .as_array()
        .expect("recovery_codes")
        .iter()
        .map(|c| c.as_str().unwrap().to_string())
        .collect();
    assert_eq!(codes.len(), 10, "ten recovery codes");
    (secret_b32, codes)
}

async fn failed_count(pool: &PgPool, id: Uuid) -> i32 {
    sqlx::query_scalar("SELECT portal_failed_login_count FROM contacts WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("count")
}

// The whole lifecycle: enrol, the password alone is refused, a wrong
// code ticks the counter, the right code signs in, `me` reports the
// flag, disable needs password plus code, and the password alone signs
// in again afterwards.
#[sqlx::test]
async fn enrolment_gates_the_login_and_disable_lifts_it(pool: PgPool) {
    let contact = seed_portal_contact(&pool, "mfa@example.com").await;
    let app = common::boot(pool.clone()).await;
    let token = common::contact_token(&app, &contact).await;

    // Setup stages a secret without turning MFA on: the password still
    // signs in until enable proves the authenticator works.
    let setup = post_json(
        &app,
        &token,
        "/api/v1/contact/auth/me/mfa/setup",
        serde_json::json!({ "current_password": common::CONTACT_PASSWORD }),
    )
    .await;
    assert_eq!(setup.status(), reqwest::StatusCode::OK);
    let staged = login_with(&app, &contact, serde_json::json!({})).await;
    assert_eq!(staged.status(), reqwest::StatusCode::OK);
    let staged: serde_json::Value = staged.json().await.unwrap();
    assert_eq!(staged["mfa_required"], false, "staged secret does not gate");
    assert!(!staged["access_token"].as_str().unwrap().is_empty());

    let (secret_b32, _codes) = enrol(&app, &token).await;

    // Sealed at rest: the column does not hold the base32 secret.
    let stored: Option<String> =
        sqlx::query_scalar("SELECT portal_mfa_secret FROM contacts WHERE id = $1")
            .bind(contact.id)
            .fetch_one(&pool)
            .await
            .expect("stored secret");
    let stored = stored.expect("secret stored");
    assert_ne!(stored, secret_b32, "secret is not stored in the clear");
    assert!(stored.len() > 32, "ciphertext shape, got {stored}");

    // /me says so.
    let me: serde_json::Value = app
        .client
        .get(app.url("/api/v1/contact/auth/me"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(me["mfa_enabled"], true);

    // Password alone: mfa_required, no tokens, no counter tick.
    let gated = login_with(&app, &contact, serde_json::json!({})).await;
    assert_eq!(gated.status(), reqwest::StatusCode::OK);
    let gated: serde_json::Value = gated.json().await.unwrap();
    assert_eq!(gated["mfa_required"], true);
    assert_eq!(gated["access_token"], "");
    assert_eq!(gated["refresh_token"], "");
    assert!(gated["contact"].is_null());
    assert_eq!(failed_count(&pool, contact.id).await, 0);

    // Wrong code: 401 and the lockout counter ticks.
    let wrong = login_with(&app, &contact, serde_json::json!({ "mfa_code": "000000" })).await;
    assert_eq!(wrong.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(
        failed_count(&pool, contact.id).await,
        1,
        "wrong TOTP ticks the counter"
    );

    // Right code: a session, and the counter resets.
    let secret = mokosh_server::utils::totp::base32_decode(&secret_b32).unwrap();
    let code = mokosh_server::utils::totp::code_at(&secret, chrono::Utc::now());
    let ok = login_with(&app, &contact, serde_json::json!({ "mfa_code": code })).await;
    assert_eq!(ok.status(), reqwest::StatusCode::OK);
    let ok: serde_json::Value = ok.json().await.unwrap();
    assert_eq!(ok["mfa_required"], false);
    assert!(!ok["access_token"].as_str().unwrap().is_empty());
    assert_eq!(ok["contact"]["mfa_enabled"], true);
    assert_eq!(failed_count(&pool, contact.id).await, 0);

    // Disable: wrong password is 401, wrong code is 401, both right is 204.
    let code = mokosh_server::utils::totp::code_at(&secret, chrono::Utc::now());
    let bad_pw = post_json(
        &app,
        &token,
        "/api/v1/contact/auth/me/mfa/disable",
        serde_json::json!({ "current_password": "not-the-password", "code": code }),
    )
    .await;
    assert_eq!(bad_pw.status(), reqwest::StatusCode::UNAUTHORIZED);
    let bad_code = post_json(
        &app,
        &token,
        "/api/v1/contact/auth/me/mfa/disable",
        serde_json::json!({ "current_password": common::CONTACT_PASSWORD, "code": "000000" }),
    )
    .await;
    assert_eq!(bad_code.status(), reqwest::StatusCode::UNAUTHORIZED);
    let off = post_json(
        &app,
        &token,
        "/api/v1/contact/auth/me/mfa/disable",
        serde_json::json!({ "current_password": common::CONTACT_PASSWORD, "code": code }),
    )
    .await;
    assert_eq!(off.status(), reqwest::StatusCode::NO_CONTENT);

    let row: (bool, Option<String>, Vec<String>) = sqlx::query_as(
        "SELECT portal_mfa_enabled, portal_mfa_secret, portal_mfa_recovery_codes_hashes \
         FROM contacts WHERE id = $1",
    )
    .bind(contact.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row, (false, None, vec![]), "disable clears everything");

    let plain = login_with(&app, &contact, serde_json::json!({})).await;
    assert_eq!(plain.status(), reqwest::StatusCode::OK);
    let plain: serde_json::Value = plain.json().await.unwrap();
    assert_eq!(plain["mfa_required"], false);
    assert!(!plain["access_token"].as_str().unwrap().is_empty());
}

// A recovery code signs in once, wins over a bad TOTP sent beside it,
// and is refused on replay.
#[sqlx::test]
async fn a_recovery_code_signs_in_exactly_once(pool: PgPool) {
    let contact = seed_portal_contact(&pool, "recover@example.com").await;
    let app = common::boot(pool.clone()).await;
    let token = common::contact_token(&app, &contact).await;
    let (_, codes) = enrol(&app, &token).await;

    let first = login_with(
        &app,
        &contact,
        serde_json::json!({ "mfa_code": "", "recovery_code": codes[0] }),
    )
    .await;
    assert_eq!(first.status(), reqwest::StatusCode::OK);
    let first: serde_json::Value = first.json().await.unwrap();
    assert_eq!(first["mfa_required"], false);
    assert!(!first["access_token"].as_str().unwrap().is_empty());

    let left: Vec<String> =
        sqlx::query_scalar("SELECT portal_mfa_recovery_codes_hashes FROM contacts WHERE id = $1")
            .bind(contact.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(left.len(), 9, "the spent code is gone");

    let replay = login_with(
        &app,
        &contact,
        serde_json::json!({ "recovery_code": codes[0] }),
    )
    .await;
    assert_eq!(replay.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(
        failed_count(&pool, contact.id).await,
        1,
        "a spent code counts as a failure"
    );

    // Lower-case, with the hyphen dropped: canonicalised the same way.
    let sloppy = codes[1].replace('-', "").to_lowercase();
    let second = login_with(
        &app,
        &contact,
        serde_json::json!({ "recovery_code": sloppy }),
    )
    .await;
    assert_eq!(second.status(), reqwest::StatusCode::OK);
}

// Setup, enable and disable all sit behind the current password; enable
// needs a staged secret; setup refuses while MFA is on.
#[sqlx::test]
async fn every_mfa_change_needs_the_current_password(pool: PgPool) {
    let contact = seed_portal_contact(&pool, "guard@example.com").await;
    let app = common::boot(pool.clone()).await;
    let token = common::contact_token(&app, &contact).await;

    let no_body = app
        .client
        .post(app.url("/api/v1/contact/auth/me/mfa/setup"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert!(no_body.status().is_client_error(), "{}", no_body.status());

    let no_session = app
        .client
        .post(app.url("/api/v1/contact/auth/me/mfa/setup"))
        .json(&serde_json::json!({ "current_password": common::CONTACT_PASSWORD }))
        .send()
        .await
        .unwrap();
    assert_eq!(no_session.status(), reqwest::StatusCode::UNAUTHORIZED);

    let wrong_pw = post_json(
        &app,
        &token,
        "/api/v1/contact/auth/me/mfa/setup",
        serde_json::json!({ "current_password": "not-the-password" }),
    )
    .await;
    assert_eq!(wrong_pw.status(), reqwest::StatusCode::UNAUTHORIZED);
    let secret: Option<String> =
        sqlx::query_scalar("SELECT portal_mfa_secret FROM contacts WHERE id = $1")
            .bind(contact.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(secret.is_none(), "a refused setup stages nothing");

    // Enable before setup: 400.
    let early = post_json(
        &app,
        &token,
        "/api/v1/contact/auth/me/mfa/enable",
        serde_json::json!({ "code": "000000", "current_password": common::CONTACT_PASSWORD }),
    )
    .await;
    assert_eq!(early.status(), reqwest::StatusCode::BAD_REQUEST);

    // Setup, then enable with the wrong password or the wrong code:
    // refused, and still off.
    let setup = post_json(
        &app,
        &token,
        "/api/v1/contact/auth/me/mfa/setup",
        serde_json::json!({ "current_password": common::CONTACT_PASSWORD }),
    )
    .await;
    let setup: serde_json::Value = setup.json().await.unwrap();
    let secret =
        mokosh_server::utils::totp::base32_decode(setup["secret"].as_str().unwrap()).unwrap();
    let code = mokosh_server::utils::totp::code_at(&secret, chrono::Utc::now());
    let enable_wrong_pw = post_json(
        &app,
        &token,
        "/api/v1/contact/auth/me/mfa/enable",
        serde_json::json!({ "code": code, "current_password": "not-the-password" }),
    )
    .await;
    assert_eq!(enable_wrong_pw.status(), reqwest::StatusCode::UNAUTHORIZED);
    let enable_wrong_code = post_json(
        &app,
        &token,
        "/api/v1/contact/auth/me/mfa/enable",
        serde_json::json!({ "code": "000000", "current_password": common::CONTACT_PASSWORD }),
    )
    .await;
    assert_eq!(enable_wrong_code.status(), reqwest::StatusCode::BAD_REQUEST);
    let enabled: bool = sqlx::query_scalar("SELECT portal_mfa_enabled FROM contacts WHERE id = $1")
        .bind(contact.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!enabled, "still off after the refused enables");

    let (_, _) = enrol(&app, &token).await;
    let again = post_json(
        &app,
        &token,
        "/api/v1/contact/auth/me/mfa/setup",
        serde_json::json!({ "current_password": common::CONTACT_PASSWORD }),
    )
    .await;
    assert_eq!(
        again.status(),
        reqwest::StatusCode::CONFLICT,
        "setup while on is 409"
    );
}

// A secret stored in the pre-encryption plaintext shape still verifies,
// and is rewritten sealed once it has.
#[sqlx::test]
async fn a_legacy_plaintext_secret_verifies_and_is_sealed_on_the_way(pool: PgPool) {
    let contact = seed_portal_contact(&pool, "legacy@example.com").await;
    let secret = mokosh_server::utils::totp::generate_secret();
    let secret_b32 = mokosh_server::utils::totp::base32_encode(&secret);
    sqlx::query(
        "UPDATE contacts SET portal_mfa_enabled = TRUE, portal_mfa_secret = $1 WHERE id = $2",
    )
    .bind(&secret_b32)
    .bind(contact.id)
    .execute(&pool)
    .await
    .unwrap();
    let app = common::boot(pool.clone()).await;

    let code = mokosh_server::utils::totp::code_at(&secret, chrono::Utc::now());
    let ok = login_with(&app, &contact, serde_json::json!({ "mfa_code": code })).await;
    assert_eq!(ok.status(), reqwest::StatusCode::OK);
    let ok: serde_json::Value = ok.json().await.unwrap();
    assert_eq!(ok["mfa_required"], false);

    let stored: String = sqlx::query_scalar("SELECT portal_mfa_secret FROM contacts WHERE id = $1")
        .bind(contact.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_ne!(
        stored, secret_b32,
        "rewritten sealed after the first verification"
    );

    // And it keeps working sealed.
    let code = mokosh_server::utils::totp::code_at(&secret, chrono::Utc::now());
    let again = login_with(&app, &contact, serde_json::json!({ "mfa_code": code })).await;
    assert_eq!(again.status(), reqwest::StatusCode::OK);
}
