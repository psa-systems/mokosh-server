//! mokosh-contact-login prompt 004: end-to-end tests for the
//! contact-plane auth service.
//!
//! Covers: magic-link setup, login, refresh rotation, logout revoke,
//! me hydration, tenant-suspend kick, forgot-password enum resistance,
//! and JWT typ isolation across planes.

mod common;

use sqlx::PgPool;
use uuid::Uuid;

/// Seed a Company + Contact + granted portal access under
/// DEFAULT_TENANT. Returns the contact's magic-link setup token +
/// the Company's portal_slug so the calling test can drive the
/// contact-plane HTTP endpoints directly.
async fn seed_portal_contact(pool: &PgPool, email: &str) -> (Uuid, String, String) {
    let company_id = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, 'MCL P004 Co')")
        .bind(company_id)
        .bind(common::DEFAULT_TENANT_ID)
        .execute(pool)
        .await
        .expect("seed company");
    let contact_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contacts (id, tenant_id, company_id, first_name, last_name, email) \
         VALUES ($1, $2, $3, 'Test', 'Contact', $4)",
    )
    .bind(contact_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .bind(email)
    .execute(pool)
    .await
    .expect("seed contact");

    // Reuse the staff-side grant path so the slug + setup token
    // land through the production code path (prompt 003).
    let db = mokosh_server::Database::from_pool(pool.clone());
    let contact_svc = mokosh_server::modules::contacts::ContactService::new(db);
    let roles: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM portal_roles WHERE tenant_id = $1 AND name = 'Support Contact'",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_all(pool)
    .await
    .expect("read Support role");
    let role_ids: Vec<Uuid> = roles.into_iter().map(|(id,)| id).collect();
    let outcome = contact_svc
        .grant_portal_access(
            mokosh_server::modules::auth::TenantId::from_trusted(common::DEFAULT_TENANT_ID),
            contact_id,
            &role_ids,
            &mokosh_server::modules::audit::AuditCtx::system(common::DEFAULT_TENANT_ID),
        )
        .await
        .expect("grant_portal_access");

    // Extract the token out of the setup_link. The URL shape is
    // `{app_url}/portal/{slug}/set-password?token={contact_id}.{secret}`.
    let prefix = format!("/portal/{}/set-password?token=", outcome.portal_slug);
    let token = outcome
        .setup_link
        .split(&prefix)
        .nth(1)
        .expect("token in setup_link")
        .to_string();
    (contact_id, outcome.portal_slug, token)
}

/// mokosh-contact-login prompt 004: happy-path setup + login + me.
///
/// Redeems the magic link via POST /contact/auth/set-password,
/// signs in via POST /contact/auth/login, then hydrates via GET
/// /contact/auth/me with the returned Bearer.
#[sqlx::test]
async fn contact_full_flow_setup_login_me(pool: PgPool) {
    let (_contact_id, slug, token) = seed_portal_contact(&pool, "flow@mcl.example").await;
    let app = common::boot(pool.clone()).await;

    // Set-password (magic link redemption).
    let strong = "Kq7$mZ2n#PxR9wLf";
    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/set-password"))
        .json(&serde_json::json!({ "token": token, "password": strong }))
        .send()
        .await
        .expect("set-password");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::NO_CONTENT,
        "mokosh-contact-login prompt 004: fresh magic link must redeem to 204"
    );

    // Login with the fresh password.
    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/login"))
        .json(&serde_json::json!({
            "slug": slug,
            "email": "flow@mcl.example",
            "password": strong,
        }))
        .send()
        .await
        .expect("login");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "prompt 004: valid credentials must return 200"
    );
    // Set-Cookie carries the refresh token.
    let cookie_header = resp
        .headers()
        .get("set-cookie")
        .expect("Set-Cookie on login response")
        .to_str()
        .expect("header text")
        .to_string();
    assert!(
        cookie_header.contains("mokosh:contact_token=")
            && cookie_header.contains("HttpOnly")
            && cookie_header.contains("SameSite=Lax"),
        "prompt 004: login must Set-Cookie with HttpOnly + SameSite=Lax, got {cookie_header}"
    );
    let body: serde_json::Value = resp.json().await.expect("login JSON");
    let access = body["access_token"]
        .as_str()
        .expect("access_token")
        .to_string();
    let refresh = body["refresh_token"]
        .as_str()
        .expect("refresh_token")
        .to_string();
    assert!(!access.is_empty() && !refresh.is_empty());
    let caps = body["contact"]["caps"]
        .as_array()
        .expect("contact.caps")
        .iter()
        .map(|c| c.as_str().unwrap_or_default().to_string())
        .collect::<Vec<_>>();
    assert!(
        caps.iter().any(|c| c == "tickets:read"),
        "prompt 004: Support Contact role must confer tickets:read, got {caps:?}"
    );

    // GET /me with the Bearer.
    let resp = app
        .client
        .get(app.url("/api/v1/contact/auth/me"))
        .bearer_auth(&access)
        .send()
        .await
        .expect("me");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let me: serde_json::Value = resp.json().await.expect("me JSON");
    assert_eq!(me["email"].as_str(), Some("flow@mcl.example"));
    assert_eq!(me["portal_slug"].as_str(), Some(slug.as_str()));
    assert_eq!(me["company_name"].as_str(), Some("MCL P004 Co"));

    // Refresh rotates - fresh access + refresh pair; old refresh is
    // now dead.
    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/refresh"))
        .json(&serde_json::json!({ "refresh_token": refresh }))
        .send()
        .await
        .expect("refresh");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("refresh JSON");
    let refresh2 = body["refresh_token"]
        .as_str()
        .expect("refresh2")
        .to_string();
    assert_ne!(
        refresh, refresh2,
        "prompt 004: refresh must rotate the token"
    );

    // Replaying the old refresh -> 401.
    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/refresh"))
        .json(&serde_json::json!({ "refresh_token": refresh }))
        .send()
        .await
        .expect("replay old refresh");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "prompt 004: old refresh after rotation must 401"
    );

    // Logout revokes the current refresh.
    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/logout"))
        .json(&serde_json::json!({ "refresh_token": refresh2 }))
        .send()
        .await
        .expect("logout");
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);

    // Refresh after logout -> 401.
    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/refresh"))
        .json(&serde_json::json!({ "refresh_token": refresh2 }))
        .send()
        .await
        .expect("refresh after logout");
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

/// mokosh-contact-login prompt 004: login with a wrong password 401s
/// and bumps the failed-login counter. Enumeration-resistant: the
/// same 401 shape for unknown-email, wrong-password, and unknown-slug.
#[sqlx::test]
async fn contact_login_with_wrong_password_401s(pool: PgPool) {
    let (contact_id, slug, token) = seed_portal_contact(&pool, "wrong@mcl.example").await;
    let app = common::boot(pool.clone()).await;

    // Redeem so the account is loginable.
    let strong = "Kq7$mZ2n#PxR9wLf";
    app.client
        .post(app.url("/api/v1/contact/auth/set-password"))
        .json(&serde_json::json!({ "token": token, "password": strong }))
        .send()
        .await
        .expect("set-password");

    // Wrong password.
    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/login"))
        .json(&serde_json::json!({
            "slug": slug,
            "email": "wrong@mcl.example",
            "password": "not-the-password",
        }))
        .send()
        .await
        .expect("login");
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    let counter: i32 =
        sqlx::query_scalar("SELECT portal_failed_login_count FROM contacts WHERE id = $1")
            .bind(contact_id)
            .fetch_one(&pool)
            .await
            .expect("read counter");
    assert!(
        counter >= 1,
        "prompt 004: wrong password must bump portal_failed_login_count, got {counter}"
    );

    // Unknown email -> same 401.
    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/login"))
        .json(&serde_json::json!({
            "slug": slug,
            "email": "unknown@mcl.example",
            "password": strong,
        }))
        .send()
        .await
        .expect("unknown email login");
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    // Unknown slug -> same 401.
    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/login"))
        .json(&serde_json::json!({
            "slug": "ZZZZZZZZZZZZZZZZ",
            "email": "wrong@mcl.example",
            "password": strong,
        }))
        .send()
        .await
        .expect("unknown slug login");
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

/// mokosh-contact-login prompt 004: contact login against a suspended
/// tenant 401s. Mirrors MAPPS-557 on the retired portal plane.
#[sqlx::test]
async fn contact_login_against_suspended_tenant_401s(pool: PgPool) {
    let (_contact_id, slug, token) = seed_portal_contact(&pool, "suspend@mcl.example").await;
    let app = common::boot(pool.clone()).await;
    let strong = "Kq7$mZ2n#PxR9wLf";
    app.client
        .post(app.url("/api/v1/contact/auth/set-password"))
        .json(&serde_json::json!({ "token": token, "password": strong }))
        .send()
        .await
        .expect("set-password");

    sqlx::query("UPDATE tenants SET status = 'suspended' WHERE id = $1")
        .bind(common::DEFAULT_TENANT_ID)
        .execute(&pool)
        .await
        .expect("suspend tenant");

    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/login"))
        .json(&serde_json::json!({
            "slug": slug,
            "email": "suspend@mcl.example",
            "password": strong,
        }))
        .send()
        .await
        .expect("login");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "prompt 004: login against suspended tenant must 401 (enum-resistant)"
    );
}

/// mokosh-contact-login prompt 004: forgot-password returns 204
/// regardless of whether the (slug, email) matches a contact. No
/// email dispatched on a miss.
#[sqlx::test]
async fn contact_forgot_password_is_enumeration_resistant(pool: PgPool) {
    let (_contact_id, slug, _token) = seed_portal_contact(&pool, "forgot@mcl.example").await;
    let app = common::boot(pool.clone()).await;

    // Miss.
    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/forgot-password"))
        .json(&serde_json::json!({
            "slug": slug,
            "email": "unknown@mcl.example",
        }))
        .send()
        .await
        .expect("forgot miss");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::NO_CONTENT,
        "prompt 004: forgot on unknown email must still 204"
    );

    // Hit.
    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/forgot-password"))
        .json(&serde_json::json!({
            "slug": slug,
            "email": "forgot@mcl.example",
        }))
        .send()
        .await
        .expect("forgot hit");
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);
}

/// mokosh-contact-login prompt 004: staff JWT rejected on
/// /contact/auth/me and contact JWT rejected on staff endpoints. The
/// `typ` claim gate is what prevents cross-plane replay.
#[sqlx::test]
async fn contact_token_rejected_on_staff_endpoint(pool: PgPool) {
    let (_contact_id, slug, token) = seed_portal_contact(&pool, "typ@mcl.example").await;
    let app = common::boot(pool.clone()).await;
    let strong = "Kq7$mZ2n#PxR9wLf";
    app.client
        .post(app.url("/api/v1/contact/auth/set-password"))
        .json(&serde_json::json!({ "token": token, "password": strong }))
        .send()
        .await
        .expect("set-password");
    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/login"))
        .json(&serde_json::json!({
            "slug": slug,
            "email": "typ@mcl.example",
            "password": strong,
        }))
        .send()
        .await
        .expect("login");
    let body: serde_json::Value = resp.json().await.expect("login JSON");
    let contact_access = body["access_token"]
        .as_str()
        .expect("access_token")
        .to_string();

    // Contact bearer on a staff endpoint (contacts list) -> 403.
    // Prompt 004 asserted 401 here because the staff `RequireAuth`
    // extractor did not see an AuthState and folded to Unauthorized.
    // Prompt 008 layers the Companies + Contacts CRM with an explicit
    // contact-plane rejection so an authenticated contact bearer that
    // reaches the staff CRM now returns 403 instead: the caller IS
    // authenticated, but the surface is staff-only.
    let resp = app
        .client
        .get(app.url("/api/v1/contacts/contacts"))
        .bearer_auth(&contact_access)
        .send()
        .await
        .expect("staff endpoint with contact bearer");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::FORBIDDEN,
        "prompt 008: staff CRM must 403 on a `typ: contact` bearer"
    );

    // Staff bearer on /contact/auth/me -> 401.
    let (_admin_id, admin_email, admin_password) = common::seed_admin(&pool).await;
    let staff_access = common::login(&app, &admin_email, &admin_password).await;
    let resp = app
        .client
        .get(app.url("/api/v1/contact/auth/me"))
        .bearer_auth(&staff_access)
        .send()
        .await
        .expect("contact /me with staff bearer");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "prompt 004: /contact/auth/me must 401 on a `typ: access` staff bearer"
    );
}

/// mokosh-contact-login prompt 004: /portal/{slug}/host returns 200
/// with the branding hint (including raw tenant status) so the SPA
/// can render a suspended splash. Unknown slugs 404 (enum-resistant).
#[sqlx::test]
async fn contact_portal_host_returns_hint_for_known_and_404s_for_unknown(pool: PgPool) {
    let (_contact_id, slug, _token) = seed_portal_contact(&pool, "host@mcl.example").await;
    let app = common::boot(pool.clone()).await;

    let resp = app
        .client
        .get(app.url(&format!("/api/v1/contact/portal/{slug}/host")))
        .send()
        .await
        .expect("host known");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("host JSON");
    assert_eq!(body["portal_slug"].as_str(), Some(slug.as_str()));
    assert_eq!(body["company_name"].as_str(), Some("MCL P004 Co"));
    assert_eq!(body["tenant_status"].as_str(), Some("active"));

    let resp = app
        .client
        .get(app.url("/api/v1/contact/portal/ZZZZZZZZZZZZZZZZ/host"))
        .send()
        .await
        .expect("host unknown");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::NOT_FOUND,
        "prompt 004: unknown slug on /portal/{{slug}}/host must 404"
    );
}

// ============================================================================
// MAPPS-647 / PMS-917 AC4: negative tests against every contact-plane auth
// path so a contact with `portal_password_hash IS NULL` cannot mint a session
// on any surface. The password-login NULL-hash branch, the DTO empty-password
// refusal, `refresh` without a prior session, and `reset-password` returning
// no session tokens were all unpinned before this closeout. Magic-link redeem
// is already covered by `tests/contact_magic_link_login.rs:913`.
// ============================================================================

/// PMS-917 AC4: a contact whose `portal_password_hash IS NULL` is refused
/// with the same 401 shape as a wrong-password login. Pins the
/// `ok_or(Unauthorized)` branch in `contact_portal::service::login`.
#[sqlx::test]
async fn contact_login_with_no_credential_returns_401(pool: PgPool) {
    let (_contact_id, slug, _token) = seed_portal_contact(&pool, "no-cred@mcl.example").await;
    // Deliberately skip set-password so `portal_password_hash` stays NULL.
    let app = common::boot(pool.clone()).await;

    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/login"))
        .json(&serde_json::json!({
            "slug": slug,
            "email": "no-cred@mcl.example",
            "password": "anything-nonempty",
        }))
        .send()
        .await
        .expect("no-cred login");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "PMS-917: NULL portal_password_hash must 401, indistinguishable from wrong-password"
    );
}

/// PMS-917 AC4: an empty submitted password is refused by DTO validation
/// before it reaches the hash-compare, so the "empty submitted password"
/// branch cannot slip through even if a future service-layer refactor
/// weakens the NULL-hash guard.
#[sqlx::test]
async fn contact_login_with_empty_password_returns_400(pool: PgPool) {
    let (_contact_id, slug, _token) = seed_portal_contact(&pool, "empty-pw@mcl.example").await;
    let app = common::boot(pool.clone()).await;

    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/login"))
        .json(&serde_json::json!({
            "slug": slug,
            "email": "empty-pw@mcl.example",
            "password": "",
        }))
        .send()
        .await
        .expect("empty-password login");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "PMS-917: DTO validator must refuse an empty password with 400"
    );
}

/// PMS-917 AC4: `refresh` cannot originate a session for a no-credential
/// contact. A forged/unknown refresh token 401s without touching the
/// contact row, so a NULL-hash contact has no way to obtain access tokens
/// through this path either.
#[sqlx::test]
async fn contact_refresh_with_bogus_token_returns_401(pool: PgPool) {
    let (_contact_id, _slug, _token) =
        seed_portal_contact(&pool, "refresh-nocred@mcl.example").await;
    let app = common::boot(pool.clone()).await;

    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/refresh"))
        .json(&serde_json::json!({
            "refresh_token": "not-a-real-token",
        }))
        .send()
        .await
        .expect("bogus refresh");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "PMS-917: refresh must 401 on an unknown token; no session may be minted"
    );
    let cookie_header = resp.headers().get("set-cookie");
    assert!(
        cookie_header.is_none(),
        "PMS-917: refresh 401 must not Set-Cookie a contact session, got {cookie_header:?}"
    );
}

/// PMS-917 AC4: `reset-password` writes `portal_password_hash` and returns
/// 204 without any session material. Even though it now legitimately gives
/// a no-credential contact a credential, it does so WITHOUT minting a
/// session; the SPA then has to drive `POST /contact/auth/login` with the
/// freshly-set password. Pins that contract.
#[sqlx::test]
async fn contact_reset_password_returns_no_session(pool: PgPool) {
    let (_contact_id, _slug, token) =
        seed_portal_contact(&pool, "reset-nosession@mcl.example").await;
    let app = common::boot(pool.clone()).await;

    // The `portal_setup_tokens` table backs both setup + reset; the
    // seed's token can drive reset_password directly (they share
    // `setup_password` under the hood, see service.rs:531).
    let strong = "Kq7$mZ2n#PxR9wLf";
    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/reset-password"))
        .json(&serde_json::json!({ "token": token, "password": strong }))
        .send()
        .await
        .expect("reset-password");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::NO_CONTENT,
        "PMS-917: reset-password must 204 with no body"
    );
    assert!(
        resp.headers().get("set-cookie").is_none(),
        "PMS-917: reset-password must not Set-Cookie a contact session"
    );
    let body = resp.text().await.unwrap_or_default();
    assert!(
        body.trim().is_empty(),
        "PMS-917: reset-password must return an empty body (no tokens), got {body:?}"
    );
}
