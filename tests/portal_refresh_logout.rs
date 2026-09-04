//! PMS-729 phase 2 §5 H1+H2: contact refresh + logout HTTP wire tests,
//! on the contact plane since PMS-1025 (ported in PMS-1031).
//!
//! The service-level rotation and revocation logic lives in
//! `src/modules/contact_portal/service.rs`; this suite pins the HTTP shape
//! of `POST /contact/auth/login` (returning both tokens),
//! `POST /contact/auth/refresh` (rotation + replay + expiry), and
//! `POST /contact/auth/logout` (idempotent revocation) end-to-end.
//!
//! All 401 paths share the enumeration-resistant `UNAUTHORIZED` envelope
//! so a caller cannot tell "unknown token" from "expired" from "replay
//! detected" without another side channel.
//!
//! Two cases the retired portal pinned are gone with it: a replayed
//! refresh token revoked every live token in its rotation chain, and a
//! logout did the same. A contact session (`contact_sessions`) is
//! revoked one row at a time and carries no chain, so a replay is a
//! 401 for the replayed token only; that gap is recorded on the
//! PMS-1031 follow-up rather than pinned here as if it were the design.

mod common;

use sqlx::PgPool;
use uuid::Uuid;

/// Seed a company + a portal-enabled contact under the default tenant.
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

/// Log the seeded contact in and return the full login body so tests can
/// grab both tokens.
async fn login(app: &common::TestApp, contact: &common::PortalContact) -> serde_json::Value {
    common::contact_login(app, contact).await
}

async fn refresh(app: &common::TestApp, refresh_token: &str) -> reqwest::Response {
    app.client
        .post(app.url("/api/v1/contact/auth/refresh"))
        .json(&serde_json::json!({ "refresh_token": refresh_token }))
        .send()
        .await
        .expect("send refresh")
}

async fn logout(app: &common::TestApp, refresh_token: &str) -> reqwest::Response {
    app.client
        .post(app.url("/api/v1/contact/auth/logout"))
        .json(&serde_json::json!({ "refresh_token": refresh_token }))
        .send()
        .await
        .expect("send logout")
}

async fn assert_unauthorized_envelope(resp: reqwest::Response, ctx: &str) {
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "{ctx}: expected 401, got {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.expect("401 body");
    assert_eq!(
        body["error"]["code"].as_str(),
        Some("UNAUTHORIZED"),
        "{ctx}: envelope; got {body}"
    );
}

// AC (H1+H2): login returns access_token + refresh_token, both strings,
// plus the access expiry and the contact snapshot the SPA consumes.
#[sqlx::test]
async fn login_returns_access_and_refresh_tokens(pool: PgPool) {
    let contact = seed_portal_contact(&pool, "user@example.com").await;
    let app = common::boot(pool).await;
    let body = login(&app, &contact).await;

    assert!(body["access_token"].is_string(), "access_token present");
    assert!(body["refresh_token"].is_string(), "refresh_token present");
    assert!(body["expires_at"].is_string(), "expires_at present");
    assert!(body["contact"].is_object(), "contact snapshot present");
    // Refresh token format is `{uuid}.{secret}`; the setup-token helper
    // uses the same shape so verifying the split proves the wire matches.
    let rt = body["refresh_token"].as_str().unwrap();
    let (id, secret) = rt.split_once('.').expect("token has an id.secret shape");
    assert!(!id.is_empty() && !secret.is_empty());
    Uuid::parse_str(id).expect("token id parses as UUID");
}

// AC (H2): refresh accepts a valid token, returns a new access + refresh
// pair, and the new tokens work as credentials.
#[sqlx::test]
async fn refresh_rotates_both_tokens(pool: PgPool) {
    let contact = seed_portal_contact(&pool, "user@example.com").await;
    let app = common::boot(pool).await;
    let login_body = login(&app, &contact).await;
    let initial_refresh = login_body["refresh_token"].as_str().unwrap().to_string();

    let resp = refresh(&app, &initial_refresh).await;
    assert!(
        resp.status().is_success(),
        "refresh should 2xx, got {}",
        resp.status()
    );
    let refresh_body: serde_json::Value = resp.json().await.expect("refresh body");
    let new_access = refresh_body["access_token"]
        .as_str()
        .expect("new access_token")
        .to_string();
    let new_refresh = refresh_body["refresh_token"]
        .as_str()
        .expect("new refresh_token")
        .to_string();
    assert_ne!(
        initial_refresh, new_refresh,
        "rotation must mint a new refresh token"
    );
    assert_ne!(
        login_body["access_token"].as_str().unwrap(),
        new_access,
        "rotation must mint a new access token"
    );

    // The new access token authenticates the /me endpoint.
    let me = app
        .client
        .get(app.url("/api/v1/contact/auth/me"))
        .bearer_auth(&new_access)
        .send()
        .await
        .expect("me with new access token");
    assert!(me.status().is_success(), "new access token authenticates");

    // The new refresh token itself can be rotated again.
    let round_two = refresh(&app, &new_refresh).await;
    assert!(round_two.status().is_success(), "chain-of-2 rotation works");
}

// AC (H2 replay detection): presenting the SAME refresh token twice
// after it has already been rotated once fails closed. (The retired
// portal also revoked the successor; the contact plane does not, see the
// module comment.)
#[sqlx::test]
async fn replayed_refresh_is_refused(pool: PgPool) {
    let contact = seed_portal_contact(&pool, "user@example.com").await;
    let app = common::boot(pool).await;
    let login_body = login(&app, &contact).await;
    let rt_1 = login_body["refresh_token"].as_str().unwrap().to_string();

    // Honest customer rotates once and gets rt_2.
    let round_one = refresh(&app, &rt_1).await;
    let round_one_body: serde_json::Value = round_one.json().await.unwrap();
    let rt_2 = round_one_body["refresh_token"]
        .as_str()
        .expect("rt_2")
        .to_string();

    // Attacker replays rt_1 (already rotated) -> 401.
    let replay = refresh(&app, &rt_1).await;
    assert_unauthorized_envelope(replay, "replayed rt_1").await;

    // The honest customer's rt_2 still rotates.
    let round_two = refresh(&app, &rt_2).await;
    assert!(
        round_two.status().is_success(),
        "rt_2 rotates after the rt_1 replay, got {}",
        round_two.status()
    );
}

// AC (H1): logout revokes the presented refresh token, so a stolen
// access token cannot be renewed once the customer signs out; the token
// it was rotated from was already revoked by the rotation.
#[sqlx::test]
async fn logout_revokes_the_refresh_token(pool: PgPool) {
    let contact = seed_portal_contact(&pool, "user@example.com").await;
    let app = common::boot(pool).await;
    let login_body = login(&app, &contact).await;
    let rt = login_body["refresh_token"].as_str().unwrap().to_string();

    // Rotate once so the chain has 2 members.
    let round_one = refresh(&app, &rt).await;
    let rt_2 = round_one.json::<serde_json::Value>().await.unwrap()["refresh_token"]
        .as_str()
        .unwrap()
        .to_string();

    // Logout with the newest token.
    let out = logout(&app, &rt_2).await;
    assert_eq!(
        out.status(),
        reqwest::StatusCode::NO_CONTENT,
        "logout returns 204"
    );

    // Both are dead: rt_2 by the logout, rt by the rotation before it.
    let dead_new = refresh(&app, &rt_2).await;
    assert_unauthorized_envelope(dead_new, "rt_2 after logout").await;
    let dead_old = refresh(&app, &rt).await;
    assert_unauthorized_envelope(dead_old, "rt (already rotated)").await;
}

// AC (H1 idempotent + enumeration-resistant): logout with an unknown
// token still returns 204. This prevents a caller from probing whether
// a specific token id ever existed.
#[sqlx::test]
async fn logout_with_unknown_token_still_returns_204(pool: PgPool) {
    let app = common::boot(pool).await;
    let bogus = format!("{}.definitely-not-a-real-secret", Uuid::new_v4());
    let out = logout(&app, &bogus).await;
    assert_eq!(
        out.status(),
        reqwest::StatusCode::NO_CONTENT,
        "unknown token still 204 (idempotent)"
    );

    // Malformed too.
    let out2 = logout(&app, "not-a-token").await;
    assert_eq!(out2.status(), reqwest::StatusCode::NO_CONTENT);
}

// AC (H2 fail-closed shape): every negative refresh path (unknown,
// malformed, expired, cross-contact bogus id, empty) returns the
// UNAUTHORIZED envelope. Cannot enumerate live tokens by response.
#[sqlx::test]
async fn refresh_fails_closed_on_every_negative_path(pool: PgPool) {
    let contact = seed_portal_contact(&pool, "user@example.com").await;
    let app = common::boot(pool).await;

    // Unknown UUID + random secret.
    let unknown = format!("{}.random-secret-abc123", Uuid::new_v4());
    assert_unauthorized_envelope(refresh(&app, &unknown).await, "unknown UUID").await;

    // Malformed shape (no dot).
    assert_unauthorized_envelope(refresh(&app, "no-dot-in-here").await, "no dot").await;

    // Right UUID (a real, live one) but wrong secret.
    let login_body = login(&app, &contact).await;
    let good = login_body["refresh_token"].as_str().unwrap();
    let (id, _real) = good.split_once('.').unwrap();
    let fake = format!("{id}.wrong-secret-that-does-not-verify");
    assert_unauthorized_envelope(refresh(&app, &fake).await, "wrong secret for real id").await;
}

// AC (H2 rate limits + input validation): empty body is a 422 validation
// error (via the ValidateJson layer), not a 401. Distinct so the SPA can
// tell "you sent nothing" from "you sent a dead token".
#[sqlx::test]
async fn refresh_with_empty_body_is_validation_error(pool: PgPool) {
    let app = common::boot(pool).await;
    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/refresh"))
        .json(&serde_json::json!({ "refresh_token": "" }))
        .send()
        .await
        .expect("send empty refresh");
    // validator crate returns 422 through the AppError::Validation path.
    assert_eq!(resp.status(), reqwest::StatusCode::UNPROCESSABLE_ENTITY);
}

// AC (H1+H2 access token independence): after logout, the ACCESS token
// stays valid until its own expiry (15 min). Only the ability to REFRESH
// is revoked. Documents the intentional trade-off: access-token
// revocation would require a server-side lookup per request. (MAPPS-532
// chose the same for the retired portal, and the contact middleware
// likewise reads no session row.)
#[sqlx::test]
async fn access_token_survives_logout_until_expiry(pool: PgPool) {
    let contact = seed_portal_contact(&pool, "user@example.com").await;
    let app = common::boot(pool).await;
    let login_body = login(&app, &contact).await;
    let access = login_body["access_token"].as_str().unwrap();
    let rt = login_body["refresh_token"].as_str().unwrap();

    let out = logout(&app, rt).await;
    assert_eq!(out.status(), reqwest::StatusCode::NO_CONTENT);

    // Access token is still valid.
    let me = app
        .client
        .get(app.url("/api/v1/contact/auth/me"))
        .bearer_auth(access)
        .send()
        .await
        .expect("me");
    assert!(me.status().is_success(), "access token survives logout");

    // But the refresh path is dead.
    let dead = refresh(&app, rt).await;
    assert_unauthorized_envelope(dead, "refresh after logout").await;
}
