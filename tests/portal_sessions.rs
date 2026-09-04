//! PMS-729 phase 2 §5 H6: portal session listing + per-session revoke
//! HTTP wire tests.
//!
//! Setup + rotation + logout are exercised by `portal_refresh_logout`;
//! this file focuses on the SPA-visible view of live sessions and the
//! "sign out this other browser" delete path.

mod common;

use sqlx::PgPool;
use uuid::Uuid;

const PORTAL_PASSWORD: &str = "portal-password-12345";

async fn seed_portal_contact(pool: &PgPool, email: &str) -> Uuid {
    // Company name must be unique per tenant (idx_companies_tenant_name_unique);
    // derive from the contact email so co-seeded contacts get distinct rows.
    let company = Uuid::new_v4();
    let company_name = format!("Co-{}", email.split('@').next().unwrap_or("x"));
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, $3)")
        .bind(company)
        .bind(common::DEFAULT_TENANT_ID)
        .bind(&company_name)
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

/// Log in and return (access_token, refresh_token) so tests can drive
/// the session endpoints from an authenticated caller.
async fn login(app: &common::TestApp, email: &str) -> (String, String) {
    let resp = app
        .client
        .post(app.url("/api/v1/portal/auth/login"))
        .json(&serde_json::json!({
            "tenant_slug": "default",
            "email": email,
            "password": PORTAL_PASSWORD,
        }))
        .send()
        .await
        .expect("login");
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.unwrap();
    (
        body["access_token"].as_str().unwrap().to_string(),
        body["refresh_token"].as_str().unwrap().to_string(),
    )
}

async fn list_sessions(app: &common::TestApp, access: &str) -> Vec<serde_json::Value> {
    let resp = app
        .client
        .get(app.url("/api/v1/portal/auth/me/sessions"))
        .bearer_auth(access)
        .send()
        .await
        .expect("list sessions");
    assert!(resp.status().is_success());
    resp.json().await.unwrap()
}

async fn refresh(app: &common::TestApp, refresh_token: &str) -> (String, String) {
    let resp = app
        .client
        .post(app.url("/api/v1/portal/auth/refresh"))
        .json(&serde_json::json!({ "refresh_token": refresh_token }))
        .send()
        .await
        .expect("refresh");
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.unwrap();
    (
        body["access_token"].as_str().unwrap().to_string(),
        body["refresh_token"].as_str().unwrap().to_string(),
    )
}

// AC (H6 list one session): a fresh login lists exactly one session
// and marks it `current`.
#[sqlx::test]
async fn list_after_login_returns_one_current_session(pool: PgPool) {
    seed_portal_contact(&pool, "user@example.com").await;
    let app = common::boot(pool).await;
    let (access, _refresh) = login(&app, "user@example.com").await;

    let sessions = list_sessions(&app, &access).await;
    assert_eq!(sessions.len(), 1, "one live session after login");
    assert_eq!(sessions[0]["current"].as_bool(), Some(true));
    assert!(sessions[0]["id"].as_str().is_some());
    assert!(sessions[0]["issued_at"].as_str().is_some());
    assert!(sessions[0]["expires_at"].as_str().is_some());
}

// AC (H6 list two sessions): after logging in from two "browsers"
// (two separate login calls), both show up, and only the caller's own
// session is `current`.
#[sqlx::test]
async fn list_two_sessions_marks_only_the_current(pool: PgPool) {
    seed_portal_contact(&pool, "user@example.com").await;
    let app = common::boot(pool).await;
    // "Browser A" logs in.
    let (access_a, _rt_a) = login(&app, "user@example.com").await;
    // "Browser B" logs in (fresh access + refresh pair, different sid).
    let (access_b, _rt_b) = login(&app, "user@example.com").await;

    // List via browser A: two rows, only A's is current.
    let sessions_a = list_sessions(&app, &access_a).await;
    assert_eq!(sessions_a.len(), 2, "two live sessions after two logins");
    let current_count = sessions_a
        .iter()
        .filter(|s| s["current"].as_bool() == Some(true))
        .count();
    assert_eq!(
        current_count, 1,
        "exactly one session marked current per caller"
    );

    // List via browser B: also two rows, but B's is current (not A's).
    let sessions_b = list_sessions(&app, &access_b).await;
    assert_eq!(sessions_b.len(), 2);
    let a_id_from_a = sessions_a
        .iter()
        .find(|s| s["current"].as_bool() == Some(true))
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let a_id_from_b = sessions_b
        .iter()
        .find(|s| s["current"].as_bool() != Some(true))
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        a_id_from_a, a_id_from_b,
        "A's session id is stable across viewers"
    );
}

// AC (H6 rotation): after a refresh, the caller's `sid` changes so
// the SAME chain shows up in the list with the NEW id (rotation
// walked forward).
#[sqlx::test]
async fn current_session_id_rotates_after_refresh(pool: PgPool) {
    seed_portal_contact(&pool, "user@example.com").await;
    let app = common::boot(pool).await;
    let (access_1, rt_1) = login(&app, "user@example.com").await;
    let sessions_before = list_sessions(&app, &access_1).await;
    let sid_before = sessions_before[0]["id"].as_str().unwrap().to_string();

    // Rotate.
    let (access_2, _rt_2) = refresh(&app, &rt_1).await;
    let sessions_after = list_sessions(&app, &access_2).await;
    assert_eq!(
        sessions_after.len(),
        1,
        "still one live session (rotation replaces)"
    );
    let sid_after = sessions_after[0]["id"].as_str().unwrap().to_string();
    assert_ne!(sid_after, sid_before, "sid rotates on refresh");
    assert_eq!(sessions_after[0]["current"].as_bool(), Some(true));
}

// AC (H6 revoke another): revoking a different session works and
// removes it from the list.
#[sqlx::test]
async fn revoke_another_session_removes_it(pool: PgPool) {
    seed_portal_contact(&pool, "user@example.com").await;
    let app = common::boot(pool).await;
    let (access_a, _rt_a) = login(&app, "user@example.com").await;
    let (_access_b, _rt_b) = login(&app, "user@example.com").await;

    // From A, find B's session id (the non-current one).
    let sessions = list_sessions(&app, &access_a).await;
    let target_id = sessions
        .iter()
        .find(|s| s["current"].as_bool() != Some(true))
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    let resp = app
        .client
        .delete(app.url(&format!("/api/v1/portal/auth/me/sessions/{target_id}")))
        .bearer_auth(&access_a)
        .send()
        .await
        .expect("delete");
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);

    // List shrinks to one (A's own session).
    let after = list_sessions(&app, &access_a).await;
    assert_eq!(after.len(), 1);
    assert_eq!(after[0]["current"].as_bool(), Some(true));
    assert_ne!(after[0]["id"].as_str(), Some(target_id.as_str()));
}

// AC (H6 self-revoke refused): revoking the caller's own session id
// returns 400 with the "use /logout" hint (do NOT quietly succeed and
// leave the SPA with a stale in-memory token).
#[sqlx::test]
async fn cannot_revoke_own_current_session(pool: PgPool) {
    seed_portal_contact(&pool, "user@example.com").await;
    let app = common::boot(pool).await;
    let (access, _rt) = login(&app, "user@example.com").await;

    let sessions = list_sessions(&app, &access).await;
    let own_id = sessions[0]["id"].as_str().unwrap().to_string();

    let resp = app
        .client
        .delete(app.url(&format!("/api/v1/portal/auth/me/sessions/{own_id}")))
        .bearer_auth(&access)
        .send()
        .await
        .expect("delete self");
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .contains("/portal/auth/logout"));
}

// AC (H6 cross-contact refused): a caller cannot revoke another
// contact's session even if they guess a valid id. Silent 204 same
// as an unknown id (enumeration-resistant).
#[sqlx::test]
async fn cannot_revoke_another_contacts_session(pool: PgPool) {
    seed_portal_contact(&pool, "alice@example.com").await;
    seed_portal_contact(&pool, "bob@example.com").await;
    let app = common::boot(pool.clone()).await;
    let (alice_access, _rt) = login(&app, "alice@example.com").await;
    let (_bob_access, _bob_rt) = login(&app, "bob@example.com").await;

    // Find Bob's session id by inspecting the row directly.
    let (bob_row,): (Uuid,) = sqlx::query_as(
        "SELECT id FROM portal_refresh_tokens \
         WHERE contact_id = (SELECT id FROM contacts WHERE email = 'bob@example.com') \
         AND revoked_at IS NULL LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .expect("select bob's session");

    // Alice tries to revoke Bob's session.
    let resp = app
        .client
        .delete(app.url(&format!("/api/v1/portal/auth/me/sessions/{bob_row}")))
        .bearer_auth(&alice_access)
        .send()
        .await
        .expect("delete other");
    // Silent 204: no leak about whether the id existed.
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);

    // Bob's row is still live.
    let (revoked,): (Option<chrono::DateTime<chrono::Utc>>,) =
        sqlx::query_as("SELECT revoked_at FROM portal_refresh_tokens WHERE id = $1")
            .bind(bob_row)
            .fetch_one(&pool)
            .await
            .expect("select bob's row");
    assert!(
        revoked.is_none(),
        "cross-contact revoke must NOT actually revoke"
    );
}

// AC (H6 unauth): both routes require a valid portal session.
#[sqlx::test]
async fn sessions_routes_require_auth(pool: PgPool) {
    let app = common::boot(pool).await;

    let list = app
        .client
        .get(app.url("/api/v1/portal/auth/me/sessions"))
        .send()
        .await
        .expect("list without auth");
    assert_eq!(list.status(), reqwest::StatusCode::UNAUTHORIZED);

    let delete = app
        .client
        .delete(app.url(&format!(
            "/api/v1/portal/auth/me/sessions/{}",
            Uuid::new_v4()
        )))
        .send()
        .await
        .expect("delete without auth");
    assert_eq!(delete.status(), reqwest::StatusCode::UNAUTHORIZED);
}
