//! PMS-1085: a contact's live sessions and "sign out that other
//! browser", on the contact plane. Setup, rotation and logout are
//! pinned by `portal_refresh_logout`; this file is the SPA-visible
//! list (one row per rotation family, PMS-1062) and the per-session
//! delete.

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

/// `(access_token, refresh_token)` for one "browser".
async fn login(app: &common::TestApp, contact: &common::PortalContact) -> (String, String) {
    let body = common::contact_login(app, contact).await;
    (
        body["access_token"].as_str().unwrap().to_string(),
        body["refresh_token"].as_str().unwrap().to_string(),
    )
}

async fn list(app: &common::TestApp, access: &str) -> Vec<serde_json::Value> {
    let resp = app
        .client
        .get(app.url("/api/v1/contact/auth/me/sessions"))
        .bearer_auth(access)
        .send()
        .await
        .expect("list sessions");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    resp.json::<Vec<serde_json::Value>>()
        .await
        .expect("sessions JSON")
}

async fn revoke(app: &common::TestApp, access: &str, id: &str) -> reqwest::Response {
    app.client
        .delete(app.url(&format!("/api/v1/contact/auth/me/sessions/{id}")))
        .bearer_auth(access)
        .send()
        .await
        .expect("revoke session")
}

async fn refresh(app: &common::TestApp, refresh_token: &str) -> reqwest::Response {
    app.client
        .post(app.url("/api/v1/contact/auth/refresh"))
        .json(&serde_json::json!({ "refresh_token": refresh_token }))
        .send()
        .await
        .expect("refresh")
}

fn current_id(rows: &[serde_json::Value]) -> String {
    rows.iter()
        .find(|r| r["current"] == true)
        .expect("a current session")["id"]
        .as_str()
        .unwrap()
        .to_string()
}

// A fresh login lists exactly one session, marked current, with the
// fields the SPA renders.
#[sqlx::test]
async fn a_fresh_login_lists_one_current_session(pool: PgPool) {
    let contact = seed_portal_contact(&pool, "user@example.com").await;
    let app = common::boot(pool).await;
    let (access, _) = login(&app, &contact).await;
    let rows = list(&app, &access).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["current"], true);
    for key in ["id", "issued_at", "last_seen_at", "expires_at"] {
        assert!(!rows[0][key].is_null(), "{key} present: {:?}", rows[0]);
    }
}

// Two browsers: two rows, and each caller sees only its own as current.
// The id is the family, so a refresh keeps it while the session stays
// current.
#[sqlx::test]
async fn two_logins_list_two_sessions_and_the_id_survives_rotation(pool: PgPool) {
    let contact = seed_portal_contact(&pool, "user@example.com").await;
    let app = common::boot(pool).await;
    let (access_a, refresh_a) = login(&app, &contact).await;
    let (access_b, _) = login(&app, &contact).await;

    let rows_a = list(&app, &access_a).await;
    let rows_b = list(&app, &access_b).await;
    assert_eq!(rows_a.len(), 2);
    assert_eq!(rows_b.len(), 2);
    let cur_a = current_id(&rows_a);
    let cur_b = current_id(&rows_b);
    assert_ne!(cur_a, cur_b, "each browser is current only to itself");
    assert_eq!(rows_a.iter().filter(|r| r["current"] == true).count(), 1);

    // Rotate A: new access token, same family id, still current.
    let rotated = refresh(&app, &refresh_a).await;
    assert!(rotated.status().is_success());
    let rotated: serde_json::Value = rotated.json().await.unwrap();
    let access_a2 = rotated["access_token"].as_str().unwrap();
    let rows_a2 = list(&app, access_a2).await;
    assert_eq!(rows_a2.len(), 2, "rotation adds no session");
    assert_eq!(
        current_id(&rows_a2),
        cur_a,
        "the family id is stable across rotation"
    );
}

// Revoking the other browser removes it from the list and kills its
// refresh token; the caller's own keeps rotating.
#[sqlx::test]
async fn revoking_another_session_signs_that_browser_out(pool: PgPool) {
    let contact = seed_portal_contact(&pool, "user@example.com").await;
    let app = common::boot(pool).await;
    let (access_a, refresh_a) = login(&app, &contact).await;
    let (_, refresh_b) = login(&app, &contact).await;

    let rows = list(&app, &access_a).await;
    let other = rows
        .iter()
        .find(|r| r["current"] == false)
        .expect("the other browser")["id"]
        .as_str()
        .unwrap()
        .to_string();
    let resp = revoke(&app, &access_a, &other).await;
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);

    let rows = list(&app, &access_a).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["current"], true);
    let dead = refresh(&app, &refresh_b).await;
    assert_eq!(
        dead.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "B is signed out"
    );
    let alive = refresh(&app, &refresh_a).await;
    assert!(alive.status().is_success(), "A still rotates");
}

// The caller's own session is refused with a 400 that points at logout,
// and stays live.
#[sqlx::test]
async fn revoking_the_current_session_is_refused(pool: PgPool) {
    let contact = seed_portal_contact(&pool, "user@example.com").await;
    let app = common::boot(pool).await;
    let (access, refresh_token) = login(&app, &contact).await;
    let own = current_id(&list(&app, &access).await);
    let resp = revoke(&app, &access, &own).await;
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body.to_string().contains("/auth/logout"),
        "points at logout: {body}"
    );
    assert!(refresh(&app, &refresh_token).await.status().is_success());
}

// Another contact's session id is a silent 204 and that session
// survives; so is an id that names nothing.
#[sqlx::test]
async fn another_contacts_session_cannot_be_revoked(pool: PgPool) {
    let alice = seed_portal_contact(&pool, "alice@example.com").await;
    let bob = seed_portal_contact(&pool, "bob@example.com").await;
    let app = common::boot(pool).await;
    let (access_alice, _) = login(&app, &alice).await;
    let (access_bob, refresh_bob) = login(&app, &bob).await;
    let bobs = current_id(&list(&app, &access_bob).await);

    let resp = revoke(&app, &access_alice, &bobs).await;
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT, "silent");
    assert!(
        refresh(&app, &refresh_bob).await.status().is_success(),
        "Bob survives"
    );
    let unknown = revoke(&app, &access_alice, &Uuid::new_v4().to_string()).await;
    assert_eq!(unknown.status(), reqwest::StatusCode::NO_CONTENT);
    assert_eq!(
        list(&app, &access_bob).await.len(),
        1,
        "Bob still lists his session"
    );
}

// Both routes need a session.
#[sqlx::test]
async fn session_routes_require_auth(pool: PgPool) {
    let _contact = seed_portal_contact(&pool, "user@example.com").await;
    let app = common::boot(pool).await;
    let list = app
        .client
        .get(app.url("/api/v1/contact/auth/me/sessions"))
        .send()
        .await
        .unwrap();
    assert_eq!(list.status(), reqwest::StatusCode::UNAUTHORIZED);
    let del = app
        .client
        .delete(app.url(&format!(
            "/api/v1/contact/auth/me/sessions/{}",
            Uuid::new_v4()
        )))
        .send()
        .await
        .unwrap();
    assert_eq!(del.status(), reqwest::StatusCode::UNAUTHORIZED);
}
