//! Integration test: legacy HS256 auth happy path.
//!
//! Covers PMS-124 F10 acceptance for the auth route group: a freshly
//! seeded super_admin can POST `/api/v1/auth/login` and the resulting
//! cookie authenticates a subsequent GET `/api/v1/auth/me`.

mod common;

use sqlx::PgPool;

#[sqlx::test]
async fn login_then_me_happy_path(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;

    let login_resp = common::login(&app, &email, &password).await;
    assert_eq!(
        login_resp.status(),
        reqwest::StatusCode::OK,
        "login should succeed for seeded admin"
    );

    let me = app
        .client
        .get(app.url("/api/v1/auth/me"))
        .send()
        .await
        .expect("send /me request");
    assert_eq!(
        me.status(),
        reqwest::StatusCode::OK,
        "/me should authenticate via the login cookie"
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
