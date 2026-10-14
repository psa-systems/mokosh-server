//! PMS-1487: `POST /api/v1/grants/invitations` must require
//! `invitee_email` on every call. Before this, an id-only body was
//! accepted and the handler stringified the Bunyip id into the
//! `invitee_email` column, so the mailer tried to deliver to a UUID.

mod common;

use mokosh_test::mokosh_test;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

#[mokosh_test]
async fn id_only_body_is_rejected(pool: PgPool) {
    let (_admin_id, admin_email, admin_pw) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &admin_email, &admin_pw).await;

    let resp = app
        .client
        .post(app.url("/api/v1/grants/invitations"))
        .bearer_auth(&token)
        .json(&json!({
            "invitee_bunyip_user_id": Uuid::new_v4(),
            "role": "admin",
        }))
        .send()
        .await
        .expect("create invitation");

    assert!(
        resp.status().is_client_error(),
        "id-only create should be a 4xx; got {}",
        resp.status()
    );
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.expect("error body");
    assert!(
        status == reqwest::StatusCode::BAD_REQUEST
            || status == reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "expected 400 or 422; got {status}"
    );
    let names_field = body.to_string().contains("invitee_email");
    assert!(
        names_field,
        "error body should name invitee_email; got {body:?}"
    );

    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM mokosh_grant_invitations")
        .fetch_one(&pool)
        .await
        .expect("count invitations");
    assert_eq!(count, 0, "no row should have been persisted");
}

#[mokosh_test]
async fn email_only_body_still_succeeds(pool: PgPool) {
    let (_admin_id, admin_email, admin_pw) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &admin_email, &admin_pw).await;

    let resp = app
        .client
        .post(app.url("/api/v1/grants/invitations"))
        .bearer_auth(&token)
        .json(&json!({
            "invitee_email": "grantee@example.com",
            "role": "admin",
        }))
        .send()
        .await
        .expect("create invitation");

    assert!(
        resp.status().is_success(),
        "email-only create should 2xx; got {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.expect("created body");
    assert_eq!(body["invitee_email"], "grantee@example.com");
}

#[mokosh_test]
async fn id_plus_email_body_still_succeeds(pool: PgPool) {
    let (_admin_id, admin_email, admin_pw) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &admin_email, &admin_pw).await;

    let resp = app
        .client
        .post(app.url("/api/v1/grants/invitations"))
        .bearer_auth(&token)
        .json(&json!({
            "invitee_bunyip_user_id": Uuid::new_v4(),
            "invitee_email": "other-grantee@example.com",
            "role": "admin",
        }))
        .send()
        .await
        .expect("create invitation");

    assert!(
        resp.status().is_success(),
        "id+email create should 2xx; got {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.expect("created body");
    assert_eq!(body["invitee_email"], "other-grantee@example.com");
}
