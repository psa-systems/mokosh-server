//! Regression tests for the "suspended tenant returns 401" bug.
//!
//! Fresh login against a suspended tenant AND an authenticated request
//! whose tenant gets suspended mid-flight must BOTH surface as 403 with
//! the "This organization is not active" copy - not the generic 401 the
//! SPA renders as "session expired".

mod common;

use sqlx::PgPool;

/// Login against a tenant whose status is not `active` must return 403
/// with the server's "not active" message so the SPA can render the
/// correct splash instead of prompting for re-authentication.
#[sqlx::test]
async fn login_against_suspended_tenant_returns_403_not_401(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    sqlx::query("UPDATE tenants SET status = 'suspended' WHERE id = $1")
        .bind(common::DEFAULT_TENANT_ID)
        .execute(&pool)
        .await
        .expect("suspend tenant");
    let app = common::boot(pool.clone()).await;

    let resp = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .json(&serde_json::json!({
            "email": email,
            "password": password,
            "tenant_slug": "default",
        }))
        .send()
        .await
        .expect("send /login");

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::FORBIDDEN,
        "suspended-tenant login must return 403 so the SPA renders the correct copy \
         (see src/modules/auth/service.rs ensure_tenant_active)"
    );
    let body: serde_json::Value = resp.json().await.expect("login JSON");
    let message = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.to_lowercase().contains("organization")
            || message.to_lowercase().contains("not active"),
        "message must name the suspension so the SPA can hydrate its splash: got {message:?}"
    );
}

/// A live authenticated session whose tenant gets suspended mid-flight
/// must have the very next agent-plane request return 403 with the same
/// copy, NOT 401.
#[sqlx::test]
async fn authed_request_after_tenant_suspend_returns_403_not_401(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;

    let access = common::login(&app, &email, &password).await;

    sqlx::query("UPDATE tenants SET status = 'suspended' WHERE id = $1")
        .bind(common::DEFAULT_TENANT_ID)
        .execute(&pool)
        .await
        .expect("suspend tenant mid-flight");

    let resp = app
        .client
        .get(app.url("/api/v1/tickets"))
        .bearer_auth(&access)
        .send()
        .await
        .expect("send /tickets after suspend");

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::FORBIDDEN,
        "authed request after tenant suspend must return 403 so the SPA renders the correct copy \
         (see src/modules/auth/middleware.rs auth_middleware - the Err(_) arm currently drops to \
         AuthState::default, which reads back as 401 downstream)"
    );
    let body: serde_json::Value = resp.json().await.expect("tickets JSON");
    let message = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.to_lowercase().contains("organization")
            || message.to_lowercase().contains("not active"),
        "authed-response message must name the suspension too: got {message:?}"
    );
}
