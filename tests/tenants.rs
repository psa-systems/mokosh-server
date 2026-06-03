//! Integration test: tenants list returns the seeded default tenant.

mod common;

use sqlx::PgPool;

#[sqlx::test]
async fn list_tenants_returns_default(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let resp = app
        .client
        .get(app.url("/api/v1/tenants"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send list tenants");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "list tenants should succeed for a super_admin"
    );

    let body: serde_json::Value = resp.json().await.expect("tenants list JSON");
    let items = body["data"].as_array().expect("tenants list has data");
    let default = items
        .iter()
        .find(|t| t["id"].as_str() == Some(&common::DEFAULT_TENANT_ID.to_string()))
        .expect("default tenant must be present in the list");
    assert_eq!(default["slug"].as_str(), Some("default"));
}
