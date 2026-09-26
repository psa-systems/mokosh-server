//! Integration tests for the opportunities module. Drives the real
//! HTTP surface (`/api/v1/crm/opportunities`) so routing and the
//! service are exercised alongside the store.

mod common;

use mokosh_test::mokosh_test;
use sqlx::PgPool;
use uuid::Uuid;

/// The happy path: create an opportunity against a real company, read
/// it back, then read the list and see it there.
#[mokosh_test]
async fn create_get_list(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let resp = app
        .client
        .post(app.url("/api/v1/crm/opportunities"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "company_id": company_id,
            "title": "Renew MSP contract",
            "value_amount": "5000.00",
            "expected_close_date": "2026-12-31",
        }))
        .send()
        .await
        .expect("send create");
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);
    let created: serde_json::Value = resp.json().await.expect("create JSON");
    let opp_id = created["id"].as_str().expect("id");
    assert_eq!(created["stage"], "lead");
    assert!(created["closed_at"].is_null());

    let resp = app
        .client
        .get(app.url(&format!("/api/v1/crm/opportunities/{opp_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send get");
    assert!(resp.status().is_success());
    let one: serde_json::Value = resp.json().await.expect("get JSON");
    assert_eq!(one["title"], "Renew MSP contract");

    let resp = app
        .client
        .get(app.url(&format!(
            "/api/v1/crm/opportunities?company_id={company_id}"
        )))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send list");
    let listed: Vec<serde_json::Value> = resp.json().await.expect("list JSON");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["id"].as_str(), Some(opp_id));
}

/// The update path advances the stage without closing. Closing is
/// refused: an open transition to `won` / `lost` has to go through the
/// close endpoint, so the paired stage / outcome / closed_at write
/// lives in one place.
#[mokosh_test]
async fn stage_transitions_through_the_update_endpoint_except_the_close_ones(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let created: serde_json::Value = app
        .client
        .post(app.url("/api/v1/crm/opportunities"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "company_id": company_id,
            "title": "Firewall refresh",
        }))
        .send()
        .await
        .expect("send create")
        .json()
        .await
        .expect("create JSON");
    let opp_id = created["id"].as_str().expect("id").to_string();

    // Advance through open stages.
    for stage in ["qualified", "proposal", "negotiation"] {
        let resp = app
            .client
            .put(app.url(&format!("/api/v1/crm/opportunities/{opp_id}")))
            .bearer_auth(&token)
            .json(&serde_json::json!({ "stage": stage }))
            .send()
            .await
            .expect("send update");
        assert!(
            resp.status().is_success(),
            "advancing to {stage} must succeed, got {}",
            resp.status()
        );
    }

    // The update endpoint refuses a close-stage move.
    let resp = app
        .client
        .put(app.url(&format!("/api/v1/crm/opportunities/{opp_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "stage": "won" }))
        .send()
        .await
        .expect("send close-via-update");
    assert_eq!(resp.status(), reqwest::StatusCode::UNPROCESSABLE_ENTITY);
}

/// Closing sets stage, outcome and closed_at together, and (on won)
/// accepts an optional link to the quote that closed the sale.
#[mokosh_test]
async fn closing_is_a_single_write(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let created: serde_json::Value = app
        .client
        .post(app.url("/api/v1/crm/opportunities"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "company_id": company_id,
            "title": "Managed detection and response upgrade",
        }))
        .send()
        .await
        .expect("send create")
        .json()
        .await
        .expect("create JSON");
    let opp_id = created["id"].as_str().expect("id").to_string();

    let resp = app
        .client
        .post(app.url(&format!("/api/v1/crm/opportunities/{opp_id}/close")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "outcome": "lost" }))
        .send()
        .await
        .expect("send close");
    assert!(resp.status().is_success(), "close must 200 or 201");
    let closed: serde_json::Value = resp.json().await.expect("close JSON");
    assert_eq!(closed["stage"], "lost");
    assert_eq!(closed["outcome"], "lost");
    assert!(closed["closed_at"].is_string());

    // A second close on the same row is refused.
    let resp = app
        .client
        .post(app.url(&format!("/api/v1/crm/opportunities/{opp_id}/close")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "outcome": "won" }))
        .send()
        .await
        .expect("send re-close");
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

/// A foreign company id is refused up front so the FK is a backstop
/// rather than the first defence. Foreign as in "belongs to another
/// tenant": the RLS policy makes the row invisible, so the service's
/// `assert_company_in_tenant` finds no match and refuses.
#[mokosh_test]
async fn creating_against_a_foreign_company_is_rejected(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let (foreign_tenant_id, _uid, _e, _p) =
        common::seed_tenant_with_admin(&pool, "foreign-tenant").await;
    // Company on the OTHER tenant.
    let foreign_company_id = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, $3)")
        .bind(foreign_company_id)
        .bind(foreign_tenant_id)
        .bind("Not Our Company")
        .execute(&pool)
        .await
        .expect("seed foreign company");

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let resp = app
        .client
        .post(app.url("/api/v1/crm/opportunities"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "company_id": foreign_company_id,
            "title": "Not our deal",
        }))
        .send()
        .await
        .expect("send create");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "a company id from another tenant must be refused up front"
    );
}
