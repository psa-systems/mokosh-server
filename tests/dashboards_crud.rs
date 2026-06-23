//! PMS-453: integration test for saved dashboards CRUD.
//!
//! Drives the real HTTP surface as a seeded admin: create two
//! dashboards, promote the second to default, confirm GET /default
//! surfaces it, confirm the first is no longer default, then delete
//! the second and confirm GET /default returns null. Catches the
//! partial-unique-index swap-default ceremony at the route layer
//! instead of only at unit-test layer.

mod common;

use serde_json::Value;
use sqlx::PgPool;

#[sqlx::test]
async fn saved_dashboards_default_swap_cycle(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    // GET /default on an empty set returns null without 500'ing.
    let resp = app
        .client
        .get(app.url("/api/v1/dashboards/default"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get default initial");
    assert!(resp.status().is_success(), "default empty -> 200");
    let initial: Value = resp.json().await.expect("default body");
    assert!(initial.is_null(), "no dashboards yet -> null");

    // Create the first dashboard (not default).
    let first: Value = app
        .client
        .post(app.url("/api/v1/dashboards"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "name": "Tickets overview",
            "layout": { "widgets": ["tickets-by-status"] },
            "is_default": false,
        }))
        .send()
        .await
        .expect("create first")
        .json()
        .await
        .expect("first body");
    assert_eq!(first["is_default"], false);

    // Create the second dashboard AS default - the route should clear
    // any other default in the same transaction. With first.is_default
    // = false this is a no-op clear, but the route still runs.
    let second: Value = app
        .client
        .post(app.url("/api/v1/dashboards"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "name": "SLA dashboard",
            "layout": { "widgets": ["sla-at-risk"] },
            "is_default": true,
        }))
        .send()
        .await
        .expect("create second")
        .json()
        .await
        .expect("second body");
    assert_eq!(second["is_default"], true);

    // PATCH the first to promote it to default. This must clear the
    // second's default flag in the same transaction so the unique
    // index does not fire.
    let promoted: Value = app
        .client
        .patch(app.url(&format!(
            "/api/v1/dashboards/{}",
            first["id"].as_str().unwrap()
        )))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "is_default": true }))
        .send()
        .await
        .expect("patch first to default")
        .json()
        .await
        .expect("promoted body");
    assert_eq!(promoted["is_default"], true);

    // GET /default now surfaces the first row.
    let now_default: Value = app
        .client
        .get(app.url("/api/v1/dashboards/default"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get default after swap")
        .json()
        .await
        .expect("default body");
    assert_eq!(now_default["id"], first["id"]);

    // The second row is no longer default.
    let second_check: Value = app
        .client
        .get(app.url(&format!(
            "/api/v1/dashboards/{}",
            second["id"].as_str().unwrap()
        )))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get second after swap")
        .json()
        .await
        .expect("second body");
    assert_eq!(second_check["is_default"], false);

    // List returns the default-first ordering.
    let list: Value = app
        .client
        .get(app.url("/api/v1/dashboards"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list")
        .json()
        .await
        .expect("list body");
    let arr = list.as_array().expect("array");
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["id"], first["id"]);

    // Delete the default row; GET /default returns null again.
    let del = app
        .client
        .delete(app.url(&format!(
            "/api/v1/dashboards/{}",
            first["id"].as_str().unwrap()
        )))
        .bearer_auth(&token)
        .send()
        .await
        .expect("delete first");
    assert!(del.status().is_success());
    let after_delete: Value = app
        .client
        .get(app.url("/api/v1/dashboards/default"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("default after delete")
        .json()
        .await
        .expect("default body");
    assert!(
        after_delete.is_null(),
        "default deleted -> /default returns null"
    );
}
