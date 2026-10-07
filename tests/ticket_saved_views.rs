//! MAPPS-998 slice 1: per-user saved views for the Tickets list.
//!
//! Covers the shape acceptance criteria pin: scope on (tenant_id, user_id),
//! name-ascending list, unique name per user (409), cross-user id is 404
//! (no existence oracle), and a rename to another USER's existing name
//! succeeds (uniqueness is per user, not per tenant).

mod common;

use mokosh_test::mokosh_test;
use serde_json::{json, Value};
use sqlx::PgPool;

#[mokosh_test]
async fn save_list_update_delete_round_trip(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    // Save two views for this user.
    let morning: Value = app
        .client
        .post(app.url("/api/v1/tickets/saved-views"))
        .bearer_auth(&token)
        .json(&json!({
            "name": "Morning queue",
            "filter": { "status_id": "11111111-1111-4111-8111-111111111111" },
            "sort": { "key": "updated_at", "direction": "desc" },
        }))
        .send()
        .await
        .expect("create morning")
        .json()
        .await
        .expect("create morning body");
    assert_eq!(morning["name"], "Morning queue");

    let evening: Value = app
        .client
        .post(app.url("/api/v1/tickets/saved-views"))
        .bearer_auth(&token)
        .json(&json!({
            "name": "Evening sweep",
            "filter": {},
            "sort": {},
        }))
        .send()
        .await
        .expect("create evening")
        .json()
        .await
        .expect("create evening body");

    // List comes back name-ascending.
    let list: Vec<Value> = app
        .client
        .get(app.url("/api/v1/tickets/saved-views"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list")
        .json()
        .await
        .expect("list body");
    assert_eq!(list.len(), 2);
    assert_eq!(list[0]["name"], "Evening sweep");
    assert_eq!(list[1]["name"], "Morning queue");

    // Rename the first one; it keeps its id and moves in the list.
    let evening_id = evening["id"].as_str().expect("evening id");
    let renamed: Value = app
        .client
        .put(app.url(&format!("/api/v1/tickets/saved-views/{evening_id}")))
        .bearer_auth(&token)
        .json(&json!({ "name": "Zed last" }))
        .send()
        .await
        .expect("rename")
        .json()
        .await
        .expect("rename body");
    assert_eq!(renamed["name"], "Zed last");
    assert_eq!(renamed["id"], evening_id);

    // Delete the morning view; the list now has one.
    let morning_id = morning["id"].as_str().expect("morning id");
    let del = app
        .client
        .delete(app.url(&format!("/api/v1/tickets/saved-views/{morning_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("delete");
    assert!(del.status().is_success(), "delete status {}", del.status());
    let after: Vec<Value> = app
        .client
        .get(app.url("/api/v1/tickets/saved-views"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list after")
        .json()
        .await
        .expect("list after body");
    assert_eq!(after.len(), 1);
    assert_eq!(after[0]["name"], "Zed last");
}

#[mokosh_test]
async fn a_duplicate_name_for_the_same_user_is_a_409(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let first = app
        .client
        .post(app.url("/api/v1/tickets/saved-views"))
        .bearer_auth(&token)
        .json(&json!({ "name": "Morning queue", "filter": {}, "sort": {} }))
        .send()
        .await
        .expect("first create");
    assert!(first.status().is_success());

    let second = app
        .client
        .post(app.url("/api/v1/tickets/saved-views"))
        .bearer_auth(&token)
        .json(&json!({ "name": "Morning queue", "filter": {}, "sort": {} }))
        .send()
        .await
        .expect("second create");
    assert_eq!(
        second.status(),
        409,
        "the second create with the same name must 409"
    );
}

#[mokosh_test]
async fn a_cross_user_id_answers_404(pool: PgPool) {
    // User A seeds a view.
    let (_admin_id, email_a, password_a) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token_a = common::login(&app, &email_a, &password_a).await;

    let view: Value = app
        .client
        .post(app.url("/api/v1/tickets/saved-views"))
        .bearer_auth(&token_a)
        .json(&json!({ "name": "A's view", "filter": {}, "sort": {} }))
        .send()
        .await
        .expect("A create")
        .json()
        .await
        .expect("A body");
    let view_id = view["id"].as_str().expect("view id");

    // User B exists in the same tenant.
    let (_b_id, email_b, password_b) = common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "someone-else@example.com",
        "admin",
    )
    .await;
    let token_b = common::login(&app, &email_b, &password_b).await;

    // B cannot see A's view in their own list.
    let b_list: Vec<Value> = app
        .client
        .get(app.url("/api/v1/tickets/saved-views"))
        .bearer_auth(&token_b)
        .send()
        .await
        .expect("B list")
        .json()
        .await
        .expect("B list body");
    assert!(
        b_list.is_empty(),
        "A's views must not reach B's own list: {b_list:?}"
    );

    // B cannot update A's view (404, not 403 - no existence oracle).
    let update = app
        .client
        .put(app.url(&format!("/api/v1/tickets/saved-views/{view_id}")))
        .bearer_auth(&token_b)
        .json(&json!({ "name": "stolen" }))
        .send()
        .await
        .expect("B update");
    assert_eq!(
        update.status(),
        404,
        "B updating A's view must 404, not 403: {}",
        update.status()
    );

    // B cannot delete A's view either.
    let delete = app
        .client
        .delete(app.url(&format!("/api/v1/tickets/saved-views/{view_id}")))
        .bearer_auth(&token_b)
        .send()
        .await
        .expect("B delete");
    assert_eq!(
        delete.status(),
        404,
        "B deleting A's view must 404, not 403: {}",
        delete.status()
    );

    // A's view is still there.
    let a_list: Vec<Value> = app
        .client
        .get(app.url("/api/v1/tickets/saved-views"))
        .bearer_auth(&token_a)
        .send()
        .await
        .expect("A list")
        .json()
        .await
        .expect("A list body");
    assert_eq!(a_list.len(), 1);
}

#[mokosh_test]
async fn a_whitespace_only_name_is_a_400_not_a_500(pool: PgPool) {
    // " " passes the untrimmed `length(min = 1)` check but trims to "",
    // which the column CHECK rejects; the request-layer validator must
    // catch this before it ever reaches the database (PMS-1474).
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let create = app
        .client
        .post(app.url("/api/v1/tickets/saved-views"))
        .bearer_auth(&token)
        .json(&json!({ "name": " ", "filter": {}, "sort": {} }))
        .send()
        .await
        .expect("create");
    assert_eq!(
        create.status(),
        422,
        "create with a whitespace-only name must be a validation error, not 500: {}",
        create.status()
    );

    let view: Value = app
        .client
        .post(app.url("/api/v1/tickets/saved-views"))
        .bearer_auth(&token)
        .json(&json!({ "name": "Morning queue", "filter": {}, "sort": {} }))
        .send()
        .await
        .expect("seed create")
        .json()
        .await
        .expect("seed create body");
    let view_id = view["id"].as_str().expect("view id");

    let update = app
        .client
        .put(app.url(&format!("/api/v1/tickets/saved-views/{view_id}")))
        .bearer_auth(&token)
        .json(&json!({ "name": " " }))
        .send()
        .await
        .expect("update");
    assert_eq!(
        update.status(),
        422,
        "update with a whitespace-only name must be a validation error, not 500: {}",
        update.status()
    );
}

#[mokosh_test]
async fn two_users_in_one_tenant_can_hold_the_same_view_name(pool: PgPool) {
    // Uniqueness is per (tenant_id, user_id, name), not per tenant: two
    // operators should each be able to have their own "Morning queue".
    let (_a_id, email_a, password_a) = common::seed_admin(&pool).await;
    let (_b_id, email_b, password_b) = common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "second@example.com",
        "admin",
    )
    .await;

    let app = common::boot(pool).await;
    let token_a = common::login(&app, &email_a, &password_a).await;
    let token_b = common::login(&app, &email_b, &password_b).await;

    for token in [&token_a, &token_b] {
        let r = app
            .client
            .post(app.url("/api/v1/tickets/saved-views"))
            .bearer_auth(token)
            .json(&json!({ "name": "Morning queue", "filter": {}, "sort": {} }))
            .send()
            .await
            .expect("create");
        assert!(
            r.status().is_success(),
            "both users must be able to hold 'Morning queue' independently: {}",
            r.status()
        );
    }
}
