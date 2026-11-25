//! Closes a parent-cycle TOCTOU race: `assert_no_parent_cycle` used to run
//! its ancestry walk in its own short-lived transaction, opened and
//! committed before `update_company`'s
//! own write transaction even began. Two concurrent `PATCH`-equivalent
//! (`PUT`) calls each read the other's pre-write state, both passed, and both
//! committed, landing a 2-cycle the check exists to prevent. The fix moves the
//! check inside `update_company`'s own transaction, behind a `FOR UPDATE` lock
//! on both the company and its proposed parent (ascending id order, so the
//! two concurrent callers never want the two locks in opposite orders).
//!
//! Covers:
//! - A single, non-concurrent call still rejects a self-id or an
//!   already-cyclic parent (unchanged behaviour).
//! - Two concurrent calls that would together close a 2-cycle: exactly one
//!   succeeds, the other is rejected with the existing cycle error, and the
//!   cycle never lands in the database.

use crate::common;

use mokosh_test::mokosh_test;
use sqlx::PgPool;

async fn create_company(app: &common::TestApp, token: &str, name: &str) -> String {
    let body = serde_json::json!({ "name": name });
    let resp = app
        .client
        .post(app.url("/api/v1/contacts/companies"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("send create company");
    assert!(
        resp.status().is_success(),
        "create company should 2xx, got {}",
        resp.status()
    );
    let v: serde_json::Value = resp.json().await.expect("create response JSON");
    v["id"]
        .as_str()
        .expect("created company has an id")
        .to_string()
}

async fn set_parent(
    app: &common::TestApp,
    token: &str,
    company_id: &str,
    parent_id: &str,
) -> reqwest::Response {
    app.client
        .put(app.url(&format!("/api/v1/contacts/companies/{company_id}")))
        .bearer_auth(token)
        .json(&serde_json::json!({ "parent_company_id": parent_id }))
        .send()
        .await
        .expect("send update company")
}

/// AC: a single, non-concurrent call setting a self-id or an already-cyclic
/// parent still fails exactly as it does today.
#[mokosh_test]
async fn self_or_existing_cycle_is_rejected_outside_a_race(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let a = create_company(&app, &token, "Alpha").await;
    let b = create_company(&app, &token, "Beta").await;

    // Self-parent.
    let resp = set_parent(&app, &token, &a, &a).await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "a company cannot be its own parent"
    );

    // B becomes A's child, then A tries to become B's child: A is already an
    // ancestor of B, so this closes a loop.
    let resp = set_parent(&app, &token, &b, &a).await;
    assert!(resp.status().is_success(), "B -> A must be allowed");
    let resp = set_parent(&app, &token, &a, &b).await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "A cannot become a child of its own descendant B"
    );
}

/// AC: two concurrent calls setting `A.parent_company_id = B` and
/// `B.parent_company_id = A` result in exactly one succeeding and the other
/// failing with the cycle-rejection error, never both succeeding. Fails on
/// the tree before this change (both checks run in their own transaction,
/// before either write commits, so both pass and both writes land) and
/// passes after it.
#[mokosh_test]
async fn concurrent_opposite_reparents_never_both_succeed(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let a = create_company(&app, &token, "Alpha").await;
    let b = create_company(&app, &token, "Beta").await;

    let (a_resp, b_resp) = tokio::join!(
        set_parent(&app, &token, &a, &b),
        set_parent(&app, &token, &b, &a),
    );

    let statuses = [a_resp.status(), b_resp.status()];
    let successes = statuses.iter().filter(|s| s.is_success()).count();
    let rejections = statuses
        .iter()
        .filter(|s| *s == &reqwest::StatusCode::UNPROCESSABLE_ENTITY)
        .count();
    assert_eq!(
        successes, 1,
        "exactly one of the two opposite reparents must succeed, got {statuses:?}"
    );
    assert_eq!(
        rejections, 1,
        "the loser must be rejected with the cycle error, got {statuses:?}"
    );

    // Whichever side lost, the database must never hold the 2-cycle.
    let both_set: bool = sqlx::query_scalar(
        "SELECT EXISTS ( \
             SELECT 1 FROM companies x, companies y \
             WHERE x.id = $1 AND y.id = $2 \
               AND x.parent_company_id = y.id AND y.parent_company_id = x.id \
         )",
    )
    .bind(uuid::Uuid::parse_str(&a).expect("a is a uuid"))
    .bind(uuid::Uuid::parse_str(&b).expect("b is a uuid"))
    .fetch_one(&app.pool)
    .await
    .expect("check for the 2-cycle");
    assert!(
        !both_set,
        "A and B must never both point at each other as parent"
    );
}
