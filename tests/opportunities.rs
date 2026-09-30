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

/// An `update` racing a `close` that commits first: both read
/// `closed_at IS NULL` before either writes, so the pre-write guard alone
/// (`existing.closed_at.is_some()`) cannot catch the loser, exactly the
/// failing interleaving PMS-1434 describes. A third transaction holds the
/// opportunity's row lock; a direct SQL statement standing in for the
/// concurrent `close` (the "equivalent direct post-close call" the issue's
/// acceptance criteria allows) queues for that lock first, then the `update`
/// request's own write queues behind it; releasing the lock lets the
/// close-equivalent commit before the update's write runs. The update's own
/// `UPDATE ... WHERE closed_at IS NULL` must then match zero rows and return
/// the immutability error rather than silently overwriting the now-closed
/// row.
#[mokosh_test]
async fn a_concurrent_update_loses_the_close_race(pool: PgPool) {
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
            "title": "Backup solution refresh",
        }))
        .send()
        .await
        .expect("send create")
        .json()
        .await
        .expect("create JSON");
    let opp_id: Uuid = created["id"].as_str().expect("id").parse().expect("uuid");

    let mut blocker = pool.begin().await.expect("open blocking transaction");
    sqlx::query("SELECT id FROM opportunities WHERE id = $1 FOR UPDATE")
        .bind(opp_id)
        .execute(&mut *blocker)
        .await
        .expect("take the opportunity row lock");

    // Stands in for a concurrent `close` that has already passed its own
    // pre-write guard and is now writing. It queues for the row lock first.
    let closer_pool = pool.clone();
    let closer = tokio::spawn(async move {
        let mut tx = closer_pool.begin().await.expect("open closer transaction");
        sqlx::query(
            "UPDATE opportunities \
             SET stage = 'lost', outcome = 'lost', closed_at = NOW(), updated_at = NOW() \
             WHERE tenant_id = $1 AND id = $2 AND closed_at IS NULL",
        )
        .bind(common::DEFAULT_TENANT_ID)
        .bind(opp_id)
        .execute(&mut *tx)
        .await
        .expect("closer update");
        tx.commit().await.expect("closer commit");
    });
    // Long enough for `closer` to reach and queue on the row lock before
    // the update request below does.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let (update_resp, closer_result, ()) = tokio::join!(
        app.client
            .put(app.url(&format!("/api/v1/crm/opportunities/{opp_id}")))
            .bearer_auth(&token)
            .json(&serde_json::json!({ "notes": "still negotiating" }))
            .send(),
        closer,
        async {
            // Long enough for the update request to reach its own read
            // (sees the row still open) and park behind `closer` on the
            // write lock.
            tokio::time::sleep(std::time::Duration::from_millis(750)).await;
            blocker
                .rollback()
                .await
                .expect("release the opportunity row lock");
        },
    );
    closer_result.expect("closer task");
    let update_resp = update_resp.expect("send update");

    assert_eq!(
        update_resp.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "the update racing a winning close must be rejected as immutable, got {}",
        update_resp.status()
    );

    let (notes, closed_at): (Option<String>, Option<chrono::DateTime<chrono::Utc>>) =
        sqlx::query_as("SELECT notes, closed_at FROM opportunities WHERE id = $1")
            .bind(opp_id)
            .fetch_one(&pool)
            .await
            .expect("read opportunity state");
    assert!(closed_at.is_some(), "the opportunity is closed");
    assert_ne!(
        notes.as_deref(),
        Some("still negotiating"),
        "the losing update must not have silently mutated the closed row"
    );
}
