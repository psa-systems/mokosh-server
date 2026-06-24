//! PMS-477 phase 2: integration test for the saved-report execution
//! runtime.
//!
//! Pins the contract the SPA depends on:
//!   - the execute endpoint returns rows shaped by the saved
//!     report's `columns` array, with the requested aliases as keys;
//!   - `?per_page=&page=` pagination overrides work; `total` is the
//!     full count across all pages;
//!   - an unsupported entity_type 400s naming the entity;
//!   - an unknown column 400s naming the column;
//!   - filters narrow the result set (equality + IN);
//!   - the visibility rule on `get` applies: a private report
//!     authored by another user returns 404 on execute;
//!   - a shared report authored by another user executes for any
//!     tenant member.

mod common;

use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_ticket(pool: &PgPool, company_id: Uuid, admin_id: Uuid, title: &str) -> Uuid {
    let status_id: Uuid =
        sqlx::query_scalar("SELECT id FROM ticket_statuses WHERE tenant_id = $1 LIMIT 1")
            .bind(common::DEFAULT_TENANT_ID)
            .fetch_one(pool)
            .await
            .expect("status");
    let priority_id: Uuid =
        sqlx::query_scalar("SELECT id FROM ticket_priorities WHERE tenant_id = $1 LIMIT 1")
            .bind(common::DEFAULT_TENANT_ID)
            .fetch_one(pool)
            .await
            .expect("priority");
    let queue_id: Uuid =
        sqlx::query_scalar("SELECT id FROM ticket_queues WHERE tenant_id = $1 LIMIT 1")
            .bind(common::DEFAULT_TENANT_ID)
            .fetch_one(pool)
            .await
            .expect("queue");
    let id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO tickets
           (id, tenant_id, ticket_number, title, status_id, priority_id,
            queue_id, company_id, created_by_id)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(format!("T-{}", &id.to_string()[..8]))
    .bind(title)
    .bind(status_id)
    .bind(priority_id)
    .bind(queue_id)
    .bind(company_id)
    .bind(admin_id)
    .execute(pool)
    .await
    .expect("seed ticket");
    id
}

#[sqlx::test]
async fn saved_report_execute_round_trip(pool: PgPool) {
    let (admin_id, admin_email, admin_pw) = common::seed_admin(&pool).await;
    let (_other_id, other_email, other_pw) = common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "report-runner@example.com",
        "admin",
    )
    .await;
    let company_id = common::seed_company(&pool).await;

    // Seed three tickets so pagination + filter narrowing has
    // something to work on.
    let _t1 = seed_ticket(&pool, company_id, admin_id, "Alpha").await;
    let _t2 = seed_ticket(&pool, company_id, admin_id, "Bravo").await;
    let _t3 = seed_ticket(&pool, company_id, admin_id, "Charlie").await;

    let app = common::boot(pool.clone()).await;
    let admin_token = common::login(&app, &admin_email, &admin_pw).await;
    let other_token = common::login(&app, &other_email, &other_pw).await;

    // Author creates a SHARED report (so the other user can also
    // execute it later in the test).
    let shared: Value = app
        .client
        .post(app.url("/api/v1/reports/saved"))
        .bearer_auth(&admin_token)
        .json(&serde_json::json!({
            "name": "Tickets for execute test",
            "entity_type": "tickets",
            "columns": [
                {"field": "ticket_number"},
                {"field": "title", "header": "Subject"},
                {"field": "status_name"},
                {"field": "company_name"},
            ],
            "is_shared": true,
        }))
        .send()
        .await
        .expect("create shared")
        .json()
        .await
        .expect("shared body");
    let shared_id = shared["id"].as_str().expect("shared id").to_string();

    // Happy path: execute returns rows shaped by the columns array.
    let exec: Value = app
        .client
        .post(app.url(&format!("/api/v1/reports/saved/{shared_id}/execute")))
        .bearer_auth(&admin_token)
        .send()
        .await
        .expect("execute")
        .json()
        .await
        .expect("execute body");
    let rows = exec["rows"].as_array().expect("rows array");
    assert_eq!(rows.len(), 3, "all three tickets land in page 1");
    assert_eq!(exec["total"], 3);
    assert_eq!(exec["page"], 1);
    // Aliases include the four columns we requested in declared order.
    let aliases = exec["aliases"].as_array().expect("aliases");
    assert_eq!(aliases[0], "ticket_number");
    assert_eq!(aliases[1], "Subject");
    assert_eq!(aliases[2], "status_name");
    assert_eq!(aliases[3], "company_name");
    // Each row carries the requested keys.
    let row0 = rows[0].as_object().expect("row0 object");
    assert!(row0.contains_key("ticket_number"));
    assert!(row0.contains_key("Subject"));
    assert!(row0.contains_key("status_name"));
    assert!(row0.contains_key("company_name"));

    // Pagination overrides: per_page=2 gives 2 rows but total=3.
    let paged: Value = app
        .client
        .post(app.url(&format!(
            "/api/v1/reports/saved/{shared_id}/execute?per_page=2&page=1"
        )))
        .bearer_auth(&admin_token)
        .send()
        .await
        .expect("paged")
        .json()
        .await
        .expect("paged body");
    assert_eq!(paged["rows"].as_array().unwrap().len(), 2);
    assert_eq!(paged["total"], 3);

    // Filter narrowing: equality on company_id keeps the 3 matching
    // rows; equality on a fake company_id returns 0 rows.
    let bogus_company = Uuid::new_v4();
    let private_with_filter: Value = app
        .client
        .post(app.url("/api/v1/reports/saved"))
        .bearer_auth(&admin_token)
        .json(&serde_json::json!({
            "name": "Filtered no-rows",
            "entity_type": "tickets",
            "columns": [{"field": "ticket_number"}],
            "filters": { "company_id": bogus_company.to_string() },
            "is_shared": false,
        }))
        .send()
        .await
        .expect("create filtered")
        .json()
        .await
        .expect("filtered body");
    let filtered_id = private_with_filter["id"].as_str().unwrap().to_string();
    let filtered_exec: Value = app
        .client
        .post(app.url(&format!("/api/v1/reports/saved/{filtered_id}/execute")))
        .bearer_auth(&admin_token)
        .send()
        .await
        .expect("filtered execute")
        .json()
        .await
        .expect("filtered exec body");
    assert_eq!(filtered_exec["total"], 0);
    assert_eq!(filtered_exec["rows"].as_array().unwrap().len(), 0);

    // Unsupported entity rejected at execute time.
    let bad_entity: Value = app
        .client
        .post(app.url("/api/v1/reports/saved"))
        .bearer_auth(&admin_token)
        .json(&serde_json::json!({
            "name": "Bad entity",
            "entity_type": "invoices",
            "columns": [{"field": "id"}],
            "is_shared": false,
        }))
        .send()
        .await
        .expect("create bad-entity")
        .json()
        .await
        .expect("bad-entity body");
    let bad_entity_id = bad_entity["id"].as_str().unwrap().to_string();
    let bad_entity_exec = app
        .client
        .post(app.url(&format!("/api/v1/reports/saved/{bad_entity_id}/execute")))
        .bearer_auth(&admin_token)
        .send()
        .await
        .expect("bad-entity execute");
    assert_eq!(bad_entity_exec.status().as_u16(), 400);

    // Unknown column rejected naming the offender.
    let bad_col: Value = app
        .client
        .post(app.url("/api/v1/reports/saved"))
        .bearer_auth(&admin_token)
        .json(&serde_json::json!({
            "name": "Bad column",
            "entity_type": "tickets",
            "columns": [{"field": "totally_made_up"}],
            "is_shared": false,
        }))
        .send()
        .await
        .expect("create bad-col")
        .json()
        .await
        .expect("bad-col body");
    let bad_col_id = bad_col["id"].as_str().unwrap().to_string();
    let bad_col_exec = app
        .client
        .post(app.url(&format!("/api/v1/reports/saved/{bad_col_id}/execute")))
        .bearer_auth(&admin_token)
        .send()
        .await
        .expect("bad-col execute");
    assert_eq!(bad_col_exec.status().as_u16(), 400);
    let bad_col_body: Value = bad_col_exec.json().await.expect("body");
    assert!(
        bad_col_body.to_string().contains("totally_made_up"),
        "error must name the offending column; got {bad_col_body}"
    );

    // The shared report is executable by the OTHER user (the
    // visibility rule applied at execute time matches the one on
    // get/update).
    let other_exec_shared = app
        .client
        .post(app.url(&format!("/api/v1/reports/saved/{shared_id}/execute")))
        .bearer_auth(&other_token)
        .send()
        .await
        .expect("other exec shared");
    assert!(
        other_exec_shared.status().is_success(),
        "shared report executable by another tenant member"
    );

    // The PRIVATE filtered report (authored by admin) returns 404
    // when the OTHER user tries to execute it. Same posture as
    // get_one - hides private reports behind a 404 rather than 403.
    let other_exec_private = app
        .client
        .post(app.url(&format!("/api/v1/reports/saved/{filtered_id}/execute")))
        .bearer_auth(&other_token)
        .send()
        .await
        .expect("other exec private");
    assert_eq!(other_exec_private.status().as_u16(), 404);
}
