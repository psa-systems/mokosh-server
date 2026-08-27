//! PMS-940: the approvals payload names its subject.
//!
//! Before this, `ApprovalResponse` resolved a display name for all
//! three people on the row (requester, approver, decider) and carried
//! the thing being approved as `(target, entity_id)` alone, so the
//! SPA's queue printed a raw UUID. These tests pin the resolved
//! `entity_reference` / `entity_label` for each of the four targets,
//! and pin that an orphaned approval still reads.

mod common;

use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

const TICKET_TITLE: &str = "Printer offline in Accounts";

async fn seed_company(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, 'Label Co')")
        .bind(id)
        .bind(common::DEFAULT_TENANT_ID)
        .execute(pool)
        .await
        .expect("seed company");
    id
}

async fn seed_ticket(pool: &PgPool, company_id: Uuid, admin_id: Uuid, number: &str) -> Uuid {
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
    .bind(number)
    .bind(TICKET_TITLE)
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

/// A time entry with a fixed date and duration, so the resolved label
/// is an exact string rather than something the DB's clock decides.
async fn seed_time_entry(pool: &PgPool, admin_id: Uuid, company_id: Uuid) -> Uuid {
    let work_type_id: Uuid =
        sqlx::query_scalar("SELECT id FROM work_types WHERE tenant_id = $1 LIMIT 1")
            .bind(common::DEFAULT_TENANT_ID)
            .fetch_one(pool)
            .await
            .expect("work_type");
    let id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO time_entries
           (id, tenant_id, user_id, date, duration_minutes, work_type_id, company_id, is_billable)
           VALUES ($1, $2, $3, DATE '2026-03-04', 90, $4, $5, true)"#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(admin_id)
    .bind(work_type_id)
    .bind(company_id)
    .execute(pool)
    .await
    .expect("seed time entry");
    id
}

async fn seed_change_request(pool: &PgPool, admin_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO change_requests
           (id, tenant_id, title, summary, requested_by_id, status)
           VALUES ($1, $2, 'Fail over to the replica', 'Cut over DB', $3, 'submitted')"#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(admin_id)
    .execute(pool)
    .await
    .expect("seed change_request");
    id
}

async fn seed_quote(pool: &PgPool, admin_id: Uuid, company_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO quotes
           (id, tenant_id, company_id, quote_number, title, summary, requested_by_id,
            total, currency, status)
           VALUES ($1, $2, $3, 'Q-2026-0007', 'Tier-2 hosting', 'Monthly', $4,
                   300.00, 'USD', 'submitted')"#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .bind(admin_id)
    .execute(pool)
    .await
    .expect("seed quote");
    id
}

/// Request an approval on `prefix/{entity_id}` and hand back the
/// created row as the API returned it.
async fn request_approval(
    app: &common::TestApp,
    token: &str,
    prefix: &str,
    entity_id: Uuid,
) -> Value {
    let resp = app
        .client
        .post(app.url(&format!("/api/v1/{prefix}/{entity_id}/approvals")))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "approver_role": "super_admin",
            "notes": "sign off",
        }))
        .send()
        .await
        .expect("create approval");
    assert!(
        resp.status().is_success(),
        "{prefix} create should 2xx; got {}",
        resp.status()
    );
    resp.json().await.expect("create body")
}

async fn pending_queue(app: &common::TestApp, token: &str) -> Vec<Value> {
    let resp = app
        .client
        .get(app.url("/api/v1/approvals/pending"))
        .bearer_auth(token)
        .send()
        .await
        .expect("pending");
    assert!(resp.status().is_success(), "pending should 2xx");
    let body: Value = resp.json().await.expect("pending body");
    body.as_array().expect("array").clone()
}

fn find(rows: &[Value], approval_id: &str) -> Value {
    rows.iter()
        .find(|r| r["id"].as_str() == Some(approval_id))
        .unwrap_or_else(|| panic!("approval {approval_id} missing from queue; got {rows:?}"))
        .clone()
}

#[sqlx::test]
async fn a_ticket_approval_carries_the_ticket_number_and_title(pool: PgPool) {
    let (admin_id, admin_email, admin_pw) = common::seed_admin(&pool).await;
    let company = seed_company(&pool).await;
    let ticket = seed_ticket(&pool, company, admin_id, "T000123").await;

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &admin_email, &admin_pw).await;

    let created = request_approval(&app, &token, "tickets", ticket).await;
    assert_eq!(created["entity_reference"], "T000123");
    assert_eq!(created["entity_label"], TICKET_TITLE);

    // The queue is the surface that shipped the UUID, so assert there
    // too rather than trusting that both reads share a SELECT.
    let row = find(
        &pending_queue(&app, &token).await,
        created["id"].as_str().unwrap(),
    );
    assert_eq!(row["entity_reference"], "T000123");
    assert_eq!(row["entity_label"], TICKET_TITLE);
}

#[sqlx::test]
async fn a_time_entry_approval_names_its_duration_and_date(pool: PgPool) {
    let (admin_id, admin_email, admin_pw) = common::seed_admin(&pool).await;
    let company = seed_company(&pool).await;
    let entry = seed_time_entry(&pool, admin_id, company).await;

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &admin_email, &admin_pw).await;

    let created = request_approval(&app, &token, "time-entries", entry).await;
    assert!(
        created["entity_reference"].is_null(),
        "a time entry has no number column; got {created:?}"
    );
    assert_eq!(created["entity_label"], "90 min on 2026-03-04");
}

#[sqlx::test]
async fn a_change_request_approval_carries_its_title(pool: PgPool) {
    let (admin_id, admin_email, admin_pw) = common::seed_admin(&pool).await;
    let cr = seed_change_request(&pool, admin_id).await;

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &admin_email, &admin_pw).await;

    let created = request_approval(&app, &token, "change-requests", cr).await;
    assert!(
        created["entity_reference"].is_null(),
        "a change request has no number column; got {created:?}"
    );
    assert_eq!(created["entity_label"], "Fail over to the replica");
}

#[sqlx::test]
async fn a_quote_approval_carries_its_number_and_title(pool: PgPool) {
    let (admin_id, admin_email, admin_pw) = common::seed_admin(&pool).await;
    let company = seed_company(&pool).await;
    let quote = seed_quote(&pool, admin_id, company).await;

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &admin_email, &admin_pw).await;

    let created = request_approval(&app, &token, "quotes", quote).await;
    assert_eq!(created["entity_reference"], "Q-2026-0007");
    assert_eq!(created["entity_label"], "Tier-2 hosting");
}

#[sqlx::test]
async fn an_orphaned_approval_still_reads(pool: PgPool) {
    // `entity_id` carries no foreign key (it is polymorphic), so a
    // deleted time entry leaves its approval behind. The joins are
    // LEFT for exactly this: the row keeps its place in the queue
    // with both resolved columns null, rather than disappearing or
    // failing the read.
    let (admin_id, admin_email, admin_pw) = common::seed_admin(&pool).await;
    let company = seed_company(&pool).await;
    let entry = seed_time_entry(&pool, admin_id, company).await;

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &admin_email, &admin_pw).await;

    let created = request_approval(&app, &token, "time-entries", entry).await;
    let approval_id = created["id"].as_str().unwrap().to_string();

    sqlx::query("DELETE FROM time_entries WHERE id = $1")
        .bind(entry)
        .execute(&pool)
        .await
        .expect("delete the parent");

    let row = find(&pending_queue(&app, &token).await, &approval_id);
    assert!(
        row["entity_label"].is_null() && row["entity_reference"].is_null(),
        "a missing parent resolves to null, not an error; got {row:?}"
    );
    assert_eq!(
        row["entity_id"].as_str().map(str::to_string),
        Some(entry.to_string()),
        "entity_id stays, so the client has something to fall back to"
    );
}
