//! PMS-470 / PMS-451 phase 2 + PMS-484: integration test for
//! polymorphic approvals.
//!
//! Pins these guarantees:
//!   - A time_entry approval round-trips through the
//!     `/time-entries/{id}/approvals` surface and surfaces in the
//!     caller's `/approvals/pending` queue with `target='time_entry'`.
//!   - The phase-1 ticket-scoped surface keeps returning rows with
//!     `target='ticket'` and the new `entity_id` field populated.
//!   - PMS-484: A change_request approval round-trips through
//!     `/change-requests/{id}/approvals` and a quote approval through
//!     `/quotes/{id}/approvals`. Both call paths reject an unknown
//!     entity id with 404 (tenant-scoped existence check).

mod common;

use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_company(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, 'Approvals Co')")
        .bind(id)
        .bind(common::DEFAULT_TENANT_ID)
        .execute(pool)
        .await
        .expect("seed company");
    id
}

async fn seed_ticket(pool: &PgPool, company_id: Uuid, admin_id: Uuid) -> Uuid {
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
           VALUES ($1, $2, $3, 'Phase 2', $4, $5, $6, $7, $8)"#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(format!("T-{}", &id.to_string()[..8]))
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
           VALUES ($1, $2, $3, CURRENT_DATE, 60, $4, $5, true)"#,
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

#[sqlx::test]
async fn time_entry_approval_round_trip(pool: PgPool) {
    let (admin_id, admin_email, admin_pw) = common::seed_admin(&pool).await;
    let company = seed_company(&pool).await;
    let time_entry = seed_time_entry(&pool, admin_id, company).await;

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &admin_email, &admin_pw).await;

    // Create an approval against the time entry, assigned by role
    // (any admin in the tenant can decide). The admin is the only
    // user we have, so the same caller decides.
    let create_resp = app
        .client
        .post(app.url(&format!("/api/v1/time-entries/{time_entry}/approvals")))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "approver_role": "super_admin",
            "notes": "above billable threshold",
        }))
        .send()
        .await
        .expect("create approval");
    assert!(
        create_resp.status().is_success(),
        "create should 2xx; got {}",
        create_resp.status()
    );
    let row: Value = create_resp.json().await.expect("body");
    assert_eq!(row["target"], "time_entry");
    assert_eq!(
        row["entity_id"].as_str().map(str::to_string),
        Some(time_entry.to_string())
    );
    assert!(
        row["ticket_id"].is_null(),
        "ticket_id stays NULL on non-ticket targets; got {row:?}"
    );
    let approval_id = Uuid::parse_str(row["id"].as_str().unwrap()).unwrap();

    // Pending queue includes the row.
    let pending: Value = app
        .client
        .get(app.url("/api/v1/approvals/pending"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("pending")
        .json()
        .await
        .expect("pending body");
    let rows = pending.as_array().expect("array");
    assert!(
        rows.iter().any(
            |r| r["id"].as_str() == Some(approval_id.to_string().as_str())
                && r["target"].as_str() == Some("time_entry")
        ),
        "pending must include the time_entry approval; got {rows:?}"
    );

    // Decide approve.
    let decide_resp = app
        .client
        .post(app.url(&format!("/api/v1/approvals/{approval_id}/decision")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "decision": "approve" }))
        .send()
        .await
        .expect("decide");
    assert!(
        decide_resp.status().is_success(),
        "decide should 2xx; got {}",
        decide_resp.status()
    );
    let decided: Value = decide_resp.json().await.expect("decide body");
    assert_eq!(decided["status"], "approved");
    assert_eq!(decided["target"], "time_entry");
}

#[sqlx::test]
async fn ticket_approval_carries_target_and_entity_id(pool: PgPool) {
    // The phase-1 ticket-only surface must still produce rows that
    // now carry the new `target` + `entity_id` fields, so the SPA
    // can rely on them being present regardless of which prefix
    // created the row.
    let (admin_id, admin_email, admin_pw) = common::seed_admin(&pool).await;
    let company = seed_company(&pool).await;
    let ticket = seed_ticket(&pool, company, admin_id).await;

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &admin_email, &admin_pw).await;

    let create_resp = app
        .client
        .post(app.url(&format!("/api/v1/tickets/{ticket}/approvals")))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "approver_role": "super_admin",
            "notes": "ship it?",
        }))
        .send()
        .await
        .expect("create");
    assert!(create_resp.status().is_success());
    let row: Value = create_resp.json().await.expect("body");
    assert_eq!(row["target"], "ticket");
    assert_eq!(
        row["entity_id"].as_str().map(str::to_string),
        Some(ticket.to_string())
    );
    assert_eq!(
        row["ticket_id"].as_str().map(str::to_string),
        Some(ticket.to_string()),
        "phase-1 ticket_id stays populated on ticket rows for backwards compat"
    );
}

async fn seed_change_request(pool: &PgPool, admin_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO change_requests
           (id, tenant_id, title, summary, requested_by_id, status)
           VALUES ($1, $2, 'Failover plan', 'Cut over DB to replica', $3, 'submitted')"#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(admin_id)
    .execute(pool)
    .await
    .expect("seed change_request");
    id
}

async fn seed_quote(pool: &PgPool, admin_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO quotes
           (id, tenant_id, title, summary, requested_by_id, total_cents, currency, status)
           VALUES ($1, $2, 'Q1 hosting', 'Tier-2 monthly', $3, 30000, 'USD', 'submitted')"#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(admin_id)
    .execute(pool)
    .await
    .expect("seed quote");
    id
}

async fn round_trip_for(prefix: &str, entity_id: Uuid, app: &common::TestApp, token: &str) {
    let create_resp = app
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
        create_resp.status().is_success(),
        "{prefix} create should 2xx; got {}",
        create_resp.status()
    );
    let row: Value = create_resp.json().await.expect("body");
    let expected_target = match prefix {
        "change-requests" => "change_request",
        "quotes" => "quote",
        other => other,
    };
    assert_eq!(row["target"], expected_target);
    assert_eq!(
        row["entity_id"].as_str().map(str::to_string),
        Some(entity_id.to_string())
    );
    let approval_id = Uuid::parse_str(row["id"].as_str().unwrap()).unwrap();

    let list_resp = app
        .client
        .get(app.url(&format!("/api/v1/{prefix}/{entity_id}/approvals")))
        .bearer_auth(token)
        .send()
        .await
        .expect("list approvals");
    assert!(list_resp.status().is_success());
    let listed: Value = list_resp.json().await.expect("list body");
    assert!(
        listed
            .as_array()
            .map(|a| a
                .iter()
                .any(|r| r["id"].as_str() == Some(approval_id.to_string().as_str())))
            .unwrap_or(false),
        "list must include the approval; got {listed:?}"
    );

    let decide_resp = app
        .client
        .post(app.url(&format!("/api/v1/approvals/{approval_id}/decision")))
        .bearer_auth(token)
        .json(&serde_json::json!({ "decision": "approve" }))
        .send()
        .await
        .expect("decide");
    assert!(decide_resp.status().is_success());
    let decided: Value = decide_resp.json().await.expect("decide body");
    assert_eq!(decided["status"], "approved");
    assert_eq!(decided["target"], expected_target);
}

#[sqlx::test]
async fn change_request_approval_round_trip(pool: PgPool) {
    let (admin_id, admin_email, admin_pw) = common::seed_admin(&pool).await;
    let cr = seed_change_request(&pool, admin_id).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &admin_email, &admin_pw).await;
    round_trip_for("change-requests", cr, &app, &token).await;
}

#[sqlx::test]
async fn quote_approval_round_trip(pool: PgPool) {
    let (admin_id, admin_email, admin_pw) = common::seed_admin(&pool).await;
    let quote = seed_quote(&pool, admin_id).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &admin_email, &admin_pw).await;
    round_trip_for("quotes", quote, &app, &token).await;
}

#[sqlx::test]
async fn unknown_parent_returns_404(pool: PgPool) {
    let (_admin_id, admin_email, admin_pw) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &admin_email, &admin_pw).await;

    for prefix in ["change-requests", "quotes", "time-entries"] {
        let resp = app
            .client
            .get(app.url(&format!(
                "/api/v1/{prefix}/00000000-0000-0000-0000-000000000000/approvals"
            )))
            .bearer_auth(&token)
            .send()
            .await
            .expect("unknown parent GET");
        assert_eq!(
            resp.status().as_u16(),
            404,
            "{prefix} unknown parent must 404; got {}",
            resp.status()
        );
    }
}
