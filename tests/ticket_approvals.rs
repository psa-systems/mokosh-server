//! PMS-451 phase 1: integration test for ticket approvals.
//!
//! Drives the HTTP surface as a seeded super_admin: seed a ticket,
//! request approval assigned to a role the same admin holds, confirm
//! the approval surfaces in the pending queue, decide approve, confirm
//! the row flips to status='approved' and that a second decide attempt
//! returns 400 (already-decided guard). Catches the XOR routing + the
//! pending-queue role match in one pass.

mod common;

use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test]
async fn approval_round_trip_role_assigned(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;

    // Seed a single ticket so the create-approval endpoint has
    // something to bind to. Reuse the same shape as the reports test.
    let status_id: Uuid =
        sqlx::query_scalar("SELECT id FROM ticket_statuses WHERE tenant_id = $1 LIMIT 1")
            .bind(common::DEFAULT_TENANT_ID)
            .fetch_one(&pool)
            .await
            .expect("a status");
    let priority_id: Uuid =
        sqlx::query_scalar("SELECT id FROM ticket_priorities WHERE tenant_id = $1 LIMIT 1")
            .bind(common::DEFAULT_TENANT_ID)
            .fetch_one(&pool)
            .await
            .expect("a priority");
    let queue_id: Uuid =
        sqlx::query_scalar("SELECT id FROM ticket_queues WHERE tenant_id = $1 LIMIT 1")
            .bind(common::DEFAULT_TENANT_ID)
            .fetch_one(&pool)
            .await
            .expect("a queue");
    let ticket_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO tickets
           (id, tenant_id, ticket_number, title, status_id, priority_id,
            queue_id, company_id, created_by_id)
           VALUES ($1, $2, 'T-APPROVAL', 'Needs sign-off', $3, $4, $5, $6, $7)"#,
    )
    .bind(ticket_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(status_id)
    .bind(priority_id)
    .bind(queue_id)
    .bind(company_id)
    .bind(admin_id)
    .execute(&pool)
    .await
    .expect("seed ticket");

    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    // Request approval via role assignment. The seeded admin holds
    // super_admin, so they are a valid approver for any role - but
    // assign to `super_admin` explicitly to exercise the role path.
    let create: Value = app
        .client
        .post(app.url(&format!("/api/v1/tickets/{ticket_id}/approvals")))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "approver_role": "super_admin",
            "notes": "Cost exceeds soft cap",
        }))
        .send()
        .await
        .expect("create approval")
        .json()
        .await
        .expect("create body");
    assert_eq!(create["status"], "pending");
    assert_eq!(create["approver_role"], "super_admin");
    let approval_id = create["id"].as_str().expect("id").to_string();

    // Confirm the row surfaces in the caller's pending queue.
    let pending: Value = app
        .client
        .get(app.url("/api/v1/approvals/pending"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("pending list")
        .json()
        .await
        .expect("pending body");
    let arr = pending.as_array().expect("array");
    assert!(
        arr.iter()
            .any(|row| row["id"].as_str() == Some(&approval_id)),
        "approval should be in caller's pending queue: {pending}"
    );

    // Reject the XOR mis-call: both fields set must 400.
    let xor_bad = app
        .client
        .post(app.url(&format!("/api/v1/tickets/{ticket_id}/approvals")))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "approver_user_id": admin_id,
            "approver_role": "admin",
        }))
        .send()
        .await
        .expect("xor request");
    assert_eq!(xor_bad.status().as_u16(), 400);

    // Approve.
    let approve: Value = app
        .client
        .post(app.url(&format!("/api/v1/approvals/{approval_id}/decision")))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "decision": "approve",
            "decision_notes": "Confirmed with the customer",
        }))
        .send()
        .await
        .expect("decide approve")
        .json()
        .await
        .expect("approve body");
    assert_eq!(approve["status"], "approved");
    assert_eq!(approve["decided_by_id"], serde_json::json!(admin_id));

    // Second decide attempt returns 400 because the row is no longer
    // pending. Guards a race between two approvers double-deciding.
    let already = app
        .client
        .post(app.url(&format!("/api/v1/approvals/{approval_id}/decision")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "decision": "reject" }))
        .send()
        .await
        .expect("decide again");
    assert_eq!(already.status().as_u16(), 400);
}
