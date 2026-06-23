//! PMS-448 phase 2: integration test for the transition triggers.
//!
//! Pins three guarantees:
//!   - a `ticket.status_changed` rule whose `to_status_id` matches
//!     fires when the agent moves the ticket into that status, and
//!     records a `workflow_rule_runs` row;
//!   - a `ticket.priority_changed` rule whose `from_priority_id`
//!     matches but `to_priority_id` does not is filtered out (AND
//!     semantics across keys);
//!   - the create-rule endpoint accepts the new triggers (Phase 2
//!     widened the allow-list).

mod common;

use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

async fn lookup_two(pool: &PgPool, table: &str) -> (Uuid, Uuid) {
    let rows: Vec<(Uuid,)> = sqlx::query_as(&format!(
        "SELECT id FROM {table} WHERE tenant_id = $1 ORDER BY id LIMIT 2"
    ))
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_all(pool)
    .await
    .unwrap_or_else(|e| panic!("lookup pair from {table}: {e}"));
    assert!(
        rows.len() >= 2,
        "{table} needs at least 2 rows for the transition test"
    );
    (rows[0].0, rows[1].0)
}

#[sqlx::test]
async fn transition_triggers_fire_and_filter(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let (status_a, status_b) = lookup_two(&pool, "ticket_statuses").await;
    let (priority_a, priority_b) = lookup_two(&pool, "ticket_priorities").await;
    let queue_id: Uuid =
        sqlx::query_scalar("SELECT id FROM ticket_queues WHERE tenant_id = $1 LIMIT 1")
            .bind(common::DEFAULT_TENANT_ID)
            .fetch_one(&pool)
            .await
            .expect("queue");

    // Status-changed rule: matches transitions INTO status_b.
    sqlx::query(
        r#"INSERT INTO workflow_rules
            (tenant_id, trigger_event, name, conditions, actions, priority, is_active, created_by_id)
           VALUES ($1, 'ticket.status_changed', 'Log when moved to B',
                   $2::jsonb, '{}'::jsonb, 10, true, $3)"#,
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(serde_json::json!({ "to_status_id": [status_b.to_string()] }))
    .bind(admin_id)
    .execute(&pool)
    .await
    .expect("seed status_changed rule");

    // Priority-changed rule: matches transitions FROM priority_a TO
    // a DIFFERENT priority than what we will actually move to. AND
    // semantics mean this rule should NOT fire.
    sqlx::query(
        r#"INSERT INTO workflow_rules
            (tenant_id, trigger_event, name, conditions, actions, priority, is_active, created_by_id)
           VALUES ($1, 'ticket.priority_changed', 'AND-filter: from A but to not-B',
                   $2::jsonb, '{}'::jsonb, 10, true, $3)"#,
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(serde_json::json!({
        "from_priority_id": [priority_a.to_string()],
        "to_priority_id": [Uuid::new_v4().to_string()],
    }))
    .bind(admin_id)
    .execute(&pool)
    .await
    .expect("seed priority_changed rule");

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    // Create a ticket in (status_a, priority_a).
    let create: Value = app
        .client
        .post(app.url("/api/v1/tickets"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "title": "Transition test",
            "company_id": company_id,
            "priority_id": priority_a,
            "queue_id": queue_id,
        }))
        .send()
        .await
        .expect("create ticket")
        .json()
        .await
        .expect("create body");
    let ticket_id = create["id"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .expect("ticket id");

    // Force the seeded ticket's status to status_a (the create path
    // might have used a default-flagged status; we want a known
    // starting point).
    sqlx::query("UPDATE tickets SET status_id = $1 WHERE id = $2")
        .bind(status_a)
        .bind(ticket_id)
        .execute(&pool)
        .await
        .expect("force start status");

    // Transition the ticket: status A -> B (should fire the
    // status_changed rule) AND priority A -> B (should NOT fire the
    // priority_changed rule because the `to_priority_id` condition
    // is mismatched).
    let patch = app
        .client
        .put(app.url(&format!("/api/v1/tickets/{ticket_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "status_id": status_b,
            "priority_id": priority_b,
        }))
        .send()
        .await
        .expect("PATCH ticket");
    assert!(
        patch.status().is_success(),
        "PATCH should succeed: {}",
        patch.status()
    );

    // Exactly one run row was logged: the status_changed rule. The
    // priority_changed rule was filtered out by the AND semantics.
    let runs: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT r.id, wr.trigger_event \
         FROM workflow_rule_runs r \
         JOIN workflow_rules wr ON wr.id = r.rule_id \
         WHERE r.tenant_id = $1 AND r.entity_id = $2 \
         ORDER BY r.ran_at",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(ticket_id)
    .fetch_all(&pool)
    .await
    .expect("runs");
    assert_eq!(
        runs.len(),
        1,
        "exactly one rule should fire (status_changed match); got: {runs:?}"
    );
    assert_eq!(runs[0].1, "ticket.status_changed");

    // The create-rule endpoint accepts both new triggers (Phase 2
    // widened the allow-list).
    for trigger in ["ticket.status_changed", "ticket.priority_changed"] {
        let resp = app
            .client
            .post(app.url("/api/v1/workflow-rules"))
            .bearer_auth(&token)
            .json(&serde_json::json!({
                "trigger_event": trigger,
                "name": format!("Phase 2 trigger {trigger}"),
            }))
            .send()
            .await
            .expect("create rule");
        assert!(
            resp.status().is_success(),
            "create-rule should accept '{trigger}', got {}",
            resp.status()
        );
    }

    // An unknown trigger still 400s.
    let bad = app
        .client
        .post(app.url("/api/v1/workflow-rules"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "trigger_event": "ticket.invented",
            "name": "Should fail",
        }))
        .send()
        .await
        .expect("bad trigger");
    assert_eq!(bad.status().as_u16(), 400);
}
