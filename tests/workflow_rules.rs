//! PMS-448 phase 1: integration test for the ticket.created
//! workflow executor.
//!
//! Pins three guarantees:
//!   - a rule with a matching condition fires when a ticket is
//!     created via the agent path, mutates the ticket atomically
//!     (the response carries the assignee the rule set), and
//!     records a `workflow_rule_runs` row;
//!   - a rule with a non-matching condition does NOT fire (no run
//!     row, no mutation);
//!   - an inactive rule is skipped entirely.

mod common;

use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

async fn lookup_id(pool: &PgPool, table: &str) -> Uuid {
    sqlx::query_scalar(&format!(
        "SELECT id FROM {table} WHERE tenant_id = $1 LIMIT 1"
    ))
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("lookup id from {table}: {e}"))
}

#[sqlx::test]
async fn ticket_created_rule_fires_and_assigns(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let priority_id = lookup_id(&pool, "ticket_priorities").await;
    let queue_id = lookup_id(&pool, "ticket_queues").await;
    let _ = lookup_id(&pool, "ticket_statuses").await;

    // Seed a second admin who will be the rule's assignee target.
    let (assignee_id, _, _) = common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "rule-assignee@example.com",
        "admin",
    )
    .await;

    // Rule that matches this priority + this queue, assigns to the
    // second admin, and tags the ticket.
    sqlx::query(
        r#"INSERT INTO workflow_rules
            (tenant_id, trigger_event, name, conditions, actions, priority, is_active, created_by_id)
           VALUES ($1, 'ticket.created', 'Route high-priority tickets',
                   $2::jsonb, $3::jsonb, 10, true, $4)"#,
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(serde_json::json!({
        "priority_id": [priority_id.to_string()],
        "queue_id": [queue_id.to_string()],
    }))
    .bind(serde_json::json!({
        "assign_to_user_id": assignee_id.to_string(),
        "add_tag": "auto-routed",
    }))
    .bind(admin_id)
    .execute(&pool)
    .await
    .expect("seed matching rule");

    // Rule with mismatched priority - must NOT fire.
    sqlx::query(
        r#"INSERT INTO workflow_rules
            (tenant_id, trigger_event, name, conditions, actions, priority, is_active, created_by_id)
           VALUES ($1, 'ticket.created', 'Wrong priority',
                   $2::jsonb, $3::jsonb, 20, true, $4)"#,
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(serde_json::json!({
        "priority_id": [Uuid::new_v4().to_string()],
    }))
    .bind(serde_json::json!({
        "add_tag": "should-not-appear",
    }))
    .bind(admin_id)
    .execute(&pool)
    .await
    .expect("seed mismatched rule");

    // Inactive rule that WOULD match - must NOT fire because is_active=false.
    sqlx::query(
        r#"INSERT INTO workflow_rules
            (tenant_id, trigger_event, name, conditions, actions, priority, is_active, created_by_id)
           VALUES ($1, 'ticket.created', 'Inactive rule',
                   $2::jsonb, $3::jsonb, 5, false, $4)"#,
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(serde_json::json!({}))
    .bind(serde_json::json!({
        "add_tag": "inactive-fires",
    }))
    .bind(admin_id)
    .execute(&pool)
    .await
    .expect("seed inactive rule");

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    // Create a ticket via the real API. The executor runs in-line.
    let ticket: Value = app
        .client
        .post(app.url("/api/v1/tickets"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "title": "Customer cannot print",
            "company_id": company_id,
            "priority_id": priority_id,
            "queue_id": queue_id,
            "source": "email",
        }))
        .send()
        .await
        .expect("create ticket")
        .json()
        .await
        .expect("ticket body");

    // Matching rule's action landed: assigned_to_id == assignee_id and
    // tags contains "auto-routed".
    assert_eq!(
        ticket["assigned_to_id"].as_str(),
        Some(assignee_id.to_string().as_str()),
        "matching rule must set assigned_to_id"
    );
    let tags = ticket["tags"]
        .as_array()
        .expect("tags array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect::<Vec<_>>();
    assert!(
        tags.contains(&"auto-routed"),
        "matching rule must add tag; got {tags:?}"
    );
    assert!(
        !tags.contains(&"should-not-appear"),
        "mismatched rule must not fire"
    );
    assert!(
        !tags.contains(&"inactive-fires"),
        "inactive rule must not fire"
    );

    // Exactly one `workflow_rule_runs` row for this ticket: the
    // matching rule. The mismatched and inactive rules must NOT
    // have produced runs.
    let ticket_id = ticket["id"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .expect("ticket id");
    let runs: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM workflow_rule_runs WHERE tenant_id = $1 AND entity_id = $2",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(ticket_id)
    .fetch_one(&pool)
    .await
    .expect("run count");
    assert_eq!(
        runs.0, 1,
        "exactly one run row (the matching rule), not the mismatched or inactive ones"
    );
}
