//! PMS-467 / PMS-448 phase 3: integration test for mutating actions
//! on transition triggers + the cycle cap.
//!
//! Pins three guarantees:
//!   - a `ticket.status_changed` rule whose actions include
//!     `add_internal_note` fires when the matching transition lands
//!     and the note is inserted into `ticket_notes`;
//!   - a `ticket.status_changed` rule that re-sets `status_id` back
//!     into the matching status loops up to the per-tenant cap and
//!     then writes a depth-cap row whose `error` quotes the cap;
//!   - a `ticket.priority_changed` rule with NO mutating action
//!     fires exactly once and does not cascade.

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

async fn lookup_one(pool: &PgPool, table: &str) -> Uuid {
    sqlx::query_scalar(&format!(
        "SELECT id FROM {table} WHERE tenant_id = $1 LIMIT 1"
    ))
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("lookup id from {table}: {e}"))
}

#[sqlx::test]
async fn status_changed_mutating_rule_fires_note(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let (status_a, status_b) = lookup_two(&pool, "ticket_statuses").await;
    let priority_id = lookup_one(&pool, "ticket_priorities").await;
    let queue_id = lookup_one(&pool, "ticket_queues").await;

    sqlx::query(
        r#"INSERT INTO workflow_rules
            (tenant_id, trigger_event, name, conditions, actions, priority, is_active, created_by_id)
           VALUES ($1, 'ticket.status_changed', 'Note on enter B',
                   $2::jsonb, $3::jsonb, 10, true, $4)"#,
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(serde_json::json!({ "to_status_id": [status_b.to_string()] }))
    .bind(serde_json::json!({ "add_internal_note": "moved to B" }))
    .bind(admin_id)
    .execute(&pool)
    .await
    .expect("seed status_changed rule");

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let create: Value = app
        .client
        .post(app.url("/api/v1/tickets"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "title": "Phase 3 note",
            "company_id": company_id,
            "priority_id": priority_id,
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

    sqlx::query("UPDATE tickets SET status_id = $1 WHERE id = $2")
        .bind(status_a)
        .bind(ticket_id)
        .execute(&pool)
        .await
        .expect("force start status");

    let patch = app
        .client
        .put(app.url(&format!("/api/v1/tickets/{ticket_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "status_id": status_b }))
        .send()
        .await
        .expect("PATCH ticket");
    assert!(patch.status().is_success(), "PATCH should succeed");

    let notes: Vec<(String,)> = sqlx::query_as(
        "SELECT content FROM ticket_notes \
         WHERE tenant_id = $1 AND ticket_id = $2 AND note_type = 'internal' \
         ORDER BY created_at",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(ticket_id)
    .fetch_all(&pool)
    .await
    .expect("notes");
    assert!(
        notes.iter().any(|(c,)| c == "moved to B"),
        "mutating add_internal_note should land an internal note; got {notes:?}"
    );

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
        "exactly one run row for the matching status_changed rule"
    );
}

#[sqlx::test]
async fn status_changed_self_cascade_hits_depth_cap(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let (status_a, status_b) = lookup_two(&pool, "ticket_statuses").await;
    let priority_id = lookup_one(&pool, "ticket_priorities").await;
    let queue_id = lookup_one(&pool, "ticket_queues").await;

    // Self-cascading rule: any status_changed transition re-asserts
    // status_b. Once the ticket is in status_b the rule's condition
    // always re-matches, so the executor walks depth 0 -> 1 -> 2 ->
    // depth-cap. With max_depth = 3 the cascade chain is:
    //   depth 0: apply (status A -> B, cascade)
    //   depth 1: apply (status B -> B is a no-op so no UPDATE fires
    //            and no further cascade; the rule's run row is logged
    //            with no error)
    //   ...
    // To force the deepest-cascade case we need an action that
    // re-fires the trigger on every level. Easiest: alternate status_a
    // and status_b on every level. We do that with TWO rules:
    //   rule_to_b: matches to_status_id=A, action set_status_id=B
    //   rule_to_a: matches to_status_id=B, action set_status_id=A
    sqlx::query(
        r#"INSERT INTO workflow_rules
            (tenant_id, trigger_event, name, conditions, actions, priority, is_active, created_by_id)
           VALUES ($1, 'ticket.status_changed', 'A->B',
                   $2::jsonb, $3::jsonb, 10, true, $4)"#,
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(serde_json::json!({ "to_status_id": [status_a.to_string()] }))
    .bind(serde_json::json!({ "set_status_id": status_b.to_string() }))
    .bind(admin_id)
    .execute(&pool)
    .await
    .expect("seed A->B rule");
    sqlx::query(
        r#"INSERT INTO workflow_rules
            (tenant_id, trigger_event, name, conditions, actions, priority, is_active, created_by_id)
           VALUES ($1, 'ticket.status_changed', 'B->A',
                   $2::jsonb, $3::jsonb, 10, true, $4)"#,
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(serde_json::json!({ "to_status_id": [status_b.to_string()] }))
    .bind(serde_json::json!({ "set_status_id": status_a.to_string() }))
    .bind(admin_id)
    .execute(&pool)
    .await
    .expect("seed B->A rule");

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let create: Value = app
        .client
        .post(app.url("/api/v1/tickets"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "title": "Cycle cap",
            "company_id": company_id,
            "priority_id": priority_id,
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

    sqlx::query("UPDATE tickets SET status_id = $1 WHERE id = $2")
        .bind(status_b)
        .bind(ticket_id)
        .execute(&pool)
        .await
        .expect("force start status");

    let patch = app
        .client
        .put(app.url(&format!("/api/v1/tickets/{ticket_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "status_id": status_a }))
        .send()
        .await
        .expect("PATCH ticket");
    assert!(patch.status().is_success(), "PATCH should succeed");

    let runs: Vec<(Option<String>,)> = sqlx::query_as(
        "SELECT error FROM workflow_rule_runs \
         WHERE tenant_id = $1 AND entity_id = $2 \
         ORDER BY ran_at",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(ticket_id)
    .fetch_all(&pool)
    .await
    .expect("runs");

    // The cap is the default 3 (seeded by migration 072). The
    // cascade chain is: depth 0 A->B rule fires + cascades,
    // depth 1 B->A rule fires + cascades, depth 2 A->B rule fires +
    // cascades, depth 3 B->A rule is REFUSED with the cap message.
    // That is 4 run rows: 3 successful + 1 depth-cap refusal.
    assert!(
        runs.len() >= 4,
        "expected the cascade to produce at least 4 run rows (3 fires + 1 cap), got {}: {runs:?}",
        runs.len()
    );
    let cap_runs: Vec<&Option<String>> = runs
        .iter()
        .map(|(e,)| e)
        .filter(|e| {
            e.as_deref()
                .is_some_and(|s| s.starts_with("cycle cap reached at depth"))
        })
        .collect();
    assert!(
        !cap_runs.is_empty(),
        "at least one run row should carry the depth-cap error; got {runs:?}"
    );
    let last = cap_runs.last().unwrap().as_deref().unwrap();
    assert_eq!(
        last, "cycle cap reached at depth 3",
        "depth-cap message should quote the cap; got {last:?}"
    );
}

#[sqlx::test]
async fn priority_changed_non_mutating_rule_fires_once(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let (priority_a, priority_b) = lookup_two(&pool, "ticket_priorities").await;
    let status_id = lookup_one(&pool, "ticket_statuses").await;
    let queue_id = lookup_one(&pool, "ticket_queues").await;

    // Non-mutating rule on the priority_changed trigger: add a tag
    // but do not re-set priority. Must fire exactly once with no
    // cascade and no depth-cap row.
    sqlx::query(
        r#"INSERT INTO workflow_rules
            (tenant_id, trigger_event, name, conditions, actions, priority, is_active, created_by_id)
           VALUES ($1, 'ticket.priority_changed', 'Tag on priority change',
                   $2::jsonb, $3::jsonb, 10, true, $4)"#,
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(serde_json::json!({ "to_priority_id": [priority_b.to_string()] }))
    .bind(serde_json::json!({ "add_tag": "escalated" }))
    .bind(admin_id)
    .execute(&pool)
    .await
    .expect("seed priority_changed rule");

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let create: Value = app
        .client
        .post(app.url("/api/v1/tickets"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "title": "Non-mutating priority rule",
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

    sqlx::query("UPDATE tickets SET priority_id = $1, status_id = $2 WHERE id = $3")
        .bind(priority_a)
        .bind(status_id)
        .bind(ticket_id)
        .execute(&pool)
        .await
        .expect("force start state");

    let patch = app
        .client
        .put(app.url(&format!("/api/v1/tickets/{ticket_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "priority_id": priority_b }))
        .send()
        .await
        .expect("PATCH ticket");
    assert!(patch.status().is_success(), "PATCH should succeed");

    let runs: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM workflow_rule_runs WHERE tenant_id = $1 AND entity_id = $2",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(ticket_id)
    .fetch_one(&pool)
    .await
    .expect("run count");
    assert_eq!(runs.0, 1, "non-mutating rule should fire exactly once");

    let cap_runs: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM workflow_rule_runs \
         WHERE tenant_id = $1 AND entity_id = $2 AND error IS NOT NULL",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(ticket_id)
    .fetch_one(&pool)
    .await
    .expect("error run count");
    assert_eq!(cap_runs.0, 0, "no depth-cap rows for a non-cascading rule");

    let row: (Vec<String>,) =
        sqlx::query_as("SELECT tags FROM tickets WHERE tenant_id = $1 AND id = $2")
            .bind(common::DEFAULT_TENANT_ID)
            .bind(ticket_id)
            .fetch_one(&pool)
            .await
            .expect("tags");
    assert!(
        row.0.iter().any(|t| t == "escalated"),
        "add_tag should land; got {:?}",
        row.0
    );
}
