//! Integration test: SLA at-risk / breach notifications (PMS-106
//! follow-up).
//!
//! Drives `SlaSweepWorker` directly (no HTTP, no sleep) against a ticket
//! whose `resolution_due` is already in the past and which has an
//! assignee. Asserts:
//!   * one tick enqueues an in-app `notifications` row for the assignee
//!     AND writes a `sla_notifications` ledger row (kind
//!     `resolution_breached`);
//!   * a second tick is a no-op (the ledger dedupes, so no new
//!     notification row appears).
//!
//! Determinism: the due time is set via SQL relative to NOW() so the
//! milestone is unambiguously breached the moment the worker runs; no
//! wall-clock sleeps are involved.
//!
//! The default tenant (00000000-0000-0000-0000-000000000001) already
//! exists from migration 002 and is seeded with priorities / statuses /
//! queues by migration 023 and with the `sla.breached` / `sla.at_risk`
//! in-app rule + template by migration 027, so this test reuses those
//! and creates only the ticket-specific rows.

mod common;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use mokosh_server::modules::notifications::NotificationsService;
use mokosh_server::modules::sla::{SlaService, SlaSweepWorker};
use mokosh_server::Database;

/// Count in-app notification rows targeting `user_id` for the SLA
/// breach event in this tenant.
async fn breach_notification_count(pool: &PgPool, tenant_id: Uuid, user_id: Uuid) -> i64 {
    sqlx::query_scalar(
        r#"SELECT COUNT(*)
           FROM notifications n
           JOIN notification_templates t ON t.id = n.template_id
           WHERE n.tenant_id = $1
             AND n.user_id = $2
             AND n.channel_type = 'in_app'
             AND t.event_type = 'sla.breached'"#,
    )
    .bind(tenant_id)
    .bind(user_id)
    .fetch_one(pool)
    .await
    .expect("count breach notifications")
}

#[sqlx::test]
async fn sweep_dispatches_breach_then_dedupes(pool: PgPool) {
    let tenant_id = common::DEFAULT_TENANT_ID;
    // Seeded super_admin under the default tenant; used as the assignee.
    let (assignee_id, _email, _password) = common::seed_admin(&pool).await;

    // Reuse the seeded default priority / status / queue.
    let priority_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM ticket_priorities WHERE tenant_id = $1 AND is_default = TRUE",
    )
    .bind(tenant_id)
    .fetch_one(&pool)
    .await
    .expect("seeded default priority");
    let status_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM ticket_statuses WHERE tenant_id = $1 AND is_default = TRUE",
    )
    .bind(tenant_id)
    .fetch_one(&pool)
    .await
    .expect("seeded default status");
    let queue_id: Uuid =
        sqlx::query_scalar("SELECT id FROM ticket_queues WHERE tenant_id = $1 LIMIT 1")
            .bind(tenant_id)
            .fetch_one(&pool)
            .await
            .expect("seeded queue");

    // Company for the ticket FK.
    let company_id = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, 'SLA Notify Co')")
        .bind(company_id)
        .bind(tenant_id)
        .execute(&pool)
        .await
        .expect("seed company");

    // Ticket created 10h ago with resolution_due 1h in the PAST and an
    // assignee. created_at is in the past too so the window is positive
    // and the row is unambiguously breached. first_response_due is left
    // NULL so only the resolution milestone fires.
    let ticket_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO tickets
           (id, tenant_id, ticket_number, title, status_id, priority_id, queue_id,
            company_id, assigned_to_id, created_by_id, created_at, resolution_due)
           VALUES ($1, $2, 'SLA-NOTIFY-1', 'Past-due resolution', $3, $4, $5, $6, $7, $8,
                   NOW() - INTERVAL '10 hours', NOW() - INTERVAL '1 hour')"#,
    )
    .bind(ticket_id)
    .bind(tenant_id)
    .bind(status_id)
    .bind(priority_id)
    .bind(queue_id)
    .bind(company_id)
    .bind(assignee_id)
    .bind(assignee_id)
    .execute(&pool)
    .await
    .expect("seed ticket");

    // Worker wired with a real dispatcher (encryption key irrelevant for
    // in_app rows, which carry no encrypted channel config).
    let notifications =
        NotificationsService::with_encryption_key(Database::from_pool(pool.clone()), [0u8; 32]);
    let service = SlaService::with_dispatcher(Database::from_pool(pool.clone()), notifications);
    let worker = SlaSweepWorker::new(service);

    // First tick: one fan-out (the in_app rule for the assignee).
    let dispatched = worker.run_tick().await.expect("first sweep tick");
    assert_eq!(
        dispatched, 1,
        "first tick should dispatch exactly one in-app alert",
    );

    // Ledger row exists with the resolution_breached kind.
    let ledger: Vec<(String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT kind, sent_at FROM sla_notifications WHERE tenant_id = $1 AND ticket_id = $2",
    )
    .bind(tenant_id)
    .bind(ticket_id)
    .fetch_all(&pool)
    .await
    .expect("query ledger");
    assert_eq!(ledger.len(), 1, "exactly one ledger row, got {ledger:?}");
    assert_eq!(
        ledger[0].0, "resolution_breached",
        "ledger kind must be resolution_breached",
    );

    // A notification row was enqueued for the assignee on the breach
    // event.
    assert_eq!(
        breach_notification_count(&pool, tenant_id, assignee_id).await,
        1,
        "exactly one in-app breach notification for the assignee",
    );

    // Second tick: dedupe. No new dispatch, ledger and notification
    // counts unchanged.
    let dispatched2 = worker.run_tick().await.expect("second sweep tick");
    assert_eq!(
        dispatched2, 0,
        "second tick must be a no-op (ledger dedupe)",
    );

    let ledger_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sla_notifications WHERE ticket_id = $1")
            .bind(ticket_id)
            .fetch_one(&pool)
            .await
            .expect("re-count ledger");
    assert_eq!(ledger_count, 1, "ledger must not grow on a second tick");

    assert_eq!(
        breach_notification_count(&pool, tenant_id, assignee_id).await,
        1,
        "no duplicate notification on a second tick",
    );
}
