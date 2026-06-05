//! Integration tests for the appointment-reminder worker (PMS-58 follow-up).
//!
//! Drives `CalendarReminderWorker` directly against a per-test database
//! (no HTTP layer needed for worker math), mirroring the `tests/contracts.rs`
//! / `tests/notifications.rs` pattern: `Database::from_pool(pool.clone())`,
//! the seeded default tenant (`common::DEFAULT_TENANT_ID`), and direct SQL
//! for fixtures. The default-tenant `appointment.reminder` template + rule
//! come from migration 028, so the test does not seed them.
//!
//! Coverage:
//!   * an appointment whose reminder fire-time has already passed
//!     (start ~5min out, reminder_minutes={10} => fired ~5min ago) gets
//!     exactly one reminder: a `notifications` row for the assignee plus
//!     an `appointment_reminders` ledger row.
//!   * a second tick dispatches nothing (the ledger dedupes), and no
//!     extra notification row appears.
//!
//! Deterministic: the appointment's times are set in SQL relative to
//! NOW(), and the worker tick is driven with an explicit `now` so the
//! window math does not depend on wall-clock timing within the test.

mod common;

use chrono::Utc;
use mokosh_server::modules::calendar::{CalendarReminderWorker, CalendarService};
use mokosh_server::modules::notifications::NotificationsService;
use mokosh_server::Database;
use sqlx::PgPool;
use uuid::Uuid;

/// Insert an appointment for the seeded admin starting ~5 minutes from
/// now with a single 10-minute reminder (so the fire-time is ~5 minutes
/// in the past). Times are set relative to NOW() in SQL for determinism.
async fn seed_due_appointment(pool: &PgPool, assignee_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO appointments
            (id, tenant_id, title, assigned_to_id, start_time, end_time,
             reminder_minutes)
        VALUES
            ($1, $2, 'Onsite visit', $3,
             NOW() + INTERVAL '5 minutes', NOW() + INTERVAL '65 minutes',
             ARRAY[10]::INTEGER[])
        "#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(assignee_id)
    .execute(pool)
    .await
    .expect("seed due appointment");
    id
}

fn worker(pool: &PgPool) -> CalendarReminderWorker {
    let db = Database::from_pool(pool.clone());
    // Same zero key the HTTP test harness uses; channel config is not
    // exercised by the in_app reminder path.
    let notifications = NotificationsService::with_encryption_key(db.clone(), [0u8; 32]);
    CalendarReminderWorker::new(CalendarService::with_dispatcher(db, notifications))
}

#[sqlx::test]
async fn reminder_fires_once_and_dedupes(pool: PgPool) {
    let (admin_id, _email, _password) = common::seed_admin(&pool).await;
    let appt_id = seed_due_appointment(&pool, admin_id).await;
    let tenant_id = common::DEFAULT_TENANT_ID;

    let worker = worker(&pool);

    // First tick: the 10-minute reminder for a start ~5min out has
    // already fired (start is still in the future), so exactly one
    // reminder should dispatch.
    let dispatched = worker.run_tick(Utc::now()).await.expect("first tick");
    assert_eq!(
        dispatched, 1,
        "first tick should dispatch exactly one reminder"
    );

    // A ledger row recording (appointment, occurrence, offset).
    let ledger: Vec<(Uuid, i32)> = sqlx::query_as(
        r#"SELECT appointment_id, reminder_minutes
           FROM appointment_reminders
           WHERE tenant_id = $1 AND appointment_id = $2"#,
    )
    .bind(tenant_id)
    .bind(appt_id)
    .fetch_all(&pool)
    .await
    .expect("query appointment_reminders");
    assert_eq!(ledger.len(), 1, "exactly one ledger row, got {ledger:?}");
    assert_eq!(ledger[0].1, 10, "ledger records the 10-minute offset");

    // A notification enqueued for the assignee on the in_app channel.
    let notifs: Vec<(Option<Uuid>, String, Option<String>)> = sqlx::query_as(
        r#"SELECT user_id, channel_type, status
           FROM notifications
           WHERE tenant_id = $1 AND user_id = $2"#,
    )
    .bind(tenant_id)
    .bind(admin_id)
    .fetch_all(&pool)
    .await
    .expect("query notifications");
    assert_eq!(
        notifs.len(),
        1,
        "exactly one notification for the assignee, got {notifs:?}"
    );
    assert_eq!(
        notifs[0].0,
        Some(admin_id),
        "notification targets the assignee"
    );
    assert_eq!(
        notifs[0].1, "in_app",
        "reminder goes out on the in_app channel"
    );
    assert_eq!(
        notifs[0].2.as_deref(),
        Some("pending"),
        "freshly dispatched reminder is pending"
    );

    // Second tick: the ledger row dedupes the same (appointment,
    // occurrence, offset), so nothing new dispatches and no new
    // notification row appears.
    let dispatched_again = worker.run_tick(Utc::now()).await.expect("second tick");
    assert_eq!(
        dispatched_again, 0,
        "second tick must dispatch nothing (dedupe)"
    );

    let notif_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM notifications WHERE tenant_id = $1 AND user_id = $2",
    )
    .bind(tenant_id)
    .bind(admin_id)
    .fetch_one(&pool)
    .await
    .expect("recount notifications");
    assert_eq!(
        notif_count, 1,
        "no additional notification after the dedup tick"
    );

    let ledger_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM appointment_reminders WHERE tenant_id = $1 AND appointment_id = $2",
    )
    .bind(tenant_id)
    .bind(appt_id)
    .fetch_one(&pool)
    .await
    .expect("recount ledger");
    assert_eq!(ledger_count, 1, "ledger still holds exactly one row");
}
