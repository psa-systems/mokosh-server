//! Appointment-reminder worker (PMS-58 follow-up).
//!
//! Each tick enumerates appointment occurrences whose reminder fire-time
//! has arrived (see [`CalendarService::due_reminders`]) and, for each
//! (occurrence, offset) pair not already recorded in the
//! `appointment_reminders` ledger, dispatches an `appointment.reminder`
//! event through [`NotificationsService`] and stamps the ledger row.
//!
//! Dedupe is the ledger's `UNIQUE(appointment_id, occurrence_start,
//! reminder_minutes)`: the worker INSERTs the ledger row with `ON
//! CONFLICT DO NOTHING` and only dispatches when that insert wins the
//! race, so a recurring occurrence is reminded exactly once per offset
//! even across overlapping ticks or multiple replicas. Recipient is the
//! appointment's `assigned_to_id`, threaded through the dispatch context
//! as `recipient_user_id` (the rule's own recipients stay empty, mirroring
//! the transactional auth/ticket events).
//!
//! Implements the shared [`Job`](crate::scheduler::Job) trait; the spawn
//! site is `src/main.rs`. A 60s interval matches the minute granularity
//! of `reminder_minutes`.

use async_trait::async_trait;

use crate::modules::auth::TenantId;
use crate::scheduler::Job;
use crate::utils::error::AppResult;

use super::service::CalendarService;

/// Worker handle. Clone is cheap (the service wraps an `Arc`-backed
/// `Database` plus an optional `NotificationsService` clone).
#[derive(Clone)]
pub struct CalendarReminderWorker {
    calendar: CalendarService,
}

impl CalendarReminderWorker {
    pub fn new(calendar: CalendarService) -> Self {
        Self { calendar }
    }

    /// Run one reminder pass against `now`. Returns the number of
    /// reminders actually dispatched (ledger inserts that won the
    /// uniqueness race). Pulled out of [`Job::run`] so tests can drive a
    /// deterministic tick and assert the count.
    #[tracing::instrument(skip_all)]
    pub async fn run_tick(&self, now: chrono::DateTime<chrono::Utc>) -> AppResult<u64> {
        // Without a dispatcher there is nothing to fire; the ledger would
        // record sends that never happened, so skip entirely.
        let Some(notifications) = self.calendar.notifications() else {
            return Ok(0);
        };

        let candidates = self.calendar.due_reminders(now).await?;
        let mut dispatched = 0u64;
        for c in candidates {
            // Claim the (appointment, occurrence, offset) slot first. If a
            // prior tick (or a sibling replica) already inserted it, the
            // row count is 0 and we skip the dispatch - this is the
            // dedupe. Stamping the ledger before dispatch (rather than
            // after) means a crash between insert and dispatch drops a
            // single reminder rather than risking a duplicate; reminders
            // are best-effort, so under-delivery on crash is the safer
            // failure mode than spamming on every retry.
            let inserted = sqlx::query(
                r#"INSERT INTO appointment_reminders
                       (tenant_id, appointment_id, occurrence_start, reminder_minutes)
                   VALUES ($1, $2, $3, $4)
                   ON CONFLICT (appointment_id, occurrence_start, reminder_minutes)
                   DO NOTHING"#,
            )
            .bind(c.tenant_id)
            .bind(c.appointment_id)
            .bind(c.occurrence_start)
            .bind(c.reminder_minutes)
            .execute(self.calendar.pool())
            .await?
            .rows_affected();
            if inserted == 0 {
                continue;
            }

            let context = serde_json::json!({
                "recipient_user_id": c.assigned_to_id.to_string(),
                "appointment_id": c.appointment_id.to_string(),
                "start": c.occurrence_start,
                "reminder_minutes": c.reminder_minutes,
            });
            if let Err(e) = notifications
                .dispatch(
                    TenantId::from_trusted(c.tenant_id),
                    "appointment.reminder",
                    &context,
                )
                .await
            {
                // Ledger row already committed above, so this reminder is
                // recorded-but-undelivered. Log and move on rather than
                // failing the whole tick; a transient notifications error
                // must not stall reminders for other appointments.
                tracing::warn!(
                    tenant_id = %c.tenant_id,
                    appointment_id = %c.appointment_id,
                    occurrence_start = %c.occurrence_start,
                    error = ?e,
                    "appointment reminder dispatch failed; ledger row stamped but no message queued",
                );
                continue;
            }
            dispatched += 1;
        }
        if dispatched > 0 {
            tracing::info!(dispatched, "appointment reminder sweep");
        }
        Ok(dispatched)
    }
}

#[async_trait]
impl Job for CalendarReminderWorker {
    fn name(&self) -> &'static str {
        "calendar_reminders"
    }

    async fn run(&self) -> AppResult<()> {
        self.run_tick(chrono::Utc::now()).await?;
        Ok(())
    }
}
