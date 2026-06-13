//! SLA sweep worker (PMS-106 follow-up).
//!
//! Periodically scans open tickets that have SLA due times set
//! (`first_response_due` / `resolution_due`) and dispatches an at-risk
//! or breach notification the first time each milestone is crossed.
//! Cross-tenant, like the notifications dispatcher and the contract
//! lifecycle worker: this worker owns the cadence, the
//! `NotificationsService` owns the fan-out, and the `sla_notifications`
//! ledger owns the dedupe.
//!
//! ## Milestones (per due field)
//!
//! For each of the two due fields the worker derives up to one kind:
//!   * `*_breached`  when `now >= due`
//!   * `*_at_risk`   when `now >= due - lead` (but not yet breached)
//!
//! where `lead = 20% of (due - created_at)`, i.e. the alert fires once
//! 80% of the SLA window has elapsed. The lead is clamped to
//! `[5 minutes, 24 hours]` so a multi-week resolution target does not
//! warn days early and a sub-minute target still gets a warning before
//! it breaches. A non-positive window (`due <= created_at`, e.g.
//! clock-skewed or hand-edited rows) falls back to the 5-minute floor.
//!
//! Each (ticket, kind) pair is dispatched exactly once: the worker
//! INSERTs a `sla_notifications` row after a successful dispatch and the
//! `UNIQUE(ticket_id, kind)` constraint plus an `ON CONFLICT DO NOTHING`
//! guard make a second tick a no-op. The breach row is independent of
//! the at-risk row, so a ticket that is already past due on first sight
//! gets only the breach alert (the at-risk INSERT for the same field is
//! never attempted once breached).
//!
//! The dispatch target is the ticket's assignee
//! (`tickets.assigned_to_id`), passed via `context.recipient_user_id`;
//! tickets with no assignee are skipped (nobody to notify). The spawn
//! site is `src/main.rs`.

use crate::modules::auth::TenantId;
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde_json::json;
use uuid::Uuid;

use crate::scheduler::Job;
use crate::utils::error::AppResult;

use super::service::SlaService;

/// Lower bound on the at-risk lead so sub-minute SLA windows still warn
/// before they breach.
const LEAD_FLOOR: Duration = Duration::minutes(5);
/// Upper bound on the at-risk lead so a multi-week resolution target
/// does not warn days in advance.
const LEAD_CEIL: Duration = Duration::hours(24);

/// One due field the worker evaluates, paired with the ledger `kind`
/// strings and the event_type to dispatch.
struct Milestone {
    /// `first_response_due` or `resolution_due` value for the ticket.
    due: Option<DateTime<Utc>>,
    /// Ledger kind written when this field breaches.
    breached_kind: &'static str,
    /// Ledger kind written when this field is at risk.
    at_risk_kind: &'static str,
    /// When `true` the milestone is already satisfied (e.g.
    /// `first_response_at IS NOT NULL`) and is skipped entirely.
    satisfied: bool,
}

/// Worker handle. Clone is cheap (the service wraps an `Arc`-backed
/// `Database` plus an optional `NotificationsService` clone).
#[derive(Clone)]
pub struct SlaSweepWorker {
    service: SlaService,
}

impl SlaSweepWorker {
    pub fn new(service: SlaService) -> Self {
        Self { service }
    }

    /// One sweep. Exposed publicly so the integration test can drive it
    /// deterministically (no sleep, no spawn). Returns the number of
    /// notifications dispatched this tick.
    #[tracing::instrument(skip_all)]
    pub async fn run_tick(&self) -> AppResult<u64> {
        // Nothing to do without a dispatcher wired in (the `new`
        // constructor path). Bail before touching the DB.
        let Some(notifications) = self.service.notifications() else {
            return Ok(0);
        };
        let pool = self.service.pool();
        let now = Utc::now();

        // Open tickets with at least one SLA due time set. "Open" =
        // not resolved, not closed, and the current status is not a
        // closed status. first_response_at is read so a ticket that
        // already got its first response skips that milestone.
        let rows = sqlx::query_as::<_, TicketRow>(
            r#"SELECT t.id, t.tenant_id, t.assigned_to_id, t.created_at,
                      t.first_response_due, t.first_response_at, t.resolution_due
               FROM tickets t
               JOIN ticket_statuses s ON s.id = t.status_id
               WHERE t.resolved_at IS NULL
                 AND t.closed_at IS NULL
                 AND COALESCE(s.is_closed, FALSE) = FALSE
                 AND (t.first_response_due IS NOT NULL OR t.resolution_due IS NOT NULL)"#,
        )
        .fetch_all(pool)
        .await?;

        let mut dispatched = 0u64;
        for t in rows {
            // No assignee => nobody to notify. Skip rather than fan out
            // to an empty recipient set (the rule carries no recipients
            // of its own).
            let Some(assignee_id) = t.assigned_to_id else {
                continue;
            };

            let milestones = [
                Milestone {
                    due: t.first_response_due,
                    breached_kind: "first_response_breached",
                    at_risk_kind: "first_response_at_risk",
                    satisfied: t.first_response_at.is_some(),
                },
                Milestone {
                    due: t.resolution_due,
                    breached_kind: "resolution_breached",
                    at_risk_kind: "resolution_at_risk",
                    satisfied: false,
                },
            ];

            for m in milestones {
                if m.satisfied {
                    continue;
                }
                let Some(due) = m.due else {
                    continue;
                };

                // Breach takes precedence: once past due there is no
                // point emitting the at-risk alert for the same field.
                let (kind, event_type) = if now >= due {
                    (m.breached_kind, "sla.breached")
                } else if now >= due - lead_for(t.created_at, due) {
                    (m.at_risk_kind, "sla.at_risk")
                } else {
                    continue;
                };

                // Ledger-first dedupe: try to claim this (ticket, kind)
                // pair. The UNIQUE(ticket_id, kind) constraint means a
                // concurrent worker (or a prior tick) that already
                // claimed it leaves `rows_affected() == 0`, so we skip
                // the dispatch. Claiming before dispatch keeps a
                // duplicate alert from going out if two replicas race;
                // the cost is that a dispatch failure leaves the ledger
                // row in place (the milestone is not retried), which is
                // acceptable for an at-risk/breach heads-up.
                let claimed = self
                    .service
                    .claim_sla_notification(t.tenant_id, t.id, kind)
                    .await?;
                if claimed == 0 {
                    continue;
                }

                let context = json!({
                    "recipient_user_id": assignee_id.to_string(),
                    "ticket_id": t.id.to_string(),
                    "kind": kind,
                    "due": due.to_rfc3339(),
                });
                match notifications
                    .dispatch(TenantId::from_trusted(t.tenant_id), event_type, &context)
                    .await
                {
                    Ok(n) => {
                        dispatched += n;
                        tracing::info!(
                            ticket_id = %t.id, %kind, fanout = n,
                            "sla sweep dispatched alert",
                        );
                    }
                    Err(e) => {
                        // The ledger row is already committed, so this
                        // milestone will not be retried. Log loudly; a
                        // missed heads-up is preferable to a tight retry
                        // loop hammering the queue.
                        tracing::warn!(
                            ticket_id = %t.id, %kind, error = ?e,
                            "sla sweep dispatch failed; ledger row kept, milestone not retried",
                        );
                    }
                }
            }
        }
        Ok(dispatched)
    }
}

/// Compute the at-risk lead for a ticket: 20% of the SLA window
/// (`due - created_at`), clamped to `[LEAD_FLOOR, LEAD_CEIL]`. A
/// non-positive window falls back to `LEAD_FLOOR`.
fn lead_for(created_at: DateTime<Utc>, due: DateTime<Utc>) -> Duration {
    let window = due - created_at;
    if window <= Duration::zero() {
        return LEAD_FLOOR;
    }
    // 20% via integer milliseconds to avoid float round-trips.
    let lead = Duration::milliseconds(window.num_milliseconds() / 5);
    lead.clamp(LEAD_FLOOR, LEAD_CEIL)
}

#[async_trait]
impl Job for SlaSweepWorker {
    fn name(&self) -> &'static str {
        "sla_sweep"
    }

    async fn run(&self) -> AppResult<()> {
        let dispatched = self.run_tick().await?;
        if dispatched > 0 {
            tracing::info!(dispatched, "sla sweep tick");
        }
        Ok(())
    }
}

#[derive(sqlx::FromRow)]
struct TicketRow {
    id: Uuid,
    tenant_id: Uuid,
    assigned_to_id: Option<Uuid>,
    created_at: DateTime<Utc>,
    first_response_due: Option<DateTime<Utc>>,
    first_response_at: Option<DateTime<Utc>>,
    resolution_due: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utc(y: i32, mo: u32, d: u32, h: u32, mi: u32) -> DateTime<Utc> {
        use chrono::TimeZone;
        Utc.with_ymd_and_hms(y, mo, d, h, mi, 0).unwrap()
    }

    #[test]
    fn lead_is_twenty_percent_within_bounds() {
        // 10h window => 2h lead, inside [5m, 24h].
        let created = utc(2026, 6, 1, 0, 0);
        let due = created + Duration::hours(10);
        assert_eq!(lead_for(created, due), Duration::hours(2));
    }

    #[test]
    fn lead_clamps_to_floor_for_tiny_window() {
        // 10m window => 2m raw, clamped up to the 5m floor.
        let created = utc(2026, 6, 1, 0, 0);
        let due = created + Duration::minutes(10);
        assert_eq!(lead_for(created, due), LEAD_FLOOR);
    }

    #[test]
    fn lead_clamps_to_ceil_for_huge_window() {
        // 30d window => 6d raw, clamped down to the 24h ceiling.
        let created = utc(2026, 6, 1, 0, 0);
        let due = created + Duration::days(30);
        assert_eq!(lead_for(created, due), LEAD_CEIL);
    }

    #[test]
    fn lead_falls_back_to_floor_for_nonpositive_window() {
        let created = utc(2026, 6, 1, 0, 0);
        assert_eq!(lead_for(created, created), LEAD_FLOOR);
        assert_eq!(lead_for(created, created - Duration::hours(1)), LEAD_FLOOR);
    }
}
