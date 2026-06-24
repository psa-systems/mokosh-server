//! PMS-478: scheduled report delivery worker.
//!
//! Ticks the `scheduled_reports` queue: picks `is_active = true` rows
//! whose `next_run_at <= NOW()`, materialises the report via the
//! existing executor, renders the result set to CSV, and enqueues an
//! `email` row into `notifications` so the DispatcherWorker
//! (notifications/worker.rs) handles the SMTP send + retry backoff.
//! After each row the cron expression advances `last_run_at` /
//! `next_run_at`; a failure stamps `last_error` but still advances
//! the cadence so a single bad row does not stall the next firing.
//!
//! Locks rows via `SELECT ... FOR UPDATE SKIP LOCKED` so multiple
//! replicas can drain in parallel without double-sending. The
//! report execution + CSV render run inside the locking transaction,
//! which is acceptable at v1 throughput (one mokosh-server, a
//! handful of schedules per tenant). Move the materialise out of
//! the lock once tenants run more than ~100 schedules combined.

use std::sync::Arc;

use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

use crate::db::Database;
use crate::modules::saved_reports::SavedReportsService;
use crate::scheduler::Job;
use crate::utils::error::AppResult;

/// Rows drained per tick. Schedules are coarse-grained (a typical
/// tenant has a handful) so the small batch keeps the locking
/// transaction short.
const TICK_BATCH_SIZE: i64 = 10;

/// Cap on per-page row fetch when materialising. The executor caps
/// at 10k; for scheduled delivery we ask for the maximum so a
/// weekly export does not silently truncate.
const PER_PAGE: u32 = 10_000;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ScheduledReportsTickStats {
    pub examined: u64,
    pub delivered: u64,
    pub failed: u64,
    pub skipped: u64,
}

#[derive(Clone)]
pub struct ScheduledReportsWorker {
    db: Database,
    reports: Arc<SavedReportsService>,
}

impl ScheduledReportsWorker {
    pub fn new(db: Database, reports: Arc<SavedReportsService>) -> Self {
        Self { db, reports }
    }

    /// Process up to `limit` due schedules in a single transaction.
    /// Exposed publicly so the integration test can drive the worker
    /// deterministically (no sleep / no spawn).
    #[tracing::instrument(skip_all)]
    pub async fn run_tick(&self, limit: i64) -> AppResult<ScheduledReportsTickStats> {
        // The migrator pool bypasses RLS so the worker can scan every
        // tenant in one query; each row carries `tenant_id` for the
        // downstream work. Mirrors the DispatcherWorker pattern.
        let mut tx = self.db.migrator_pool().begin().await?;

        let rows = sqlx::query(
            "SELECT id, tenant_id, saved_report_id, user_id, cron_expr, \
                    recipient_email, last_run_at \
             FROM scheduled_reports \
             WHERE is_active = true AND next_run_at <= NOW() \
             ORDER BY next_run_at \
             LIMIT $1 \
             FOR UPDATE SKIP LOCKED",
        )
        .bind(limit)
        .fetch_all(&mut *tx)
        .await?;

        let mut stats = ScheduledReportsTickStats::default();
        for row in rows {
            stats.examined += 1;
            let id: Uuid = row.try_get("id")?;
            let tenant_id: Uuid = row.try_get("tenant_id")?;
            let saved_report_id: Uuid = row.try_get("saved_report_id")?;
            let user_id: Uuid = row.try_get("user_id")?;
            let cron_expr: String = row.try_get("cron_expr")?;
            let recipient_email: Option<String> = row.try_get("recipient_email")?;

            let outcome = self
                .materialise_and_enqueue(
                    &mut tx,
                    tenant_id,
                    saved_report_id,
                    user_id,
                    recipient_email.as_deref(),
                )
                .await;

            // Advance the schedule regardless of outcome. A failing
            // report should not stall its next cadence; the
            // `last_error` column captures the failure so the SPA can
            // render a "last delivery failed" badge.
            let now = chrono::Utc::now();
            let next = match super::service::compute_next_run(&cron_expr, now) {
                Ok(t) => t,
                Err(e) => {
                    tracing::error!(%id, %e, "failed to advance schedule; disabling");
                    sqlx::query(
                        "UPDATE scheduled_reports \
                             SET is_active = false, last_error = $1, updated_at = NOW() \
                         WHERE id = $2",
                    )
                    .bind(format!("Disabled: {e}"))
                    .bind(id)
                    .execute(&mut *tx)
                    .await?;
                    stats.skipped += 1;
                    continue;
                }
            };

            let (last_err, ok) = match outcome {
                Ok(()) => (None::<String>, true),
                Err(e) => (Some(e.to_string()), false),
            };
            sqlx::query(
                "UPDATE scheduled_reports \
                     SET last_run_at = $1, next_run_at = $2, last_error = $3, updated_at = NOW() \
                 WHERE id = $4",
            )
            .bind(now)
            .bind(next)
            .bind(last_err)
            .bind(id)
            .execute(&mut *tx)
            .await?;
            if ok {
                stats.delivered += 1;
            } else {
                stats.failed += 1;
            }
        }

        tx.commit().await?;
        Ok(stats)
    }

    /// Run one schedule end-to-end: materialise via the executor,
    /// render to CSV, look up the recipient, and INSERT into
    /// `notifications` so the DispatcherWorker sends the email.
    async fn materialise_and_enqueue(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        tenant_id: Uuid,
        saved_report_id: Uuid,
        user_id: Uuid,
        recipient_override: Option<&str>,
    ) -> AppResult<()> {
        // execute() runs against the service's own pool, not the
        // worker's tx. That's intentional: the row-fetch can be
        // multi-megabyte and we do NOT want it inside the FOR UPDATE
        // SKIP LOCKED transaction. The schedule row is held by the
        // outer tx; the result-set fetch is independent.
        let result = self
            .reports
            .execute(tenant_id, user_id, saved_report_id, 1, PER_PAGE)
            .await?;
        let csv = render_csv(&result.aliases, &result.rows);
        let report_name = self
            .reports
            .get(tenant_id, user_id, saved_report_id)
            .await
            .map(|r| r.name)
            .unwrap_or_else(|_| "Scheduled report".into());

        // Resolve recipient: explicit override > owner's users.email.
        let to: String = match recipient_override {
            Some(s) if !s.trim().is_empty() => s.to_string(),
            _ => sqlx::query_scalar::<_, Option<String>>(
                "SELECT email FROM users WHERE tenant_id = $1 AND id = $2",
            )
            .bind(tenant_id)
            .bind(user_id)
            .fetch_optional(&mut **tx)
            .await?
            .flatten()
            .ok_or_else(|| {
                crate::utils::error::AppError::Internal(format!(
                    "schedule owner {user_id} has no email and no recipient override"
                ))
            })?,
        };

        let subject = format!(
            "{report_name} - {date}",
            date = chrono::Utc::now().format("%Y-%m-%d")
        );
        let body = format!(
            "Your scheduled report is attached inline below ({rows} rows, {total} matched).\n\n{csv}",
            rows = result.rows.len(),
            total = result.total,
        );

        sqlx::query(
            "INSERT INTO notifications \
                 (tenant_id, user_id, channel_type, recipient, subject, body, status) \
             VALUES ($1, $2, 'email', $3, $4, $5, 'pending')",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(&to)
        .bind(subject)
        .bind(body)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }
}

#[async_trait]
impl Job for ScheduledReportsWorker {
    fn name(&self) -> &'static str {
        "scheduled_reports"
    }
    async fn run(&self) -> AppResult<()> {
        let stats = self.run_tick(TICK_BATCH_SIZE).await?;
        if stats.examined > 0 {
            tracing::debug!(?stats, "scheduled reports tick");
        }
        Ok(())
    }
}

/// Render the executor's `(aliases, rows)` pair into a CSV string.
/// Each row's JSON object is keyed by alias; missing keys land as
/// empty cells. Values are stringified with `serde_json::to_string`
/// so a comma in a text column is quoted automatically.
fn render_csv(aliases: &[String], rows: &[serde_json::Value]) -> String {
    let mut out = String::new();
    out.push_str(
        &aliases
            .iter()
            .map(|a| csv_quote(a))
            .collect::<Vec<_>>()
            .join(","),
    );
    out.push('\n');
    for row in rows {
        let cells: Vec<String> = aliases
            .iter()
            .map(|alias| {
                let v = row.get(alias);
                match v {
                    Some(serde_json::Value::Null) | None => String::new(),
                    Some(serde_json::Value::String(s)) => csv_quote(s),
                    Some(other) => csv_quote(&other.to_string()),
                }
            })
            .collect();
        out.push_str(&cells.join(","));
        out.push('\n');
    }
    out
}

/// Wrap a cell in CSV quotes when it contains a comma, quote, or
/// newline. Doubles internal quotes per RFC 4180.
fn csv_quote(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        let escaped = s.replace('"', "\"\"");
        format!("\"{escaped}\"")
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn csv_renders_header_and_rows() {
        let aliases = vec!["id".to_string(), "Subject".to_string()];
        let rows = vec![
            json!({ "id": "abc", "Subject": "Hello" }),
            json!({ "id": "def", "Subject": "with, comma" }),
        ];
        let csv = render_csv(&aliases, &rows);
        let mut lines = csv.lines();
        assert_eq!(lines.next(), Some("id,Subject"));
        assert_eq!(lines.next(), Some("abc,Hello"));
        assert_eq!(lines.next(), Some("def,\"with, comma\""));
    }

    #[test]
    fn csv_missing_cells_blank() {
        let aliases = vec!["a".to_string(), "b".to_string()];
        let rows = vec![json!({ "a": "x" })];
        let csv = render_csv(&aliases, &rows);
        assert!(csv.lines().nth(1).unwrap().ends_with(','));
    }
}
