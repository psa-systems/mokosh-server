//! PMS-471: scheduled dashboard delivery worker.
//!
//! Ticks the `scheduled_dashboards` queue: picks `is_active = true`
//! rows whose `next_run_at <= NOW()`, renders a snapshot of the
//! dashboard's layout JSONB into a text summary, and enqueues an
//! `email` row into `notifications` so the existing DispatcherWorker
//! (notifications/worker.rs) handles the SMTP send + retry backoff.
//! After each row the cron expression advances `last_run_at` /
//! `next_run_at`; a failure stamps `last_error` but still advances
//! the cadence so a single bad row does not stall the next firing.
//!
//! The "materialise" step is intentionally shallow at v1: the
//! SPA-side widget surface (PMS-453 phase 2a) is being built in
//! parallel and there is no server-side widget execute path to drive
//! yet. The snapshot today is a name + the widget keys from the
//! layout JSONB; once 2a lands the worker can swap in a richer
//! renderer without touching the schedule machinery.
//!
//! Locks rows via `SELECT ... FOR UPDATE SKIP LOCKED` so multiple
//! replicas can drain in parallel without double-sending. Mirrors
//! the scheduled_reports worker pattern from PMS-478.

use std::sync::Arc;

use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

use crate::db::Database;
use crate::modules::dashboards::DashboardsService;
use crate::scheduler::Job;
use crate::utils::error::AppResult;

/// Rows drained per tick. Schedules are coarse-grained (a typical
/// tenant has a handful) so the small batch keeps the locking
/// transaction short.
const TICK_BATCH_SIZE: i64 = 10;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ScheduledDashboardsTickStats {
    pub examined: u64,
    pub delivered: u64,
    pub failed: u64,
    pub skipped: u64,
}

#[derive(Clone)]
pub struct ScheduledDashboardsWorker {
    db: Database,
    dashboards: Arc<DashboardsService>,
}

impl ScheduledDashboardsWorker {
    pub fn new(db: Database, dashboards: Arc<DashboardsService>) -> Self {
        Self { db, dashboards }
    }

    /// Process up to `limit` due schedules in a single transaction.
    /// Exposed publicly so the integration test can drive the
    /// worker deterministically (no sleep / no spawn).
    #[tracing::instrument(skip_all)]
    pub async fn run_tick(&self, limit: i64) -> AppResult<ScheduledDashboardsTickStats> {
        // The migrator pool bypasses RLS so the worker can scan
        // every tenant in one query; each row carries `tenant_id`
        // for the downstream work. Mirrors the DispatcherWorker /
        // ScheduledReportsWorker pattern.
        let mut tx = self.db.migrator_pool().begin().await?;

        let rows = sqlx::query(
            "SELECT id, tenant_id, dashboard_id, user_id, cron_expr, recipient_email \
             FROM scheduled_dashboards \
             WHERE is_active = true AND next_run_at <= NOW() \
             ORDER BY next_run_at \
             LIMIT $1 \
             FOR UPDATE SKIP LOCKED",
        )
        .bind(limit)
        .fetch_all(&mut *tx)
        .await?;

        let mut stats = ScheduledDashboardsTickStats::default();
        for row in rows {
            stats.examined += 1;
            let id: Uuid = row.try_get("id")?;
            let tenant_id: Uuid = row.try_get("tenant_id")?;
            let dashboard_id: Uuid = row.try_get("dashboard_id")?;
            let user_id: Uuid = row.try_get("user_id")?;
            let cron_expr: String = row.try_get("cron_expr")?;
            let recipient_email: Option<String> = row.try_get("recipient_email")?;

            let outcome = self
                .materialise_and_enqueue(
                    &mut tx,
                    tenant_id,
                    dashboard_id,
                    user_id,
                    recipient_email.as_deref(),
                )
                .await;

            // Advance the schedule regardless of outcome. A failing
            // render should not stall its next cadence; the
            // `last_error` column captures the failure so the SPA
            // can render a "last delivery failed" badge.
            let now = chrono::Utc::now();
            let next = match super::service::compute_next_run(&cron_expr, now) {
                Ok(t) => t,
                Err(e) => {
                    tracing::error!(%id, %e, "failed to advance schedule; disabling");
                    sqlx::query(
                        "UPDATE scheduled_dashboards \
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
                "UPDATE scheduled_dashboards \
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

    /// Run one schedule end-to-end: pull the dashboard, render a
    /// text snapshot of its layout, look up the recipient, and
    /// INSERT into `notifications` so the DispatcherWorker sends
    /// the email.
    async fn materialise_and_enqueue(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        tenant_id: Uuid,
        dashboard_id: Uuid,
        user_id: Uuid,
        recipient_override: Option<&str>,
    ) -> AppResult<()> {
        // Fetch via the dashboards service so the per-user
        // visibility rule still applies (a schedule whose owner has
        // since lost access cannot resurrect a snapshot).
        let dashboard = self
            .dashboards
            .get(tenant_id, user_id, dashboard_id)
            .await?;
        let snapshot = render_snapshot(&dashboard.name, &dashboard.layout);

        // Resolve recipient: explicit override > owner's
        // `users.email`.
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
            "Dashboard: {name} - {date}",
            name = dashboard.name,
            date = chrono::Utc::now().format("%Y-%m-%d")
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
        .bind(snapshot)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }
}

#[async_trait]
impl Job for ScheduledDashboardsWorker {
    fn name(&self) -> &'static str {
        "scheduled_dashboards"
    }
    async fn run(&self) -> AppResult<()> {
        let stats = self.run_tick(TICK_BATCH_SIZE).await?;
        if stats.examined > 0 {
            tracing::debug!(?stats, "scheduled dashboards tick");
        }
        Ok(())
    }
}

/// Render the dashboard's layout JSONB into a text snapshot suitable
/// for the email body. v1 surfaces the dashboard name + the widget
/// keys the SPA stored - enough for the recipient to know what got
/// scheduled without having to click through. The richer widget
/// render replaces this once PMS-453 phase 2a lands.
fn render_snapshot(name: &str, layout: &serde_json::Value) -> String {
    let mut out = format!("Snapshot of dashboard: {name}\n\n");
    let widgets = extract_widget_keys(layout);
    if widgets.is_empty() {
        out.push_str("(no widgets configured)\n");
    } else {
        out.push_str("Widgets:\n");
        for w in widgets {
            out.push_str(&format!("  - {w}\n"));
        }
    }
    out.push_str("\nThis is an automated scheduled delivery.");
    out
}

/// Pull a flat list of widget keys / labels out of the SPA-owned
/// `layout` blob. The blob is opaque to the server; the shape the SPA
/// actually writes (PMS-453) is
/// `{ "widgets": [{"widget_key": "...", "grid_col": 1, ...}, ...] }`,
/// and these hand-authored shapes are also accepted:
///   - `{ "widgets": [{"key": "..."}, ...] }`
///   - `{ "widgets": ["...", ...] }`
///   - `{ "rows": [{"widgets": [...]}, ...] }`
///
/// This pulls keys from any of the shapes; unknown shapes return an
/// empty Vec so the snapshot still renders. The raw key is rendered
/// rather than a catalog title because the widget catalog lives in the
/// SPA, not here.
fn extract_widget_keys(layout: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    walk(layout, &mut out);
    out
}

fn walk(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::Object(map) => {
            // `widget_key` is what the SPA's WidgetSpec serialises; `key`
            // and `label` stay as fallbacks for hand-authored blobs.
            let name = map
                .get("widget_key")
                .and_then(|v| v.as_str())
                .or_else(|| map.get("key").and_then(|v| v.as_str()))
                .or_else(|| map.get("label").and_then(|v| v.as_str()));
            if let Some(name) = name {
                out.push(name.to_string());
            }
            for child in map.values() {
                walk(child, out);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                if let Some(s) = item.as_str() {
                    out.push(s.to_string());
                } else {
                    walk(item, out);
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The exact document the SPA's `WidgetSpec` serialises (PMS-770).
    #[test]
    fn snapshot_lists_widget_keys() {
        let layout = json!({
            "widgets": [
                {"widget_key": "open_tickets", "grid_col": 1, "grid_row": 1, "grid_col_span": 4, "grid_row_span": 1},
                {"widget_key": "weekly_hours", "grid_col": 1, "grid_row": 2, "grid_col_span": 4, "grid_row_span": 1},
            ]
        });
        let snap = render_snapshot("My Board", &layout);
        assert!(snap.contains("My Board"));
        assert!(snap.contains("open_tickets"));
        assert!(snap.contains("weekly_hours"));
        assert!(!snap.contains("no widgets configured"));
    }

    #[test]
    fn snapshot_lists_legacy_key_and_label_widgets() {
        let layout = json!({
            "widgets": [
                {"key": "open_tickets", "size": "lg"},
                {"label": "Weekly hours", "size": "sm"},
            ]
        });
        let snap = render_snapshot("Legacy Board", &layout);
        assert!(snap.contains("open_tickets"));
        assert!(snap.contains("Weekly hours"));
        assert!(!snap.contains("no widgets configured"));
    }

    #[test]
    fn snapshot_handles_empty_layout() {
        let snap = render_snapshot("Empty", &json!({}));
        assert!(snap.contains("no widgets configured"));
    }

    /// The empty state belongs to an empty dashboard only, not to the
    /// populated document the SPA writes.
    #[test]
    fn snapshot_empty_state_only_for_empty_widget_list() {
        let snap = render_snapshot("Empty", &json!({ "widgets": [] }));
        assert!(snap.contains("no widgets configured"));

        let populated = render_snapshot(
            "Populated",
            &json!({ "widgets": [{"widget_key": "open_tickets", "grid_col": 1, "grid_row": 1, "grid_col_span": 4, "grid_row_span": 1}] }),
        );
        assert!(populated.contains("open_tickets"));
        assert!(!populated.contains("no widgets configured"));
    }

    #[test]
    fn snapshot_handles_string_array_layout() {
        let layout = json!({ "widgets": ["alpha", "bravo"] });
        let snap = render_snapshot("Strings", &layout);
        assert!(snap.contains("alpha") && snap.contains("bravo"));
    }
}
