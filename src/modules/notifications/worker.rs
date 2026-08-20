//! Notifications dispatcher worker.
//!
//! Drains the `notifications` queue (`status = 'pending'` and
//! `next_attempt_at <= NOW()`) and fires the right transport per row.
//! Each row corresponds to one (recipient, channel) fanout written by
//! `NotificationsService::dispatch`.
//!
//! Backoff ladder for transient failures: 1m, 5m, 30m, 2h, 6h. After
//! the sixth attempt (i.e. five retries) the row is marked `failed`
//! with the last error in `error_message`. Permanent failures (channel
//! has no transport, recipient unresolvable) also short-circuit to
//! `failed` so they do not sit on the queue forever burning attempts.
//!
//! The worker uses `SELECT ... FOR UPDATE SKIP LOCKED` so multiple
//! replicas can run in parallel without double-sending. The send call
//! runs inside the row's transaction, which keeps the lock held for
//! the duration of the SMTP RTT; that is acceptable at v1 throughput
//! (a single mokosh-server instance and a handful of recipients per
//! event). Move the send out of the locking transaction if the queue
//! grows past what a single connection can drain.
//!
//! See PMS-92 in YouTrack for the spec; the spawn site is
//! `src/main.rs` (the server boots the worker after the router is
//! built).

use std::sync::Arc;

use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

use crate::db::Database;
use crate::scheduler::Job;
use crate::utils::email::Mailer;
use crate::utils::error::{AppError, AppResult};

/// Backoff intervals (seconds) for transient send failures, indexed by
/// `attempt_count - 1`. After the array is exhausted the row is marked
/// `failed`.
const BACKOFF_SECS: &[i64] = &[60, 300, 1800, 7200, 21600];

/// Rows drained per scheduler tick. Was the `batch_size` argument to the
/// old `run_forever`; now a constant since the [`Job`] trait owns the tick
/// loop and carries no per-tick parameters (PMS-198).
const TICK_BATCH_SIZE: i64 = 25;

/// Outcome of a single dispatcher tick.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TickStats {
    pub examined: u64,
    pub sent: u64,
    pub retried: u64,
    pub failed: u64,
}

/// Worker handle: holds the dependencies needed to fire a channel
/// transport. Clone is cheap (Arc + handle).
#[derive(Clone)]
pub struct DispatcherWorker {
    db: Database,
    mailer: Arc<dyn Mailer>,
}

impl DispatcherWorker {
    pub fn new(db: Database, mailer: Arc<dyn Mailer>) -> Self {
        Self { db, mailer }
    }

    /// Process up to `limit` pending notifications in a single
    /// transaction. Exposed publicly so the integration test can drive
    /// the worker deterministically (no sleep, no spawn).
    #[tracing::instrument(skip_all)]
    pub async fn run_tick(&self, limit: i64) -> AppResult<TickStats> {
        // SAFETY (PMS-285): the dispatcher drains pending `notifications` across
        // EVERY tenant in one `FOR UPDATE SKIP LOCKED` batch (the worker owns the
        // cadence), so it cannot set a single tenant GUC and runs on the migrator
        // (BYPASSRLS) pool. Each row carries its own `tenant_id` for the delivery
        // / status-update work that follows.
        let mut tx = self.db.migrator_pool().begin().await?;

        let rows = sqlx::query(
            r#"
            SELECT id, tenant_id, user_id, channel_type, recipient,
                   subject, body, body_html, attempt_count, created_at
            FROM notifications
            WHERE status = 'pending'
              AND (next_attempt_at IS NULL OR next_attempt_at <= NOW())
            ORDER BY created_at
            LIMIT $1
            FOR UPDATE SKIP LOCKED
            "#,
        )
        .bind(limit)
        .fetch_all(&mut *tx)
        .await?;

        let mut stats = TickStats::default();
        for row in rows {
            stats.examined += 1;
            let id: Uuid = row.try_get("id")?;
            let tenant_id: Uuid = row.try_get("tenant_id")?;
            let user_id: Option<Uuid> = row.try_get("user_id")?;
            let channel: String = row.try_get("channel_type")?;
            let recipient: Option<String> = row.try_get("recipient")?;
            let subject: Option<String> = row.try_get("subject")?;
            let body: String = row.try_get("body")?;
            let body_html: Option<String> = row.try_get("body_html")?;
            let attempt: i32 = row.try_get("attempt_count")?;
            let created_at: chrono::DateTime<chrono::Utc> = row.try_get("created_at")?;

            let new_attempt = attempt + 1;
            let send_result = self
                .deliver(
                    tenant_id,
                    user_id,
                    &channel,
                    recipient.as_deref(),
                    subject.as_deref().unwrap_or(""),
                    &body,
                    body_html.as_deref(),
                )
                .await;

            match send_result {
                Ok(()) => {
                    sqlx::query(
                        r#"UPDATE notifications
                           SET status = 'sent', sent_at = NOW(),
                               attempt_count = $1, next_attempt_at = NULL,
                               error_message = NULL
                           WHERE id = $2"#,
                    )
                    .bind(new_attempt)
                    .bind(id)
                    .execute(&mut *tx)
                    .await?;
                    stats.sent += 1;
                    // PMS-788: make the enqueue-to-sent handoff visible so an
                    // operator can tell app-side latency from downstream delivery.
                    let latency_ms = (chrono::Utc::now() - created_at).num_milliseconds();
                    tracing::info!(%id, channel = %channel, latency_ms, "notification sent");
                }
                Err(DeliveryError::Permanent(msg)) => {
                    sqlx::query(
                        r#"UPDATE notifications
                           SET status = 'failed', attempt_count = $1,
                               next_attempt_at = NULL, error_message = $2
                           WHERE id = $3"#,
                    )
                    .bind(new_attempt)
                    .bind(&msg)
                    .bind(id)
                    .execute(&mut *tx)
                    .await?;
                    stats.failed += 1;
                    tracing::warn!(
                        %id, %channel, %msg,
                        "notification permanently failed; will not retry",
                    );
                }
                Err(DeliveryError::Transient(msg)) => {
                    let idx = (new_attempt - 1) as usize;
                    if idx >= BACKOFF_SECS.len() {
                        sqlx::query(
                            r#"UPDATE notifications
                               SET status = 'failed', attempt_count = $1,
                                   next_attempt_at = NULL, error_message = $2
                               WHERE id = $3"#,
                        )
                        .bind(new_attempt)
                        .bind(&msg)
                        .bind(id)
                        .execute(&mut *tx)
                        .await?;
                        stats.failed += 1;
                        tracing::warn!(
                            %id, %channel, attempt = new_attempt, %msg,
                            "notification failed after final retry",
                        );
                    } else {
                        let secs = BACKOFF_SECS[idx];
                        sqlx::query(
                            r#"UPDATE notifications
                               SET attempt_count = $1,
                                   next_attempt_at = NOW() + ($2 * INTERVAL '1 second'),
                                   error_message = $3
                               WHERE id = $4"#,
                        )
                        .bind(new_attempt)
                        .bind(secs)
                        .bind(&msg)
                        .bind(id)
                        .execute(&mut *tx)
                        .await?;
                        stats.retried += 1;
                        tracing::info!(
                            %id, %channel, attempt = new_attempt, retry_in_secs = secs, %msg,
                            "notification transient failure; backing off",
                        );
                    }
                }
            }
        }

        tx.commit().await?;
        Ok(stats)
    }

    /// Resolve recipient + invoke the right transport. The recipient
    /// resolution rules are:
    ///   * if the row carries `user_id`, look up the user's email
    ///     for any channel that needs an address (currently `email`);
    ///     the `in_app` channel is purely a database flip and does not
    ///     need an address.
    ///   * else if the row carries an explicit `recipient`, use that.
    ///   * else fail permanently (nothing to send to).
    ///
    /// `body_html` is the HTML alternative rendered at dispatch time
    /// (PMS-700); `Some` makes the email a `multipart/alternative`, `None`
    /// keeps it single-part plain text.
    #[allow(clippy::too_many_arguments)]
    async fn deliver(
        &self,
        tenant_id: Uuid,
        user_id: Option<Uuid>,
        channel: &str,
        recipient: Option<&str>,
        subject: &str,
        body: &str,
        body_html: Option<&str>,
    ) -> Result<(), DeliveryError> {
        match channel {
            "in_app" => {
                // Row is already visible via GET /api/v1/notifications;
                // flipping status to 'sent' IS the delivery for in-app.
                if user_id.is_none() {
                    return Err(DeliveryError::Permanent(
                        "in_app notification has no user_id".to_string(),
                    ));
                }
                Ok(())
            }
            "email" => {
                let to = match (user_id, recipient) {
                    (Some(uid), _) => self
                        .lookup_user_email(tenant_id, uid)
                        .await
                        .map_err(|e| DeliveryError::Permanent(format!("user email lookup: {e}")))?
                        .ok_or_else(|| {
                            DeliveryError::Permanent(format!("user {uid} has no email"))
                        })?,
                    (None, Some(addr)) => addr.to_string(),
                    (None, None) => {
                        return Err(DeliveryError::Permanent(
                            "email notification has no user_id and no recipient".to_string(),
                        ));
                    }
                };
                self.mailer
                    .send_multipart(&to, subject, body, body_html)
                    .await
                    .map_err(|e| DeliveryError::Transient(format!("smtp: {e}")))
            }
            // Chat / SMS channels are not wired in v1. Mark these rows
            // failed loudly so a deployment that forgets to register a
            // transport is visible in the status column, not silently
            // queued forever.
            other => Err(DeliveryError::Permanent(format!(
                "no transport registered for channel '{other}'"
            ))),
        }
    }

    async fn lookup_user_email(&self, tenant_id: Uuid, user_id: Uuid) -> AppResult<Option<String>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: Option<(String,)> =
            sqlx::query_as("SELECT email FROM users WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(user_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| AppError::Database(format!("lookup_user_email: {e}")))?;
        Ok(row.map(|(e,)| e))
    }
}

#[async_trait]
impl Job for DispatcherWorker {
    fn name(&self) -> &'static str {
        "notifications_dispatcher"
    }

    async fn run(&self) -> AppResult<()> {
        let stats = self.run_tick(TICK_BATCH_SIZE).await?;
        if stats.examined > 0 {
            tracing::debug!(?stats, "dispatcher tick");
        }
        Ok(())
    }
}

/// Outcome of a single delivery attempt. Transient failures back off
/// and retry; permanent failures short-circuit to `status = failed`.
#[derive(Debug)]
enum DeliveryError {
    Transient(String),
    Permanent(String),
}
