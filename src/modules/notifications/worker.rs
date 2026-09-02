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
//! A tick is three phases, and no database transaction is open across a
//! transport call (PMS-782):
//!
//!   1. **Claim.** One statement marks the due batch `status = 'sending'`,
//!      bumps `attempt_count` and stamps `next_attempt_at = NOW() +
//!      [`CLAIM_TIMEOUT_SECS`]`, returning the claimed rows. `FOR UPDATE SKIP
//!      LOCKED` still keeps parallel replicas off each other's rows, but the
//!      claim is now durable in the row itself rather than in a held lock, so
//!      the transaction ends immediately.
//!   2. **Send.** Recipient addresses are resolved up front (one read per
//!      tenant in the batch), then every row is delivered with nothing open.
//!   3. **Settle.** One transaction writes the outcomes back in at most two
//!      batched `UPDATE ... FROM UNNEST(...)` statements.
//!
//! Before PMS-782 the whole batch was delivered inside the claiming
//! transaction, so a 25-row batch against a 500 ms relay held a migrator
//! connection and 25 row locks for ~12 s per tick and overlapped the next
//! tick.
//!
//! Crash recovery needs no extra column: a row left in `sending` by a worker
//! that died is re-claimed by any later tick once its `next_attempt_at` (the
//! claim timeout) has passed, on the same predicate that picks up a due
//! `pending` row.
//!
//! See PMS-92 in YouTrack for the spec; the spawn site is
//! `src/main.rs` (the server boots the worker after the router is
//! built).

use std::collections::HashMap;
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

/// How long a claim stays valid. A row still `sending` this long after it was
/// claimed is assumed to belong to a worker that died mid-tick and is handed
/// to the next tick. Comfortably longer than a batch of SMTP round trips, so
/// a slow relay does not get its rows re-sent underneath it.
const CLAIM_TIMEOUT_SECS: i64 = 600;

/// Outcome of a single dispatcher tick.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TickStats {
    pub examined: u64,
    pub sent: u64,
    pub retried: u64,
    pub failed: u64,
}

/// One row claimed by phase one, carrying everything phase two needs to
/// deliver it without touching the database again.
struct ClaimedRow {
    id: Uuid,
    tenant_id: Uuid,
    user_id: Option<Uuid>,
    channel: String,
    recipient: Option<String>,
    subject: Option<String>,
    body: String,
    body_html: Option<String>,
    /// `attempt_count` AFTER the claim incremented it: the attempt this tick
    /// is making, and the index into [`BACKOFF_SECS`].
    attempt: i32,
    created_at: chrono::DateTime<chrono::Utc>,
}

/// What phase two decided about a row, written back by phase three.
struct Settlement {
    id: Uuid,
    status: &'static str,
    /// `Some(secs)` schedules a retry that far out; `None` clears
    /// `next_attempt_at` (a terminal row).
    retry_in_secs: Option<i64>,
    error_message: Option<String>,
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

    /// Process up to `limit` pending notifications: claim, send, settle.
    /// Exposed publicly so the integration test can drive the worker
    /// deterministically (no sleep, no spawn).
    #[tracing::instrument(skip_all)]
    pub async fn run_tick(&self, limit: i64) -> AppResult<TickStats> {
        let claimed = self.claim(limit).await?;
        if claimed.is_empty() {
            return Ok(TickStats::default());
        }

        let addresses = self.resolve_addresses(&claimed).await;

        let mut stats = TickStats {
            examined: claimed.len() as u64,
            ..TickStats::default()
        };
        let mut sent_ids: Vec<Uuid> = Vec::new();
        let mut settlements: Vec<Settlement> = Vec::new();

        // No transaction is open from here until `settle`: the relay round
        // trip is the whole point of PMS-782.
        for row in &claimed {
            match self.deliver(row, &addresses).await {
                Ok(()) => {
                    sent_ids.push(row.id);
                    stats.sent += 1;
                    // PMS-788: make the enqueue-to-sent handoff visible so an
                    // operator can tell app-side latency from downstream delivery.
                    let latency_ms = (chrono::Utc::now() - row.created_at).num_milliseconds();
                    tracing::info!(
                        id = %row.id, channel = %row.channel, latency_ms,
                        "notification sent",
                    );
                }
                Err(DeliveryError::Permanent(msg)) => {
                    tracing::warn!(
                        id = %row.id, channel = %row.channel, %msg,
                        "notification permanently failed; will not retry",
                    );
                    settlements.push(Settlement {
                        id: row.id,
                        status: "failed",
                        retry_in_secs: None,
                        error_message: Some(msg),
                    });
                    stats.failed += 1;
                }
                Err(DeliveryError::Transient(msg)) => {
                    let idx = (row.attempt - 1).max(0) as usize;
                    match BACKOFF_SECS.get(idx) {
                        None => {
                            tracing::warn!(
                                id = %row.id, channel = %row.channel, attempt = row.attempt, %msg,
                                "notification failed after final retry",
                            );
                            settlements.push(Settlement {
                                id: row.id,
                                status: "failed",
                                retry_in_secs: None,
                                error_message: Some(msg),
                            });
                            stats.failed += 1;
                        }
                        Some(&secs) => {
                            tracing::info!(
                                id = %row.id, channel = %row.channel, attempt = row.attempt,
                                retry_in_secs = secs, %msg,
                                "notification transient failure; backing off",
                            );
                            settlements.push(Settlement {
                                id: row.id,
                                status: "pending",
                                retry_in_secs: Some(secs),
                                error_message: Some(msg),
                            });
                            stats.retried += 1;
                        }
                    }
                }
            }
        }

        self.settle(&sent_ids, &settlements).await?;
        Ok(stats)
    }

    /// Phase one: take ownership of the due batch in one statement and let the
    /// transaction close immediately.
    ///
    /// The claim is `status = 'sending'` plus the incremented attempt counter
    /// plus a `next_attempt_at` in the future, so it survives this process
    /// dying: no other worker touches the row until the claim expires, and
    /// once it does the row is due again. `FOR UPDATE SKIP LOCKED` inside the
    /// CTE keeps two live workers from claiming the same row.
    async fn claim(&self, limit: i64) -> AppResult<Vec<ClaimedRow>> {
        // SAFETY (PMS-285): the dispatcher drains pending `notifications` across
        // EVERY tenant in one `FOR UPDATE SKIP LOCKED` batch (the worker owns the
        // cadence), so it cannot set a single tenant GUC and runs on the migrator
        // (BYPASSRLS) pool. Each row carries its own `tenant_id` for the delivery
        // / status-update work that follows.
        let rows = sqlx::query(
            r#"
            WITH due AS (
                SELECT id
                FROM notifications
                WHERE status IN ('pending', 'sending')
                  AND (
                        (status = 'pending' AND (next_attempt_at IS NULL OR next_attempt_at <= NOW()))
                     OR (status = 'sending' AND next_attempt_at IS NOT NULL AND next_attempt_at <= NOW())
                  )
                ORDER BY created_at
                LIMIT $1
                FOR UPDATE SKIP LOCKED
            )
            UPDATE notifications n
            SET status = 'sending',
                attempt_count = n.attempt_count + 1,
                next_attempt_at = NOW() + ($2 * INTERVAL '1 second')
            FROM due
            WHERE n.id = due.id
            RETURNING n.id, n.tenant_id, n.user_id, n.channel_type, n.recipient,
                      n.subject, n.body, n.body_html, n.attempt_count, n.created_at
            "#,
        )
        .bind(limit)
        .bind(CLAIM_TIMEOUT_SECS)
        .fetch_all(self.db.migrator_pool())
        .await?;

        rows.into_iter()
            .map(|row| {
                Ok(ClaimedRow {
                    id: row.try_get("id")?,
                    tenant_id: row.try_get("tenant_id")?,
                    user_id: row.try_get("user_id")?,
                    channel: row.try_get("channel_type")?,
                    recipient: row.try_get("recipient")?,
                    subject: row.try_get("subject")?,
                    body: row.try_get("body")?,
                    body_html: row.try_get("body_html")?,
                    attempt: row.try_get("attempt_count")?,
                    created_at: row.try_get("created_at")?,
                })
            })
            .collect()
    }

    /// Resolve the address of every user-addressed row in the batch, one
    /// tenant-scoped read per tenant, BEFORE any send runs. Keyed by
    /// `(tenant_id, user_id)`.
    ///
    /// A tenant whose read fails is not silently dropped: the error string is
    /// stored in place of the address, so [`deliver`](Self::deliver) turns it
    /// into a transient failure that backs off and is eventually reported on
    /// the row, instead of a permanent failure (the read is the thing that
    /// broke, not the notification) or an unbounded retry loop.
    async fn resolve_addresses(
        &self,
        claimed: &[ClaimedRow],
    ) -> HashMap<(Uuid, Uuid), Result<String, String>> {
        let mut wanted: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
        for row in claimed {
            if row.channel == "email" {
                if let Some(uid) = row.user_id {
                    wanted.entry(row.tenant_id).or_default().push(uid);
                }
            }
        }

        let mut resolved: HashMap<(Uuid, Uuid), Result<String, String>> = HashMap::new();
        for (tenant_id, user_ids) in wanted {
            match self.lookup_user_emails(tenant_id, &user_ids).await {
                Ok(found) => {
                    for (uid, email) in found {
                        resolved.insert((tenant_id, uid), Ok(email));
                    }
                }
                Err(e) => {
                    let msg = format!("user email lookup: {e}");
                    tracing::error!(
                        %tenant_id, error = %e,
                        "notification recipient lookup failed; rows will back off",
                    );
                    for uid in user_ids {
                        resolved.insert((tenant_id, uid), Err(msg.clone()));
                    }
                }
            }
        }
        resolved
    }

    /// Resolve recipient + invoke the right transport. The recipient
    /// resolution rules are:
    ///   * if the row carries `user_id`, use the address resolved for it
    ///     up front for any channel that needs one (currently `email`);
    ///     the `in_app` channel is purely a database flip and does not
    ///     need an address.
    ///   * else if the row carries an explicit `recipient`, use that.
    ///   * else fail permanently (nothing to send to).
    ///
    /// `body_html` is the HTML alternative rendered at dispatch time
    /// (PMS-700); `Some` makes the email a `multipart/alternative`, `None`
    /// keeps it single-part plain text.
    async fn deliver(
        &self,
        row: &ClaimedRow,
        addresses: &HashMap<(Uuid, Uuid), Result<String, String>>,
    ) -> Result<(), DeliveryError> {
        match row.channel.as_str() {
            "in_app" => {
                // Row is already visible via GET /api/v1/notifications;
                // flipping status to 'sent' IS the delivery for in-app.
                if row.user_id.is_none() {
                    return Err(DeliveryError::Permanent(
                        "in_app notification has no user_id".to_string(),
                    ));
                }
                Ok(())
            }
            "email" => {
                let to = match (row.user_id, row.recipient.as_deref()) {
                    (Some(uid), _) => match addresses.get(&(row.tenant_id, uid)) {
                        Some(Ok(addr)) => addr.clone(),
                        Some(Err(msg)) => return Err(DeliveryError::Transient(msg.clone())),
                        None => {
                            return Err(DeliveryError::Permanent(format!(
                                "user {uid} has no email"
                            )))
                        }
                    },
                    (None, Some(addr)) => addr.to_string(),
                    (None, None) => {
                        return Err(DeliveryError::Permanent(
                            "email notification has no user_id and no recipient".to_string(),
                        ));
                    }
                };
                self.mailer
                    .send_multipart(
                        &to,
                        row.subject.as_deref().unwrap_or(""),
                        &row.body,
                        row.body_html.as_deref(),
                    )
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

    async fn lookup_user_emails(
        &self,
        tenant_id: Uuid,
        user_ids: &[Uuid],
    ) -> AppResult<Vec<(Uuid, String)>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows: Vec<(Uuid, String)> =
            sqlx::query_as("SELECT id, email FROM users WHERE tenant_id = $1 AND id = ANY($2)")
                .bind(tenant_id)
                .bind(user_ids)
                .fetch_all(&mut *tx)
                .await
                .map_err(|e| AppError::Database(format!("lookup_user_emails: {e}")))?;
        // Committed rather than dropped: a dropped read-only transaction is
        // rolled back lazily, which parks the connection `idle in transaction`
        // for as long as the pool takes to reuse it, i.e. across the sends
        // this phase exists to get out of a transaction (PMS-782).
        tx.commit().await?;
        Ok(rows)
    }

    /// Phase three: write every outcome of the tick back in one transaction,
    /// at most two statements, both independent of the batch size.
    async fn settle(&self, sent_ids: &[Uuid], settlements: &[Settlement]) -> AppResult<()> {
        if sent_ids.is_empty() && settlements.is_empty() {
            return Ok(());
        }

        // SAFETY (PMS-285): a claimed batch spans tenants, so the write-back
        // runs on the migrator (BYPASSRLS) pool for the same reason the claim
        // does. Every row is addressed by the id this tick claimed.
        let mut tx = self.db.migrator_pool().begin().await?;

        if !sent_ids.is_empty() {
            sqlx::query(
                r#"UPDATE notifications
                   SET status = 'sent', sent_at = NOW(),
                       next_attempt_at = NULL, error_message = NULL
                   WHERE id = ANY($1::uuid[])"#,
            )
            .bind(sent_ids)
            .execute(&mut *tx)
            .await?;
        }

        if !settlements.is_empty() {
            let ids: Vec<Uuid> = settlements.iter().map(|s| s.id).collect();
            let statuses: Vec<String> = settlements.iter().map(|s| s.status.to_string()).collect();
            let retries: Vec<Option<i64>> = settlements.iter().map(|s| s.retry_in_secs).collect();
            let errors: Vec<Option<String>> = settlements
                .iter()
                .map(|s| s.error_message.clone())
                .collect();

            sqlx::query(
                r#"UPDATE notifications n
                   SET status = v.status,
                       next_attempt_at = CASE
                           WHEN v.retry_in_secs IS NULL THEN NULL
                           ELSE NOW() + (v.retry_in_secs * INTERVAL '1 second')
                       END,
                       error_message = v.error_message
                   FROM UNNEST($1::uuid[], $2::text[], $3::bigint[], $4::text[])
                        AS v(id, status, retry_in_secs, error_message)
                   WHERE n.id = v.id"#,
            )
            .bind(&ids)
            .bind(&statuses)
            .bind(&retries)
            .bind(&errors)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
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
