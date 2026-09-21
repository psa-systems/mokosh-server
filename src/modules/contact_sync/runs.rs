//! PMS-1215 (PSA-70 phase 5): running the sync and reporting what happened.
//!
//! A run is a `contact_sync_runs` row (migration 229). A person starting an
//! import inserts one and gets its id back; [`ContactSyncRunner`], a `Job` on
//! the scheduler in the `rmm_sync` shape, drains the queue. Nothing about the
//! run lives in the request that started it, so closing the tab changes
//! nothing and a restart resumes it.
//!
//! # A tick
//!
//! 1. **Recover.** A `running` row whose heartbeat is older than
//!    [`STALE_AFTER_MINUTES`] belonged to a process that died; it goes back to
//!    `queued`. Resuming replays from the connection's sync token, which the
//!    sync only advances once every record has landed, so records the dead
//!    run already applied replay as no-ops (PMS-1213).
//! 2. **Schedule.** A live connection with a label selection, past its
//!    `sync_interval_minutes` and with no active run, gets a `scheduled` run.
//!    A connection waiting on a reconnect is left alone: a run cannot succeed
//!    and would only repeat the failure.
//! 3. **Claim and run.** Up to [`RUNS_PER_TICK`] queued rows, oldest first,
//!    claimed with `FOR UPDATE SKIP LOCKED` so two replicas never run one row.
//!
//! # Outcomes
//!
//! * Every record landed: `completed`, and the connection's failure streak
//!   resets.
//! * Some records did not: `failed`, with what DID land still counted on the
//!   row and each failure listed with its reason, so partial is visible as
//!   partial rather than as a failed import that imported nothing.
//! * Rate limited: back to `queued` with `not_before` pushed out. Being asked
//!   to wait is not a failure (PSA-70 I), and the connection reads
//!   `throttled`.
//! * Anything else: `failed`, with the reason.
//!
//! Each failure adds one to `consecutive_failures`. At [`NOTIFY_AFTER`] in a
//! row, or at once when the grant was revoked (the one state only a human can
//! fix), `contact_sync.failing` is dispatched once per streak.
//!
//! # An uploaded file (PMS-1290)
//!
//! A `vcard` run imports the upload its row names, read from storage by
//! [`file_import::load_source`]. It is never scheduled, the Google on/off
//! switch does not govern it, and it has no failure streak: a file that did
//! not import is the person's to upload again, not a connection going bad.
//! Whatever its outcome, the held upload is discarded once the run ends, and
//! each tick discards any upload held past its day.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::file_import::{self, VCARD};
use super::google::GoogleContactsProvider;
use super::provider::ContactSyncProvider;
use super::service::ContactSyncService;
use super::sync::{ContactSyncEngine, SyncReport};
use crate::db::Database;
use crate::modules::auth::TenantId;
use crate::modules::notifications::NotificationsService;
use crate::scheduler::Job;
use crate::utils::error::{AppError, AppResult};

/// A running row with no heartbeat for this long belonged to a process that
/// is gone. Long, because one Google page can legitimately wait out a minute
/// of backoff and a read of a large account is many pages.
pub const STALE_AFTER_MINUTES: i64 = 30;

/// Runs started per tick. A tick is sequential, so this bounds how long one
/// tick can hold the worker.
pub const RUNS_PER_TICK: i64 = 5;

/// Why a run the tenant turned the integration off under did not happen.
const TURNED_OFF: &str =
    "Google Contacts was turned off for this organization before this import ran.";

/// Consecutive failed runs before anyone is told.
pub const NOTIFY_AFTER: i32 = 3;

/// How to reach a connection's source. The seam a test replaces: production
/// refreshes a Google access token, a suite hands back a fake.
#[async_trait]
pub trait SourceFactory: Send + Sync {
    async fn source(
        &self,
        tenant_id: TenantId,
        connection_id: Uuid,
        provider: &str,
    ) -> AppResult<Box<dyn ContactSyncProvider>>;
}

/// Production: a fresh access token per run, never stored (PMS-1212).
pub struct GoogleSourceFactory {
    service: Arc<ContactSyncService>,
    http: reqwest::Client,
}

impl GoogleSourceFactory {
    pub fn new(service: Arc<ContactSyncService>) -> Self {
        Self {
            service,
            http: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl SourceFactory for GoogleSourceFactory {
    async fn source(
        &self,
        tenant_id: TenantId,
        connection_id: Uuid,
        provider: &str,
    ) -> AppResult<Box<dyn ContactSyncProvider>> {
        let token = self
            .service
            .access_token(tenant_id, connection_id, provider)
            .await?;
        Ok(Box::new(GoogleContactsProvider::new(
            self.http.clone(),
            token,
        )))
    }
}

/// One run, as a client polls it.
#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct RunStatus {
    pub id: Uuid,
    pub connection_id: Uuid,
    pub trigger: String,
    pub status: String,
    pub requested_by_user_id: Option<Uuid>,
    pub not_before: Option<DateTime<Utc>>,
    pub attempts: i32,
    pub full_read: Option<bool>,
    pub total: Option<i32>,
    pub processed: i32,
    pub created: i32,
    pub linked: i32,
    pub updated: i32,
    pub queued_for_review: i32,
    pub skipped: i32,
    pub deleted_in_source: i32,
    pub failed_records: i32,
    pub failures: serde_json::Value,
    pub error: Option<String>,
    pub cancel_requested_at: Option<DateTime<Utc>>,
    pub heartbeat_at: Option<DateTime<Utc>>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// The column list every run read shares, so a field added to [`RunStatus`]
/// is added once.
pub const RUN_COLUMNS: &str =
    "id, connection_id, trigger, status, requested_by_user_id, not_before, \
    attempts, full_read, total, processed, created, linked, updated, queued_for_review, skipped, \
    deleted_in_source, failed_records, failures, error, cancel_requested_at, heartbeat_at, \
    started_at, finished_at, created_at";

/// What one tick did, for the log and for tests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TickSummary {
    pub recovered: u64,
    pub scheduled: u64,
    pub executed: u64,
}

#[derive(sqlx::FromRow)]
struct Claimed {
    id: Uuid,
    tenant_id: Uuid,
    connection_id: Uuid,
    attempts: i32,
}

#[derive(sqlx::FromRow)]
struct StreakRow {
    provider: String,
    account_email: String,
    sync_status: String,
    last_error: Option<String>,
    consecutive_failures: i32,
    failure_notified_at: Option<DateTime<Utc>>,
    connected_by_user_id: Option<Uuid>,
}

#[derive(Clone)]
pub struct ContactSyncRunner {
    db: Database,
    engine: ContactSyncEngine,
    sources: Arc<dyn SourceFactory>,
    notifications: Option<NotificationsService>,
    spa_base_url: String,
}

impl ContactSyncRunner {
    pub fn new(
        db: Database,
        sources: Arc<dyn SourceFactory>,
        notifications: Option<NotificationsService>,
        spa_base_url: String,
    ) -> Self {
        Self {
            engine: ContactSyncEngine::new(db.clone()),
            db,
            sources,
            notifications,
            spa_base_url,
        }
    }

    pub async fn tick(&self) -> AppResult<TickSummary> {
        let mut summary = TickSummary {
            recovered: self.recover_stale().await?,
            scheduled: self.schedule_due().await?,
            executed: 0,
        };
        match file_import::discard_expired(&self.db).await {
            Ok(0) => {}
            Ok(discarded) => tracing::info!(discarded, "contact import: discarded expired uploads"),
            Err(e) => tracing::warn!("contact import: the expired-upload sweep failed: {e}"),
        }
        for _ in 0..RUNS_PER_TICK {
            let Some(claimed) = self.claim().await? else {
                break;
            };
            self.execute(claimed).await;
            summary.executed += 1;
        }
        Ok(summary)
    }

    async fn recover_stale(&self) -> AppResult<u64> {
        let recovered = sqlx::query(
            "UPDATE contact_sync_runs SET status = 'queued', heartbeat_at = NULL \
             WHERE status = 'running' \
               AND COALESCE(heartbeat_at, started_at, created_at) < NOW() - ($1 * INTERVAL '1 minute')",
        )
        .bind(STALE_AFTER_MINUTES as i32)
        // SAFETY (PMS-285): the recovery sweep spans every tenant (the worker
        // owns the queue), so it runs on the migrator pool. It only flips a
        // run's status; each run's work later sets that run's tenant GUC.
        .execute(self.db.migrator_pool())
        .await?
        .rows_affected();
        if recovered > 0 {
            tracing::warn!(
                recovered,
                "contact sync: resuming runs whose worker stopped"
            );
        }
        Ok(recovered)
    }

    async fn schedule_due(&self) -> AppResult<u64> {
        Ok(sqlx::query(
            "INSERT INTO contact_sync_runs (tenant_id, connection_id, trigger) \
             SELECT c.tenant_id, c.id, 'scheduled' FROM contact_sync_connections c \
             WHERE c.disconnected_at IS NULL AND c.is_active \
               AND c.provider <> 'vcard' \
               AND jsonb_array_length(c.selected_groups) > 0 \
               AND NOT EXISTS (SELECT 1 FROM tenant_settings s \
                               WHERE s.tenant_id = c.tenant_id AND s.category = 'integrations' \
                                 AND s.key = 'google_contacts_enabled' AND s.value = 'false'::jsonb) \
               AND c.sync_status NOT IN ('reconnect_required', 'in_progress') \
               AND c.last_sync_at IS NOT NULL \
               AND c.last_sync_at <= NOW() - (c.sync_interval_minutes * INTERVAL '1 minute') \
               AND NOT EXISTS (SELECT 1 FROM contact_sync_runs r \
                               WHERE r.connection_id = c.id AND r.status IN ('queued', 'running')) \
             ON CONFLICT (connection_id) WHERE status IN ('queued', 'running') DO NOTHING",
        )
        // SAFETY (PMS-285): scheduling reads every tenant's connections, the
        // `rmm_sync` shape, so it runs on the migrator pool; each inserted run
        // copies the tenant_id of the connection it was made for.
        .execute(self.db.migrator_pool())
        .await?
        .rows_affected())
    }

    async fn claim(&self) -> AppResult<Option<Claimed>> {
        Ok(sqlx::query_as(
            "UPDATE contact_sync_runs SET status = 'running', attempts = attempts + 1, \
                 started_at = COALESCE(started_at, NOW()), heartbeat_at = NOW() \
             WHERE id = (SELECT id FROM contact_sync_runs \
                         WHERE status = 'queued' AND (not_before IS NULL OR not_before <= NOW()) \
                         ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1) \
             RETURNING id, tenant_id, connection_id, attempts",
        )
        // SAFETY (PMS-285): the claim picks the oldest queued run across every
        // tenant. The run it returns carries its tenant_id, and everything
        // `execute` does with it is tenant-scoped.
        .fetch_optional(self.db.migrator_pool())
        .await?)
    }

    /// Start one queued run now and wait for its outcome, rather than for the
    /// next tick. What a test drives; the worker claims through [`Self::tick`].
    /// A run that cannot finish records why on its own row.
    pub async fn execute_run(&self, tenant_id: TenantId, run_id: Uuid) -> AppResult<RunStatus> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let claimed: Option<Claimed> = sqlx::query_as(
            "UPDATE contact_sync_runs SET status = 'running', attempts = attempts + 1, \
                 started_at = COALESCE(started_at, NOW()), heartbeat_at = NOW() \
             WHERE tenant_id = $1 AND id = $2 AND status = 'queued' \
             RETURNING id, tenant_id, connection_id, attempts",
        )
        .bind(tenant_id)
        .bind(run_id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        let claimed = claimed
            .ok_or_else(|| AppError::Conflict("That run is not waiting to start.".to_string()))?;
        self.execute(claimed).await;
        self.run_status(tenant_id, run_id).await
    }

    async fn execute(&self, claimed: Claimed) {
        let tenant_id = TenantId::from_trusted(claimed.tenant_id);
        let outcome = self.attempt(tenant_id, &claimed).await;
        if let Err(e) = self.settle(tenant_id, &claimed, outcome).await {
            tracing::error!(
                run_id = %claimed.id,
                "contact sync: could not record a run's outcome: {e}"
            );
        }
    }

    async fn attempt(&self, tenant_id: TenantId, claimed: &Claimed) -> AppResult<SyncReport> {
        let (provider, import_file_id): (String, Option<Uuid>) = {
            let mut tx = self.db.begin_with_tenant(tenant_id).await?;
            sqlx::query_as(
                "SELECT c.provider, r.import_file_id FROM contact_sync_runs r \
                 JOIN contact_sync_connections c ON c.id = r.connection_id \
                 WHERE r.tenant_id = $1 AND r.id = $2",
            )
            .bind(tenant_id)
            .bind(claimed.id)
            .fetch_one(&mut *tx)
            .await?
        };
        let source: Box<dyn ContactSyncProvider> = if provider == VCARD {
            let file_id = import_file_id.ok_or_else(|| {
                AppError::Internal("a vCard run names no uploaded file".to_string())
            })?;
            Box::new(file_import::load_source(tenant_id, file_id).await?)
        } else {
            // Turned off after the run was queued (PMS-1241): no token
            // refresh, no read of the account. `settle` records the run as
            // cancelled.
            if !crate::modules::settings::read_google_contacts_enabled(&self.db, tenant_id).await? {
                return Err(AppError::Conflict(TURNED_OFF.to_string()));
            }
            self.sources
                .source(tenant_id, claimed.connection_id, &provider)
                .await?
        };
        self.engine
            .run_tracked(
                tenant_id,
                claimed.connection_id,
                source.as_ref(),
                Some(claimed.id),
            )
            .await
    }

    async fn settle(
        &self,
        tenant_id: TenantId,
        claimed: &Claimed,
        outcome: AppResult<SyncReport>,
    ) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let (connection_status, disconnected, turned_off, provider, import_file_id): (
            String,
            bool,
            bool,
            String,
            Option<Uuid>,
        ) = sqlx::query_as(
            "SELECT c.sync_status, c.disconnected_at IS NOT NULL, \
                    c.provider = 'google' AND EXISTS (SELECT 1 FROM tenant_settings s \
                            WHERE s.tenant_id = c.tenant_id AND s.category = 'integrations' \
                              AND s.key = 'google_contacts_enabled' AND s.value = 'false'::jsonb), \
                    c.provider, \
                    (SELECT r.import_file_id FROM contact_sync_runs r \
                     WHERE r.tenant_id = c.tenant_id AND r.id = $3) \
             FROM contact_sync_connections c WHERE c.tenant_id = $1 AND c.id = $2",
        )
        .bind(tenant_id)
        .bind(claimed.connection_id)
        .bind(claimed.id)
        .fetch_one(&mut *tx)
        .await?;
        let from_file = provider == VCARD;

        // (run status, error, whether this counts toward the failure streak)
        let (status, error, failure): (&str, Option<String>, Option<bool>) = match &outcome {
            Ok(report) if report.cancelled => ("cancelled", None, None),
            // Disconnected while queued or running: the admin ended it, and a
            // connection that no longer exists has no failure streak.
            _ if disconnected => ("cancelled", None, None),
            Err(_) if turned_off => ("cancelled", Some(TURNED_OFF.to_string()), None),
            Ok(report) if report.failed == 0 => ("completed", None, Some(false)),
            Ok(report) => (
                "failed",
                Some(format!(
                    "{} of {} contacts could not be imported. The rest landed; {}",
                    report.failed,
                    report.total,
                    if from_file {
                        "upload the file again to retry these."
                    } else {
                        "the next sync retries these."
                    }
                )),
                Some(true),
            ),
            Err(_) if connection_status == "throttled" => ("queued", None, None),
            Err(e) => ("failed", Some(e.to_string()), Some(true)),
        };
        // A file has no streak to count: nothing will retry it by itself.
        let failure = if from_file { None } else { failure };

        if status == "queued" {
            // Wait longer each time the provider says wait, up to an hour.
            let minutes = (5 * claimed.attempts.max(1)).min(60);
            sqlx::query(
                "UPDATE contact_sync_runs SET status = 'queued', heartbeat_at = NULL, \
                     not_before = NOW() + ($3 * INTERVAL '1 minute'), \
                     error = 'Google is rate limiting this connection; the import resumes by itself.' \
                 WHERE tenant_id = $1 AND id = $2",
            )
            .bind(tenant_id)
            .bind(claimed.id)
            .bind(minutes)
            .execute(&mut *tx)
            .await?;
        } else {
            sqlx::query(
                "UPDATE contact_sync_runs SET status = $3, error = $4, finished_at = NOW(), \
                     heartbeat_at = NOW() \
                 WHERE tenant_id = $1 AND id = $2",
            )
            .bind(tenant_id)
            .bind(claimed.id)
            .bind(status)
            .bind(&error)
            .execute(&mut *tx)
            .await?;
        }
        // A failure that never reached the engine (a revoked grant, a missing
        // credential) left the connection's own status untouched, so it is
        // recorded here, where the Settings card reads it.
        if outcome.is_err()
            && status == "failed"
            && !matches!(connection_status.as_str(), "failed" | "reconnect_required")
        {
            sqlx::query(
                "UPDATE contact_sync_connections SET sync_status = 'failed', last_error = $3, \
                     last_sync_at = NOW(), updated_at = NOW() \
                 WHERE tenant_id = $1 AND id = $2",
            )
            .bind(tenant_id)
            .bind(claimed.connection_id)
            .bind(&error)
            .execute(&mut *tx)
            .await?;
        }

        let notify = match failure {
            Some(false) => {
                sqlx::query(
                    "UPDATE contact_sync_connections \
                     SET consecutive_failures = 0, failure_notified_at = NULL \
                     WHERE tenant_id = $1 AND id = $2",
                )
                .bind(tenant_id)
                .bind(claimed.connection_id)
                .execute(&mut *tx)
                .await?;
                None
            }
            Some(true) => {
                let streak: StreakRow = sqlx::query_as(
                    "UPDATE contact_sync_connections \
                     SET consecutive_failures = consecutive_failures + 1 \
                     WHERE tenant_id = $1 AND id = $2 \
                     RETURNING provider, account_email, sync_status, last_error, \
                               consecutive_failures, failure_notified_at, connected_by_user_id",
                )
                .bind(tenant_id)
                .bind(claimed.connection_id)
                .fetch_one(&mut *tx)
                .await?;
                let due = streak.failure_notified_at.is_none()
                    && (streak.consecutive_failures >= NOTIFY_AFTER
                        || streak.sync_status == "reconnect_required");
                if due {
                    sqlx::query(
                        "UPDATE contact_sync_connections SET failure_notified_at = NOW() \
                         WHERE tenant_id = $1 AND id = $2",
                    )
                    .bind(tenant_id)
                    .bind(claimed.connection_id)
                    .execute(&mut *tx)
                    .await?;
                    Some(streak)
                } else {
                    None
                }
            }
            None => None,
        };
        tx.commit().await?;

        if let Some(streak) = notify {
            self.notify_failing(tenant_id, streak, error).await;
        }
        // The run is over, so the upload has served its purpose. After the
        // commit and best effort: the sweep retries a discard that fails.
        if let (true, Some(file_id), false) = (from_file, import_file_id, status == "queued") {
            if let Err(e) = file_import::discard(&self.db, tenant_id, file_id).await {
                tracing::warn!(
                    file_id = %file_id,
                    "contact import: could not discard an imported upload: {e}"
                );
            }
        }
        Ok(())
    }

    /// Best effort, after the outcome committed: a mail that fails to queue
    /// must not undo the record of why it was sent.
    async fn notify_failing(&self, tenant_id: TenantId, streak: StreakRow, error: Option<String>) {
        let Some(notifications) = self.notifications.as_ref() else {
            return;
        };
        let recipient = async {
            let mut tx = self.db.begin_with_tenant(tenant_id).await?;
            let row: Option<(Uuid, String, String)> = sqlx::query_as(
                "SELECT id, COALESCE(first_name, ''), COALESCE(last_name, '') FROM users \
                 WHERE tenant_id = $1 AND status = 'active' \
                   AND (id = $2 OR role IN ('super_admin', 'admin')) \
                 ORDER BY (id = $2) DESC NULLS LAST, created_at \
                 LIMIT 1",
            )
            .bind(tenant_id)
            .bind(streak.connected_by_user_id)
            .fetch_optional(&mut *tx)
            .await?;
            Ok::<_, AppError>(row)
        }
        .await;
        let (recipient_id, first_name) = match recipient {
            Ok(Some((id, first, _))) => (Some(id), first),
            Ok(None) => (None, String::new()),
            Err(e) => {
                tracing::warn!(
                    "contact sync: could not find who to tell about a failing connection: {e}"
                );
                (None, String::new())
            }
        };
        let last_error = streak
            .last_error
            .or(error)
            .unwrap_or_else(|| "No reason was recorded.".to_string());
        let mut context = serde_json::json!({
            "salutation": crate::utils::email::salutation(&first_name),
            "account_email": streak.account_email,
            "failure_count": streak.consecutive_failures.to_string(),
            "last_error": last_error,
            // The Settings page the connect flow already returns to
            // (`ContactSyncService::complete_connect`).
            "settings_url": format!(
                "{}/settings/integrations/{}-contacts",
                self.spa_base_url.trim_end_matches('/'),
                streak.provider
            ),
        });
        if let (Some(id), Some(object)) = (recipient_id, context.as_object_mut()) {
            object.insert(
                "recipient_user_id".to_string(),
                serde_json::Value::String(id.to_string()),
            );
        }
        if let Err(e) = notifications
            .dispatch(tenant_id, "contact_sync.failing", &context)
            .await
        {
            tracing::warn!("contact sync: the failing-connection notification did not queue: {e}");
        }
    }

    /// One run, tenant-scoped.
    pub async fn run_status(&self, tenant_id: TenantId, run_id: Uuid) -> AppResult<RunStatus> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query_as(&format!(
            "SELECT {RUN_COLUMNS} FROM contact_sync_runs WHERE tenant_id = $1 AND id = $2"
        ))
        .bind(tenant_id)
        .bind(run_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::NotFound("Import run".to_string()))
    }
}

#[async_trait]
impl Job for ContactSyncRunner {
    fn name(&self) -> &'static str {
        "contact_sync"
    }

    async fn run(&self) -> AppResult<()> {
        let summary = self.tick().await?;
        if summary != TickSummary::default() {
            tracing::debug!(?summary, "contact sync tick");
        }
        Ok(())
    }
}
