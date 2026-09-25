//! Retention worker for `status_observations`.
//!
//! The append-only shape from the ingest ticket keeps every observation
//! forever unless something deletes them. This worker runs on the shared
//! Scheduler and drops rows older than the documented retention window.
//!
//! 13 months (395 days) is the default: it covers a year-over-year
//! comparison with a month of margin. Deployments that want a different
//! window override it at construction time; the default matches the
//! ticket's stated value.
//!
//! The tick is idempotent and safe on an empty table: with no rows older
//! than the cutoff the delete affects zero rows and the tracing line
//! records that so an operator can see the worker is running.

use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;

use super::StatusService;
use crate::scheduler::Job;
use crate::utils::error::AppResult;

/// Default retention window: 13 months, expressed in days so the value
/// stays constant across leap years.
pub const DEFAULT_RETENTION_DAYS: i64 = 395;

/// Deletes `status_observations` older than the retention cutoff.
pub struct StatusRetentionWorker {
    service: StatusService,
    retention: Duration,
}

impl StatusRetentionWorker {
    /// A worker with the default 13-month retention.
    pub fn new(service: StatusService) -> Self {
        let secs = (DEFAULT_RETENTION_DAYS as u64) * 24 * 60 * 60;
        Self {
            service,
            retention: Duration::from_secs(secs),
        }
    }

    /// A worker with a caller-chosen retention window. Used by the tests
    /// (a full 13 months is not a comfortable fixture size).
    pub fn with_retention(service: StatusService, retention: Duration) -> Self {
        Self { service, retention }
    }

    /// One tick, exposed as a plain method so a test can drive it
    /// deterministically without going through the Scheduler.
    pub async fn run_tick(&self) -> AppResult<u64> {
        let cutoff = Utc::now() - chrono::Duration::from_std(self.retention).unwrap_or_default();
        let removed = self.service.purge_older_than(cutoff).await?;
        if removed > 0 {
            tracing::info!(
                cutoff = %cutoff,
                removed,
                "status retention: purged expired observations"
            );
        } else {
            tracing::debug!(
                cutoff = %cutoff,
                "status retention: nothing to purge"
            );
        }
        Ok(removed)
    }
}

#[async_trait]
impl Job for StatusRetentionWorker {
    fn name(&self) -> &'static str {
        "status_retention"
    }

    async fn run(&self) -> AppResult<()> {
        self.run_tick().await.map(|_| ())
    }
}
