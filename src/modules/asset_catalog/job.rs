//! The 60s REFRESH job for `asset_signature_candidates_mv` (PMS-1492
//! phase 3 MR3).
//!
//! Shape copied from `features/job.rs`: a `Job` on the existing
//! scheduler so a single registry owns "run this on an interval",
//! and a failed tick logs + skips to keep the deployment on the
//! previous view contents rather than erroring out.

use crate::db::Database;
use crate::scheduler::Job;
use crate::utils::error::AppResult;

/// How often the signature detector matview refreshes. The design doc
/// commits to 60 seconds; a shorter interval buys nothing because the
/// SPA's banner is a "hey, you have a new hot pattern" nudge, not an
/// instant-feedback surface.
pub const REFRESH_INTERVAL_SECS: u64 = 60;

pub struct AssetSignatureDetectorRefresh {
    db: Database,
}

impl AssetSignatureDetectorRefresh {
    pub const JOB_NAME: &'static str = "asset_signature_detector_refresh";

    pub fn new(db: Database) -> Self {
        Self { db }
    }
}

#[async_trait::async_trait]
impl Job for AssetSignatureDetectorRefresh {
    fn name(&self) -> &'static str {
        Self::JOB_NAME
    }

    async fn run(&self) -> AppResult<()> {
        // CONCURRENTLY so readers hitting the view mid-refresh see the
        // previous contents rather than an exclusive lock. Needs the
        // unique index on the view (migration 272) and the MAINTAIN
        // privilege granted to `mokosh_app`.
        //
        // SAFETY (PMS-285): REFRESH MATERIALIZED VIEW is a DDL-adjacent
        // operation on a tenant-agnostic view (one row per tenant,
        // read-filtered at the handler), not a SELECT against a
        // tenant-scoped table. The `set_tenant` wrapper the normal
        // `.begin_with_tenant()` path uses is not meaningful here;
        // calling `.pool()` directly is the right shape.
        sqlx::query("REFRESH MATERIALIZED VIEW CONCURRENTLY asset_signature_candidates_mv")
            .execute(self.db.pool())
            .await?;
        Ok(())
    }
}
