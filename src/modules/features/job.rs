//! The 60-second refresh (PMS-1414).
//!
//! A `Job` on the existing scheduler rather than a bespoke loop, because
//! PMS-135 already owns "run this on an interval" and a second mechanism for it
//! would be a second thing to reason about when a tick stops happening. The
//! scheduler also fires every registered job once immediately at startup, which
//! is how the snapshot gets its first real value without a separate boot read.
//!
//! A failed tick logs and skips, which the trait documents. That is the right
//! outcome here: the snapshot keeps its previous value, so a database blip leaves
//! the deployment on the switches it already had rather than turning everything
//! off for a minute.

use super::service::{self, FeatureSnapshot};
use crate::db::Database;
use crate::scheduler::Job;
use crate::utils::error::AppResult;

/// How often a flip made by another process becomes visible to this one.
///
/// Bunyip's interval, kept deliberately: the switches exist to be turned on in
/// staging and looked at, so a minute of staleness between containers costs
/// nothing, and shortening it would buy a cache-invalidation protocol nobody
/// asked for.
pub const REFRESH_INTERVAL_SECS: u64 = 60;

pub struct FeatureToggleRefresh {
    db: Database,
    snapshot: FeatureSnapshot,
}

impl FeatureToggleRefresh {
    pub const JOB_NAME: &'static str = "feature_toggle_refresh";

    pub fn new(db: Database, snapshot: FeatureSnapshot) -> Self {
        Self { db, snapshot }
    }
}

#[async_trait::async_trait]
impl Job for FeatureToggleRefresh {
    fn name(&self) -> &'static str {
        Self::JOB_NAME
    }

    async fn run(&self) -> AppResult<()> {
        let loaded = service::load(&self.db).await?;
        let before = self.snapshot.current();
        if loaded != before {
            tracing::info!(
                on = ?loaded.as_map(),
                "feature toggles changed since the last refresh"
            );
        }
        self.snapshot.swap(loaded);
        Ok(())
    }
}
