//! PMS-1488: the 60-second scheduler job that refreshes
//! `asset_signature_candidates_mv`.
//!
//! Shape mirrors `features::FeatureToggleRefresh`: one `Job` impl, one
//! fixed interval, failures log + skip. The MV holds (tenant,
//! manufacturer, model, asset_type) groups with >= 5 creates in the
//! last 7 days, so a tick that fails leaves the banner showing the
//! previous snapshot rather than disappearing while the operator was
//! about to click "save as template".

use crate::db::Database;
use crate::modules::assets::AssetCatalogService;
use crate::scheduler::Job;
use crate::utils::error::AppResult;

pub const REFRESH_INTERVAL_SECS: u64 = 60;

pub struct AssetCatalogSignatureRefresh {
    db: Database,
}

impl AssetCatalogSignatureRefresh {
    pub const JOB_NAME: &'static str = "asset_catalog_signature_refresh";

    pub fn new(db: Database) -> Self {
        Self { db }
    }
}

#[async_trait::async_trait]
impl Job for AssetCatalogSignatureRefresh {
    fn name(&self) -> &'static str {
        Self::JOB_NAME
    }

    async fn run(&self) -> AppResult<()> {
        AssetCatalogService::refresh_signature_mv(&self.db).await
    }
}
