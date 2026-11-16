//! PMS-800: service composing the three documentation sources.
//!
//! The aggregate is a pure composition: it never touches `assets`,
//! `credential_vault` or `kb_articles` directly, and reuses the
//! services that already own tenant guards + encryption boundaries.
//! Credential rows come back as references (`CredentialSummary`), which
//! deliberately omits every encrypted field, so no secret material is
//! on the wire; the audited reveal handler stays the one path to a
//! password or secret_data value.

use serde::Serialize;
use uuid::Uuid;

use crate::modules::assets::models::{AssetFilter, AssetResponse, CredentialSummary};
use crate::modules::assets::AssetsService;
use crate::modules::auth::TenantId;
use crate::modules::knowledge_base::models::{KbArticleFilter, KbArticleResponse};
use crate::modules::knowledge_base::KbService;
use crate::utils::error::AppResult;
use crate::utils::pagination::PaginationParams;

// SPEC-15.1149
/// The one aggregate response. Three parallel lists, each already
/// scoped to the one company at the service level.
///
/// PMS-1664 finding: the totals used to be discarded (`_total_assets`,
/// `_total_articles`), so a company with more than `PER_LIST_LIMIT`
/// assets or articles was silently truncated. Surface each total
/// alongside its list so the SPA can show a "showing N of M; see the
/// full list" affordance.
#[derive(Debug, Serialize)]
pub struct CompanyDocumentation {
    pub assets: Vec<AssetResponse>,
    pub total_assets: u64,
    pub credentials: Vec<CredentialSummary>,
    pub articles: Vec<KbArticleResponse>,
    pub total_articles: u64,
}

// SPEC-15.1150, SPEC-15.1152
/// How many of each list the aggregate returns per request. The intent is
/// a human reading an on-call screen, not a full-tenant export; the per-page
/// cap keeps the response bounded. Call the owning module's list endpoints
/// for a deeper walk.
const PER_LIST_LIMIT: u32 = 100;

#[derive(Clone)]
pub struct DocumentationService {
    assets: AssetsService,
    kb: KbService,
}

impl DocumentationService {
    pub fn new(assets: AssetsService, kb: KbService) -> Self {
        Self { assets, kb }
    }

    // SPEC-15.1150, SPEC-15.1151, SPEC-15.1152, SPEC-15.1153, SPEC-15.1154
    /// Aggregate for one company. Each list is bounded at
    /// `PER_LIST_LIMIT`; totals and pagination belong on the module's
    /// own list endpoints.
    pub async fn documentation_for_company(
        &self,
        tenant_id: TenantId,
        company_id: Uuid,
    ) -> AppResult<CompanyDocumentation> {
        let page = PaginationParams {
            page: 1,
            per_page: PER_LIST_LIMIT,
            ..PaginationParams::default()
        };
        let asset_filter = AssetFilter {
            company_id: Some(company_id),
            ..AssetFilter::default()
        };
        let kb_filter = KbArticleFilter {
            company_id: Some(company_id),
            ..KbArticleFilter::default()
        };

        // Each call opens its own transaction over an independent, bounded
        // query with no ordering dependency between the three, so they run
        // concurrently.
        #[rustfmt::skip]
        let ((assets, total_assets), credentials, (articles, total_articles)) = tokio::try_join!(
            self.assets.list_assets(tenant_id, &asset_filter, &page),
            self.assets.list_credentials_for_company(tenant_id, company_id),
            self.kb.list_articles(tenant_id, &kb_filter, &page)
        )?;

        Ok(CompanyDocumentation {
            assets,
            total_assets,
            credentials,
            articles,
            total_articles,
        })
    }
}
