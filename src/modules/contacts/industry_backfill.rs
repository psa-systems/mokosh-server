//! PMS-602: one-time, re-runnable backfill that normalizes existing
//! free-text `companies.industry` values to the canonical set seeded by
//! PMS-601 (the `company_industries` lookup defaults).
//!
//! PMS-582 standardized NEW entries via the Industry combobox, but rows
//! created earlier keep whatever was typed ("IT", "I.T.", "Information
//! Technology", ...). This rewrites the values whose normalized form matches a
//! known variant to the canonical spelling, leaves everything else untouched,
//! and reports the unmapped values for manual review.
//!
//! Decisions (the ticket asked these be settled):
//! - Runs against the static canonical map below, not gated on each tenant's
//!   lookup rows. The map's canonical targets are exactly the PMS-601 seed, so
//!   a normalized value lands on a name the tenant's lookup already suggests
//!   (unless the admin deleted it; the field is free text so that is fine).
//! - Cross-tenant in one pass (operator tool), via the privileged pool.
//! - Re-runnable / no-op-safe: the UPDATE skips rows already at the canonical
//!   value, so a second run changes nothing. It also normalizes casing, since
//!   each canonical's own lower-cased form is a variant key.

use std::collections::BTreeMap;

use uuid::Uuid;

use crate::db::Database;
use crate::utils::error::AppResult;

/// `(normalized variant, canonical)` pairs. The variant is matched against
/// `lower(btrim(industry))`. Each canonical also appears as its own lower-cased
/// variant so an existing value that differs only in case is normalized too.
const INDUSTRY_MAP: &[(&str, &str)] = &[
    ("accounting", "Accounting"),
    ("accountancy", "Accounting"),
    ("agriculture", "Agriculture"),
    ("agri", "Agriculture"),
    ("automotive", "Automotive"),
    ("auto", "Automotive"),
    ("banking", "Banking"),
    ("bank", "Banking"),
    ("biotechnology", "Biotechnology"),
    ("biotech", "Biotechnology"),
    ("construction", "Construction"),
    ("consulting", "Consulting"),
    ("consultancy", "Consulting"),
    ("education", "Education"),
    ("edu", "Education"),
    ("energy & utilities", "Energy & Utilities"),
    ("energy and utilities", "Energy & Utilities"),
    ("energy", "Energy & Utilities"),
    ("utilities", "Energy & Utilities"),
    ("engineering", "Engineering"),
    ("entertainment & media", "Entertainment & Media"),
    ("entertainment and media", "Entertainment & Media"),
    ("entertainment", "Entertainment & Media"),
    ("media", "Entertainment & Media"),
    ("finance", "Finance"),
    ("financial", "Finance"),
    ("financial services", "Finance"),
    ("fin", "Finance"),
    ("food & beverage", "Food & Beverage"),
    ("food and beverage", "Food & Beverage"),
    ("food", "Food & Beverage"),
    ("f&b", "Food & Beverage"),
    ("government", "Government"),
    ("govt", "Government"),
    ("gov", "Government"),
    ("healthcare", "Healthcare"),
    ("health care", "Healthcare"),
    ("health", "Healthcare"),
    ("medical", "Healthcare"),
    ("hospitality", "Hospitality"),
    ("information technology", "Information Technology"),
    ("information tech", "Information Technology"),
    ("info tech", "Information Technology"),
    ("infotech", "Information Technology"),
    ("it", "Information Technology"),
    ("i.t.", "Information Technology"),
    ("i.t", "Information Technology"),
    ("tech", "Information Technology"),
    ("technology", "Information Technology"),
    ("insurance", "Insurance"),
    ("legal", "Legal"),
    ("law", "Legal"),
    ("law firm", "Legal"),
    ("manufacturing", "Manufacturing"),
    ("mfg", "Manufacturing"),
    ("marketing & advertising", "Marketing & Advertising"),
    ("marketing and advertising", "Marketing & Advertising"),
    ("marketing", "Marketing & Advertising"),
    ("advertising", "Marketing & Advertising"),
    ("nonprofit", "Nonprofit"),
    ("non-profit", "Nonprofit"),
    ("non profit", "Nonprofit"),
    ("ngo", "Nonprofit"),
    ("pharmaceuticals", "Pharmaceuticals"),
    ("pharmaceutical", "Pharmaceuticals"),
    ("pharma", "Pharmaceuticals"),
    ("real estate", "Real Estate"),
    ("real-estate", "Real Estate"),
    ("realestate", "Real Estate"),
    ("retail", "Retail"),
    ("telecommunications", "Telecommunications"),
    ("telecommunication", "Telecommunications"),
    ("telecoms", "Telecommunications"),
    ("telecom", "Telecommunications"),
    ("transportation & logistics", "Transportation & Logistics"),
    ("transportation and logistics", "Transportation & Logistics"),
    ("transportation", "Transportation & Logistics"),
    ("transport", "Transportation & Logistics"),
    ("logistics", "Transportation & Logistics"),
    ("travel & tourism", "Travel & Tourism"),
    ("travel and tourism", "Travel & Tourism"),
    ("travel", "Travel & Tourism"),
    ("tourism", "Travel & Tourism"),
    ("wholesale", "Wholesale"),
];

/// Outcome of a backfill run.
pub struct IndustryBackfillReport {
    /// Total company rows rewritten to a canonical value.
    pub updated: u64,
    /// Rewrites per tenant (tenant_id, count), only tenants that changed.
    pub per_tenant: Vec<(Uuid, u64)>,
    /// Values left untouched because they matched no known variant, with the
    /// owning tenant and how many companies carry them. For manual review.
    pub unmapped: Vec<(Uuid, String, i64)>,
}

impl std::fmt::Display for IndustryBackfillReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "normalized {} company industry value(s) across {} tenant(s)",
            self.updated,
            self.per_tenant.len()
        )?;
        for (tenant, n) in &self.per_tenant {
            writeln!(f, "  tenant {tenant}: {n} updated")?;
        }
        if self.unmapped.is_empty() {
            write!(f, "no unmapped values remain")?;
        } else {
            writeln!(f, "{} unmapped value(s) left for manual review:", self.unmapped.len())?;
            for (tenant, value, n) in &self.unmapped {
                writeln!(f, "  tenant {tenant}: {n}x {value:?}")?;
            }
            write!(
                f,
                "(add a mapping or correct these from Settings > Company Industries)"
            )?;
        }
        Ok(())
    }
}

/// Normalize existing `companies.industry` values to the canonical set across
/// every tenant. Uses the privileged (BYPASSRLS) pool because it is a
/// cross-tenant operator task. Idempotent: rows already at the canonical value
/// are skipped.
pub async fn normalize_company_industries(db: &Database) -> AppResult<IndustryBackfillReport> {
    let variants: Vec<String> = INDUSTRY_MAP.iter().map(|(v, _)| v.to_string()).collect();
    let canonicals: Vec<String> = INDUSTRY_MAP.iter().map(|(_, c)| c.to_string()).collect();
    let pool = db.migrator_pool();

    // Rewrite in one pass; UNNEST turns the parallel arrays into a (variant,
    // canonical) mapping table. RETURNING the tenant lets us count per tenant.
    let changed: Vec<(Uuid,)> = sqlx::query_as(
        r#"
        UPDATE companies c
        SET industry = m.canonical, updated_at = NOW()
        FROM (
            SELECT unnest($1::text[]) AS variant, unnest($2::text[]) AS canonical
        ) AS m
        WHERE c.industry IS NOT NULL
          AND lower(btrim(c.industry)) = m.variant
          AND c.industry <> m.canonical
        RETURNING c.tenant_id
        "#,
    )
    .bind(&variants)
    .bind(&canonicals)
    .fetch_all(pool)
    .await?;

    let mut per_tenant_map: BTreeMap<Uuid, u64> = BTreeMap::new();
    for (tenant,) in &changed {
        *per_tenant_map.entry(*tenant).or_default() += 1;
    }

    // Anything whose normalized form is not a known variant is left as-is and
    // surfaced for review. Already-canonical values are excluded because each
    // canonical's lower-cased form is itself a variant key.
    let unmapped: Vec<(Uuid, String, i64)> = sqlx::query_as(
        r#"
        SELECT c.tenant_id, c.industry, count(*) AS n
        FROM companies c
        WHERE c.industry IS NOT NULL
          AND btrim(c.industry) <> ''
          AND lower(btrim(c.industry)) <> ALL($1::text[])
        GROUP BY c.tenant_id, c.industry
        ORDER BY c.tenant_id, n DESC
        "#,
    )
    .bind(&variants)
    .fetch_all(pool)
    .await?;

    Ok(IndustryBackfillReport {
        updated: changed.len() as u64,
        per_tenant: per_tenant_map.into_iter().collect(),
        unmapped,
    })
}
