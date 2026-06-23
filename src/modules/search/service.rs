//! MAPPS-298: cross-entity search service.

use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::utils::error::AppResult;

/// One matched row in the search response. All five entity types share
/// the same shape so the SPA's grouped dropdown renders uniformly.
///
/// - `id` is the entity's primary key. The SPA composes the detail URL
///   per group (`/tickets/<id>`, `/contacts/<id>`, etc.).
/// - `label` is the primary line shown in the dropdown row (e.g.
///   ticket number + title, company name).
/// - `secondary` is the small grey line under the label when present
///   (e.g. company name on a contact row, status on a ticket row).
#[derive(Debug, Clone, Serialize)]
pub struct SearchHit {
    pub id: Uuid,
    pub label: String,
    pub secondary: Option<String>,
}

/// Grouped envelope returned by `GET /search`. Each field carries the
/// top N matches in its own kind so the SPA can render section
/// headings without re-grouping client-side.
#[derive(Debug, Clone, Serialize, Default)]
pub struct SearchResponse {
    pub tickets: Vec<SearchHit>,
    pub contacts: Vec<SearchHit>,
    pub companies: Vec<SearchHit>,
    pub assets: Vec<SearchHit>,
    pub projects: Vec<SearchHit>,
    /// Number of hits in each section. Surfaced so the SPA can render
    /// "5+ tickets" when the per-section cap clips the result set.
    pub counts: SearchCounts,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct SearchCounts {
    pub tickets: i64,
    pub contacts: i64,
    pub companies: i64,
    pub assets: i64,
    pub projects: i64,
}

/// Per-section cap. Five rows is enough to give the user a useful
/// preview without producing a dropdown that scrolls forever. The
/// matching `count` field on the response reports the true total so
/// the SPA can show "more results" affordance when it's tight.
const SECTION_LIMIT: i64 = 5;

#[derive(Clone)]
pub struct SearchService {
    pool: PgPool,
}

impl SearchService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Run the cross-entity search inside one tenant scope. The query
    /// string is sanitised at the SQL boundary: every `%` and `_` is
    /// escaped so a user typing those literally matches them
    /// literally (no accidental wildcards). The five table scans run
    /// sequentially against the same pool connection - each is cheap
    /// (per-table ILIKE on indexed name / title / number columns,
    /// LIMIT 5) so parallelising them would not amortise meaningfully
    /// and would multiply pool-connection pressure for no win.
    pub async fn search(&self, tenant_id: Uuid, q: &str) -> AppResult<SearchResponse> {
        let trimmed = q.trim();
        if trimmed.is_empty() {
            return Ok(SearchResponse::default());
        }
        // Escape SQL-LIKE wildcards so a user typing `%` matches the
        // literal character. `\` becomes the escape character because
        // Postgres ILIKE defaults to `\` when `ESCAPE` is omitted.
        let escaped = trimmed
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        let pattern = format!("%{}%", escaped);

        let tickets = self.search_tickets(tenant_id, &pattern).await?;
        let contacts = self.search_contacts(tenant_id, &pattern).await?;
        let companies = self.search_companies(tenant_id, &pattern).await?;
        let assets = self.search_assets(tenant_id, &pattern).await?;
        let projects = self.search_projects(tenant_id, &pattern).await?;

        let counts = SearchCounts {
            tickets: tickets.1,
            contacts: contacts.1,
            companies: companies.1,
            assets: assets.1,
            projects: projects.1,
        };

        Ok(SearchResponse {
            tickets: tickets.0,
            contacts: contacts.0,
            companies: companies.0,
            assets: assets.0,
            projects: projects.0,
            counts,
        })
    }

    async fn search_tickets(
        &self,
        tenant_id: Uuid,
        pattern: &str,
    ) -> AppResult<(Vec<SearchHit>, i64)> {
        let rows = sqlx::query_as::<_, (Uuid, String, String, Option<String>)>(
            "SELECT t.id, t.ticket_number, t.title, c.name \
             FROM tickets t \
             LEFT JOIN companies c ON c.id = t.company_id \
             WHERE t.tenant_id = $1 AND ( \
                 t.title ILIKE $2 OR t.ticket_number ILIKE $2 OR t.description ILIKE $2 \
             ) \
             ORDER BY t.updated_at DESC \
             LIMIT $3",
        )
        .bind(tenant_id)
        .bind(pattern)
        .bind(SECTION_LIMIT)
        .fetch_all(&self.pool)
        .await?;
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM tickets t WHERE t.tenant_id = $1 AND ( \
                t.title ILIKE $2 OR t.ticket_number ILIKE $2 OR t.description ILIKE $2 \
             )",
        )
        .bind(tenant_id)
        .bind(pattern)
        .fetch_one(&self.pool)
        .await?;
        let hits = rows
            .into_iter()
            .map(|(id, number, title, company)| SearchHit {
                id,
                label: format!("{} {}", number, title).trim().to_string(),
                secondary: company,
            })
            .collect();
        Ok((hits, total))
    }

    async fn search_contacts(
        &self,
        tenant_id: Uuid,
        pattern: &str,
    ) -> AppResult<(Vec<SearchHit>, i64)> {
        let rows = sqlx::query_as::<_, (Uuid, String, String, Option<String>)>(
            "SELECT k.id, k.first_name, k.last_name, c.name \
             FROM contacts k \
             LEFT JOIN companies c ON c.id = k.company_id \
             WHERE k.tenant_id = $1 AND ( \
                 k.first_name ILIKE $2 OR k.last_name ILIKE $2 OR k.email ILIKE $2 \
             ) \
             ORDER BY k.last_name, k.first_name \
             LIMIT $3",
        )
        .bind(tenant_id)
        .bind(pattern)
        .bind(SECTION_LIMIT)
        .fetch_all(&self.pool)
        .await?;
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM contacts k WHERE k.tenant_id = $1 AND ( \
                k.first_name ILIKE $2 OR k.last_name ILIKE $2 OR k.email ILIKE $2 \
             )",
        )
        .bind(tenant_id)
        .bind(pattern)
        .fetch_one(&self.pool)
        .await?;
        let hits = rows
            .into_iter()
            .map(|(id, first, last, company)| SearchHit {
                id,
                label: format!("{} {}", first, last).trim().to_string(),
                secondary: company,
            })
            .collect();
        Ok((hits, total))
    }

    async fn search_companies(
        &self,
        tenant_id: Uuid,
        pattern: &str,
    ) -> AppResult<(Vec<SearchHit>, i64)> {
        let rows = sqlx::query_as::<_, (Uuid, String, Option<String>)>(
            "SELECT id, name, industry \
             FROM companies \
             WHERE tenant_id = $1 AND name ILIKE $2 \
             ORDER BY name \
             LIMIT $3",
        )
        .bind(tenant_id)
        .bind(pattern)
        .bind(SECTION_LIMIT)
        .fetch_all(&self.pool)
        .await?;
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM companies WHERE tenant_id = $1 AND name ILIKE $2",
        )
        .bind(tenant_id)
        .bind(pattern)
        .fetch_one(&self.pool)
        .await?;
        let hits = rows
            .into_iter()
            .map(|(id, name, industry)| SearchHit {
                id,
                label: name,
                secondary: industry,
            })
            .collect();
        Ok((hits, total))
    }

    async fn search_assets(
        &self,
        tenant_id: Uuid,
        pattern: &str,
    ) -> AppResult<(Vec<SearchHit>, i64)> {
        let rows = sqlx::query_as::<_, (Uuid, String, Option<String>, Option<String>)>(
            "SELECT a.id, a.name, a.serial_number, c.name \
             FROM assets a \
             LEFT JOIN companies c ON c.id = a.company_id \
             WHERE a.tenant_id = $1 AND ( \
                 a.name ILIKE $2 OR a.serial_number ILIKE $2 OR a.asset_tag ILIKE $2 \
             ) \
             ORDER BY a.name \
             LIMIT $3",
        )
        .bind(tenant_id)
        .bind(pattern)
        .bind(SECTION_LIMIT)
        .fetch_all(&self.pool)
        .await?;
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM assets a WHERE a.tenant_id = $1 AND ( \
                a.name ILIKE $2 OR a.serial_number ILIKE $2 OR a.asset_tag ILIKE $2 \
             )",
        )
        .bind(tenant_id)
        .bind(pattern)
        .fetch_one(&self.pool)
        .await?;
        let hits = rows
            .into_iter()
            .map(|(id, name, serial, company)| {
                // Prefer company name as the secondary line; fall back
                // to the serial number when no company is attached
                // (e.g. shared infrastructure asset).
                let secondary = company.or(serial);
                SearchHit {
                    id,
                    label: name,
                    secondary,
                }
            })
            .collect();
        Ok((hits, total))
    }

    async fn search_projects(
        &self,
        tenant_id: Uuid,
        pattern: &str,
    ) -> AppResult<(Vec<SearchHit>, i64)> {
        let rows = sqlx::query_as::<_, (Uuid, String, Option<String>)>(
            "SELECT p.id, p.name, c.name \
             FROM projects p \
             LEFT JOIN companies c ON c.id = p.company_id \
             WHERE p.tenant_id = $1 AND p.name ILIKE $2 \
             ORDER BY p.updated_at DESC \
             LIMIT $3",
        )
        .bind(tenant_id)
        .bind(pattern)
        .bind(SECTION_LIMIT)
        .fetch_all(&self.pool)
        .await?;
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM projects p WHERE p.tenant_id = $1 AND p.name ILIKE $2",
        )
        .bind(tenant_id)
        .bind(pattern)
        .fetch_one(&self.pool)
        .await?;
        let hits = rows
            .into_iter()
            .map(|(id, name, company)| SearchHit {
                id,
                label: name,
                secondary: company,
            })
            .collect();
        Ok((hits, total))
    }
}
