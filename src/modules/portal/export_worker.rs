//! PMS-729 phase 2 §7 slice D / I15: portal data-export worker.
//!
//! Runs on the shared scheduler at a 60s cadence. Each tick:
//!   1. Picks up every `portal_exports` row currently in `queued` status
//!      (bounded by a small per-tick LIMIT so the worker stays polite
//!      under contention).
//!   2. Flips each to `running` before doing any work so a crashed pod
//!      does not re-run the same job forever, and a sibling tick does
//!      not race against the first.
//!   3. Builds the JSON bundle for the (tenant, company, contact)
//!      triple: contact profile + own-company tickets + public notes
//!      per ticket + invoices + quotes. Only fields the customer is
//!      already entitled to see through the existing portal read paths
//!      make it in; internal notes / hourly rates / RMM ids etc. stay
//!      out.
//!   4. Persists the bundle into `portal_exports.bundle_json`, sets
//!      `status = 'ready'` with a 7-day `expires_at` window (D19),
//!      and stamps `ready_at`.
//!   5. A build error stamps `status = 'failed'` + `error_message`.
//!
//! A follow-up cron (not in this file) will scan for `expired_at <=
//! NOW() AND status = 'ready'` and blank the `bundle_json` to reclaim
//! storage while keeping the audit row.
//!
//! The worker does NOT hold long-running row locks; it selects the id
//! set into a Vec, flips status per-row in its own transaction, and
//! then does the read + write off the pooled connection. That keeps
//! the row-lock window narrow and the throughput linear in the number
//! of pending jobs.

use async_trait::async_trait;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde_json::json;
use tracing::{info, warn};
use uuid::Uuid;

use crate::db::Database;
use crate::scheduler::Job;
use crate::utils::error::AppResult;

/// Cap the fanout per tick so a burst of requests does not monopolise
/// the pooled connection. Post-code-review finding #7 lowered this
/// from 10 to 3 so the in-flight bundle payload memory stays bounded
/// even when several large tenants queue at once. 3 keeps the tick
/// interactive on a mid-size box; a heavier deploy can crank it up
/// once the streaming refactor lands.
const MAX_JOBS_PER_TICK: i64 = 3;

/// Post-code-review finding #7: per-section row cap. Bundles are held
/// in memory as one JSON blob before being persisted to
/// `portal_exports.bundle_json`, so an uncapped fetch on a tenant with
/// millions of notes could OOM the worker. Each cap here bounds the
/// bundle at roughly (5k tickets * ~500 bytes) + (20k notes * ~800
/// bytes) + (10k invoices * ~400 bytes) + (5k quotes * ~400 bytes) =
/// ~22 MB max per bundle; well within the pod's budget and orders of
/// magnitude smaller than the pathological pre-fix case. When a
/// section is truncated we emit a `truncated: true` marker on the
/// bundle so the customer knows to ask for the residual data via
/// support rather than assume the export is complete.
const MAX_TICKETS_PER_BUNDLE: i64 = 5_000;
const MAX_NOTES_PER_BUNDLE: i64 = 20_000;
const MAX_INVOICES_PER_BUNDLE: i64 = 10_000;
const MAX_QUOTES_PER_BUNDLE: i64 = 5_000;

/// 7-day TTL on the finished bundle. Set on the `expires_at` column
/// at the moment the worker stamps `status = 'ready'`. D19 pinned this
/// value; the SPA and the polling route both key their "expired" copy
/// off the same column.
const BUNDLE_TTL_DAYS: i64 = 7;

pub struct PortalExportWorker {
    db: Database,
}

impl PortalExportWorker {
    pub fn new(db: Database) -> Self {
        Self { db }
    }
}

#[async_trait]
impl Job for PortalExportWorker {
    fn name(&self) -> &'static str {
        "portal_export_worker"
    }

    async fn run(&self) -> AppResult<()> {
        tick_once(&self.db).await
    }
}

pub async fn tick_once(db: &Database) -> AppResult<()> {
    // 1) Pick queued jobs. Ordered oldest-first so a stuck queue drains
    //    in request order.
    let queued: Vec<(Uuid, Uuid, Uuid, Uuid)> = sqlx::query_as(
        r#"
        SELECT id, tenant_id, company_id, contact_id
        FROM portal_exports
        WHERE status = 'queued'
        ORDER BY requested_at ASC
        LIMIT $1
        "#,
    )
    .bind(MAX_JOBS_PER_TICK)
    .fetch_all(db.migrator_pool())
    .await?;

    if queued.is_empty() {
        return Ok(());
    }

    info!(count = queued.len(), "portal_export_worker: draining queue");

    for (job_id, tenant_id, company_id, contact_id) in queued {
        // 2) Flip queued -> running. If the compare-and-set matched
        //    zero rows the job is already claimed by a sibling tick;
        //    skip it silently.
        let claimed = sqlx::query(
            r#"
            UPDATE portal_exports
            SET status = 'running'
            WHERE id = $1 AND status = 'queued'
            "#,
        )
        .bind(job_id)
        .execute(db.migrator_pool())
        .await?
        .rows_affected();
        if claimed == 0 {
            continue;
        }

        // 3 + 4 + 5) Build + persist. A failure inside `build_bundle`
        // stamps status='failed' with a short user-safe message.
        match build_bundle(db, tenant_id, company_id, contact_id).await {
            Ok(BundleBuildResult {
                bundle,
                truncated,
                section_totals,
            }) => {
                let ready_at: DateTime<Utc> = Utc::now();
                let expires_at: DateTime<Utc> = ready_at + ChronoDuration::days(BUNDLE_TTL_DAYS);
                // I15 follow-up: persist `truncated` + `section_totals`
                // to their own columns (migration 114) so the SPA
                // status endpoint can surface the truncation warning
                // without downloading and parsing the full bundle.
                sqlx::query(
                    r#"
                    UPDATE portal_exports
                    SET status = 'ready',
                        bundle_json = $2,
                        ready_at = $3,
                        expires_at = $4,
                        bundle_truncated = $5,
                        bundle_section_totals = $6
                    WHERE id = $1
                    "#,
                )
                .bind(job_id)
                .bind(&bundle)
                .bind(ready_at)
                .bind(expires_at)
                .bind(truncated)
                .bind(&section_totals)
                .execute(db.migrator_pool())
                .await?;
            }
            Err(e) => {
                warn!(
                    %job_id, %tenant_id, %contact_id, error = %e,
                    "portal_export_worker: build_bundle failed"
                );
                // Deliberately short user-visible message; the full
                // error stays in the tracing span, not the DTO.
                sqlx::query(
                    r#"
                    UPDATE portal_exports
                    SET status = 'failed',
                        error_message = 'Could not build your data bundle. Please contact support.'
                    WHERE id = $1
                    "#,
                )
                .bind(job_id)
                .execute(db.migrator_pool())
                .await?;
            }
        }
    }

    Ok(())
}

/// Worker output: the finished bundle plus the two fields the SPA
/// surfaces on the export status row (see migration 114).
///
/// - `bundle` is the full JSONB persisted to `portal_exports.bundle_json`.
/// - `truncated` mirrors the `bundle.truncated` marker; hoisted onto its
///   own column so `GET /portal/export/{id}` can render the warning
///   without downloading the whole bundle.
/// - `section_totals` mirrors `bundle.section_totals`; hoisted for the
///   same reason.
pub(crate) struct BundleBuildResult {
    pub bundle: serde_json::Value,
    pub truncated: bool,
    pub section_totals: serde_json::Value,
}

/// Build the customer-visible JSON bundle. The shape is a stable
/// top-level object with named sections so a future addition (assets,
/// contracts, projects) can slot in without breaking downstream
/// consumers.
async fn build_bundle(
    db: &Database,
    tenant_id: Uuid,
    company_id: Uuid,
    contact_id: Uuid,
) -> AppResult<BundleBuildResult> {
    // Contact profile (self).
    let (first_name, last_name, email): (String, String, String) = sqlx::query_as(
        "SELECT first_name, last_name, email FROM contacts WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant_id)
    .bind(contact_id)
    .fetch_one(db.migrator_pool())
    .await?;

    // Post-code-review finding #7: every section carries a hard LIMIT
    // so a customer at a large tenant does not OOM the worker. A
    // separate COUNT tells us whether the section was truncated so the
    // bundle can carry a `truncated: true` marker at the top level.

    // Own-company tickets: id, number, title, status name, requested_at.
    let tickets: Vec<(Uuid, String, String, String, DateTime<Utc>)> = sqlx::query_as(
        r#"
        SELECT t.id, t.ticket_number, t.title, s.name, t.created_at
        FROM tickets t
        JOIN ticket_statuses s ON s.id = t.status_id
        WHERE t.tenant_id = $1 AND t.company_id = $2
        ORDER BY t.created_at DESC
        LIMIT $3
        "#,
    )
    .bind(tenant_id)
    .bind(company_id)
    .bind(MAX_TICKETS_PER_BUNDLE)
    .fetch_all(db.migrator_pool())
    .await?;
    let tickets_total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::BIGINT FROM tickets WHERE tenant_id = $1 AND company_id = $2",
    )
    .bind(tenant_id)
    .bind(company_id)
    .fetch_one(db.migrator_pool())
    .await?;

    // Public notes across every own-company ticket.
    let notes: Vec<(Uuid, Uuid, String, DateTime<Utc>)> = sqlx::query_as(
        r#"
        SELECT n.id, n.ticket_id, n.content, n.created_at
        FROM ticket_notes n
        JOIN tickets t ON t.id = n.ticket_id
        WHERE n.tenant_id = $1
          AND t.company_id = $2
          AND n.note_type = 'public'
        ORDER BY n.created_at DESC
        LIMIT $3
        "#,
    )
    .bind(tenant_id)
    .bind(company_id)
    .bind(MAX_NOTES_PER_BUNDLE)
    .fetch_all(db.migrator_pool())
    .await?;
    let notes_total: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)::BIGINT
        FROM ticket_notes n
        JOIN tickets t ON t.id = n.ticket_id
        WHERE n.tenant_id = $1 AND t.company_id = $2 AND n.note_type = 'public'
        "#,
    )
    .bind(tenant_id)
    .bind(company_id)
    .fetch_one(db.migrator_pool())
    .await?;

    // Invoices (safe subset only).
    let invoices: Vec<(
        Uuid,
        String,
        String,
        chrono::NaiveDate,
        chrono::NaiveDate,
        rust_decimal::Decimal,
        rust_decimal::Decimal,
        Option<String>,
    )> = sqlx::query_as(
        r#"
        SELECT id, invoice_number, status, invoice_date, due_date,
               total, balance_due, currency
        FROM invoices
        WHERE tenant_id = $1 AND company_id = $2
        ORDER BY invoice_date DESC
        LIMIT $3
        "#,
    )
    .bind(tenant_id)
    .bind(company_id)
    .bind(MAX_INVOICES_PER_BUNDLE)
    .fetch_all(db.migrator_pool())
    .await?;
    let invoices_total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::BIGINT FROM invoices WHERE tenant_id = $1 AND company_id = $2",
    )
    .bind(tenant_id)
    .bind(company_id)
    .fetch_one(db.migrator_pool())
    .await?;

    // Quotes (safe subset). Filter to the same statuses `list_quotes_for_company`
    // exposes on the portal so the bundle stays consistent with the live UI.
    let quotes: Vec<(Uuid, String, String, DateTime<Utc>)> = sqlx::query_as(
        r#"
        SELECT id, title, status, updated_at
        FROM quotes
        WHERE tenant_id = $1 AND company_id = $2
          AND status IN ('sent', 'submitted', 'accepted', 'declined', 'expired', 'converted')
        ORDER BY updated_at DESC
        LIMIT $3
        "#,
    )
    .bind(tenant_id)
    .bind(company_id)
    .bind(MAX_QUOTES_PER_BUNDLE)
    .fetch_all(db.migrator_pool())
    .await?;
    let quotes_total: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)::BIGINT FROM quotes
        WHERE tenant_id = $1 AND company_id = $2
          AND status IN ('sent', 'submitted', 'accepted', 'declined', 'expired', 'converted')
        "#,
    )
    .bind(tenant_id)
    .bind(company_id)
    .fetch_one(db.migrator_pool())
    .await?;

    let truncated = tickets_total > tickets.len() as i64
        || notes_total > notes.len() as i64
        || invoices_total > invoices.len() as i64
        || quotes_total > quotes.len() as i64;

    // I15 follow-up: hoisted onto its own return field (BundleBuildResult)
    // so the worker can write it to portal_exports.bundle_section_totals
    // for the SPA status endpoint, without the SPA parsing the whole
    // bundle. Bundled a second time inside `bundle` so a downloaded
    // bundle also carries the counts.
    let section_totals = json!({
        "tickets": tickets_total,
        "ticket_notes": notes_total,
        "invoices": invoices_total,
        "quotes": quotes_total,
    });

    let bundle = json!({
        "generated_at": Utc::now(),
        // Post-code-review finding #7: signals that at least one
        // section was capped. The customer can ask support for the
        // residual data if they need it; the bundle stays a bounded
        // download either way.
        "truncated": truncated,
        "section_totals": section_totals,
        "contact": {
            "id": contact_id,
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
        },
        "tickets": tickets
            .into_iter()
            .map(|(id, number, title, status, created_at)| json!({
                "id": id,
                "ticket_number": number,
                "title": title,
                "status": status,
                "created_at": created_at,
            }))
            .collect::<Vec<_>>(),
        "ticket_notes": notes
            .into_iter()
            .map(|(id, ticket_id, content, created_at)| json!({
                "id": id,
                "ticket_id": ticket_id,
                "content": content,
                "created_at": created_at,
            }))
            .collect::<Vec<_>>(),
        "invoices": invoices
            .into_iter()
            .map(|(id, number, status, invoice_date, due_date, total, balance_due, currency)| json!({
                "id": id,
                "invoice_number": number,
                "status": status,
                "invoice_date": invoice_date,
                "due_date": due_date,
                "total": total,
                "balance_due": balance_due,
                "currency": currency.unwrap_or_else(|| "USD".to_string()),
            }))
            .collect::<Vec<_>>(),
        "quotes": quotes
            .into_iter()
            .map(|(id, title, status, updated_at)| json!({
                "id": id,
                "title": title,
                "status": status,
                "updated_at": updated_at,
            }))
            .collect::<Vec<_>>(),
    });

    Ok(BundleBuildResult {
        bundle,
        truncated,
        section_totals,
    })
}
