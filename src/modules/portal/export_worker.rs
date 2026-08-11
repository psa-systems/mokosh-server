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
/// the pooled connection. 10 is generous for phase 2 (the typical
/// tenant will queue at most a handful of exports a day).
const MAX_JOBS_PER_TICK: i64 = 10;

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
            Ok(bundle) => {
                let ready_at: DateTime<Utc> = Utc::now();
                let expires_at: DateTime<Utc> = ready_at + ChronoDuration::days(BUNDLE_TTL_DAYS);
                sqlx::query(
                    r#"
                    UPDATE portal_exports
                    SET status = 'ready',
                        bundle_json = $2,
                        ready_at = $3,
                        expires_at = $4
                    WHERE id = $1
                    "#,
                )
                .bind(job_id)
                .bind(&bundle)
                .bind(ready_at)
                .bind(expires_at)
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

/// Build the customer-visible JSON bundle. The shape is a stable
/// top-level object with named sections so a future addition (assets,
/// contracts, projects) can slot in without breaking downstream
/// consumers.
async fn build_bundle(
    db: &Database,
    tenant_id: Uuid,
    company_id: Uuid,
    contact_id: Uuid,
) -> AppResult<serde_json::Value> {
    // Contact profile (self).
    let (first_name, last_name, email): (String, String, String) = sqlx::query_as(
        "SELECT first_name, last_name, email FROM contacts WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant_id)
    .bind(contact_id)
    .fetch_one(db.migrator_pool())
    .await?;

    // Own-company tickets: id, number, title, status name, requested_at.
    let tickets: Vec<(Uuid, String, String, String, DateTime<Utc>)> = sqlx::query_as(
        r#"
        SELECT t.id, t.ticket_number, t.title, s.name, t.created_at
        FROM tickets t
        JOIN ticket_statuses s ON s.id = t.status_id
        WHERE t.tenant_id = $1 AND t.company_id = $2
        ORDER BY t.created_at DESC
        "#,
    )
    .bind(tenant_id)
    .bind(company_id)
    .fetch_all(db.migrator_pool())
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
        "#,
    )
    .bind(tenant_id)
    .bind(company_id)
    .fetch_all(db.migrator_pool())
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
        "#,
    )
    .bind(tenant_id)
    .bind(company_id)
    .fetch_all(db.migrator_pool())
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
        "#,
    )
    .bind(tenant_id)
    .bind(company_id)
    .fetch_all(db.migrator_pool())
    .await?;

    let bundle = json!({
        "generated_at": Utc::now(),
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

    Ok(bundle)
}
