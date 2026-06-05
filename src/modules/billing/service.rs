//! Billing service. Endpoints land incrementally across PMS-33.

use chrono::{DateTime, Months, NaiveDate, Utc};
use rust_decimal::Decimal;
use uuid::Uuid;

use crate::db::Database;
use crate::modules::audit::{audit_write, AuditAction, AuditCtx};
use crate::utils::error::{AppError, AppResult};
use crate::utils::pagination::PaginationParams;

use super::models::*;

/// Billing operations: invoices, payments, gateway configs, tax rates.
#[derive(Clone)]
pub struct BillingService {
    db: Database,
    /// 32-byte AES-256-GCM key used to encrypt
    /// `payment_gateway_configs.config_encrypted` at rest. Sourced from
    /// `AppConfig::encryption_key`; falls back to a zero-key for the
    /// default `new()` constructor so non-production callers stay
    /// compilable.
    encryption_key: [u8; 32],
}

impl BillingService {
    pub fn new(db: Database) -> Self {
        Self {
            db,
            encryption_key: [0u8; 32],
        }
    }

    /// Production constructor: takes the same `ENCRYPTION_KEY` env that
    /// auth uses for token encryption. Hands the key down to the
    /// payment-gateway-config write path so secrets never hit the DB
    /// in cleartext.
    pub fn with_encryption_key(db: Database, encryption_key: [u8; 32]) -> Self {
        Self { db, encryption_key }
    }

    /// PMS-35: paginated + filterable invoice list. `lines` is left
    /// `None` on list rollups — the customer-facing UI fetches lines
    /// only when expanding a row.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_invoices(
        &self,
        tenant_id: Uuid,
        filter: &InvoiceFilter,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<InvoiceResponse>, u64)> {
        let offset = pagination.offset() as i64;
        let limit = pagination.limit() as i64;

        // Parallel WHERE clauses so the data and count queries each get
        // correctly numbered placeholders. data has $1 tenant + $2 limit
        // + $3 offset → filter binds at $4+; count has $1 tenant only →
        // filter binds at $2+.
        let mut data_conds = vec!["tenant_id = $1".to_string()];
        let mut count_conds = vec!["tenant_id = $1".to_string()];
        let mut data_idx = 4;
        let mut count_idx = 2;
        if filter.company_id.is_some() {
            data_conds.push(format!("company_id = ${data_idx}"));
            count_conds.push(format!("company_id = ${count_idx}"));
            data_idx += 1;
            count_idx += 1;
        }
        if filter.status.is_some() {
            data_conds.push(format!("status = ${data_idx}"));
            count_conds.push(format!("status = ${count_idx}"));
            data_idx += 1;
            count_idx += 1;
        }
        if filter.contract_id.is_some() {
            data_conds.push(format!("contract_id = ${data_idx}"));
            count_conds.push(format!("contract_id = ${count_idx}"));
            data_idx += 1;
            count_idx += 1;
        }
        if filter.q.is_some() {
            data_conds.push(format!(
                "(invoice_number ILIKE ${data_idx} OR po_number ILIKE ${data_idx})"
            ));
            count_conds.push(format!(
                "(invoice_number ILIKE ${count_idx} OR po_number ILIKE ${count_idx})"
            ));
        }

        let data_where = data_conds.join(" AND ");
        let count_where = count_conds.join(" AND ");
        // default_field must be a bare column (order_by appends the
        // direction); "invoice_date DESC" produced "... DESC DESC" -> 500.
        let order_by = pagination.order_by(
            "invoice_date",
            &["invoice_date", "due_date", "total", "created_at"],
        );
        let query = format!(
            r#"
            SELECT id, tenant_id, invoice_number, company_id, billing_contact_id,
                   contract_id, status, invoice_date, due_date, payment_terms,
                   subtotal, tax_amount, discount_amount, total, amount_paid,
                   balance_due, currency, notes, po_number, sent_at, paid_at,
                   created_at, updated_at
            FROM invoices
            WHERE {data_where}
            ORDER BY {order_by}
            LIMIT $2 OFFSET $3
            "#
        );
        let count_query = format!("SELECT COUNT(*) FROM invoices WHERE {count_where}");

        let mut q = sqlx::query_as::<_, InvoiceRow>(&query)
            .bind(tenant_id)
            .bind(limit)
            .bind(offset);
        let mut cq = sqlx::query_scalar::<_, i64>(&count_query).bind(tenant_id);
        if let Some(cid) = filter.company_id {
            q = q.bind(cid);
            cq = cq.bind(cid);
        }
        if let Some(ref status) = filter.status {
            q = q.bind(status);
            cq = cq.bind(status);
        }
        if let Some(ctid) = filter.contract_id {
            q = q.bind(ctid);
            cq = cq.bind(ctid);
        }
        if let Some(ref s) = filter.q {
            let pattern = format!("%{s}%");
            q = q.bind(pattern.clone());
            cq = cq.bind(pattern);
        }

        let rows = q.fetch_all(self.db.pool()).await?;
        let total = cq.fetch_one(self.db.pool()).await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    /// PMS-37: create an invoice with its line items in one
    /// transaction. Atomically increments `invoice_sequences.last_number`
    /// (per tenant) for the human-readable invoice number; computes
    /// `subtotal = sum(line.total)` and `total = subtotal + tax -
    /// discount`. `balance_due` is initialised to `total`; payments
    /// move it down via PMS-39.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_invoice(
        &self,
        tenant_id: Uuid,
        request: &CreateInvoiceRequest,
        ctx: &AuditCtx,
    ) -> AppResult<InvoiceResponse> {
        let mut tx = self.db.pool().begin().await?;

        // Per-tenant invoice sequence is row-locked by UPDATE
        // RETURNING; concurrent invoice creates serialise on this row
        // so numbers are dense and unique.
        let seq_row: Option<(i32, Option<String>)> = sqlx::query_as(
            r#"
            UPDATE invoice_sequences
            SET last_number = last_number + 1
            WHERE tenant_id = $1
            RETURNING last_number, prefix
            "#,
        )
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await?;
        let (next_number, prefix) = match seq_row {
            Some(v) => v,
            None => {
                // First invoice for this tenant: seed the sequence row.
                sqlx::query(
                    "INSERT INTO invoice_sequences (tenant_id, last_number) VALUES ($1, 1)",
                )
                .bind(tenant_id)
                .execute(&mut *tx)
                .await?;
                (1, Some("INV-".to_string()))
            }
        };
        let invoice_number = format!(
            "{}{:06}",
            prefix.unwrap_or_else(|| "INV-".to_string()),
            next_number
        );

        // Compute totals from the supplied lines. Tax / discount are
        // optional - default to 0.
        let subtotal: Decimal = request
            .lines
            .iter()
            .map(|l| l.quantity * l.unit_price)
            .sum();
        let tax = request.tax_amount.unwrap_or(Decimal::ZERO);
        let discount = request.discount_amount.unwrap_or(Decimal::ZERO);
        let total = subtotal + tax - discount;

        let invoice_id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO invoices (
                id, tenant_id, invoice_number, company_id, billing_contact_id,
                contract_id, status, invoice_date, due_date, payment_terms,
                subtotal, tax_amount, discount_amount, total, amount_paid,
                balance_due, currency, notes, po_number
            )
            VALUES ($1, $2, $3, $4, $5, $6, 'draft', $7, $8, $9, $10, $11,
                    $12, $13, 0, $13, $14, $15, $16)
            "#,
        )
        .bind(invoice_id)
        .bind(tenant_id)
        .bind(&invoice_number)
        .bind(request.company_id)
        .bind(request.billing_contact_id)
        .bind(request.contract_id)
        .bind(request.invoice_date)
        .bind(request.due_date)
        .bind(&request.payment_terms)
        .bind(subtotal)
        .bind(tax)
        .bind(discount)
        .bind(total)
        .bind(request.currency.as_deref().unwrap_or("USD"))
        .bind(&request.notes)
        .bind(&request.po_number)
        .execute(&mut *tx)
        .await?;

        for line in &request.lines {
            sqlx::query(
                r#"
                INSERT INTO invoice_lines (
                    id, invoice_id, line_type, description, quantity, unit_price,
                    total, ticket_id, project_id, sort_order
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                "#,
            )
            .bind(Uuid::new_v4())
            .bind(invoice_id)
            .bind(line.line_type.as_str())
            .bind(&line.description)
            .bind(line.quantity)
            .bind(line.unit_price)
            .bind(line.quantity * line.unit_price)
            .bind(line.ticket_id)
            .bind(line.project_id)
            .bind(line.sort_order)
            .execute(&mut *tx)
            .await?;
        }

        // Audit row in the same transaction. CREATE: old = None, after
        // captured by the new invoice id. PMS-117.
        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM invoices t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(invoice_id)
        .fetch_optional(&mut *tx)
        .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Create,
            "invoices",
            Some(invoice_id),
            None,
            after,
        )
        .await?;

        tx.commit().await?;
        self.get_invoice(tenant_id, invoice_id).await
    }

    /// PMS-33 (core): generate an invoice from a company's billable
    /// time entries in one transaction.
    ///
    /// Eligible entries are `is_billable = TRUE`, `invoice_id IS NULL`,
    /// and `billing_status = 'ready_to_bill'` (PMS-144: approval is the
    /// billing gate - timesheet approval flips billable entries from
    /// `not_billed` to `ready_to_bill`, so pending/rejected time is never
    /// invoiceable), tenant-scoped and company-scoped. When `time_entry_ids` is
    /// `Some`, the set is further restricted to those ids; `None` sweeps
    /// every eligible entry. The selected rows are `SELECT ... FOR
    /// UPDATE` so a concurrent generate cannot double-bill them.
    ///
    /// Each entry becomes one `invoice_line` with `line_type =
    /// 'time_entry'`, `time_entry_ids = ARRAY[entry.id]`, `quantity =
    /// duration_minutes / 60`, `unit_price = hourly_rate`, and `total =
    /// total_amount` (falling back to `quantity * unit_price` when the
    /// entry has no precomputed amount). Invoice number allocation
    /// reuses the same gapless `invoice_sequences` row-lock as
    /// [`create_invoice`]. After the lines are written, the source
    /// entries are flipped to `billing_status = 'billed'` with their
    /// `invoice_id` set, inside the SAME transaction.
    ///
    /// Tax is left at 0: the existing `create_invoice` does not apply a
    /// tax rate automatically (callers pass `tax_amount` explicitly), so
    /// this path mirrors that and leaves tax to a follow-up edit via
    /// `update_invoice`. Recurring contract-item billing is out of scope
    /// (depends on the unmerged PMS-64) and is a follow-up.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_invoice_from_time_entries(
        &self,
        tenant_id: Uuid,
        request: &CreateInvoiceFromTimeEntriesRequest,
        ctx: &AuditCtx,
    ) -> AppResult<InvoiceResponse> {
        let mut tx = self.db.pool().begin().await?;

        // 1. Lock the company's eligible billable entries. The `$3::uuid[]
        //    IS NULL OR id = ANY($3)` guard makes the id filter optional:
        //    a NULL array bills everything eligible. `FOR UPDATE`
        //    serialises against a concurrent generate.
        let entries: Vec<TimeEntryBillingRow> = sqlx::query_as(
            r#"
            SELECT id, duration_minutes, hourly_rate, total_amount, ticket_id
            FROM time_entries
            WHERE tenant_id = $1
              AND company_id = $2
              AND is_billable = TRUE
              AND invoice_id IS NULL
              AND billing_status = 'ready_to_bill'
              AND ($3::uuid[] IS NULL OR id = ANY($3))
            ORDER BY date, created_at
            FOR UPDATE
            "#,
        )
        .bind(tenant_id)
        .bind(request.company_id)
        .bind(request.time_entry_ids.as_deref())
        .fetch_all(&mut *tx)
        .await?;

        if entries.is_empty() {
            return Err(AppError::BadRequest(
                "no billable time entries found for this company".to_string(),
            ));
        }

        // 2. Allocate a gapless invoice number (same row-lock as
        //    `create_invoice`). Concurrent creates serialise on this row.
        let seq_row: Option<(i32, Option<String>)> = sqlx::query_as(
            r#"
            UPDATE invoice_sequences
            SET last_number = last_number + 1
            WHERE tenant_id = $1
            RETURNING last_number, prefix
            "#,
        )
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await?;
        let (next_number, prefix) = match seq_row {
            Some(v) => v,
            None => {
                sqlx::query(
                    "INSERT INTO invoice_sequences (tenant_id, last_number) VALUES ($1, 1)",
                )
                .bind(tenant_id)
                .execute(&mut *tx)
                .await?;
                (1, Some("INV-".to_string()))
            }
        };
        let invoice_number = format!(
            "{}{:06}",
            prefix.unwrap_or_else(|| "INV-".to_string()),
            next_number
        );

        // 3. Build one line per entry, accumulating the subtotal. The
        //    sixty-minute divisor is a Decimal so quantity keeps its
        //    fractional hours (e.g. 90 min -> 1.5).
        let sixty = Decimal::from(60);
        let mut lines: Vec<(Uuid, String, Decimal, Decimal, Decimal, Option<Uuid>)> =
            Vec::with_capacity(entries.len());
        let mut subtotal = Decimal::ZERO;
        for entry in &entries {
            let quantity = Decimal::from(entry.duration_minutes) / sixty;
            let unit_price = entry.hourly_rate.unwrap_or(Decimal::ZERO);
            let total = entry.total_amount.unwrap_or(quantity * unit_price);
            subtotal += total;
            let description = format!("Time entry {}", entry.id);
            lines.push((
                entry.id,
                description,
                quantity,
                unit_price,
                total,
                entry.ticket_id,
            ));
        }

        // Tax / discount left at 0 (see method doc); total == subtotal.
        let tax = Decimal::ZERO;
        let discount = Decimal::ZERO;
        let total = subtotal + tax - discount;

        // Default the invoice/due dates when the caller omits them:
        // invoice today, due in 30 days (matches the `net30` term).
        let invoice_date = request
            .invoice_date
            .unwrap_or_else(|| Utc::now().date_naive());
        let due_date = request
            .due_date
            .unwrap_or_else(|| invoice_date + chrono::Duration::days(30));

        // 4. Insert the invoice header. `balance_due` starts at `total`.
        let invoice_id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO invoices (
                id, tenant_id, invoice_number, company_id, billing_contact_id,
                contract_id, status, invoice_date, due_date, payment_terms,
                subtotal, tax_amount, discount_amount, total, amount_paid,
                balance_due, currency, notes, po_number
            )
            VALUES ($1, $2, $3, $4, $5, $6, 'draft', $7, $8, $9, $10, $11,
                    $12, $13, 0, $13, $14, $15, $16)
            "#,
        )
        .bind(invoice_id)
        .bind(tenant_id)
        .bind(&invoice_number)
        .bind(request.company_id)
        .bind(request.billing_contact_id)
        .bind(request.contract_id)
        .bind(invoice_date)
        .bind(due_date)
        .bind(&request.payment_terms)
        .bind(subtotal)
        .bind(tax)
        .bind(discount)
        .bind(total)
        .bind(request.currency.as_deref().unwrap_or("USD"))
        .bind(&request.notes)
        .bind(&request.po_number)
        .execute(&mut *tx)
        .await?;

        // 5. One line per time entry, carrying `time_entry_ids` so the
        //    line traces back to its source. `sort_order` follows the
        //    select order.
        for (idx, (entry_id, description, quantity, unit_price, line_total, ticket_id)) in
            lines.iter().enumerate()
        {
            sqlx::query(
                r#"
                INSERT INTO invoice_lines (
                    id, invoice_id, line_type, description, quantity, unit_price,
                    total, time_entry_ids, ticket_id, sort_order
                )
                VALUES ($1, $2, 'time_entry', $3, $4, $5, $6, ARRAY[$7]::uuid[], $8, $9)
                "#,
            )
            .bind(Uuid::new_v4())
            .bind(invoice_id)
            .bind(description)
            .bind(quantity)
            .bind(unit_price)
            .bind(line_total)
            .bind(entry_id)
            .bind(ticket_id)
            .bind(idx as i32)
            .execute(&mut *tx)
            .await?;
        }

        // 6. Mark the source entries billed and link them to the invoice,
        //    within the same transaction. Scoped to the locked id set so
        //    a concurrently-inserted eligible entry is not swept in.
        let billed_ids: Vec<Uuid> = entries.iter().map(|e| e.id).collect();
        sqlx::query(
            r#"
            UPDATE time_entries
            SET billing_status = 'billed',
                invoice_id     = $2,
                updated_at     = NOW()
            WHERE tenant_id = $1 AND id = ANY($3)
            "#,
        )
        .bind(tenant_id)
        .bind(invoice_id)
        .bind(&billed_ids)
        .execute(&mut *tx)
        .await?;

        // Audit row in the same transaction. CREATE: old = None, after
        // captured by the new invoice id. PMS-117.
        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM invoices t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(invoice_id)
        .fetch_optional(&mut *tx)
        .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Create,
            "invoices",
            Some(invoice_id),
            None,
            after,
        )
        .await?;

        tx.commit().await?;
        self.get_invoice(tenant_id, invoice_id).await
    }

    /// PMS-64 AC5: generate recurring billing invoices from contracts'
    /// recurring line items, idempotently per billing period.
    ///
    /// For each `active`, non-`one_time` contract in the tenant that is
    /// due for its current billing period as of `now` and carries at
    /// least one recurring item (`recurring_service` / `retainer`), this
    /// creates one draft invoice whose lines mirror those items (name,
    /// quantity, unit_price). Idempotency is enforced by the
    /// `contract_invoice_runs` ledger: a row keyed UNIQUE on
    /// `(tenant_id, contract_id, period_start)` is inserted in the SAME
    /// transaction as the invoice via `INSERT ... ON CONFLICT DO
    /// NOTHING`. If the period was already billed (a prior run, or a
    /// concurrent run that committed first), the conflict short-circuits
    /// and the would-be-duplicate invoice is rolled back, so a monthly
    /// contract yields exactly one invoice per month even across
    /// double-runs and process restarts.
    ///
    /// The due period is computed from `billing_cycle` + the contract's
    /// `start_date` (see [`current_billing_period`]): the most recent
    /// period boundary on or before `now`. Skipped: `one_time`,
    /// non-`active` (draft/expired/cancelled/renewed) contracts,
    /// contracts whose `start_date` is in the future, contracts past
    /// their `end_date` for the computed period, and contracts with no
    /// recurring items.
    ///
    /// Reuses the same gapless `invoice_sequences` row-lock and
    /// invoice + invoice_lines write path as [`create_invoice`], plus
    /// the in-transaction audit row. Tax / discount are left at 0,
    /// matching the other invoice-creation paths.
    ///
    /// `now` is injected so tests (and the scheduler) drive periods
    /// deterministically. Returns the ids of invoices actually created
    /// this run (periods already billed contribute nothing). Tenant-scoped.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn generate_due_recurring_invoices(
        &self,
        tenant_id: Uuid,
        now: DateTime<Utc>,
        ctx: &AuditCtx,
    ) -> AppResult<Vec<Uuid>> {
        let today = now.date_naive();

        // Candidate contracts: active, recurring (not one_time), already
        // started. `end_date` is checked per-period below (a contract may
        // still be due for a period that began before it expired).
        let contracts = sqlx::query_as::<_, RecurringContractRow>(
            r#"
            SELECT id, company_id, billing_cycle, start_date, end_date
            FROM contracts
            WHERE tenant_id = $1
              AND status = 'active'
              AND billing_cycle IS DISTINCT FROM 'one_time'
              AND start_date <= $2
            ORDER BY id
            "#,
        )
        .bind(tenant_id)
        .bind(today)
        .fetch_all(self.db.pool())
        .await?;

        let mut created = Vec::new();
        for contract in contracts {
            let cycle = contract
                .billing_cycle
                .as_deref()
                .unwrap_or("monthly");
            let Some((period_start, period_end)) =
                current_billing_period(cycle, contract.start_date, today)
            else {
                // Unknown cycle or no period started yet: skip.
                continue;
            };

            // Skip periods that begin after the contract's end_date: an
            // expired contract should not be billed for a period that
            // starts beyond its term. (A period that STARTED before the
            // end_date is still billed even if it ends after, matching the
            // "due for its current period" semantics.)
            if let Some(end) = contract.end_date {
                if period_start > end {
                    continue;
                }
            }

            if let Some(invoice_id) = self
                .generate_one_recurring_invoice(
                    tenant_id,
                    contract.id,
                    contract.company_id,
                    period_start,
                    period_end,
                    today,
                    ctx,
                )
                .await?
            {
                created.push(invoice_id);
            }
        }

        if !created.is_empty() {
            tracing::info!(
                count = created.len(),
                "recurring invoicing run generated invoices"
            );
        }
        Ok(created)
    }

    /// Cross-tenant driver for the recurring-invoicing scheduler job.
    /// Enumerates every tenant and runs
    /// [`generate_due_recurring_invoices`](Self::generate_due_recurring_invoices)
    /// for each, accumulating the total count of invoices created this
    /// tick. A failure for one tenant is logged and skipped so a single
    /// bad tenant cannot stall the whole run. `now` is injected (the
    /// scheduler passes `Utc::now`).
    #[tracing::instrument(skip_all)]
    pub async fn generate_due_recurring_invoices_all_tenants(
        &self,
        now: DateTime<Utc>,
    ) -> AppResult<u64> {
        let tenant_ids: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM tenants")
            .fetch_all(self.db.pool())
            .await?;

        let mut total = 0u64;
        for tenant_id in tenant_ids {
            let ctx = AuditCtx::system(tenant_id);
            match self
                .generate_due_recurring_invoices(tenant_id, now, &ctx)
                .await
            {
                Ok(ids) => total += ids.len() as u64,
                Err(e) => {
                    tracing::warn!(
                        %tenant_id,
                        error = ?e,
                        "recurring invoicing failed for tenant; skipping"
                    );
                }
            }
        }
        Ok(total)
    }

    /// Create one recurring invoice for a single contract + period, in a
    /// single transaction. Returns `Some(invoice_id)` when an invoice was
    /// created, `None` when the period was already billed (ledger
    /// conflict) or the contract has no recurring items.
    ///
    /// Split out of [`generate_due_recurring_invoices`] so each contract
    /// gets its own transaction: one contract's conflict / empty-items
    /// skip never rolls back another contract's invoice.
    #[allow(clippy::too_many_arguments)]
    async fn generate_one_recurring_invoice(
        &self,
        tenant_id: Uuid,
        contract_id: Uuid,
        company_id: Uuid,
        period_start: NaiveDate,
        period_end: NaiveDate,
        today: NaiveDate,
        ctx: &AuditCtx,
    ) -> AppResult<Option<Uuid>> {
        let mut tx = self.db.pool().begin().await?;

        // Pull this contract's recurring billing items. Mirrors
        // `ContractsService::list_recurring_items` (recurring_service +
        // retainer), but runs inside this transaction.
        let items = sqlx::query_as::<_, RecurringItemRow>(
            r#"
            SELECT name, quantity, unit_price
            FROM contract_items
            WHERE tenant_id = $1 AND contract_id = $2
              AND item_type IN ('recurring_service', 'retainer')
            ORDER BY sort_order, name
            "#,
        )
        .bind(tenant_id)
        .bind(contract_id)
        .fetch_all(&mut *tx)
        .await?;

        if items.is_empty() {
            // Nothing recurring to bill; do not record a ledger row so a
            // later-added item still gets picked up next run.
            return Ok(None);
        }

        // Generate the invoice id up front so the ledger row can carry it
        // as its (NOT NULL) `invoice_id` FK. The invoice header is
        // inserted BEFORE the ledger row so the FK references an existing
        // row at insert time (the FK is checked immediately, not
        // deferred). The ledger insert's ON CONFLICT then dedupes the
        // period; on conflict the whole transaction rolls back, discarding
        // the just-inserted invoice header and the sequence bump, so a
        // period is invoiced at most once.
        let invoice_id = Uuid::new_v4();

        // --- 1. Insert the invoice header (draft, totals computed). ---
        let subtotal: Decimal = items
            .iter()
            .map(|i| i.quantity * i.unit_price)
            .sum();
        let tax = Decimal::ZERO;
        let discount = Decimal::ZERO;
        let total = subtotal + tax - discount;

        // Invoice today, due in 30 days (matches the `net30` default term
        // and the time-entry invoice path).
        let invoice_date = today;
        let due_date = invoice_date + chrono::Duration::days(30);

        // Gapless invoice number: same per-tenant row-lock as
        // `create_invoice`. NOTE: this increments the sequence even if the
        // ledger insert below conflicts and we roll back; the rollback
        // restores the sequence value too (the UPDATE is part of this tx),
        // so numbers stay gapless.
        let seq_row: Option<(i32, Option<String>)> = sqlx::query_as(
            r#"
            UPDATE invoice_sequences
            SET last_number = last_number + 1
            WHERE tenant_id = $1
            RETURNING last_number, prefix
            "#,
        )
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await?;
        let (next_number, prefix) = match seq_row {
            Some(v) => v,
            None => {
                sqlx::query(
                    "INSERT INTO invoice_sequences (tenant_id, last_number) VALUES ($1, 1)",
                )
                .bind(tenant_id)
                .execute(&mut *tx)
                .await?;
                (1, Some("INV-".to_string()))
            }
        };
        let invoice_number = format!(
            "{}{:06}",
            prefix.unwrap_or_else(|| "INV-".to_string()),
            next_number
        );

        sqlx::query(
            r#"
            INSERT INTO invoices (
                id, tenant_id, invoice_number, company_id, billing_contact_id,
                contract_id, status, invoice_date, due_date, payment_terms,
                subtotal, tax_amount, discount_amount, total, amount_paid,
                balance_due, currency, notes, po_number
            )
            VALUES ($1, $2, $3, $4, NULL, $5, 'draft', $6, $7, 'net30', $8, $9,
                    $10, $11, 0, $11, 'USD', $12, NULL)
            "#,
        )
        .bind(invoice_id)
        .bind(tenant_id)
        .bind(&invoice_number)
        .bind(company_id)
        .bind(contract_id)
        .bind(invoice_date)
        .bind(due_date)
        .bind(subtotal)
        .bind(tax)
        .bind(discount)
        .bind(total)
        .bind(format!(
            "Recurring billing for {period_start} to {period_end}"
        ))
        .execute(&mut *tx)
        .await?;

        // --- 2. Reserve the period in the ledger. If the period was
        // already billed, ON CONFLICT DO NOTHING returns no row: roll
        // back the whole transaction (invoice header + sequence bump
        // included) so the period is invoiced at most once. ---
        let run_id: Option<Uuid> = sqlx::query_scalar(
            r#"
            INSERT INTO contract_invoice_runs
                (tenant_id, contract_id, invoice_id, period_start, period_end)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (tenant_id, contract_id, period_start) DO NOTHING
            RETURNING id
            "#,
        )
        .bind(tenant_id)
        .bind(contract_id)
        .bind(invoice_id)
        .bind(period_start)
        .bind(period_end)
        .fetch_optional(&mut *tx)
        .await?;

        if run_id.is_none() {
            // Period already billed: discard the in-progress invoice +
            // sequence bump by NOT committing. Dropping `tx` rolls back.
            return Ok(None);
        }

        // --- 3. One invoice line per recurring item (line_type 'service'). ---
        for (idx, item) in items.iter().enumerate() {
            sqlx::query(
                r#"
                INSERT INTO invoice_lines (
                    id, invoice_id, line_type, description, quantity, unit_price,
                    total, sort_order
                )
                VALUES ($1, $2, 'service', $3, $4, $5, $6, $7)
                "#,
            )
            .bind(Uuid::new_v4())
            .bind(invoice_id)
            .bind(&item.name)
            .bind(item.quantity)
            .bind(item.unit_price)
            .bind(item.quantity * item.unit_price)
            .bind(idx as i32)
            .execute(&mut *tx)
            .await?;
        }

        // --- 4. Audit row in the same transaction. CREATE: old = None. ---
        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM invoices t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(invoice_id)
        .fetch_optional(&mut *tx)
        .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Create,
            "invoices",
            Some(invoice_id),
            None,
            after,
        )
        .await?;

        tx.commit().await?;
        Ok(Some(invoice_id))
    }

    /// PMS-41: list all tax rates for the tenant. Includes inactive
    /// ones so admins can see history; filter client-side as needed.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_tax_rates(
        &self,
        tenant_id: Uuid,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<TaxRateResponse>, u64)> {
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tax_rates WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_one(self.db.pool())
            .await?;

        let rows = sqlx::query_as::<_, TaxRateRow>(
            r#"
            SELECT id, name, rate, is_default, is_active
            FROM tax_rates
            WHERE tenant_id = $1
            ORDER BY is_default DESC, name
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(tenant_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(self.db.pool())
        .await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    /// PMS-41: create a tax rate. If `is_default = true`, demote any
    /// existing default first so only one rate is the tenant default.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_tax_rate(
        &self,
        tenant_id: Uuid,
        request: &UpsertTaxRateRequest,
        ctx: &AuditCtx,
    ) -> AppResult<TaxRateResponse> {
        let mut tx = self.db.pool().begin().await?;
        if request.is_default {
            sqlx::query("UPDATE tax_rates SET is_default = FALSE WHERE tenant_id = $1")
                .bind(tenant_id)
                .execute(&mut *tx)
                .await?;
        }
        let id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO tax_rates (tenant_id, name, rate, is_default, is_active)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id
            "#,
        )
        .bind(tenant_id)
        .bind(&request.name)
        .bind(request.rate)
        .bind(request.is_default)
        .bind(request.is_active)
        .fetch_one(&mut *tx)
        .await?;

        // Audit row in the same transaction. CREATE: old = None, after
        // captured by the new tax-rate id. PMS-117.
        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM tax_rates t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Create,
            "tax_rates",
            Some(id),
            None,
            after,
        )
        .await?;
        tx.commit().await?;
        Ok(TaxRateResponse {
            id,
            name: request.name.clone(),
            rate: request.rate,
            is_default: request.is_default,
            is_active: request.is_active,
        })
    }

    /// PMS-41: update a tax rate. Same default-demote behaviour as create.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_tax_rate(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        request: &UpsertTaxRateRequest,
        ctx: &AuditCtx,
    ) -> AppResult<TaxRateResponse> {
        let mut tx = self.db.pool().begin().await?;
        // Snapshot before any mutation (including the default-demote). PMS-117.
        let before: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM tax_rates t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        if request.is_default {
            sqlx::query(
                "UPDATE tax_rates SET is_default = FALSE WHERE tenant_id = $1 AND id <> $2",
            )
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await?;
        }
        let affected = sqlx::query(
            r#"
            UPDATE tax_rates SET
                name       = $3,
                rate       = $4,
                is_default = $5,
                is_active  = $6,
                updated_at = NOW()
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(&request.name)
        .bind(request.rate)
        .bind(request.is_default)
        .bind(request.is_active)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if affected == 0 {
            return Err(AppError::NotFound("TaxRate".to_string()));
        }

        // Audit row in the same transaction. PMS-117.
        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM tax_rates t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Update,
            "tax_rates",
            Some(id),
            before,
            after,
        )
        .await?;
        tx.commit().await?;
        Ok(TaxRateResponse {
            id,
            name: request.name.clone(),
            rate: request.rate,
            is_default: request.is_default,
            is_active: request.is_active,
        })
    }

    /// PMS-41: delete a tax rate.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_tax_rate(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        ctx: &AuditCtx,
    ) -> AppResult<()> {
        // Mutation + audit row in one transaction. DELETE: snapshot
        // before, old = before, after = None. PMS-117.
        let mut tx = self.db.pool().begin().await?;
        let before: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM tax_rates t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        let affected = sqlx::query("DELETE FROM tax_rates WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if affected == 0 {
            return Err(AppError::NotFound("TaxRate".to_string()));
        }
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Delete,
            "tax_rates",
            Some(id),
            before,
            None,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// PMS-41: jurisdiction lookup. The schema has no dedicated
    /// jurisdiction column, so we treat `tax_rates.name` as the
    /// jurisdiction key (e.g. "US-CA", "EU-DE"). Returns the active
    /// rate for the supplied name, or the tenant's default if no name
    /// matches.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn lookup_tax_rate(
        &self,
        tenant_id: Uuid,
        jurisdiction: &str,
    ) -> AppResult<TaxRateResponse> {
        let row = sqlx::query_as::<_, TaxRateRow>(
            r#"
            SELECT id, name, rate, is_default, is_active
            FROM tax_rates
            WHERE tenant_id = $1 AND name = $2 AND is_active = TRUE
            LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .bind(jurisdiction)
        .fetch_optional(self.db.pool())
        .await?;
        if let Some(r) = row {
            return Ok(r.into());
        }
        let fallback = sqlx::query_as::<_, TaxRateRow>(
            r#"
            SELECT id, name, rate, is_default, is_active
            FROM tax_rates
            WHERE tenant_id = $1 AND is_default = TRUE AND is_active = TRUE
            LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .fetch_optional(self.db.pool())
        .await?
        .ok_or_else(|| AppError::NotFound("TaxRate".to_string()))?;
        Ok(fallback.into())
    }

    /// PMS-40: list payment gateway configs for the tenant. Each
    /// response carries the *decrypted* config so a finance admin can
    /// confirm what's wired without an extra round-trip to a "reveal"
    /// endpoint.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_payment_gateways(
        &self,
        tenant_id: Uuid,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<PaymentGatewayConfigResponse>, u64)> {
        let total: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM payment_gateway_configs WHERE tenant_id = $1")
                .bind(tenant_id)
                .fetch_one(self.db.pool())
                .await?;

        let rows = sqlx::query_as::<_, PaymentGatewayRow>(
            r#"
            SELECT id, provider, is_active, is_test_mode, config_encrypted
            FROM payment_gateway_configs
            WHERE tenant_id = $1
            ORDER BY provider
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(tenant_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(self.db.pool())
        .await?;

        let decrypted: Vec<PaymentGatewayConfigResponse> = rows
            .into_iter()
            .map(|r| {
                let decrypted =
                    crate::utils::crypto::decrypt(&r.config_encrypted, &self.encryption_key)?;
                let config: serde_json::Value =
                    serde_json::from_str(&decrypted).unwrap_or(serde_json::Value::Null);
                Ok(PaymentGatewayConfigResponse {
                    id: r.id,
                    provider: GatewayProvider::from_str(&r.provider)
                        .unwrap_or(GatewayProvider::Stripe),
                    is_active: r.is_active,
                    is_test_mode: r.is_test_mode,
                    config,
                })
            })
            .collect::<AppResult<Vec<_>>>()?;

        Ok((decrypted, total as u64))
    }

    /// PMS-40: upsert a payment gateway config. `(tenant_id, provider)`
    /// is unique in the schema, so the same call ends up insert-or-update.
    /// Encrypts the `config` blob at rest with the host encryption key.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn upsert_payment_gateway(
        &self,
        tenant_id: Uuid,
        request: &UpsertPaymentGatewayConfigRequest,
        ctx: &AuditCtx,
    ) -> AppResult<PaymentGatewayConfigResponse> {
        let plaintext = serde_json::to_string(&request.config)
            .map_err(|e| AppError::BadRequest(format!("config must serialise to JSON: {e}")))?;
        let encrypted = crate::utils::crypto::encrypt(&plaintext, &self.encryption_key)?;

        // Mutation + audit row in one transaction. PMS-117. The secret
        // `config_encrypted` column is subtracted from both snapshots so
        // the audit trail never stores the encrypted blob. The action is
        // Update when a row for `(tenant_id, provider)` already existed
        // (this is an INSERT .. ON CONFLICT upsert), else Create; the
        // `before` snapshot doubles as the existence check.
        let mut tx = self.db.pool().begin().await?;
        let before: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) - 'config_encrypted' FROM payment_gateway_configs t \
             WHERE tenant_id = $1 AND provider = $2",
        )
        .bind(tenant_id)
        .bind(request.provider.as_str())
        .fetch_optional(&mut *tx)
        .await?;
        let action = if before.is_some() {
            AuditAction::Update
        } else {
            AuditAction::Create
        };

        let id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO payment_gateway_configs
                (tenant_id, provider, is_active, is_test_mode, config_encrypted)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (tenant_id, provider) DO UPDATE SET
                is_active        = EXCLUDED.is_active,
                is_test_mode     = EXCLUDED.is_test_mode,
                config_encrypted = EXCLUDED.config_encrypted,
                updated_at       = NOW()
            RETURNING id
            "#,
        )
        .bind(tenant_id)
        .bind(request.provider.as_str())
        .bind(request.is_active)
        .bind(request.is_test_mode)
        .bind(&encrypted)
        .fetch_one(&mut *tx)
        .await?;

        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) - 'config_encrypted' FROM payment_gateway_configs t \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            action,
            "payment_gateway_configs",
            Some(id),
            before,
            after,
        )
        .await?;
        tx.commit().await?;

        Ok(PaymentGatewayConfigResponse {
            id,
            provider: request.provider,
            is_active: request.is_active,
            is_test_mode: request.is_test_mode,
            config: request.config.clone(),
        })
    }

    /// PMS-40: delete a payment gateway config. No-op if absent.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_payment_gateway(
        &self,
        tenant_id: Uuid,
        provider: GatewayProvider,
        ctx: &AuditCtx,
    ) -> AppResult<()> {
        // Mutation + audit row in one transaction. DELETE: snapshot
        // before (minus the secret `config_encrypted` blob), old =
        // before, after = None. PMS-117. The delete keys on `provider`
        // (the unique `(tenant_id, provider)` pair), so read the row id
        // for the audit `entity_id`. No-op when absent (no row -> no
        // audit entry), preserving the original idempotent behaviour.
        let mut tx = self.db.pool().begin().await?;
        let row: Option<(Uuid, serde_json::Value)> = sqlx::query_as(
            "SELECT id, to_jsonb(t) - 'config_encrypted' FROM payment_gateway_configs t \
             WHERE tenant_id = $1 AND provider = $2",
        )
        .bind(tenant_id)
        .bind(provider.as_str())
        .fetch_optional(&mut *tx)
        .await?;

        sqlx::query("DELETE FROM payment_gateway_configs WHERE tenant_id = $1 AND provider = $2")
            .bind(tenant_id)
            .bind(provider.as_str())
            .execute(&mut *tx)
            .await?;

        if let Some((id, before)) = row {
            audit_write(
                &mut *tx,
                tenant_id,
                ctx,
                AuditAction::Delete,
                "payment_gateway_configs",
                Some(id),
                Some(before),
                None,
            )
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// PMS-39: list payments. Optional filter on invoice_id and/or
    /// company_id.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_payments(
        &self,
        tenant_id: Uuid,
        filter: &PaymentFilter,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<PaymentResponse>, u64)> {
        let offset = pagination.offset() as i64;
        let limit = pagination.limit() as i64;
        // Parallel WHERE clauses so the data and count queries each get
        // correctly numbered placeholders. data has $1 tenant + $2 limit
        // + $3 offset → filter binds at $4+; count has $1 tenant only →
        // filter binds at $2+.
        let mut data_conds = vec!["tenant_id = $1".to_string()];
        let mut count_conds = vec!["tenant_id = $1".to_string()];
        let mut data_idx = 4;
        let mut count_idx = 2;
        if filter.invoice_id.is_some() {
            data_conds.push(format!("invoice_id = ${data_idx}"));
            count_conds.push(format!("invoice_id = ${count_idx}"));
            data_idx += 1;
            count_idx += 1;
        }
        if filter.company_id.is_some() {
            data_conds.push(format!("company_id = ${data_idx}"));
            count_conds.push(format!("company_id = ${count_idx}"));
        }
        let data_where = data_conds.join(" AND ");
        let count_where = count_conds.join(" AND ");
        // Bare column only (order_by appends the direction).
        let order_by =
            pagination.order_by("payment_date", &["payment_date", "amount", "created_at"]);
        let query = format!(
            r#"
            SELECT id, tenant_id, invoice_id, company_id, payment_date, amount,
                   payment_method, reference_number, gateway_transaction_id,
                   notes, created_at
            FROM payments
            WHERE {data_where}
            ORDER BY {order_by}
            LIMIT $2 OFFSET $3
            "#
        );
        let count_query = format!("SELECT COUNT(*) FROM payments WHERE {count_where}");
        let mut q = sqlx::query_as::<_, PaymentRow>(&query)
            .bind(tenant_id)
            .bind(limit)
            .bind(offset);
        let mut cq = sqlx::query_scalar::<_, i64>(&count_query).bind(tenant_id);
        if let Some(iid) = filter.invoice_id {
            q = q.bind(iid);
            cq = cq.bind(iid);
        }
        if let Some(cid) = filter.company_id {
            q = q.bind(cid);
            cq = cq.bind(cid);
        }
        let rows = q.fetch_all(self.db.pool()).await?;
        let total = cq.fetch_one(self.db.pool()).await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    /// PMS-39: record a payment. When `invoice_id` is set, the linked
    /// invoice's `amount_paid` is bumped and `balance_due` recomputed
    /// in the same transaction; the status moves to `paid` (or
    /// `partially_paid`) accordingly.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_payment(
        &self,
        tenant_id: Uuid,
        request: &CreatePaymentRequest,
        ctx: &AuditCtx,
    ) -> AppResult<PaymentResponse> {
        let mut tx = self.db.pool().begin().await?;

        let payment_id = Uuid::new_v4();
        let created_at: chrono::DateTime<Utc> = sqlx::query_scalar(
            r#"
            INSERT INTO payments (
                id, tenant_id, invoice_id, company_id, payment_date, amount,
                payment_method, reference_number, gateway_transaction_id, notes
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING created_at
            "#,
        )
        .bind(payment_id)
        .bind(tenant_id)
        .bind(request.invoice_id)
        .bind(request.company_id)
        .bind(request.payment_date)
        .bind(request.amount)
        .bind(request.payment_method.as_str())
        .bind(&request.reference_number)
        .bind(&request.gateway_transaction_id)
        .bind(&request.notes)
        .fetch_one(&mut *tx)
        .await?;

        if let Some(invoice_id) = request.invoice_id {
            // Pull the current totals + tenant guard.
            let current: Option<(Decimal, Decimal)> = sqlx::query_as(
                "SELECT total, amount_paid FROM invoices WHERE id = $1 AND tenant_id = $2",
            )
            .bind(invoice_id)
            .bind(tenant_id)
            .fetch_optional(&mut *tx)
            .await?;
            let Some((total, prior_paid)) = current else {
                return Err(AppError::NotFound("Invoice".to_string()));
            };
            let new_paid = prior_paid + request.amount;
            let new_balance = total - new_paid;
            let new_status = if new_balance <= Decimal::ZERO {
                "paid"
            } else if new_paid > Decimal::ZERO {
                "partially_paid"
            } else {
                "sent"
            };
            let paid_at = if new_status == "paid" {
                Some(Utc::now())
            } else {
                None
            };
            sqlx::query(
                r#"
                UPDATE invoices SET
                    amount_paid = $2,
                    balance_due = $3,
                    status      = $4,
                    paid_at     = COALESCE($5, paid_at),
                    updated_at  = NOW()
                WHERE id = $1
                "#,
            )
            .bind(invoice_id)
            .bind(new_paid)
            .bind(new_balance)
            .bind(new_status)
            .bind(paid_at)
            .execute(&mut *tx)
            .await?;
        }

        // Audit row in the same transaction. CREATE: old = None, after
        // captured by the new payment id, minus the secret
        // `gateway_response` blob. PMS-117.
        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) - 'gateway_response' FROM payments t \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(payment_id)
        .fetch_optional(&mut *tx)
        .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Create,
            "payments",
            Some(payment_id),
            None,
            after,
        )
        .await?;

        tx.commit().await?;
        Ok(PaymentResponse {
            id: payment_id,
            tenant_id,
            invoice_id: request.invoice_id,
            company_id: request.company_id,
            payment_date: request.payment_date,
            amount: request.amount,
            payment_method: request.payment_method,
            reference_number: request.reference_number.clone(),
            gateway_transaction_id: request.gateway_transaction_id.clone(),
            notes: request.notes.clone(),
            created_at,
        })
    }

    /// PMS-39: delete a payment. Reverses the linked invoice's
    /// `amount_paid` / `balance_due` / `status`. Hard delete is the
    /// right call for unposted payments; once a payment has been
    /// posted to accounting it should be voided through a credit
    /// note instead - which is out of scope for this commit.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_payment(
        &self,
        tenant_id: Uuid,
        payment_id: Uuid,
        ctx: &AuditCtx,
    ) -> AppResult<()> {
        let mut tx = self.db.pool().begin().await?;

        let row: Option<(Option<Uuid>, Decimal)> = sqlx::query_as(
            "SELECT invoice_id, amount FROM payments WHERE id = $1 AND tenant_id = $2",
        )
        .bind(payment_id)
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((invoice_id, amount)) = row else {
            return Err(AppError::NotFound("Payment".to_string()));
        };

        // Snapshot before the delete, minus the secret `gateway_response`
        // blob, for the audit `old_values`. PMS-117.
        let before: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) - 'gateway_response' FROM payments t \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(payment_id)
        .fetch_optional(&mut *tx)
        .await?;

        sqlx::query("DELETE FROM payments WHERE id = $1")
            .bind(payment_id)
            .execute(&mut *tx)
            .await?;

        if let Some(invoice_id) = invoice_id {
            let current: Option<(Decimal, Decimal)> =
                sqlx::query_as("SELECT total, amount_paid FROM invoices WHERE id = $1")
                    .bind(invoice_id)
                    .fetch_optional(&mut *tx)
                    .await?;
            if let Some((total, prior_paid)) = current {
                let new_paid = (prior_paid - amount).max(Decimal::ZERO);
                let new_balance = total - new_paid;
                let new_status = if new_paid == Decimal::ZERO {
                    "sent"
                } else if new_balance <= Decimal::ZERO {
                    "paid"
                } else {
                    "partially_paid"
                };
                sqlx::query(
                    r#"
                    UPDATE invoices SET
                        amount_paid = $2,
                        balance_due = $3,
                        status      = $4,
                        paid_at     = CASE WHEN $4 = 'paid' THEN paid_at ELSE NULL END,
                        updated_at  = NOW()
                    WHERE id = $1
                    "#,
                )
                .bind(invoice_id)
                .bind(new_paid)
                .bind(new_balance)
                .bind(new_status)
                .execute(&mut *tx)
                .await?;
            }
        }

        // Audit row in the same transaction. DELETE: old = before,
        // after = None. PMS-117.
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Delete,
            "payments",
            Some(payment_id),
            before,
            None,
        )
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// PMS-38: update an invoice header and optionally replace its
    /// line items in one transaction. Rejects edits on
    /// `InvoiceStatus::is_frozen` invoices (sent, paid, partially paid,
    /// void, written off) - correction goes through a credit note,
    /// which is out of scope for this commit.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_invoice(
        &self,
        tenant_id: Uuid,
        invoice_id: Uuid,
        request: &UpdateInvoiceRequest,
        ctx: &AuditCtx,
    ) -> AppResult<InvoiceResponse> {
        let current = self.get_invoice(tenant_id, invoice_id).await?;
        if current.status.is_frozen() {
            return Err(AppError::Conflict(format!(
                "Invoice in status '{}' cannot be edited",
                current.status.as_str()
            )));
        }

        let mut tx = self.db.pool().begin().await?;

        // Snapshot before any mutation (line replace + header update). PMS-117.
        let before: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM invoices t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(invoice_id)
        .fetch_optional(&mut *tx)
        .await?;

        // Replace lines first (if requested) so the recomputed
        // subtotal reflects the new set when we write the header.
        let subtotal = if let Some(lines) = &request.lines {
            sqlx::query("DELETE FROM invoice_lines WHERE invoice_id = $1")
                .bind(invoice_id)
                .execute(&mut *tx)
                .await?;
            let mut sub = Decimal::ZERO;
            for line in lines {
                let line_total = line.quantity * line.unit_price;
                sub += line_total;
                sqlx::query(
                    r#"
                    INSERT INTO invoice_lines (
                        id, invoice_id, line_type, description, quantity,
                        unit_price, total, ticket_id, project_id, sort_order
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                    "#,
                )
                .bind(Uuid::new_v4())
                .bind(invoice_id)
                .bind(line.line_type.as_str())
                .bind(&line.description)
                .bind(line.quantity)
                .bind(line.unit_price)
                .bind(line_total)
                .bind(line.ticket_id)
                .bind(line.project_id)
                .bind(line.sort_order)
                .execute(&mut *tx)
                .await?;
            }
            sub
        } else {
            current.subtotal
        };

        let tax = request.tax_amount.unwrap_or(current.tax_amount);
        let discount = request.discount_amount.unwrap_or(current.discount_amount);
        let total = subtotal + tax - discount;
        let balance_due = total - current.amount_paid;

        // `sent_at` is stamped when the status first moves to `sent`.
        let status = request.status.unwrap_or(current.status);
        let sent_at = if matches!(status, InvoiceStatus::Sent) && current.sent_at.is_none() {
            Some(Utc::now())
        } else {
            current.sent_at
        };

        sqlx::query(
            r#"
            UPDATE invoices SET
                billing_contact_id = COALESCE($2, billing_contact_id),
                contract_id        = COALESCE($3, contract_id),
                invoice_date       = COALESCE($4, invoice_date),
                due_date           = COALESCE($5, due_date),
                payment_terms      = COALESCE($6, payment_terms),
                notes              = COALESCE($7, notes),
                po_number          = COALESCE($8, po_number),
                status             = $9,
                subtotal           = $10,
                tax_amount         = $11,
                discount_amount    = $12,
                total              = $13,
                balance_due        = $14,
                sent_at            = $15,
                updated_at         = NOW()
            WHERE id = $1
            "#,
        )
        .bind(invoice_id)
        .bind(request.billing_contact_id)
        .bind(request.contract_id)
        .bind(request.invoice_date)
        .bind(request.due_date)
        .bind(request.payment_terms.as_deref())
        .bind(request.notes.as_deref())
        .bind(request.po_number.as_deref())
        .bind(status.as_str())
        .bind(subtotal)
        .bind(tax)
        .bind(discount)
        .bind(total)
        .bind(balance_due)
        .bind(sent_at)
        .execute(&mut *tx)
        .await?;

        // Audit row in the same transaction. PMS-117.
        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM invoices t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(invoice_id)
        .fetch_optional(&mut *tx)
        .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Update,
            "invoices",
            Some(invoice_id),
            before,
            after,
        )
        .await?;

        tx.commit().await?;
        self.get_invoice(tenant_id, invoice_id).await
    }

    /// PMS-36: read a single invoice with `lines` populated. 404 when
    /// the id is outside the tenant.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_invoice(
        &self,
        tenant_id: Uuid,
        invoice_id: Uuid,
    ) -> AppResult<InvoiceResponse> {
        let row = sqlx::query_as::<_, InvoiceRow>(
            r#"
            SELECT id, tenant_id, invoice_number, company_id, billing_contact_id,
                   contract_id, status, invoice_date, due_date, payment_terms,
                   subtotal, tax_amount, discount_amount, total, amount_paid,
                   balance_due, currency, notes, po_number, sent_at, paid_at,
                   created_at, updated_at
            FROM invoices
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(invoice_id)
        .fetch_optional(self.db.pool())
        .await?
        .ok_or_else(|| AppError::NotFound("Invoice".to_string()))?;

        let line_rows = sqlx::query_as::<_, InvoiceLineRow>(
            r#"
            SELECT id, line_type, description, quantity, unit_price, total,
                   ticket_id, project_id, sort_order
            FROM invoice_lines
            WHERE invoice_id = $1
            ORDER BY sort_order, created_at
            "#,
        )
        .bind(invoice_id)
        .fetch_all(self.db.pool())
        .await?;

        let mut resp: InvoiceResponse = row.into();
        resp.lines = Some(line_rows.into_iter().map(Into::into).collect());
        Ok(resp)
    }
}

/// Candidate-contract row for [`BillingService::generate_due_recurring_invoices`].
#[derive(sqlx::FromRow)]
struct RecurringContractRow {
    id: Uuid,
    company_id: Uuid,
    billing_cycle: Option<String>,
    start_date: NaiveDate,
    end_date: Option<NaiveDate>,
}

/// Recurring contract-item row -> one invoice line.
#[derive(sqlx::FromRow)]
struct RecurringItemRow {
    name: String,
    quantity: Decimal,
    unit_price: Decimal,
}

/// Number of whole months in one billing period for the given cycle.
/// `None` for `one_time` / unknown cycles (the caller skips them).
fn cycle_months(billing_cycle: &str) -> Option<u32> {
    match billing_cycle {
        "monthly" => Some(1),
        "quarterly" => Some(3),
        "annually" => Some(12),
        // `one_time` is filtered out upstream; treat any other value as
        // non-recurring so an unexpected cycle never bills.
        _ => None,
    }
}

/// Compute the current billing period `[period_start, period_end]` for a
/// contract, anchored at `start_date` and stepped by the `billing_cycle`
/// length, such that `period_start <= today` and `today <= period_end`.
///
/// Periods tile forward from `start_date` with no gaps:
///   monthly  : start, start+1mo, start+2mo, ...
///   quarterly: start, start+3mo, ...
///   annually : start, start+12mo, ...
/// `period_end` is the day before the next period's start.
///
/// Returns `None` when `today < start_date` (no period has begun yet) or
/// the cycle is non-recurring / unknown.
///
/// Month arithmetic uses `chrono::Months`, which clamps end-of-month
/// overflow (e.g. Jan 31 + 1 month -> Feb 28/29), so a contract that
/// starts on the 31st still produces one period per cycle.
fn current_billing_period(
    billing_cycle: &str,
    start_date: NaiveDate,
    today: NaiveDate,
) -> Option<(NaiveDate, NaiveDate)> {
    if today < start_date {
        return None;
    }
    let step = cycle_months(billing_cycle)?;
    if step == 0 {
        return None;
    }

    // Walk forward from start_date one cycle at a time until the next
    // boundary would pass `today`. Bounded by the number of cycles
    // between the two dates plus a small margin, so it always terminates
    // even on clamped month math.
    let mut period_start = start_date;
    loop {
        let next = period_start.checked_add_months(Months::new(step))?;
        if next > today {
            // `period_end` is the day before the next period starts.
            let period_end = next.pred_opt().unwrap_or(next);
            return Some((period_start, period_end));
        }
        period_start = next;
        // Defensive guard against a pathological non-advancing step
        // (cannot happen for step >= 1, but keeps the loop provably
        // terminating).
        if period_start > today {
            let period_end = period_start
                .checked_add_months(Months::new(step))
                .and_then(|d| d.pred_opt())
                .unwrap_or(period_start);
            return Some((period_start, period_end));
        }
    }
}

/// Row shape for the billable-time-entry select in
/// [`BillingService::create_invoice_from_time_entries`]. Only the
/// columns the invoice line needs are pulled.
#[derive(sqlx::FromRow)]
struct TimeEntryBillingRow {
    id: Uuid,
    duration_minutes: i32,
    hourly_rate: Option<Decimal>,
    total_amount: Option<Decimal>,
    ticket_id: Option<Uuid>,
}

#[derive(sqlx::FromRow)]
struct TaxRateRow {
    id: Uuid,
    name: String,
    rate: Decimal,
    is_default: bool,
    is_active: bool,
}

impl From<TaxRateRow> for TaxRateResponse {
    fn from(r: TaxRateRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            rate: r.rate,
            is_default: r.is_default,
            is_active: r.is_active,
        }
    }
}

#[derive(sqlx::FromRow)]
struct PaymentGatewayRow {
    id: Uuid,
    provider: String,
    is_active: bool,
    is_test_mode: bool,
    config_encrypted: String,
}

#[derive(sqlx::FromRow)]
struct PaymentRow {
    id: Uuid,
    tenant_id: Uuid,
    invoice_id: Option<Uuid>,
    company_id: Uuid,
    payment_date: chrono::NaiveDate,
    amount: Decimal,
    payment_method: String,
    reference_number: Option<String>,
    gateway_transaction_id: Option<String>,
    notes: Option<String>,
    created_at: chrono::DateTime<Utc>,
}

impl From<PaymentRow> for PaymentResponse {
    fn from(r: PaymentRow) -> Self {
        Self {
            id: r.id,
            tenant_id: r.tenant_id,
            invoice_id: r.invoice_id,
            company_id: r.company_id,
            payment_date: r.payment_date,
            amount: r.amount,
            payment_method: PaymentMethod::from_str(&r.payment_method)
                .unwrap_or(PaymentMethod::Other),
            reference_number: r.reference_number,
            gateway_transaction_id: r.gateway_transaction_id,
            notes: r.notes,
            created_at: r.created_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct InvoiceLineRow {
    id: Uuid,
    line_type: String,
    description: String,
    quantity: Decimal,
    unit_price: Decimal,
    total: Decimal,
    ticket_id: Option<Uuid>,
    project_id: Option<Uuid>,
    sort_order: i32,
}

impl From<InvoiceLineRow> for InvoiceLineResponse {
    fn from(r: InvoiceLineRow) -> Self {
        Self {
            id: r.id,
            line_type: InvoiceLineType::from_str(&r.line_type).unwrap_or(InvoiceLineType::Service),
            description: r.description,
            quantity: r.quantity,
            unit_price: r.unit_price,
            total: r.total,
            ticket_id: r.ticket_id,
            project_id: r.project_id,
            sort_order: r.sort_order,
        }
    }
}

#[derive(sqlx::FromRow)]
struct InvoiceRow {
    id: Uuid,
    tenant_id: Uuid,
    invoice_number: String,
    company_id: Uuid,
    billing_contact_id: Option<Uuid>,
    contract_id: Option<Uuid>,
    status: String,
    invoice_date: chrono::NaiveDate,
    due_date: chrono::NaiveDate,
    payment_terms: Option<String>,
    subtotal: Decimal,
    tax_amount: Decimal,
    discount_amount: Decimal,
    total: Decimal,
    amount_paid: Decimal,
    balance_due: Decimal,
    currency: Option<String>,
    notes: Option<String>,
    po_number: Option<String>,
    sent_at: Option<chrono::DateTime<Utc>>,
    paid_at: Option<chrono::DateTime<Utc>>,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
}

impl From<InvoiceRow> for InvoiceResponse {
    fn from(r: InvoiceRow) -> Self {
        Self {
            id: r.id,
            tenant_id: r.tenant_id,
            invoice_number: r.invoice_number,
            company_id: r.company_id,
            billing_contact_id: r.billing_contact_id,
            contract_id: r.contract_id,
            status: InvoiceStatus::from_str(&r.status).unwrap_or(InvoiceStatus::Draft),
            invoice_date: r.invoice_date,
            due_date: r.due_date,
            payment_terms: r.payment_terms,
            subtotal: r.subtotal,
            tax_amount: r.tax_amount,
            discount_amount: r.discount_amount,
            total: r.total,
            amount_paid: r.amount_paid,
            balance_due: r.balance_due,
            currency: r.currency,
            notes: r.notes,
            po_number: r.po_number,
            sent_at: r.sent_at,
            paid_at: r.paid_at,
            created_at: r.created_at,
            updated_at: r.updated_at,
            lines: None,
        }
    }
}

#[allow(dead_code)]
fn _force_use(_: &AppError) {}
