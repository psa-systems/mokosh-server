//! Billing service. Endpoints land incrementally across PMS-33.

use crate::modules::auth::TenantId;
use chrono::{DateTime, NaiveDate, Utc};

use crate::modules::contracts::service::CycleStep;
use rust_decimal::Decimal;
use uuid::Uuid;

use std::sync::Arc;

use crate::db::Database;
use crate::modules::audit::{audit_write, AuditAction, AuditCtx};
use crate::utils::email::Mailer;
use crate::utils::error::{AppError, AppResult};
use crate::utils::pagination::PaginationParams;

use super::models::*;
use super::provider::{self, CheckoutParams, CheckoutSession, PaymentProvider};

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
    /// Shared HTTP client for outbound provider calls (Stripe). Cheap to clone;
    /// reused across requests per reqwest's guidance (PMS-711).
    http: reqwest::Client,
    /// PMS-711: mailer used to send the outbound invoice "Pay Now" email on the
    /// send transition. `None` on the portal-side instance, which never sends.
    mailer: Option<Arc<dyn Mailer>>,
    /// PMS-711: SPA/portal origin the "Pay Now" email links point at. `None`
    /// disables the email (no base to build the link from).
    portal_origin: Option<String>,
    /// PMS-968: where a tenant's gateway credentials live. Injected rather than
    /// built here, so the backend is chosen once at startup by
    /// `secrets::store_from_env` and no constructor can pick a different one.
    secrets: Arc<dyn crate::secrets::SecretStore>,
}

/// PMS-990: the due date offset when neither the invoice's term nor the
/// tenant's default term names a count. Thirty, because that is what the
/// server-minted paths used before terms carried a number, and a fallback
/// that changed it would move due dates on tenants that configured nothing.
const DEFAULT_NET_DAYS: i32 = 30;

impl BillingService {
    /// Zero-key constructor for callers that never touch secret material (the
    /// QA seeder). Its secret store is the database one under the same zero
    /// key, so the two halves agree; nothing on that path reads a gateway
    /// credential.
    pub fn new(db: Database) -> Self {
        let secrets = Arc::new(crate::secrets::DatabaseSecretStore::new(
            db.clone(),
            [0u8; 32],
        ));
        Self {
            db,
            encryption_key: [0u8; 32],
            http: reqwest::Client::new(),
            mailer: None,
            portal_origin: None,
            secrets,
        }
    }

    /// Resolve a set of company ids to their display names, tenant-scoped
    /// (PMS-186). Returns a map so callers can attach `company_name` to
    /// invoice / payment responses without a per-row round-trip. Empty
    /// input short-circuits to an empty map.
    async fn company_name_map(
        &self,
        tenant_id: TenantId,
        ids: &[Uuid],
    ) -> AppResult<std::collections::HashMap<Uuid, String>> {
        if ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows: Vec<(Uuid, String)> =
            sqlx::query_as("SELECT id, name FROM companies WHERE tenant_id = $1 AND id = ANY($2)")
                .bind(tenant_id)
                .bind(ids)
                .fetch_all(&mut *tx)
                .await?;
        Ok(rows.into_iter().collect())
    }

    /// Resolve a set of invoice ids to their human invoice numbers,
    /// tenant-scoped (PMS-186). Used to label payments by invoice number
    /// instead of the invoice UUID.
    async fn invoice_number_map(
        &self,
        tenant_id: TenantId,
        ids: &[Uuid],
    ) -> AppResult<std::collections::HashMap<Uuid, String>> {
        if ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT id, invoice_number FROM invoices WHERE tenant_id = $1 AND id = ANY($2)",
        )
        .bind(tenant_id)
        .bind(ids)
        .fetch_all(&mut *tx)
        .await?;
        Ok(rows.into_iter().collect())
    }

    /// Allocate the next gapless, per-tenant invoice number inside the
    /// caller's transaction (PMS-194).
    ///
    /// Atomically bumps `invoice_sequences.last_number` (the row-lock
    /// serialises concurrent invoice creates so numbers stay dense and
    /// unique); seeds the sequence row on the tenant's first invoice. The
    /// bump lives in the caller's `tx`, so a rollback restores the
    /// sequence value too and numbers stay gapless. Shared by every
    /// invoice-creating path (`create_invoice`,
    /// `create_invoice_from_time_entries`, and the recurring-billing run)
    /// so the seed-or-bump logic lives in one place.
    /// PMS-933, rewritten for PMS-944: describe why a company's time did not
    /// produce an invoice, for the message on the empty path.
    ///
    /// PMS-933 answered "held by approval", because PMS-144 made timesheet
    /// approval the gate. PMS-944 removed that gate, so the old sentence would
    /// name a state that can no longer occur. What survives is the requirement
    /// it was defending, which is that "no billable time found" is a claim
    /// about the user's data and must not be made when the data is there.
    ///
    /// Deliberately the SAME predicate as the eligibility select minus the
    /// `is_billable`, `invoice_id` and `billing_status` clauses, so this can
    /// only ever describe rows those three excluded, and it counts each of them
    /// separately so no excluded row goes unaccounted for. If the two drift,
    /// this starts explaining the absence of rows that were never eligible for
    /// another reason, which is worse than the message it replaced.
    async fn uninvoiceable_time_for_company(
        tx: &mut sqlx::PgConnection,
        tenant_id: TenantId,
        company_id: Uuid,
    ) -> AppResult<UninvoiceableTime> {
        let row: Option<(i64, i64, i64, i64, i64)> = sqlx::query_as(
            r#"
            SELECT
                COUNT(*) FILTER (
                    WHERE is_billable IS TRUE AND invoice_id IS NULL
                      AND billing_status IS DISTINCT FROM 'ready_to_bill'),
                COALESCE(SUM(duration_minutes) FILTER (
                    WHERE is_billable IS TRUE AND invoice_id IS NULL
                      AND billing_status IS DISTINCT FROM 'ready_to_bill'), 0),
                COUNT(*) FILTER (WHERE is_billable IS NOT TRUE),
                COALESCE(SUM(duration_minutes) FILTER (WHERE is_billable IS NOT TRUE), 0),
                COUNT(*) FILTER (WHERE is_billable IS TRUE AND invoice_id IS NOT NULL)
            FROM time_entries
            WHERE tenant_id = $1
              AND company_id = $2
              -- PMS-942: by kind, not by which company id the caller passed.
              -- The tenant's own internal company (PMS-413) is a real row in
              -- `companies`, so nothing here stopped a caller naming it and
              -- getting the MSP's own overhead time counted as a client's.
              AND entry_kind = 'client'
            "#,
        )
        .bind(tenant_id)
        .bind(company_id)
        .fetch_optional(&mut *tx)
        .await?;

        let (not_ready, not_ready_minutes, non_billable, non_billable_minutes, already_invoiced) =
            row.unwrap_or((0, 0, 0, 0, 0));
        Ok(UninvoiceableTime {
            not_ready,
            not_ready_minutes,
            non_billable,
            non_billable_minutes,
            already_invoiced,
        })
    }

    async fn next_invoice_number(
        tx: &mut sqlx::PgConnection,
        tenant_id: TenantId,
    ) -> AppResult<String> {
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
        Ok(format!(
            "{}{:06}",
            prefix.unwrap_or_else(|| "INV-".to_string()),
            next_number
        ))
    }

    /// Lock an invoice row for a payment read-modify-write and return its
    /// `(total, amount_paid)` (PMS-695).
    ///
    /// `FOR UPDATE` is what makes concurrent payment creates/deletes
    /// serialise: without it two transactions both read the pre-payment
    /// `amount_paid` under READ COMMITTED and the later write discards the
    /// earlier one. Every path that mutates an invoice's payment state takes
    /// this lock first, in the same order, so they queue rather than deadlock.
    async fn lock_invoice_totals(
        tx: &mut sqlx::PgConnection,
        tenant_id: TenantId,
        invoice_id: Uuid,
    ) -> AppResult<Option<(Decimal, Decimal)>> {
        Ok(sqlx::query_as(
            "SELECT total, amount_paid FROM invoices \
             WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
        )
        .bind(invoice_id)
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await?)
    }

    /// Recompute an invoice's `amount_paid` / `amount_credited` /
    /// `balance_due` / `status` / `paid_at` from its `payments` rows, net of
    /// `payment_refunds` (PMS-695, refunds added in PMS-711), and its issued
    /// `credit_notes` (PMS-953).
    ///
    /// The single place invoice balance state is derived, mirroring
    /// `QuotesService::recompute_totals`. Deriving from SQL sums rather than
    /// from Rust-side arithmetic makes both figures true by construction, so a
    /// full refund walks the invoice back to `sent` and a voided credit note
    /// restores the balance it had removed, with no bespoke transition logic
    /// either way. Callers must already hold the row lock from
    /// [`Self::lock_invoice_totals`].
    ///
    /// PMS-953 added credits here rather than in a second updater on purpose.
    /// `amount_paid` and `amount_credited` are two halves of one balance, and
    /// two writers with two rules is how they come to disagree.
    ///
    /// The status ladder is unchanged for an invoice with no credits: with
    /// `credited = 0` the first arm cannot fire and the rest reduce to exactly
    /// the pre-PMS-953 expression, zero-total invoices included. Crediting away
    /// the whole outstanding balance moves the invoice to `void`, which is what
    /// finally gives that status a writer: before this it was a value the model
    /// knew and no code path could reach.
    ///
    /// `paid_at` stays keyed on payments alone. A credited invoice was not
    /// paid, and stamping it would put a payment date on money nobody sent.
    async fn recompute_invoice_balance(
        tx: &mut sqlx::PgConnection,
        tenant_id: TenantId,
        invoice_id: Uuid,
    ) -> AppResult<()> {
        // A zeroed-out (or fully refunded) invoice returns to 'sent', identical
        // to the pre-PMS-695 `delete_payment` ladder this replaces.
        sqlx::query(
            r#"
            UPDATE invoices i SET
                amount_paid     = p.paid,
                amount_credited = p.credited,
                balance_due     = i.total - p.paid - p.credited,
                status      = CASE WHEN p.credited > 0
                                    AND p.credited >= i.total - p.paid THEN 'void'
                                   WHEN i.total - p.paid - p.credited <= 0 THEN 'paid'
                                   WHEN p.paid > 0 THEN 'partially_paid'
                                   ELSE 'sent' END,
                paid_at     = CASE WHEN i.total - p.paid <= 0
                                   THEN COALESCE(i.paid_at, NOW()) END,
                updated_at  = NOW()
            FROM (
                SELECT
                    COALESCE((SELECT SUM(amount) FROM payments
                              WHERE invoice_id = $1 AND tenant_id = $2), 0)
                  - COALESCE((SELECT SUM(amount) FROM payment_refunds
                              WHERE invoice_id = $1 AND tenant_id = $2), 0)
                  AS paid,
                    COALESCE((SELECT SUM(total) FROM credit_notes
                              WHERE invoice_id = $1 AND tenant_id = $2
                                AND status = 'issued'), 0)
                  AS credited
            ) p
            WHERE i.id = $1 AND i.tenant_id = $2
            "#,
        )
        .bind(invoice_id)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
        Ok(())
    }

    /// Validate that `payment_term_id` references a `payment_terms` row in the
    /// caller's tenant (PMS-333). RLS scopes the lookup, so a foreign-tenant id
    /// (whose FK would otherwise pass, since FK checks bypass RLS) is rejected
    /// with a 400 instead of silently linking across tenants.
    async fn assert_payment_term_in_tenant(
        tx: &mut sqlx::PgConnection,
        tenant_id: TenantId,
        payment_term_id: Uuid,
    ) -> AppResult<()> {
        let found: Option<i32> =
            sqlx::query_scalar("SELECT 1 FROM payment_terms WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(payment_term_id)
                .fetch_optional(&mut *tx)
                .await?;
        if found.is_none() {
            return Err(AppError::BadRequest(
                "payment_term_id does not reference a payment term in this tenant".to_string(),
            ));
        }
        Ok(())
    }

    /// PMS-990: the due date, and the term it came from.
    ///
    /// A given `due_date` wins, stored as given with whatever term the caller
    /// named. Otherwise the date is the invoice date plus the net days of the
    /// named term, or of the tenant's default term when none was named, and
    /// the term that supplied the count is returned so the invoice records
    /// it. A term with no count, or a tenant with no default, falls back to
    /// thirty days: the value the two server-minted paths hardcoded before
    /// this, so nothing changes for a tenant that never set one.
    ///
    /// Only an ACTIVE default is consulted. A retired default is an operator
    /// forgetting to move the flag, and linking new invoices to a term that
    /// no longer appears in the picker would be surprising.
    pub(crate) async fn resolve_due_date(
        tx: &mut sqlx::PgConnection,
        tenant_id: TenantId,
        invoice_date: NaiveDate,
        payment_term_id: Option<Uuid>,
        due_date: Option<NaiveDate>,
    ) -> AppResult<(NaiveDate, Option<Uuid>)> {
        if let Some(due) = due_date {
            return Ok((due, payment_term_id));
        }
        let term: Option<(Uuid, Option<i32>)> = match payment_term_id {
            Some(id) => {
                sqlx::query_as(
                    "SELECT id, net_days FROM payment_terms WHERE tenant_id = $1 AND id = $2",
                )
                .bind(tenant_id)
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?
            }
            None => {
                sqlx::query_as(
                    "SELECT id, net_days FROM payment_terms \
                 WHERE tenant_id = $1 AND is_default = TRUE AND is_active = TRUE \
                 ORDER BY sort_order, name LIMIT 1",
                )
                .bind(tenant_id)
                .fetch_optional(&mut *tx)
                .await?
            }
        };
        let (term_id, net_days) = match term {
            Some((id, days)) => (Some(id), days),
            None => (payment_term_id, None),
        };
        let days = net_days.unwrap_or(DEFAULT_NET_DAYS);
        Ok((invoice_date + chrono::Duration::days(days as i64), term_id))
    }

    /// Resolve a set of payment-term ids to their names, tenant-scoped
    /// (PMS-333). Lets `enrich_invoices` attach `payment_term_name` without a
    /// per-row round-trip.
    async fn payment_term_name_map(
        &self,
        tenant_id: TenantId,
        ids: &[Uuid],
    ) -> AppResult<std::collections::HashMap<Uuid, String>> {
        if ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT id, name FROM payment_terms WHERE tenant_id = $1 AND id = ANY($2)",
        )
        .bind(tenant_id)
        .bind(ids)
        .fetch_all(&mut *tx)
        .await?;
        Ok(rows.into_iter().collect())
    }

    /// Fill in `company_name` on a batch of invoice responses (PMS-186).
    async fn enrich_invoices(
        &self,
        tenant_id: TenantId,
        resp: &mut [InvoiceResponse],
    ) -> AppResult<()> {
        let ids: Vec<Uuid> = resp.iter().map(|r| r.company_id).collect();
        let names = self.company_name_map(tenant_id, &ids).await?;
        let term_ids: Vec<Uuid> = resp.iter().filter_map(|r| r.payment_term_id).collect();
        let term_names = self.payment_term_name_map(tenant_id, &term_ids).await?;
        for r in resp.iter_mut() {
            r.company_name = names.get(&r.company_id).cloned();
            r.payment_term_name = r
                .payment_term_id
                .and_then(|id| term_names.get(&id).cloned());
        }
        Ok(())
    }

    /// Fill in `company_name` and `invoice_number` on a batch of payment
    /// responses (PMS-186).
    async fn enrich_payments(
        &self,
        tenant_id: TenantId,
        resp: &mut [PaymentResponse],
    ) -> AppResult<()> {
        let company_ids: Vec<Uuid> = resp.iter().map(|r| r.company_id).collect();
        let names = self.company_name_map(tenant_id, &company_ids).await?;
        let invoice_ids: Vec<Uuid> = resp.iter().filter_map(|r| r.invoice_id).collect();
        let numbers = self.invoice_number_map(tenant_id, &invoice_ids).await?;
        for r in resp.iter_mut() {
            r.company_name = names.get(&r.company_id).cloned();
            r.invoice_number = r.invoice_id.and_then(|id| numbers.get(&id).cloned());
        }
        Ok(())
    }

    /// Production constructor: takes the same `ENCRYPTION_KEY` env that
    /// auth uses for token encryption. Hands the key down to the
    /// payment-gateway-config write path so secrets never hit the DB
    /// in cleartext.
    pub fn with_encryption_key(db: Database, encryption_key: [u8; 32]) -> Self {
        let secrets = Arc::new(crate::secrets::DatabaseSecretStore::new(
            db.clone(),
            encryption_key,
        ));
        Self::with_secrets(db, encryption_key, secrets)
    }

    /// PMS-968: the constructor that takes the configured secret store.
    ///
    /// `with_encryption_key` keeps the database backend, which is correct for
    /// the callers that have no configuration to consult (tests, the seeder).
    /// Every serving instance is built through here from
    /// `secrets::store_from_env`, so a deployment on Infisical has all of them
    /// on Infisical rather than whichever ones remembered.
    pub fn with_secrets(
        db: Database,
        encryption_key: [u8; 32],
        secrets: Arc<dyn crate::secrets::SecretStore>,
    ) -> Self {
        Self {
            db,
            encryption_key,
            http: reqwest::Client::new(),
            mailer: None,
            portal_origin: None,
            secrets,
        }
    }

    /// PMS-711: production constructor for the agent-facing instance, which also
    /// sends the outbound invoice "Pay Now" email on the send transition. Takes
    /// the shared mailer and the portal origin the pay link is built from. The
    /// portal-side `BillingService` keeps using [`Self::with_encryption_key`]
    /// (no mailer) since it never triggers a send.
    pub fn with_delivery(
        db: Database,
        encryption_key: [u8; 32],
        mailer: Arc<dyn Mailer>,
        portal_origin: String,
        secrets: Arc<dyn crate::secrets::SecretStore>,
    ) -> Self {
        Self {
            db,
            encryption_key,
            http: reqwest::Client::new(),
            mailer: Some(mailer),
            portal_origin: Some(portal_origin),
            secrets,
        }
    }

    /// PMS-35: paginated + filterable invoice list. `lines` is left
    /// `None` on list rollups — the customer-facing UI fetches lines
    /// only when expanding a row.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_invoices(
        &self,
        tenant_id: TenantId,
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
        let order_by = pagination.order_by("invoice_date", mokosh_types::sort::INVOICES)?;
        let query = format!(
            r#"
            SELECT id, tenant_id, invoice_number, company_id, billing_contact_id,
                   contract_id, status, invoice_date, due_date, payment_terms,
                   payment_term_id,
                   subtotal, tax_amount, discount_amount, total, amount_paid, amount_credited,
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

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows = q.fetch_all(&mut *tx).await?;
        let total = cq.fetch_one(&mut *tx).await?;
        drop(tx);
        let mut resp: Vec<InvoiceResponse> = rows.into_iter().map(Into::into).collect();
        self.enrich_invoices(tenant_id, &mut resp).await?;
        Ok((resp, total as u64))
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
        tenant_id: TenantId,
        request: &CreateInvoiceRequest,
        ctx: &AuditCtx,
    ) -> AppResult<InvoiceResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;

        // Per-tenant invoice sequence is row-locked by the shared helper;
        // concurrent invoice creates serialise on this row so numbers are
        // dense and unique.
        let invoice_number = Self::next_invoice_number(&mut tx, tenant_id).await?;

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

        if let Some(pt) = request.payment_term_id {
            Self::assert_payment_term_in_tenant(&mut tx, tenant_id, pt).await?;
        }
        // PMS-990: the due date the caller gave, or the one the term implies.
        let (due_date, payment_term_id) = Self::resolve_due_date(
            &mut tx,
            tenant_id,
            request.invoice_date,
            request.payment_term_id,
            request.due_date,
        )
        .await?;

        let invoice_id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO invoices (
                id, tenant_id, invoice_number, company_id, billing_contact_id,
                contract_id, status, invoice_date, due_date, payment_terms,
                payment_term_id,
                subtotal, tax_amount, discount_amount, total, amount_paid,
                balance_due, currency, notes, po_number
            )
            VALUES ($1, $2, $3, $4, $5, $6, 'draft', $7, $8, $9, $17, $10, $11,
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
        .bind(due_date)
        .bind(&request.payment_terms)
        .bind(subtotal)
        .bind(tax)
        .bind(discount)
        .bind(total)
        .bind(request.currency.as_deref().unwrap_or("USD"))
        .bind(&request.notes)
        .bind(&request.po_number)
        .bind(payment_term_id)
        .execute(&mut *tx)
        .await?;

        // PMS-955: every catalog link on this invoice is checked before any
        // line is written, so a bad id on the third line does not leave the
        // first two behind. RLS does not cover this: an FK check bypasses it,
        // so a foreign-tenant product would link silently (PMS-333's lesson).
        for line in &request.lines {
            if let Some(product_id) = line.product_id {
                Self::assert_product_sellable(&mut tx, tenant_id, product_id).await?;
            }
        }

        for line in &request.lines {
            sqlx::query(
                r#"
                INSERT INTO invoice_lines (
                    id, invoice_id, line_type, description, quantity, unit_price,
                    total, ticket_id, project_id, sort_order, product_id
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
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
            .bind(line.product_id)
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
    /// and `billing_status = 'ready_to_bill'` (PMS-944: an entry is armed at
    /// creation by `resolve_billing_status`, so being logged and billable is
    /// what makes it invoiceable; PMS-144 used to route that status through
    /// weekly timesheet approval instead), tenant-scoped and company-scoped.
    /// When `time_entry_ids` is
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
        tenant_id: TenantId,
        request: &CreateInvoiceFromTimeEntriesRequest,
        ctx: &AuditCtx,
    ) -> AppResult<InvoiceResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;

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
              -- PMS-942: employee time never reaches a client invoice, and it
              -- is excluded by what it IS rather than by which company id the
              -- caller happened to pass. The tenant's own internal company
              -- (PMS-413) is a real `companies` row, so before this its
              -- overhead time was invoiceable by naming it.
              AND entry_kind = 'client'
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

        // 1b. PMS-315: lock the company's eligible mileage entries with the
        //     SAME predicate (billable, unbilled, ready_to_bill). Mileage
        //     never had the timesheet gate, so a billable mileage entry has
        //     always been ready_to_bill on creation (see
        //     MileageTrackingService); PMS-944 put time on the same footing.
        //     The `time_entry_ids`
        //     id filter never restricts mileage; it names time entries only.
        let mileage: Vec<MileageBillingRow> = sqlx::query_as(
            r#"
            SELECT id, distance_miles, rate_per_mile, total_amount, ticket_id,
                   start_address, end_address
            FROM mileage_entries
            WHERE tenant_id = $1
              AND company_id = $2
              AND is_billable = TRUE
              AND invoice_id IS NULL
              AND billing_status = 'ready_to_bill'
            ORDER BY date, created_at
            FOR UPDATE
            "#,
        )
        .bind(tenant_id)
        .bind(request.company_id)
        .fetch_all(&mut *tx)
        .await?;

        if entries.is_empty() && mileage.is_empty() {
            // PMS-933: "No billable time found" is a claim about EXISTENCE, and
            // a user told their data is not there goes looking for it, closes
            // the ticket, re-logs the hours, and none of that helps. Since
            // PMS-944 the reason is never approval, but it can still be that
            // the time was logged non-billable or is already on an invoice, and
            // both of those deserve to be said rather than denied.
            //
            // Only on the empty path, so a successful generate pays nothing.
            let why = Self::uninvoiceable_time_for_company(&mut tx, tenant_id, request.company_id)
                .await?;
            return Err(AppError::BadRequest(why.into_message()));
        }

        // 2. Allocate a gapless invoice number (same row-lock as
        //    `create_invoice`). Concurrent creates serialise on this row.
        let invoice_number = Self::next_invoice_number(&mut tx, tenant_id).await?;

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

        // 3b. PMS-315: one line per mileage entry. quantity = distance_miles,
        //     unit_price = rate_per_mile, total = total_amount (falling back to
        //     quantity * unit_price). Description renders the route when either
        //     address is present, else a bare "Mileage".
        let mut mileage_lines: Vec<(Uuid, String, Decimal, Decimal, Decimal, Option<Uuid>)> =
            Vec::with_capacity(mileage.len());
        for m in &mileage {
            let quantity = m.distance_miles;
            let unit_price = m.rate_per_mile.unwrap_or(Decimal::ZERO);
            let total = m.total_amount.unwrap_or(quantity * unit_price);
            subtotal += total;
            let description = match (m.start_address.as_deref(), m.end_address.as_deref()) {
                (None, None) => "Mileage".to_string(),
                (start, end) => format!(
                    "Mileage: {} \u{2192} {}",
                    start.unwrap_or(""),
                    end.unwrap_or("")
                ),
            };
            mileage_lines.push((m.id, description, quantity, unit_price, total, m.ticket_id));
        }

        // Tax / discount left at 0 (see method doc); total == subtotal.
        let tax = Decimal::ZERO;
        let discount = Decimal::ZERO;
        let total = subtotal + tax - discount;

        // Default the invoice date to today when the caller omits it, and
        // the due date to what the tenant's default term implies (PMS-990).
        let invoice_date = request
            .invoice_date
            .unwrap_or_else(|| Utc::now().date_naive());
        let (due_date, payment_term_id) =
            Self::resolve_due_date(&mut tx, tenant_id, invoice_date, None, request.due_date)
                .await?;

        // 4. Insert the invoice header. `balance_due` starts at `total`.
        let invoice_id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO invoices (
                id, tenant_id, invoice_number, company_id, billing_contact_id,
                contract_id, status, invoice_date, due_date, payment_terms,
                subtotal, tax_amount, discount_amount, total, amount_paid,
                balance_due, currency, notes, po_number, payment_term_id
            )
            VALUES ($1, $2, $3, $4, $5, $6, 'draft', $7, $8, $9, $10, $11,
                    $12, $13, 0, $13, $14, $15, $16, $17)
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
        .bind(payment_term_id)
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

        // 5b. PMS-315: one 'mileage' line per mileage entry. `sort_order`
        //     continues after the time-entry lines. Mileage lines do not set
        //     `time_entry_ids` (that column references time_entries only); the
        //     source is traced back via the matched mileage rows below.
        let time_line_count = lines.len();
        for (offset, (_mileage_id, description, quantity, unit_price, line_total, ticket_id)) in
            mileage_lines.iter().enumerate()
        {
            sqlx::query(
                r#"
                INSERT INTO invoice_lines (
                    id, invoice_id, line_type, description, quantity, unit_price,
                    total, ticket_id, sort_order
                )
                VALUES ($1, $2, 'mileage', $3, $4, $5, $6, $7, $8)
                "#,
            )
            .bind(Uuid::new_v4())
            .bind(invoice_id)
            .bind(description)
            .bind(quantity)
            .bind(unit_price)
            .bind(line_total)
            .bind(ticket_id)
            .bind((time_line_count + offset) as i32)
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

        // 6b. PMS-315: same flip for the billed mileage entries.
        let billed_mileage_ids: Vec<Uuid> = mileage.iter().map(|m| m.id).collect();
        sqlx::query(
            r#"
            UPDATE mileage_entries
            SET billing_status = 'billed',
                invoice_id     = $2,
                updated_at     = NOW()
            WHERE tenant_id = $1 AND id = ANY($3)
            "#,
        )
        .bind(tenant_id)
        .bind(invoice_id)
        .bind(&billed_mileage_ids)
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
        tenant_id: TenantId,
        now: DateTime<Utc>,
        ctx: &AuditCtx,
    ) -> AppResult<Vec<Uuid>> {
        let today = now.date_naive();

        // Candidate contracts: active, recurring (not one_time), already
        // started. `end_date` is checked per-period below (a contract may
        // still be due for a period that began before it expired).
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
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
        .fetch_all(&mut *tx)
        .await?;
        drop(tx);

        let mut created = Vec::new();
        for contract in contracts {
            let cycle = contract.billing_cycle.as_deref().unwrap_or("monthly");
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
        // SAFETY (PMS-285): the recurring-invoicing worker enumerates EVERY
        // tenant to draft due invoices (the worker owns the cadence), reading the
        // RLS-exempt `tenants` root across all tenants. Migrator pool; the
        // per-tenant invoice generation it dispatches below sets each tenant GUC.
        let tenant_ids: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM tenants")
            .fetch_all(self.db.migrator_pool())
            .await?;

        let mut total = 0u64;
        for tenant_id in tenant_ids {
            // SAFETY (PMS-139): cross-tenant sweep driven by the billing worker.
            // `tenant_id` is read straight off the `tenants` table (a real
            // tenant id, not user input), so it bridges into the tenant-scoped
            // path through `from_trusted`.
            let ctx = AuditCtx::system(tenant_id);
            match self
                .generate_due_recurring_invoices(TenantId::from_trusted(tenant_id), now, &ctx)
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
        tenant_id: TenantId,
        contract_id: Uuid,
        company_id: Uuid,
        period_start: NaiveDate,
        period_end: NaiveDate,
        today: NaiveDate,
        ctx: &AuditCtx,
    ) -> AppResult<Option<Uuid>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;

        // Pull this contract's recurring billing items. Mirrors
        // `ContractsService::list_recurring_items` (recurring_service +
        // retainer), but runs inside this transaction.
        let items = sqlx::query_as::<_, RecurringItemRow>(
            r#"
            SELECT id, name, quantity, unit_price, product_id, billing_rule
            FROM contract_items
            WHERE tenant_id = $1 AND contract_id = $2
              AND (billing_rule = 'every_period'
                   OR (billing_rule = 'once' AND billed_at IS NULL))
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
        let subtotal: Decimal = items.iter().map(|i| i.quantity * i.unit_price).sum();
        let tax = Decimal::ZERO;
        let discount = Decimal::ZERO;
        let total = subtotal + tax - discount;

        // Invoice today, due when the tenant's default term says (PMS-990);
        // thirty days when it names no count, as this path always did.
        let invoice_date = today;
        let (due_date, payment_term_id) =
            Self::resolve_due_date(&mut tx, tenant_id, invoice_date, None, None).await?;

        // Gapless invoice number: same per-tenant row-lock as
        // `create_invoice`. NOTE: this increments the sequence even if the
        // ledger insert below conflicts and we roll back; the rollback
        // restores the sequence value too (the UPDATE is part of this tx),
        // so numbers stay gapless.
        let invoice_number = Self::next_invoice_number(&mut tx, tenant_id).await?;

        sqlx::query(
            r#"
            INSERT INTO invoices (
                id, tenant_id, invoice_number, company_id, billing_contact_id,
                contract_id, status, invoice_date, due_date, payment_terms,
                subtotal, tax_amount, discount_amount, total, amount_paid,
                balance_due, currency, notes, po_number, payment_term_id
            )
            VALUES ($1, $2, $3, $4, NULL, $5, 'draft', $6, $7, 'net30', $8, $9,
                    $10, $11, 0, $11, 'USD', $12, NULL, $13)
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
        .bind(payment_term_id)
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

        // --- 3. One invoice line per billable item (line_type 'service'). ---
        //
        // PMS-956: a `once` item is claimed here, in this transaction, with an
        // UPDATE that only matches while it is still unbilled. That is the
        // per-item idempotency the period ledger cannot give: it is keyed on
        // (tenant, contract, period_start), so it knows a PERIOD was billed and
        // a setup fee added in March would bill again in April under a new
        // period key. If the claim matches nothing another run took it, and the
        // whole transaction rolls back rather than billing it twice.
        for (idx, item) in items.iter().enumerate() {
            if item.billing_rule == "once" {
                let claimed: Option<Uuid> = sqlx::query_scalar(
                    "UPDATE contract_items SET billed_at = NOW(), updated_at = NOW() \
                     WHERE id = $1 AND tenant_id = $2 AND billed_at IS NULL RETURNING id",
                )
                .bind(item.id)
                .bind(tenant_id)
                .fetch_optional(&mut *tx)
                .await?;
                if claimed.is_none() {
                    return Ok(None);
                }
            }
            sqlx::query(
                r#"
                INSERT INTO invoice_lines (
                    id, invoice_id, line_type, description, quantity, unit_price,
                    total, sort_order, product_id
                )
                VALUES ($1, $2, 'service', $3, $4, $5, $6, $7, $8)
                "#,
            )
            .bind(Uuid::new_v4())
            .bind(invoice_id)
            .bind(&item.name)
            .bind(item.quantity)
            .bind(item.unit_price)
            .bind(item.quantity * item.unit_price)
            .bind(idx as i32)
            // PMS-955: the item's catalog link travels onto the line it
            // becomes. The PRICE does not: `item.unit_price` is what the
            // contract agreed, and re-reading the catalog here would re-price
            // a signed contract every time somebody edited the price list.
            .bind(item.product_id)
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
        tenant_id: TenantId,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<TaxRateResponse>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tax_rates WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_one(&mut *tx)
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
        .fetch_all(&mut *tx)
        .await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    /// PMS-41: create a tax rate. If `is_default = true`, demote any
    /// existing default first so only one rate is the tenant default.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_tax_rate(
        &self,
        tenant_id: TenantId,
        request: &UpsertTaxRateRequest,
        ctx: &AuditCtx,
    ) -> AppResult<TaxRateResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
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
        tenant_id: TenantId,
        id: Uuid,
        request: &UpsertTaxRateRequest,
        ctx: &AuditCtx,
    ) -> AppResult<TaxRateResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
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
            return Err(AppError::NotFound("Tax rate".to_string()));
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
        tenant_id: TenantId,
        id: Uuid,
        ctx: &AuditCtx,
    ) -> AppResult<()> {
        // Mutation + audit row in one transaction. DELETE: snapshot
        // before, old = before, after = None. PMS-117.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
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
            return Err(AppError::NotFound("Tax rate".to_string()));
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
        tenant_id: TenantId,
        jurisdiction: &str,
    ) -> AppResult<TaxRateResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
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
        .fetch_optional(&mut *tx)
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
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::NotFound("Tax rate".to_string()))?;
        Ok(fallback.into())
    }

    /// PMS-40 / PMS-342: list payment gateway configs for the tenant. The
    /// stored credential is a write-only secret, so the response carries only
    /// non-secret metadata plus `configured` (whether a secret is stored). The
    /// decrypted config is never returned; decryption stays server-internal for
    /// actual gateway calls.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_payment_gateways(
        &self,
        tenant_id: TenantId,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<PaymentGatewayConfigResponse>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM payment_gateway_configs WHERE tenant_id = $1")
                .bind(tenant_id)
                .fetch_one(&mut *tx)
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
        .fetch_all(&mut *tx)
        .await?;

        let gateways: Vec<PaymentGatewayConfigResponse> = rows
            .into_iter()
            .map(|r| PaymentGatewayConfigResponse {
                id: r.id,
                provider: GatewayProvider::from_str(&r.provider).unwrap_or(GatewayProvider::Stripe),
                is_active: r.is_active,
                is_test_mode: r.is_test_mode,
                // PMS-968: NULL means the credential is in the secret store,
                // so the row is configured. Non-NULL and non-empty is the
                // pre-move state and equally configured. Only an empty string
                // would not be, and nothing writes one.
                configured: r.config_encrypted.as_ref().is_none_or(|c| !c.is_empty()),
            })
            .collect();

        Ok((gateways, total as u64))
    }

    /// PMS-40 / PMS-342: upsert a payment gateway config. `(tenant_id,
    /// provider)` is unique in the schema, so the same call ends up
    /// insert-or-update. The credential is write-only: when `config` is
    /// provided it is encrypted at rest with the host key and replaces the
    /// stored secret; when omitted it preserves the existing secret (and is
    /// required when creating a gateway for the first time). The decrypted
    /// secret is never echoed back.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn upsert_payment_gateway(
        &self,
        tenant_id: TenantId,
        request: &UpsertPaymentGatewayConfigRequest,
        ctx: &AuditCtx,
    ) -> AppResult<PaymentGatewayConfigResponse> {
        // PMS-966: refuse to ACTIVATE a provider this build cannot serve.
        //
        // The column's CHECK and `GatewayProvider` both accept `paypal` and
        // `authorize_net`, so this call used to store an active config that
        // every resolution path then skipped: no checkout, no Pay Now button,
        // and nothing anywhere saying why. Answering here is the only point
        // where the operator is present to be told.
        //
        // Activation only, not storage. Saving credentials ahead of support
        // costs nothing and is refused by no rule; switching on something that
        // will never mint a checkout session is the part that lies.
        if request.is_active && !provider::is_supported(request.provider.as_str()) {
            return Err(AppError::BadRequest(format!(
                "Payment provider '{}' cannot be activated: it is not implemented. Supported: {}",
                request.provider.as_str(),
                provider::SUPPORTED.join(", ")
            )));
        }

        // PMS-968: a supplied credential goes to the configured secret store,
        // and the row records only that it is there. `None` still means "keep
        // the existing secret" (write-only update semantics, PMS-342).
        //
        // The store write happens BEFORE the row is touched, and that order is
        // load-bearing. The two are not one transaction, because the store may
        // be Infisical, so one of them can succeed alone. Store-first fails as
        // an orphaned secret with the row still holding whatever it held, which
        // keeps working; row-first fails as a row claiming its credential is in
        // a store that never received it, which is an integration that cannot
        // charge and cannot say why. Same rule as PMS-960's mover: the record
        // follows the thing it describes.
        let stored_in_secret_store = match request.config.as_ref() {
            Some(config) => {
                let plaintext = serde_json::to_string(config).map_err(|e| {
                    AppError::BadRequest(format!("Config must serialise to JSON: {e}"))
                })?;
                let key = crate::secrets::SecretKey::payment_gateway(
                    tenant_id.get(),
                    request.provider.as_str(),
                );
                self.secrets.put(&key, &plaintext).await?;
                true
            }
            None => false,
        };

        // Mutation + audit row in one transaction. PMS-117. The secret
        // `config_encrypted` column is subtracted from both snapshots so
        // the audit trail never stores the encrypted blob. The action is
        // Update when a row for `(tenant_id, provider)` already existed
        // (this is an INSERT .. ON CONFLICT upsert), else Create; the
        // `before` snapshot doubles as the existence check.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
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

        // PMS-969: one active gateway per tenant, enforced here rather than
        // resolved later. `payment_gateway_configs` is UNIQUE on (tenant,
        // provider) and not on the tenant, so nothing in the schema stops two
        // rows being active at once, and `select_serveable` refuses a tenant
        // in that state outright rather than guessing which one a customer's
        // money should go to. PMS-966 deferred this to the change that makes
        // two serveable actives possible, which is the second provider.
        //
        // Activating this provider deactivates the others in the same
        // transaction; deactivating it touches nothing else. The rows that
        // flip are logged by provider, not audited row-by-row: the audit entry
        // below is for the row the caller named, and a per-sibling entry is a
        // follow-up if it turns out to be wanted.
        if request.is_active {
            let flipped: Vec<String> = sqlx::query_scalar(
                "UPDATE payment_gateway_configs \
                 SET is_active = FALSE, updated_at = NOW() \
                 WHERE tenant_id = $1 AND provider <> $2 AND is_active = TRUE \
                 RETURNING provider",
            )
            .bind(tenant_id)
            .bind(request.provider.as_str())
            .fetch_all(&mut *tx)
            .await?;
            if !flipped.is_empty() {
                tracing::info!(
                    target: "mokosh_server.billing",
                    activated = request.provider.as_str(),
                    deactivated = ?flipped,
                    "one active payment gateway per tenant: siblings deactivated"
                );
            }
        }

        // A brand-new gateway must carry a config: there is no existing secret
        // to preserve.
        let id: Uuid = if stored_in_secret_store {
            {
                sqlx::query_scalar(
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
                // NULL: the credential is in the secret store now, at the
                // address this row's own (tenant_id, provider) gives.
                .bind(Option::<String>::None)
                .fetch_one(&mut *tx)
                .await?
            }
        } else {
            {
                if before.is_none() {
                    return Err(AppError::BadRequest(
                        "Config is required when first configuring a gateway".to_string(),
                    ));
                }
                // Preserve the stored secret: update metadata only, leave
                // `config_encrypted` untouched.
                sqlx::query_scalar(
                    r#"
                    UPDATE payment_gateway_configs
                    SET is_active    = $3,
                        is_test_mode = $4,
                        updated_at   = NOW()
                    WHERE tenant_id = $1 AND provider = $2
                    RETURNING id
                    "#,
                )
                .bind(tenant_id)
                .bind(request.provider.as_str())
                .bind(request.is_active)
                .bind(request.is_test_mode)
                .fetch_one(&mut *tx)
                .await?
            }
        };

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

        // After an upsert a secret is always stored (either the new one or the
        // preserved existing one), so the gateway is configured.
        Ok(PaymentGatewayConfigResponse {
            id,
            provider: request.provider,
            is_active: request.is_active,
            is_test_mode: request.is_test_mode,
            configured: true,
        })
    }

    /// PMS-40: delete a payment gateway config. No-op if absent.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_payment_gateway(
        &self,
        tenant_id: TenantId,
        provider: GatewayProvider,
        ctx: &AuditCtx,
    ) -> AppResult<()> {
        // Mutation + audit row in one transaction. DELETE: snapshot
        // before (minus the secret `config_encrypted` blob), old =
        // before, after = None. PMS-117. The delete keys on `provider`
        // (the unique `(tenant_id, provider)` pair), so read the row id
        // for the audit `entity_id`. No-op when absent (no row -> no
        // audit entry), preserving the original idempotent behaviour.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
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

        // PMS-968: the credential goes with the row. Deleting the row and
        // leaving the secret would keep a disconnected tenant's live API key in
        // the store indefinitely, and a later reconnect would silently inherit
        // it. This runs after the DELETE, matching `SecretStore::delete` being
        // best-effort: the row is the thing that points at the secret, so a
        // secret with no row is orphaned rather than dangerous, whereas a row
        // whose secret is already gone cannot serve a payment.
        self.secrets
            .delete(&crate::secrets::SecretKey::payment_gateway(
                tenant_id.get(),
                provider.as_str(),
            ))
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

    // ========================================================================
    // PMS-711: Stripe "Pay Now" - checkout sessions + webhook reconciliation.
    // ========================================================================

    /// Recover a gateway's credential, from wherever this row keeps it.
    ///
    /// PMS-968: a non-NULL `config_encrypted` is the pre-move state and is
    /// decrypted here; NULL means the credential is in the secret store, at the
    /// address the row's own `(tenant_id, provider)` gives. Both states are
    /// live at once on a deployment the mover has not finished, which is the
    /// point of keeping them distinguishable.
    ///
    /// A NULL column with nothing in the store is a hard error and never a
    /// missing-gateway `None`. The row asserts a credential exists; if it does
    /// not, something moved half-way, and answering "not configured" would turn
    /// that into a payment integration that silently switched itself off.
    async fn gateway_plaintext(
        &self,
        tenant_id: Uuid,
        provider_id: &str,
        config_encrypted: Option<String>,
    ) -> AppResult<String> {
        match config_encrypted {
            Some(ciphertext) => crate::utils::crypto::decrypt(&ciphertext, &self.encryption_key),
            None => {
                let key = crate::secrets::SecretKey::payment_gateway(tenant_id, provider_id);
                self.secrets.get(&key).await?.ok_or_else(|| {
                    AppError::Configuration(format!(
                        "gateway {provider_id:?} says its credential is in the secret store, but the store has none"
                    ))
                })
            }
        }
    }

    /// Build the provider a resolved row names.
    ///
    /// The plaintext never leaves this function as data returned to a client
    /// (PMS-342).
    async fn build_provider(
        &self,
        tenant_id: Uuid,
        provider_id: &str,
        config_encrypted: Option<String>,
    ) -> AppResult<Box<dyn PaymentProvider>> {
        let plaintext = self
            .gateway_plaintext(tenant_id, provider_id, config_encrypted)
            .await?;
        provider::build(provider_id, &plaintext, self.http.clone())
    }

    /// Pick the one active gateway this build can serve out of a tenant's rows.
    ///
    /// `payment_gateway_configs` is `UNIQUE (tenant_id, provider)`, not unique
    /// on the tenant, and `is_active` has no partial index behind it, so a
    /// tenant may legitimately hold an active row per provider. Filtering to
    /// the supported set is what makes today's behaviour identical to the
    /// `provider = 'stripe'` literal this replaced: a stored `paypal` row was
    /// invisible then and is skipped now.
    ///
    /// Two supported actives is a real ambiguity rather than a row to pick
    /// from, so it is refused. It is unreachable today, because `SUPPORTED`
    /// holds one entry; PMS-969 is what makes it reachable, and enforcing one
    /// active gateway per tenant at write time belongs with that change.
    fn select_serveable(
        rows: Vec<(String, Option<String>)>,
    ) -> AppResult<Option<(String, Option<String>)>> {
        let mut serveable: Vec<(String, Option<String>)> = rows
            .into_iter()
            .filter(|(id, _)| provider::is_supported(id))
            .collect();
        match serveable.len() {
            0 => Ok(None),
            1 => Ok(Some(serveable.remove(0))),
            _ => {
                serveable.sort_by(|a, b| a.0.cmp(&b.0));
                let names: Vec<&str> = serveable.iter().map(|(id, _)| id.as_str()).collect();
                Err(AppError::Configuration(format!(
                    "tenant has {} active payment gateways ({}); exactly one may be active",
                    names.len(),
                    names.join(", ")
                )))
            }
        }
    }

    /// Load the tenant's ACTIVE payment provider over the tenant-scoped serving
    /// connection. Used by the authenticated checkout path, where the caller's
    /// tenant is already established, so the read runs through
    /// `begin_with_tenant` like every other serving read.
    async fn active_provider(
        &self,
        tenant_id: TenantId,
    ) -> AppResult<Option<Box<dyn PaymentProvider>>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows: Vec<(String, Option<String>)> = sqlx::query_as(
            "SELECT provider, config_encrypted FROM payment_gateway_configs \
             WHERE tenant_id = $1 AND is_active = TRUE",
        )
        .bind(tenant_id)
        .fetch_all(&mut *tx)
        .await?;
        match Self::select_serveable(rows)? {
            Some((id, enc)) => Ok(Some(self.build_provider(tenant_id.into(), &id, enc).await?)),
            None => Ok(None),
        }
    }

    /// Whether the tenant has an active gateway this build can serve. Cheap
    /// existence check used to decide whether the outbound invoice email
    /// carries a Pay Now button (PMS-711).
    ///
    /// "Can serve" and not merely "is configured": a Pay Now button on an
    /// unserveable gateway is a link to a 400, sent to the customer being asked
    /// to pay. It reads the same set `active_provider` resolves from, so the
    /// button and the checkout it leads to cannot disagree.
    pub async fn has_active_gateway(&self, tenant_id: TenantId) -> AppResult<bool> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let providers: Vec<String> = sqlx::query_scalar(
            "SELECT provider FROM payment_gateway_configs \
             WHERE tenant_id = $1 AND is_active = TRUE",
        )
        .bind(tenant_id)
        .fetch_all(&mut *tx)
        .await?;
        Ok(providers.iter().any(|id| provider::is_supported(id)))
    }

    /// Build a Stripe provider scoped to the tenant's ACTIVE gateway for the
    /// inbound-webhook path. Returns `None` when the tenant has no active Stripe
    /// config (so the handler answers 404 without confirming a tenant exists).
    ///
    /// SAFETY (PMS-285 / PMS-692): the Stripe webhook is pre-auth - the caller
    /// is Stripe, not a mokosh session, and the request is only trusted AFTER
    /// its signature verifies against the secret this read returns. There is no
    /// authenticated tenant to set as the `app.current_tenant` GUC yet, so this
    /// single credential lookup runs on the BYPASSRLS `migrator_pool`, keyed by
    /// the `tenant_id` from the webhook URL path. `payment_gateway_configs` is
    /// RLS-covered and would fail closed on the unprivileged app pool here.
    pub async fn provider_for_webhook(
        &self,
        tenant_id: Uuid,
    ) -> AppResult<Option<Box<dyn PaymentProvider>>> {
        let rows: Vec<(String, Option<String>)> = sqlx::query_as(
            "SELECT provider, config_encrypted FROM payment_gateway_configs \
             WHERE tenant_id = $1 AND is_active = TRUE",
        )
        .bind(tenant_id)
        .fetch_all(self.db.migrator_pool())
        .await?;
        match Self::select_serveable(rows)? {
            Some((id, enc)) => Ok(Some(self.build_provider(tenant_id, &id, enc).await?)),
            None => Ok(None),
        }
    }

    /// PMS-711: create a hosted checkout session for an invoice's outstanding
    /// balance. Fails 400 when the tenant has no active Stripe gateway, when the
    /// invoice has nothing left to pay, or when the invoice is void / written
    /// off. The payer is redirected to the returned `url`; the payment is
    /// reconciled later by the webhook, not by this call.
    pub async fn create_invoice_checkout_session(
        &self,
        tenant_id: TenantId,
        invoice_id: Uuid,
        success_url: &str,
        cancel_url: &str,
    ) -> AppResult<CheckoutSession> {
        let invoice = self.get_invoice(tenant_id, invoice_id).await?;
        if matches!(
            invoice.status,
            InvoiceStatus::Void | InvoiceStatus::WrittenOff
        ) {
            return Err(AppError::Conflict(format!(
                "Invoice {} cannot be paid in status '{}'",
                invoice.invoice_number,
                invoice.status.as_str()
            )));
        }
        if invoice.balance_due <= Decimal::ZERO {
            return Err(AppError::BadRequest(
                "Invoice has no outstanding balance to pay".to_string(),
            ));
        }
        let Some(provider) = self.active_provider(tenant_id).await? else {
            return Err(AppError::BadRequest(
                "No active payment provider is configured for this account".to_string(),
            ));
        };

        // Prefer the invoice's billing contact email so the checkout page is
        // pre-filled; absent that, leave it for the payer to enter.
        let customer_email = match invoice.billing_contact_id {
            Some(cid) => self
                .billing_contact_email(tenant_id, cid)
                .await?
                .and_then(|(email, _)| email),
            None => None,
        };

        let currency = invoice.currency.as_deref().unwrap_or("USD");
        let params = CheckoutParams {
            tenant_id: tenant_id.get(),
            invoice_id,
            invoice_number: &invoice.invoice_number,
            amount: invoice.balance_due,
            currency,
            success_url,
            cancel_url,
            customer_email: customer_email.as_deref(),
        };
        provider.create_checkout_session(&params).await
    }

    /// PMS-711: record a gateway-confirmed payment from a verified webhook.
    /// Idempotent on the provider reference (the unique partial index on
    /// `payments(tenant_id, gateway_transaction_id)`): a redelivered event
    /// inserts nothing and returns `Ok(false)`. On first sight it inserts the
    /// `payments` row (method `credit_card`, `gateway_transaction_id` = the
    /// provider reference, `gateway_response` = the raw event, `currency`
    /// recorded) under the invoice row lock and recomputes the invoice's
    /// payment state, returning `Ok(true)`.
    pub async fn record_gateway_payment(
        &self,
        tenant_id: TenantId,
        invoice_id: Uuid,
        provider_reference: &str,
        amount: Decimal,
        currency: &str,
        raw: &serde_json::Value,
    ) -> AppResult<bool> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        // Lock the invoice so this read-modify-write serialises with manual
        // payments and concurrent webhook deliveries (PMS-695).
        if Self::lock_invoice_totals(&mut tx, tenant_id, invoice_id)
            .await?
            .is_none()
        {
            // Invoice deleted between checkout and webhook. Nothing to
            // reconcile; report handled so the provider stops retrying.
            return Ok(false);
        }

        let payment_id = Uuid::new_v4();
        let inserted: Option<Uuid> = sqlx::query_scalar(
            r#"
            INSERT INTO payments (
                id, tenant_id, invoice_id, company_id, payment_date, amount,
                currency, payment_method, gateway_transaction_id, gateway_response
            )
            SELECT $1, $2, $3, i.company_id, CURRENT_DATE, $4, $5, 'credit_card', $6, $7
            FROM invoices i
            WHERE i.id = $3 AND i.tenant_id = $2
            ON CONFLICT (tenant_id, gateway_transaction_id)
                WHERE gateway_transaction_id IS NOT NULL DO NOTHING
            RETURNING id
            "#,
        )
        .bind(payment_id)
        .bind(tenant_id)
        .bind(invoice_id)
        .bind(amount)
        .bind(currency)
        .bind(provider_reference)
        .bind(raw)
        .fetch_optional(&mut *tx)
        .await?;

        let Some(payment_id) = inserted else {
            // Already recorded by a prior delivery. Idempotent no-op.
            return Ok(false);
        };

        Self::recompute_invoice_balance(&mut tx, tenant_id, invoice_id).await?;

        // Audit row in the same transaction; no user actor (the trigger is
        // Stripe's dispatcher). Secret `gateway_response` blob is subtracted.
        let ctx = AuditCtx::system(tenant_id.get());
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
            &ctx,
            AuditAction::Create,
            "payments",
            Some(payment_id),
            None,
            after,
        )
        .await?;

        tx.commit().await?;
        Ok(true)
    }

    /// PMS-711: record one or more refunds from a verified `charge.refunded`
    /// webhook. Each refund is idempotent on its provider reference (the unique
    /// `payment_refunds(tenant_id, provider_reference)`), so redelivery and
    /// incremental partial refunds both converge. Finds the originating payment
    /// by its `gateway_transaction_id` (the charge's payment_intent); a refund
    /// for a charge mokosh never recorded is a logged no-op (the provider may
    /// refund a payment taken outside mokosh). Recomputes the invoice's net
    /// payment state after inserting.
    pub async fn record_gateway_refunds(
        &self,
        tenant_id: TenantId,
        provider_reference: &str,
        currency: &str,
        refunds: &[super::provider::RefundLine],
        raw: &serde_json::Value,
    ) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;

        // Resolve the payment this charge refers to, and its invoice.
        let payment: Option<(Uuid, Option<Uuid>)> = sqlx::query_as(
            "SELECT id, invoice_id FROM payments \
             WHERE tenant_id = $1 AND gateway_transaction_id = $2",
        )
        .bind(tenant_id)
        .bind(provider_reference)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((payment_id, invoice_id)) = payment else {
            tracing::warn!(
                target: "mokosh_server.billing",
                %provider_reference,
                "charge.refunded for a payment_intent not recorded in mokosh; ignoring"
            );
            return Ok(());
        };

        // Take the invoice lock first (same order as every other payment-state
        // mutation) so the recompute below is serialised.
        if let Some(inv) = invoice_id {
            Self::lock_invoice_totals(&mut tx, tenant_id, inv).await?;
        }

        for refund in refunds {
            sqlx::query(
                r#"
                INSERT INTO payment_refunds (
                    id, tenant_id, payment_id, invoice_id, amount, currency,
                    provider, provider_reference, gateway_response
                )
                VALUES ($1, $2, $3, $4, $5, $6, 'stripe', $7, $8)
                ON CONFLICT (tenant_id, provider_reference) DO NOTHING
                "#,
            )
            .bind(Uuid::new_v4())
            .bind(tenant_id)
            .bind(payment_id)
            .bind(invoice_id)
            .bind(refund.amount)
            .bind(currency)
            .bind(&refund.provider_reference)
            .bind(raw)
            .execute(&mut *tx)
            .await?;
        }

        if let Some(inv) = invoice_id {
            Self::recompute_invoice_balance(&mut tx, tenant_id, inv).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Resolve a billing contact to `(email, first_name)`, tenant-scoped. Used
    /// to pre-fill the checkout page and address the Pay Now email (PMS-711).
    async fn billing_contact_email(
        &self,
        tenant_id: TenantId,
        contact_id: Uuid,
    ) -> AppResult<Option<(Option<String>, Option<String>)>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: Option<(Option<String>, String)> = sqlx::query_as(
            "SELECT email, first_name FROM contacts WHERE id = $1 AND tenant_id = $2",
        )
        .bind(contact_id)
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await?;
        Ok(row.map(|(email, first)| (email, Some(first))))
    }

    /// PMS-39: list payments. Optional filter on invoice_id and/or
    /// company_id.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_payments(
        &self,
        tenant_id: TenantId,
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
        let order_by = pagination.order_by("payment_date", mokosh_types::sort::PAYMENTS)?;
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
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows = q.fetch_all(&mut *tx).await?;
        let total = cq.fetch_one(&mut *tx).await?;
        drop(tx);
        let mut resp: Vec<PaymentResponse> = rows.into_iter().map(Into::into).collect();
        self.enrich_payments(tenant_id, &mut resp).await?;
        Ok((resp, total as u64))
    }

    /// PMS-39: record a payment. When `invoice_id` is set, the linked
    /// invoice's `amount_paid` is bumped and `balance_due` recomputed
    /// in the same transaction; the status moves to `paid` (or
    /// `partially_paid`) accordingly.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_payment(
        &self,
        tenant_id: TenantId,
        request: &CreatePaymentRequest,
        ctx: &AuditCtx,
    ) -> AppResult<PaymentResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;

        // PMS-695: take the invoice row lock before anything else, so the
        // whole read-modify-write is serialised and an overpayment rejection
        // does not have to unwind an already-inserted payment row.
        if let Some(invoice_id) = request.invoice_id {
            let Some((total, prior_paid)) =
                Self::lock_invoice_totals(&mut tx, tenant_id, invoice_id).await?
            else {
                return Err(AppError::NotFound("Invoice".to_string()));
            };
            // Reject overpayment so `balance_due` never goes negative
            // (PMS-194). The remaining balance is `total - prior_paid`; a
            // payment larger than that is a data-integrity error, not a
            // valid partial/full payment.
            let remaining = total - prior_paid;
            if request.amount > remaining {
                return Err(AppError::BadRequest(format!(
                    "Payment amount {} exceeds invoice balance due {}",
                    request.amount, remaining
                )));
            }
        }

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
            Self::recompute_invoice_balance(&mut tx, tenant_id, invoice_id).await?;
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
        let company_name = self
            .company_name_map(tenant_id, &[request.company_id])
            .await?
            .remove(&request.company_id);
        let invoice_number = match request.invoice_id {
            Some(id) => self.invoice_number_map(tenant_id, &[id]).await?.remove(&id),
            None => None,
        };
        Ok(PaymentResponse {
            id: payment_id,
            tenant_id: tenant_id.get(),
            invoice_id: request.invoice_id,
            invoice_number,
            company_id: request.company_id,
            company_name,
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
        tenant_id: TenantId,
        payment_id: Uuid,
        ctx: &AuditCtx,
    ) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;

        let row: Option<(Option<Uuid>,)> =
            sqlx::query_as("SELECT invoice_id FROM payments WHERE id = $1 AND tenant_id = $2")
                .bind(payment_id)
                .bind(tenant_id)
                .fetch_optional(&mut *tx)
                .await?;
        let Some((invoice_id,)) = row else {
            return Err(AppError::NotFound("Payment".to_string()));
        };

        // PMS-695: lock the invoice before removing the payment row, in the
        // same order `create_payment` takes it, so a delete racing a create
        // queues instead of losing one of the two updates.
        if let Some(invoice_id) = invoice_id {
            Self::lock_invoice_totals(&mut tx, tenant_id, invoice_id).await?;
        }

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
            Self::recompute_invoice_balance(&mut tx, tenant_id, invoice_id).await?;
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
        tenant_id: TenantId,
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

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;

        // PMS-695: this path also rewrites `balance_due` and `status` from a
        // read of `amount_paid`, so it takes the same invoice row lock as the
        // payment paths and re-reads both under it. The pre-transaction
        // `get_invoice` above is only a fast-path guard; a payment committed
        // between it and here would otherwise be written back out.
        let locked: Option<(Decimal, String)> = sqlx::query_as(
            "SELECT amount_paid, status FROM invoices \
             WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
        )
        .bind(invoice_id)
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((amount_paid, locked_status)) = locked else {
            return Err(AppError::NotFound("Invoice".to_string()));
        };
        let locked_status = InvoiceStatus::from_str(&locked_status).unwrap_or(InvoiceStatus::Draft);
        if locked_status.is_frozen() {
            return Err(AppError::Conflict(format!(
                "Invoice in status '{}' cannot be edited",
                locked_status.as_str()
            )));
        }

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
            // PMS-955: same check as the create path, and before the DELETE
            // below, so a rejected link cannot take the existing lines with it.
            for line in lines {
                if let Some(product_id) = line.product_id {
                    Self::assert_product_sellable(&mut tx, tenant_id, product_id).await?;
                }
            }
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
                        unit_price, total, ticket_id, project_id, sort_order,
                        product_id
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
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
                .bind(line.product_id)
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
        let balance_due = total - amount_paid;

        // `sent_at` is stamped when the status first moves to `sent`.
        let status = request.status.unwrap_or(locked_status);
        let sent_at = if matches!(status, InvoiceStatus::Sent) && current.sent_at.is_none() {
            Some(Utc::now())
        } else {
            current.sent_at
        };

        if let Some(pt) = request.payment_term_id {
            Self::assert_payment_term_in_tenant(&mut tx, tenant_id, pt).await?;
        }
        // PMS-990: a term change with no due date re-derives the due date
        // from the (possibly updated) invoice date, because an invoice moved
        // from Net 30 to Net 15 that kept its old due date would carry a term
        // its own dates contradict. A given due date always wins, and an
        // update that leaves the term alone leaves the date alone.
        let due_date = match (request.payment_term_id, request.due_date) {
            (Some(term), None) => {
                let invoice_date = request.invoice_date.unwrap_or(current.invoice_date);
                Some(
                    Self::resolve_due_date(&mut tx, tenant_id, invoice_date, Some(term), None)
                        .await?
                        .0,
                )
            }
            (_, given) => given,
        };

        // PMS-911: the MSP's identity as it stands right now, frozen onto the
        // invoice on the transition that freezes the invoice. In this
        // transaction and not in the `just_sent` hook below it, because that
        // hook is post-commit and best-effort: an invoice must never freeze
        // carrying no identity.
        let issuer_snapshot = if matches!(status, InvoiceStatus::Sent) && current.sent_at.is_none()
        {
            Some(Self::freeze_issuer(&mut tx, tenant_id).await?)
        } else {
            None
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
                payment_term_id    = COALESCE($16, payment_term_id),
                -- PMS-911: COALESCE so it is written once, on the send that
                -- freezes the invoice, and never overwritten by a later update.
                -- A snapshot that could be rewritten would be no snapshot.
                issuer_snapshot    = COALESCE(issuer_snapshot, $17),
                updated_at         = NOW()
            WHERE id = $1
            "#,
        )
        .bind(invoice_id)
        .bind(request.billing_contact_id)
        .bind(request.contract_id)
        .bind(request.invoice_date)
        .bind(due_date)
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
        .bind(request.payment_term_id)
        .bind(
            issuer_snapshot
                .as_ref()
                .map(serde_json::to_value)
                .transpose()
                .map_err(|e| AppError::Internal(format!("issuer snapshot: {e}")))?,
        )
        .execute(&mut *tx)
        .await?;

        // PMS-959: the document the client receives, kept as it was sent.
        //
        // Inside this transaction and after the UPDATE, so it renders the
        // invoice that is about to commit rather than what a second connection
        // could see, and so an invoice cannot reach `sent` without one. Storing
        // it afterwards would leave exactly that gap; storing it before the row
        // lock would let a concurrent edit make the document disagree with the
        // invoice.
        //
        // Regenerating later would ALMOST work - branding is frozen (PMS-911)
        // and `pdf::render` is deterministic - which is precisely the trap.
        // What a re-render cannot survive is an edit to the renderer or the
        // document layout, at which point every past invoice quietly reprints
        // differently. These bytes are insurance against this codebase
        // changing.
        if let Some(issuer) = &issuer_snapshot {
            let document = Self::load_invoice(&mut tx, tenant_id, invoice_id).await?;
            let logo = crate::modules::billing::issuer::logo_bytes(tenant_id.get(), issuer).await;
            let bytes = crate::pdf::render(&crate::modules::billing::documents::invoice(
                &document, issuer, logo,
            ))?;
            crate::modules::billing::documents::store_issued(
                &mut tx,
                tenant_id.get(),
                invoice_id,
                &document.invoice_number,
                "invoice_document",
                &bytes,
            )
            .await?;
        }

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

        // PMS-711: on the first send transition, email the billing contact a
        // "Pay Now" link. Best-effort and post-commit: a mail failure must not
        // undo the status change. No-op unless this instance carries a mailer
        // (agent-facing only), the invoice actually just moved to `sent`, and
        // the tenant has an active payment gateway.
        let just_sent = matches!(status, InvoiceStatus::Sent) && current.sent_at.is_none();
        if just_sent {
            self.notify_invoice_pay_now(tenant_id, invoice_id).await;
        }

        self.get_invoice(tenant_id, invoice_id).await
    }

    /// PMS-911: read the tenant's live branding and freeze it.
    ///
    /// `tenants` is the isolation root and is RLS-exempt (migration 038), so
    /// this reads it through the caller's own transaction with the tenant id in
    /// the predicate rather than needing a privileged pool.
    ///
    /// The logo store is built from the environment here rather than injected,
    /// the way every other consumer of `crate::storage` does it, so this does
    /// not widen a constructor that four call sites already use.
    async fn freeze_issuer(
        tx: &mut crate::db::TenantTransaction<'_>,
        tenant_id: TenantId,
    ) -> AppResult<crate::modules::billing::issuer::Issuer> {
        let row: Option<(String, serde_json::Value)> =
            sqlx::query_as("SELECT name, branding FROM tenants WHERE id = $1")
                .bind(tenant_id)
                .fetch_optional(&mut **tx)
                .await?;
        let (name, branding) = row.ok_or_else(|| AppError::NotFound("Tenant".to_string()))?;
        // A branding document that will not destructure is an empty one, not a
        // failure: an unreadable logo colour must not stop an invoice being
        // sent.
        let branding: mokosh_types::tenants::TenantBranding =
            serde_json::from_value(branding).unwrap_or_default();
        let logos = crate::modules::tenants::logo::TenantLogoStore::new(
            crate::modules::tenants::logo::TenantLogoConfig::from_env(),
        );
        Ok(
            crate::modules::billing::issuer::freeze(tenant_id.get(), &name, &branding, &logos)
                .await,
        )
    }

    /// PMS-911: the identity a rendered invoice should show.
    ///
    /// The frozen snapshot when there is one, and the tenant's live branding
    /// when there is not - which is every invoice sent before PMS-911, and
    /// every draft. A draft resolving live is right: it has not been sent, so
    /// there is nothing to preserve yet.
    pub async fn invoice_issuer(
        &self,
        tenant_id: TenantId,
        invoice_id: Uuid,
    ) -> AppResult<crate::modules::billing::issuer::Issuer> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let snapshot: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT issuer_snapshot FROM invoices WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(invoice_id)
        .fetch_optional(&mut *tx)
        .await?
        .flatten();
        if let Some(value) = snapshot {
            if let Ok(issuer) = serde_json::from_value(value) {
                return Ok(issuer);
            }
        }
        let row: Option<(String, serde_json::Value)> =
            sqlx::query_as("SELECT name, branding FROM tenants WHERE id = $1")
                .bind(tenant_id)
                .fetch_optional(&mut *tx)
                .await?;
        let (name, branding) = row.ok_or_else(|| AppError::NotFound("Tenant".to_string()))?;
        let branding: mokosh_types::tenants::TenantBranding =
            serde_json::from_value(branding).unwrap_or_default();
        Ok(crate::modules::billing::issuer::resolve(&name, &branding))
    }

    /// PMS-911: the tenant's identity as it stands now, for a document that is
    /// not snapshotted (the statement).
    pub async fn tenant_issuer(
        &self,
        tenant_id: TenantId,
    ) -> AppResult<crate::modules::billing::issuer::Issuer> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        Self::tenant_issuer_in_tx(&mut tx, tenant_id).await
    }

    /// The same read, in a transaction the caller owns (PMS-959), for the
    /// credit-note document rendered inside its creating transaction.
    async fn tenant_issuer_in_tx(
        tx: &mut crate::db::TenantTransaction<'_>,
        tenant_id: TenantId,
    ) -> AppResult<crate::modules::billing::issuer::Issuer> {
        let row: Option<(String, serde_json::Value)> =
            sqlx::query_as("SELECT name, branding FROM tenants WHERE id = $1")
                .bind(tenant_id)
                .fetch_optional(&mut **tx)
                .await?;
        let (name, branding) = row.ok_or_else(|| AppError::NotFound("Tenant".to_string()))?;
        let branding: mokosh_types::tenants::TenantBranding =
            serde_json::from_value(branding).unwrap_or_default();
        Ok(crate::modules::billing::issuer::resolve(&name, &branding))
    }

    /// PMS-711: best-effort outbound invoice "Pay Now" email. Short-circuits
    /// when this service instance has no mailer/origin, when the tenant has no
    /// active gateway (a Pay Now button would be dead), or when the invoice has
    /// no billing contact with an email. Every failure is logged, never
    /// propagated: the caller has already committed the send.
    async fn notify_invoice_pay_now(&self, tenant_id: TenantId, invoice_id: Uuid) {
        let (Some(mailer), Some(origin)) = (self.mailer.as_ref(), self.portal_origin.as_ref())
        else {
            return;
        };
        // Only offer online payment when a gateway is actually connected.
        match self.has_active_gateway(tenant_id).await {
            Ok(true) => {}
            Ok(false) => return,
            Err(e) => {
                tracing::warn!(target: "mokosh_server.billing", error = %e, "pay-now email: gateway check failed");
                return;
            }
        }
        let invoice = match self.get_invoice(tenant_id, invoice_id).await {
            Ok(inv) => inv,
            Err(e) => {
                tracing::warn!(target: "mokosh_server.billing", error = %e, "pay-now email: invoice reload failed");
                return;
            }
        };
        let Some(contact_id) = invoice.billing_contact_id else {
            return;
        };
        let email = match self.billing_contact_email(tenant_id, contact_id).await {
            Ok(Some((Some(email), _))) => email,
            Ok(_) => return, // no contact, or contact has no email on file
            Err(e) => {
                tracing::warn!(target: "mokosh_server.billing", error = %e, "pay-now email: contact lookup failed");
                return;
            }
        };
        let base = origin.trim_end_matches('/');
        let link = format!("{base}/portal/invoices/{invoice_id}");
        let currency = invoice.currency.as_deref().unwrap_or("USD");
        let amount_due = format!("{} {}", invoice.balance_due, currency);
        let due_date = invoice.due_date.to_string();

        // PMS-761: an email asking someone to pay has to say who is asking.
        // Skipped rather than sent anonymously if the identity cannot be read:
        // the invoice is already visible in the portal, and an unattributed
        // payment request is the shape of invoice fraud.
        let org = match crate::modules::tenants::OrgIdentity::load(&self.db, tenant_id).await {
            Ok(org) => org,
            Err(e) => {
                tracing::warn!(
                    target: "mokosh_server.billing", error = %e,
                    "pay-now email: organisation identity unreadable, not sending",
                );
                return;
            }
        };
        let contact_line = org.contact_line("Questions about this invoice?", None);
        let from = crate::utils::email::SenderIdentity {
            org_name: org.name(),
            contact_line: &contact_line,
        };

        if let Err(e) = mailer
            .send_invoice_pay_now(
                &email,
                from,
                crate::utils::email::InvoicePayNow {
                    invoice_number: &invoice.invoice_number,
                    amount_due: &amount_due,
                    due_date: &due_date,
                    portal_link: &link,
                },
            )
            .await
        {
            tracing::warn!(target: "mokosh_server.billing", error = %e, "pay-now email: send failed");
        }
    }

    /// PMS-36: read a single invoice with `lines` populated. 404 when
    /// the id is outside the tenant.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_invoice(
        &self,
        tenant_id: TenantId,
        invoice_id: Uuid,
    ) -> AppResult<InvoiceResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        Self::load_invoice(&mut tx, tenant_id, invoice_id).await
    }

    /// Assemble one invoice, in a transaction the caller owns (PMS-959).
    ///
    /// The whole of what an invoice response is, in one place with two entry
    /// points: [`Self::get_invoice`] opens a transaction and calls this, and
    /// the send path calls it on the transaction it is already holding, so the
    /// document it renders is the invoice that is about to commit rather than
    /// whatever a second connection can see. The alternative was a second
    /// assembly beside this one, which is a second definition of what a
    /// document contains and the first thing to drift.
    ///
    /// It resolves `company_name` and `payment_term_name` itself rather than
    /// calling `enrich_invoices`, which opens its own transactions and cannot
    /// be reached from inside one. `enrich_invoices` stays for the list paths,
    /// where batching one query for many rows is the point.
    async fn load_invoice(
        tx: &mut crate::db::TenantTransaction<'_>,
        tenant_id: TenantId,
        invoice_id: Uuid,
    ) -> AppResult<InvoiceResponse> {
        let row = sqlx::query_as::<_, InvoiceRow>(
            r#"
            SELECT id, tenant_id, invoice_number, company_id, billing_contact_id,
                   contract_id, status, invoice_date, due_date, payment_terms,
                   payment_term_id,
                   subtotal, tax_amount, discount_amount, total, amount_paid, amount_credited,
                   balance_due, currency, notes, po_number, sent_at, paid_at,
                   created_at, updated_at
            FROM invoices
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(invoice_id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| AppError::NotFound("Invoice".to_string()))?;

        let line_rows = sqlx::query_as::<_, InvoiceLineRow>(
            r#"
            SELECT id, line_type, description, quantity, unit_price, total,
                   ticket_id, project_id, sort_order, product_id
            FROM invoice_lines
            WHERE invoice_id = $1
            ORDER BY sort_order, created_at
            "#,
        )
        .bind(invoice_id)
        .fetch_all(&mut **tx)
        .await?;

        let mut resp: InvoiceResponse = row.into();
        resp.lines = Some(line_rows.into_iter().map(Into::into).collect());
        resp.company_name =
            sqlx::query_scalar("SELECT name FROM companies WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(resp.company_id)
                .fetch_optional(&mut **tx)
                .await?;
        if let Some(term_id) = resp.payment_term_id {
            resp.payment_term_name = sqlx::query_scalar(
                "SELECT name FROM payment_terms WHERE tenant_id = $1 AND id = $2",
            )
            .bind(tenant_id)
            .bind(term_id)
            .fetch_optional(&mut **tx)
            .await?;
        }
        Ok(resp)
    }

    // ========================================================================
    // PMS-333 payment terms lookup (mirrors work_types; single default/tenant).
    // ========================================================================

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_payment_terms(
        &self,
        tenant_id: TenantId,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<PaymentTermResponse>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM payment_terms WHERE tenant_id = $1")
                .bind(tenant_id)
                .fetch_one(&mut *tx)
                .await?;
        let rows = sqlx::query_as::<_, PaymentTermRow>(
            r#"SELECT id, name, is_default, is_active, sort_order, net_days
               FROM payment_terms WHERE tenant_id = $1 ORDER BY sort_order, name
               LIMIT $2 OFFSET $3"#,
        )
        .bind(tenant_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&mut *tx)
        .await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_payment_term(
        &self,
        tenant_id: TenantId,
        request: &UpsertPaymentTermRequest,
        ctx: &AuditCtx,
    ) -> AppResult<PaymentTermResponse> {
        let id = Uuid::new_v4();
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        if request.is_default {
            sqlx::query("UPDATE payment_terms SET is_default = FALSE, updated_at = NOW() WHERE tenant_id = $1 AND is_default = TRUE")
                .bind(tenant_id)
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query(
            r#"INSERT INTO payment_terms (id, tenant_id, name, is_default, is_active, sort_order, net_days)
               VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&request.name)
        .bind(request.is_default)
        .bind(request.is_active)
        .bind(request.sort_order)
        .bind(request.net_days)
        .execute(&mut *tx)
        .await?;
        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM payment_terms t WHERE tenant_id = $1 AND id = $2",
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
            "payment_terms",
            Some(id),
            None,
            after,
        )
        .await?;
        tx.commit().await?;
        Ok(PaymentTermResponse {
            id,
            name: request.name.clone(),
            is_default: request.is_default,
            is_active: request.is_active,
            sort_order: request.sort_order,
            net_days: request.net_days,
        })
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_payment_term(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        request: &UpsertPaymentTermRequest,
    ) -> AppResult<PaymentTermResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        if request.is_default {
            sqlx::query("UPDATE payment_terms SET is_default = FALSE, updated_at = NOW() WHERE tenant_id = $1 AND is_default = TRUE AND id <> $2")
                .bind(tenant_id)
                .bind(id)
                .execute(&mut *tx)
                .await?;
        }
        let row: Option<PaymentTermRow> = sqlx::query_as(
            r#"UPDATE payment_terms
               SET name = $3, is_default = $4, is_active = $5, sort_order = $6, net_days = $7,
                   updated_at = NOW()
               WHERE tenant_id = $1 AND id = $2
               RETURNING id, name, is_default, is_active, sort_order, net_days"#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(&request.name)
        .bind(request.is_default)
        .bind(request.is_active)
        .bind(request.sort_order)
        .bind(request.net_days)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            return Err(AppError::NotFound("Payment term".to_string()));
        };
        tx.commit().await?;
        Ok(row.into())
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_payment_term(&self, tenant_id: TenantId, id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let result = sqlx::query("DELETE FROM payment_terms WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await;
        let affected = match result {
            Ok(r) => r.rows_affected(),
            Err(e) => {
                // An invoice still references this term (FK 23503): 409, not 500.
                if e.as_database_error().and_then(|d| d.code()).as_deref() == Some("23503") {
                    return Err(AppError::Conflict(
                        "Cannot delete this payment term: it is still referenced by an invoice"
                            .to_string(),
                    ));
                }
                return Err(e.into());
            }
        };
        if affected == 0 {
            return Err(AppError::NotFound("Payment term".to_string()));
        }
        tx.commit().await?;
        Ok(())
    }

    // ========================================================================
    // PMS-953: credit notes
    // ========================================================================

    /// Allocate the next gapless, per-tenant credit-note number inside the
    /// caller's transaction.
    ///
    /// Same seed-or-bump as [`Self::next_invoice_number`] (PMS-194) against a
    /// separate sequence, because a credit note is a different document and an
    /// accountant reading `INV-000042` expects an invoice.
    async fn next_credit_note_number(
        tx: &mut sqlx::PgConnection,
        tenant_id: TenantId,
    ) -> AppResult<String> {
        let seq_row: Option<(i32, Option<String>)> = sqlx::query_as(
            r#"
            UPDATE credit_note_sequences
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
                    "INSERT INTO credit_note_sequences (tenant_id, last_number) VALUES ($1, 1)",
                )
                .bind(tenant_id)
                .execute(&mut *tx)
                .await?;
                (1, Some("CN-".to_string()))
            }
        };
        Ok(format!(
            "{}{:06}",
            prefix.unwrap_or_else(|| "CN-".to_string()),
            next_number
        ))
    }

    /// PMS-953: correct an issued invoice by crediting it.
    ///
    /// This is the path `update_invoice` and `delete_payment` have deferred to
    /// since PMS-38 and PMS-39, in comments that both said "out of scope for
    /// this commit". Until it existed, an issued invoice could not be edited,
    /// cancelled or written off by any route, and `void` was a status the model
    /// knew and nothing could write.
    ///
    /// The invoice is not touched beyond its derived balance: its lines, totals
    /// and number stay exactly as the customer received them, because the
    /// customer holds that copy. Everything about the correction lives on the
    /// credit note.
    ///
    /// The invoice row is locked FIRST and in the same order the payment paths
    /// take it (PMS-695), so a credit racing a payment on one invoice queues
    /// rather than losing one of the two writes.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_credit_note(
        &self,
        tenant_id: TenantId,
        request: &CreateCreditNoteRequest,
        ctx: &AuditCtx,
    ) -> AppResult<CreditNoteResponse> {
        // Every line is a positive amount to give back. A negative line would
        // be a charge hidden inside a credit, and checking only the total would
        // miss one that a larger positive line offsets.
        let mut subtotal = Decimal::ZERO;
        for line in &request.lines {
            if line.quantity <= Decimal::ZERO || line.unit_price <= Decimal::ZERO {
                return Err(AppError::BadRequest(
                    "A credit note line must have a positive quantity and unit price; the document \
                     as a whole is the credit"
                        .to_string(),
                ));
            }
            subtotal += line.quantity * line.unit_price;
        }
        let tax = request.tax_amount.unwrap_or(Decimal::ZERO);
        if tax < Decimal::ZERO {
            return Err(AppError::BadRequest(
                "A credit note's tax amount cannot be negative".to_string(),
            ));
        }
        let total = subtotal + tax;
        if total <= Decimal::ZERO {
            return Err(AppError::BadRequest(
                "A credit note must credit something".to_string(),
            ));
        }

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;

        let invoice: Option<(Decimal, Decimal, String, Uuid, Option<String>, String)> =
            sqlx::query_as(
                "SELECT total, amount_credited, status, company_id, currency, invoice_number \
                 FROM invoices WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
            )
            .bind(request.invoice_id)
            .bind(tenant_id)
            .fetch_optional(&mut *tx)
            .await?;
        let Some((
            invoice_total,
            already_credited,
            invoice_status,
            company_id,
            invoice_currency,
            _invoice_number,
        )) = invoice
        else {
            return Err(AppError::NotFound("Invoice".to_string()));
        };

        // A draft or pending invoice has no correction problem: it can still be
        // edited, and crediting one would leave a document correcting something
        // the customer was never sent.
        let status = InvoiceStatus::from_str(&invoice_status).unwrap_or(InvoiceStatus::Draft);
        if !status.is_frozen() {
            return Err(AppError::BadRequest(format!(
                "Invoice in status '{}' can still be edited, so it does not need a credit note",
                status.as_str()
            )));
        }

        // Capped at the invoice's own total, less what is already credited, and
        // deliberately NOT less what has been paid: an invoice the customer has
        // already paid can still be credited in full, which is exactly the case
        // where they are owed money back.
        let remaining = invoice_total - already_credited;
        if total > remaining {
            return Err(AppError::BadRequest(format!(
                "A credit note for {total} exceeds what is left to credit on this invoice \
                 ({remaining} of {invoice_total})"
            )));
        }

        let credit_note_id = Uuid::new_v4();
        let number = Self::next_credit_note_number(&mut tx, tenant_id).await?;
        let issue_date = request
            .issue_date
            .unwrap_or_else(|| chrono::Utc::now().date_naive());
        // The invoice's currency unless the caller names one, so the two
        // documents cannot silently disagree about what is being credited.
        let currency = request
            .currency
            .clone()
            .or(invoice_currency)
            .unwrap_or_else(|| "USD".to_string());

        sqlx::query(
            r#"
            INSERT INTO credit_notes (
                id, tenant_id, credit_note_number, company_id, invoice_id,
                status, issue_date, reason, subtotal, tax_amount, total,
                currency, notes, created_by_id
            )
            VALUES ($1, $2, $3, $4, $5, 'issued', $6, $7, $8, $9, $10, $11, $12, $13)
            "#,
        )
        .bind(credit_note_id)
        .bind(tenant_id)
        .bind(&number)
        .bind(company_id)
        .bind(request.invoice_id)
        .bind(issue_date)
        .bind(&request.reason)
        .bind(subtotal)
        .bind(tax)
        .bind(total)
        .bind(&currency)
        .bind(&request.notes)
        .bind(ctx.user_id)
        .execute(&mut *tx)
        .await?;

        for line in &request.lines {
            sqlx::query(
                r#"
                INSERT INTO credit_note_lines (
                    id, credit_note_id, line_type, description, quantity,
                    unit_price, total, sort_order
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                "#,
            )
            .bind(Uuid::new_v4())
            .bind(credit_note_id)
            .bind(line.line_type.as_str())
            .bind(&line.description)
            .bind(line.quantity)
            .bind(line.unit_price)
            .bind(line.quantity * line.unit_price)
            .bind(line.sort_order)
            .execute(&mut *tx)
            .await?;
        }

        Self::recompute_invoice_balance(&mut tx, tenant_id, request.invoice_id).await?;

        // PMS-959: a credit note is issued at creation and never edited
        // (PMS-953), so this is its moment. Voiding one later does not replace
        // the document: the customer holds what was issued, and a void is a
        // status the credit note carries rather than a different document.
        //
        // The issuer is resolved live rather than snapshotted, because unlike
        // an invoice a credit note has no separate freeze point to snapshot AT
        // - it is frozen the instant it exists, and these bytes are the
        // snapshot.
        let note = Self::load_credit_note(&mut tx, tenant_id, credit_note_id).await?;
        let issuer = Self::tenant_issuer_in_tx(&mut tx, tenant_id).await?;
        let logo = crate::modules::billing::issuer::live_logo_bytes(tenant_id.get(), &issuer).await;
        let bytes = crate::pdf::render(&crate::modules::billing::documents::credit_note(
            &note, &issuer, logo,
        ))?;
        crate::modules::billing::documents::store_issued(
            &mut tx,
            tenant_id.get(),
            credit_note_id,
            &note.credit_note_number,
            "credit_note_document",
            &bytes,
        )
        .await?;

        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM credit_notes t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(credit_note_id)
        .fetch_optional(&mut *tx)
        .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Create,
            "credit_notes",
            Some(credit_note_id),
            None,
            after,
        )
        .await?;

        tx.commit().await?;
        self.get_credit_note(tenant_id, credit_note_id).await
    }

    /// PMS-953: void a credit note, restoring the balance it removed.
    ///
    /// A credit note is never edited, for the reason its invoice is not: the
    /// customer holds a copy. Voiding changes no amount and no line, it only
    /// stops the credit counting, and `recompute_invoice_balance` sums issued
    /// notes alone so the invoice walks back to whatever status it would have
    /// had. Without this the fix for a wrong invoice would itself be
    /// uncorrectable, which is the dead end this whole issue removes.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn void_credit_note(
        &self,
        tenant_id: TenantId,
        credit_note_id: Uuid,
        ctx: &AuditCtx,
    ) -> AppResult<CreditNoteResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;

        let row: Option<(Uuid, String)> = sqlx::query_as(
            "SELECT invoice_id, status FROM credit_notes WHERE id = $1 AND tenant_id = $2",
        )
        .bind(credit_note_id)
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((invoice_id, status)) = row else {
            return Err(AppError::NotFound("Credit note".to_string()));
        };
        if status == "void" {
            return Err(AppError::Conflict(
                "This credit note is already void".to_string(),
            ));
        }

        // Same lock, same order as every other write to this invoice's balance.
        Self::lock_invoice_totals(&mut tx, tenant_id, invoice_id).await?;

        let before: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM credit_notes t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(credit_note_id)
        .fetch_optional(&mut *tx)
        .await?;

        sqlx::query(
            "UPDATE credit_notes SET status = 'void', voided_at = NOW(), voided_by_id = $3, \
             updated_at = NOW() WHERE id = $1 AND tenant_id = $2",
        )
        .bind(credit_note_id)
        .bind(tenant_id)
        .bind(ctx.user_id)
        .execute(&mut *tx)
        .await?;

        Self::recompute_invoice_balance(&mut tx, tenant_id, invoice_id).await?;

        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM credit_notes t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(credit_note_id)
        .fetch_optional(&mut *tx)
        .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Update,
            "credit_notes",
            Some(credit_note_id),
            before,
            after,
        )
        .await?;

        tx.commit().await?;
        self.get_credit_note(tenant_id, credit_note_id).await
    }

    /// PMS-953: one credit note with its lines.
    pub async fn get_credit_note(
        &self,
        tenant_id: TenantId,
        credit_note_id: Uuid,
    ) -> AppResult<CreditNoteResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        Self::load_credit_note(&mut tx, tenant_id, credit_note_id).await
    }

    /// Assemble one credit note, in a transaction the caller owns (PMS-959).
    ///
    /// Same shape and same reason as [`Self::load_invoice`]: the creating
    /// transaction renders the document from what is about to commit, and there
    /// is one assembly rather than two definitions of what a credit note
    /// contains.
    async fn load_credit_note(
        tx: &mut crate::db::TenantTransaction<'_>,
        tenant_id: TenantId,
        credit_note_id: Uuid,
    ) -> AppResult<CreditNoteResponse> {
        let row: Option<CreditNoteRow> = sqlx::query_as(
            r#"
            SELECT cn.id, cn.tenant_id, cn.credit_note_number, cn.company_id,
                   c.name AS company_name, cn.invoice_id, i.invoice_number,
                   cn.status, cn.issue_date, cn.reason, cn.subtotal,
                   cn.tax_amount, cn.total, cn.currency, cn.notes,
                   cn.created_by_id, cn.voided_at, cn.created_at, cn.updated_at
            FROM credit_notes cn
            LEFT JOIN companies c ON c.id = cn.company_id
            LEFT JOIN invoices i ON i.id = cn.invoice_id
            WHERE cn.id = $1 AND cn.tenant_id = $2
            "#,
        )
        .bind(credit_note_id)
        .bind(tenant_id)
        .fetch_optional(&mut **tx)
        .await?;
        let Some(row) = row else {
            return Err(AppError::NotFound("Credit note".to_string()));
        };

        let lines: Vec<CreditNoteLineRow> = sqlx::query_as(
            r#"
            SELECT id, line_type, description, quantity, unit_price, total, sort_order
            FROM credit_note_lines
            WHERE credit_note_id = $1
            ORDER BY sort_order, id
            "#,
        )
        .bind(credit_note_id)
        .fetch_all(&mut **tx)
        .await?;

        let mut response = CreditNoteResponse::from(row);
        response.lines = Some(
            lines
                .into_iter()
                .map(CreditNoteLineResponse::from)
                .collect(),
        );
        Ok(response)
    }

    /// PMS-953: credit notes for the tenant, newest first.
    pub async fn list_credit_notes(
        &self,
        tenant_id: TenantId,
        filter: &CreditNoteFilter,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<CreditNoteResponse>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM credit_notes
            WHERE tenant_id = $1
              AND ($2::uuid IS NULL OR company_id = $2)
              AND ($3::uuid IS NULL OR invoice_id = $3)
              AND ($4::text IS NULL OR status = $4)
            "#,
        )
        .bind(tenant_id)
        .bind(filter.company_id)
        .bind(filter.invoice_id)
        .bind(filter.status.as_deref())
        .fetch_one(&mut *tx)
        .await?;

        let rows: Vec<CreditNoteRow> = sqlx::query_as(
            r#"
            SELECT cn.id, cn.tenant_id, cn.credit_note_number, cn.company_id,
                   c.name AS company_name, cn.invoice_id, i.invoice_number,
                   cn.status, cn.issue_date, cn.reason, cn.subtotal,
                   cn.tax_amount, cn.total, cn.currency, cn.notes,
                   cn.created_by_id, cn.voided_at, cn.created_at, cn.updated_at
            FROM credit_notes cn
            LEFT JOIN companies c ON c.id = cn.company_id
            LEFT JOIN invoices i ON i.id = cn.invoice_id
            WHERE cn.tenant_id = $1
              AND ($2::uuid IS NULL OR cn.company_id = $2)
              AND ($3::uuid IS NULL OR cn.invoice_id = $3)
              AND ($4::text IS NULL OR cn.status = $4)
            ORDER BY cn.created_at DESC, cn.id DESC
            LIMIT $5 OFFSET $6
            "#,
        )
        .bind(tenant_id)
        .bind(filter.company_id)
        .bind(filter.invoice_id)
        .bind(filter.status.as_deref())
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&mut *tx)
        .await?;

        Ok((
            rows.into_iter().map(CreditNoteResponse::from).collect(),
            total.max(0) as u64,
        ))
    }

    // ========================================================================
    // PMS-954: statements
    // ========================================================================

    /// A statement is an account, and an account is what the client owes.
    /// A draft or pending invoice has not been issued, so it is not owed and
    /// does not appear; every other status does, `void` included, because the
    /// credit note that voided it appears too and dropping both would remove
    /// the correction from the record along with the charge.
    const STATEMENT_ISSUED_INVOICE: &'static str = "status NOT IN ('draft', 'pending')";

    /// PMS-954: a company's account over a period.
    ///
    /// Derived at read time from the invoices, payments, refunds and credit
    /// notes it summarises, and stored nowhere: a stored statement would be a
    /// second source of truth for numbers that already have one, and the two
    /// would part company the first time a payment was backdated.
    ///
    /// Every figure comes from a DATED row. Nothing reads `invoices.balance_due`
    /// or `amount_paid`, which are current values: a statement for a period that
    /// closed last month must show what was outstanding then, and those columns
    /// have moved since. That is also why `closing_balance` is arithmetic over
    /// the four buckets rather than a sum of today's balances.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn build_statement(
        &self,
        tenant_id: TenantId,
        query: &StatementQuery,
    ) -> AppResult<StatementResponse> {
        if query.period_end < query.period_start {
            return Err(AppError::BadRequest(
                "A statement's period cannot end before it starts".to_string(),
            ));
        }

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;

        let company: Option<(String,)> =
            sqlx::query_as("SELECT name FROM companies WHERE id = $1 AND tenant_id = $2")
                .bind(query.company_id)
                .bind(tenant_id)
                .fetch_optional(&mut *tx)
                .await?;
        let Some((company_name,)) = company else {
            return Err(AppError::NotFound("Company".to_string()));
        };

        // The opening balance is everything before the period, netted. It is
        // computed here rather than carried on the company, because a stored
        // running total is a third home for a number that already has one and
        // the only one that can be silently wrong.
        let opening: (Decimal, Decimal, Decimal, Decimal) = sqlx::query_as(&format!(
            r#"
            SELECT
                COALESCE((SELECT SUM(total) FROM invoices
                          WHERE tenant_id = $1 AND company_id = $2
                            AND invoice_date < $3 AND {issued}), 0),
                COALESCE((SELECT SUM(amount) FROM payments
                          WHERE tenant_id = $1 AND company_id = $2
                            AND payment_date < $3), 0),
                COALESCE((SELECT SUM(r.amount) FROM payment_refunds r
                          JOIN payments p ON p.id = r.payment_id
                          WHERE r.tenant_id = $1 AND p.company_id = $2
                            AND r.created_at::date < $3), 0),
                COALESCE((SELECT SUM(total) FROM credit_notes
                          WHERE tenant_id = $1 AND company_id = $2
                            AND status = 'issued' AND issue_date < $3), 0)
            "#,
            issued = Self::STATEMENT_ISSUED_INVOICE,
        ))
        .bind(tenant_id)
        .bind(query.company_id)
        .bind(query.period_start)
        .fetch_one(&mut *tx)
        .await?;
        let (open_invoiced, open_paid, open_refunded, open_credited) = opening;
        let opening_balance = open_invoiced + open_refunded - open_paid - open_credited;

        let invoices: Vec<StatementInvoiceRow> = sqlx::query_as(&format!(
            r#"
            SELECT id, invoice_number, invoice_date, due_date, status, total
            FROM invoices
            WHERE tenant_id = $1 AND company_id = $2
              AND invoice_date BETWEEN $3 AND $4
              AND {issued}
            ORDER BY invoice_date, invoice_number
            "#,
            issued = Self::STATEMENT_ISSUED_INVOICE,
        ))
        .bind(tenant_id)
        .bind(query.company_id)
        .bind(query.period_start)
        .bind(query.period_end)
        .fetch_all(&mut *tx)
        .await?;

        let payments: Vec<StatementPaymentRow> = sqlx::query_as(
            r#"
            SELECT p.id, p.payment_date, p.amount, p.payment_method,
                   p.reference_number, i.invoice_number
            FROM payments p
            LEFT JOIN invoices i ON i.id = p.invoice_id
            WHERE p.tenant_id = $1 AND p.company_id = $2
              AND p.payment_date BETWEEN $3 AND $4
            ORDER BY p.payment_date, p.id
            "#,
        )
        .bind(tenant_id)
        .bind(query.company_id)
        .bind(query.period_start)
        .bind(query.period_end)
        .fetch_all(&mut *tx)
        .await?;

        // Joined through `payments` rather than `payment_refunds.invoice_id`,
        // which is nullable: a refund of an unapplied payment still belongs to
        // the company that made it.
        let refunds: Vec<StatementRefundRow> = sqlx::query_as(
            r#"
            SELECT r.id, r.created_at::date AS refund_date, r.amount, i.invoice_number
            FROM payment_refunds r
            JOIN payments p ON p.id = r.payment_id
            LEFT JOIN invoices i ON i.id = r.invoice_id
            WHERE r.tenant_id = $1 AND p.company_id = $2
              AND r.created_at::date BETWEEN $3 AND $4
            ORDER BY r.created_at, r.id
            "#,
        )
        .bind(tenant_id)
        .bind(query.company_id)
        .bind(query.period_start)
        .bind(query.period_end)
        .fetch_all(&mut *tx)
        .await?;

        let credit_notes: Vec<StatementCreditRow> = sqlx::query_as(
            r#"
            SELECT cn.id, cn.credit_note_number, cn.issue_date, cn.total,
                   cn.reason, i.invoice_number
            FROM credit_notes cn
            LEFT JOIN invoices i ON i.id = cn.invoice_id
            WHERE cn.tenant_id = $1 AND cn.company_id = $2
              AND cn.status = 'issued'
              AND cn.issue_date BETWEEN $3 AND $4
            ORDER BY cn.issue_date, cn.credit_note_number
            "#,
        )
        .bind(tenant_id)
        .bind(query.company_id)
        .bind(query.period_start)
        .bind(query.period_end)
        .fetch_all(&mut *tx)
        .await?;

        let total_invoiced: Decimal = invoices.iter().map(|i| i.total).sum();
        let total_paid: Decimal = payments.iter().map(|p| p.amount).sum();
        let total_refunded: Decimal = refunds.iter().map(|r| r.amount).sum();
        let total_credited: Decimal = credit_notes.iter().map(|c| c.total).sum();

        Ok(StatementResponse {
            company_id: query.company_id,
            company_name: Some(company_name),
            period_start: query.period_start,
            period_end: query.period_end,
            opening_balance,
            invoices: invoices.into_iter().map(Into::into).collect(),
            payments: payments.into_iter().map(Into::into).collect(),
            refunds: refunds.into_iter().map(Into::into).collect(),
            credit_notes: credit_notes.into_iter().map(Into::into).collect(),
            total_invoiced,
            total_paid,
            total_refunded,
            total_credited,
            closing_balance: opening_balance + total_invoiced + total_refunded
                - total_paid
                - total_credited,
        })
    }

    // ========================================================================
    // PMS-955: product catalog
    // ========================================================================

    /// Validate that `product_id` names a product in the caller's tenant, and
    /// that it is still on sale.
    ///
    /// Tenant-checked for the reason `assert_payment_term_in_tenant` is
    /// (PMS-333): an FK check bypasses RLS, so a foreign-tenant id would pass
    /// the constraint and link across tenants silently. Active-checked because
    /// that is what deactivating a product is FOR; a document already written
    /// against it is untouched, since nothing re-validates history.
    async fn assert_product_sellable(
        tx: &mut sqlx::PgConnection,
        tenant_id: TenantId,
        product_id: Uuid,
    ) -> AppResult<()> {
        let found: Option<bool> =
            sqlx::query_scalar("SELECT is_active FROM products WHERE id = $1 AND tenant_id = $2")
                .bind(product_id)
                .bind(tenant_id)
                .fetch_optional(&mut *tx)
                .await?;
        match found {
            None => Err(AppError::BadRequest(
                "product_id does not name a product in this tenant".to_string(),
            )),
            Some(false) => Err(AppError::BadRequest(
                "That product has been retired and cannot be put on a new document".to_string(),
            )),
            Some(true) => Ok(()),
        }
    }

    pub async fn list_products(
        &self,
        tenant_id: TenantId,
        filter: &ProductFilter,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<ProductResponse>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let pattern = filter.q.as_ref().map(|q| format!("%{}%", q.trim()));
        let total: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM products
            WHERE tenant_id = $1
              AND ($2::bool IS NULL OR is_active = $2)
              AND ($3::text IS NULL OR name ILIKE $3 OR sku ILIKE $3)
            "#,
        )
        .bind(tenant_id)
        .bind(filter.is_active)
        .bind(pattern.as_deref())
        .fetch_one(&mut *tx)
        .await?;

        let rows: Vec<ProductRow> = sqlx::query_as(
            r#"
            SELECT id, sku, name, description, unit_price, unit, is_taxable,
                   is_active, created_at, updated_at
            FROM products
            WHERE tenant_id = $1
              AND ($2::bool IS NULL OR is_active = $2)
              AND ($3::text IS NULL OR name ILIKE $3 OR sku ILIKE $3)
            ORDER BY name
            LIMIT $4 OFFSET $5
            "#,
        )
        .bind(tenant_id)
        .bind(filter.is_active)
        .bind(pattern.as_deref())
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&mut *tx)
        .await?;

        Ok((
            rows.into_iter().map(ProductResponse::from).collect(),
            total.max(0) as u64,
        ))
    }

    pub async fn get_product(
        &self,
        tenant_id: TenantId,
        product_id: Uuid,
    ) -> AppResult<ProductResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: Option<ProductRow> = sqlx::query_as(
            r#"
            SELECT id, sku, name, description, unit_price, unit, is_taxable,
                   is_active, created_at, updated_at
            FROM products WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(product_id)
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await?;
        row.map(ProductResponse::from)
            .ok_or_else(|| AppError::NotFound("Product".to_string()))
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_product(
        &self,
        tenant_id: TenantId,
        request: &UpsertProductRequest,
        ctx: &AuditCtx,
    ) -> AppResult<ProductResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let id = Uuid::new_v4();
        let row: Result<ProductRow, sqlx::Error> = sqlx::query_as(
            r#"
            INSERT INTO products (id, tenant_id, sku, name, description,
                                  unit_price, unit, is_taxable, is_active)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id, sku, name, description, unit_price, unit, is_taxable,
                      is_active, created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(
            request
                .sku
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty()),
        )
        .bind(request.name.trim())
        .bind(&request.description)
        .bind(request.unit_price)
        .bind(request.unit.trim())
        .bind(request.is_taxable)
        .bind(request.is_active)
        .fetch_one(&mut *tx)
        .await;
        let row = row.map_err(Self::product_conflict)?;

        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM products t WHERE tenant_id = $1 AND id = $2",
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
            "products",
            Some(id),
            None,
            after,
        )
        .await?;
        tx.commit().await?;
        Ok(ProductResponse::from(row))
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_product(
        &self,
        tenant_id: TenantId,
        product_id: Uuid,
        request: &UpsertProductRequest,
        ctx: &AuditCtx,
    ) -> AppResult<ProductResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let before: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM products t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(product_id)
        .fetch_optional(&mut *tx)
        .await?;
        if before.is_none() {
            return Err(AppError::NotFound("Product".to_string()));
        }

        // Editing the catalog price is legal and changes nothing already
        // written: `invoice_lines.unit_price` is the price at the moment the
        // line was written, and nothing reads through to here at render time.
        let row: Result<ProductRow, sqlx::Error> = sqlx::query_as(
            r#"
            UPDATE products SET sku = $3, name = $4, description = $5,
                                unit_price = $6, unit = $7, is_taxable = $8,
                                is_active = $9, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING id, sku, name, description, unit_price, unit, is_taxable,
                      is_active, created_at, updated_at
            "#,
        )
        .bind(product_id)
        .bind(tenant_id)
        .bind(
            request
                .sku
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty()),
        )
        .bind(request.name.trim())
        .bind(&request.description)
        .bind(request.unit_price)
        .bind(request.unit.trim())
        .bind(request.is_taxable)
        .bind(request.is_active)
        .fetch_one(&mut *tx)
        .await;
        let row = row.map_err(Self::product_conflict)?;

        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM products t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(product_id)
        .fetch_optional(&mut *tx)
        .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Update,
            "products",
            Some(product_id),
            before,
            after,
        )
        .await?;
        tx.commit().await?;
        Ok(ProductResponse::from(row))
    }

    /// Delete a product that nothing has sold.
    ///
    /// A referenced product is refused by the database, and that refusal is
    /// turned into a 409 naming the alternative rather than a 500: retiring a
    /// product an MSP has sold is `is_active = false`, because the documents
    /// that sold it still name it.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_product(
        &self,
        tenant_id: TenantId,
        product_id: Uuid,
        ctx: &AuditCtx,
    ) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let before: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM products t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(product_id)
        .fetch_optional(&mut *tx)
        .await?;
        if before.is_none() {
            return Err(AppError::NotFound("Product".to_string()));
        }

        let deleted = sqlx::query("DELETE FROM products WHERE id = $1 AND tenant_id = $2")
            .bind(product_id)
            .bind(tenant_id)
            .execute(&mut *tx)
            .await;
        if let Err(sqlx::Error::Database(e)) = &deleted {
            if e.code().as_deref() == Some("23503") {
                return Err(AppError::Conflict(
                    "This product is on an invoice or a contract and cannot be deleted.                      Retire it instead by marking it inactive."
                        .to_string(),
                ));
            }
        }
        deleted?;

        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Delete,
            "products",
            Some(product_id),
            before,
            None,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Turn the two catalog uniqueness violations into a 409 that names which
    /// one was hit, rather than a 500 quoting an index name.
    fn product_conflict(e: sqlx::Error) -> AppError {
        if let sqlx::Error::Database(db) = &e {
            if db.code().as_deref() == Some("23505") {
                let constraint = db.constraint().unwrap_or_default();
                if constraint.contains("sku") {
                    return AppError::Conflict("Another product already uses that SKU".to_string());
                }
                return AppError::Conflict("Another product already uses that name".to_string());
            }
        }
        e.into()
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
    id: Uuid,
    name: String,
    quantity: Decimal,
    unit_price: Decimal,
    /// PMS-955: the catalog link, carried onto the invoice line this item
    /// becomes. `None` for every item written before the catalog existed.
    product_id: Option<Uuid>,
    /// PMS-956: `every_period` or `once`; the SELECT excludes everything else,
    /// and a `once` item is claimed before its line is written.
    billing_rule: String,
}

/// Compute the current billing period `[period_start, period_end]` for a
/// contract, anchored at `start_date` and stepped by the `billing_cycle`
/// length, such that `period_start <= today` and `today <= period_end`.
///
/// Periods tile forward from `start_date` with no gaps:
///   weekly   : start, start+7d, start+14d, ...
///   bi_weekly: start, start+14d, ...
///   monthly  : start, start+1mo, start+2mo, ...
///   quarterly: start, start+3mo, ...
///   annually : start, start+12mo, ...
/// `period_end` is the day before the next period's start.
///
/// Returns `None` when `today < start_date` (no period has begun yet) or
/// the cycle is non-recurring / unknown.
///
/// Sub-month cycles (`weekly`/`bi_weekly`) step by whole days via
/// `chrono::Days`; month-or-longer cycles step via `chrono::Months`,
/// which clamps end-of-month overflow (e.g. Jan 31 + 1 month ->
/// Feb 28/29), so a contract that starts on the 31st still produces one
/// period per cycle (PMS-404).
fn current_billing_period(
    billing_cycle: &str,
    start_date: NaiveDate,
    today: NaiveDate,
) -> Option<(NaiveDate, NaiveDate)> {
    if today < start_date {
        return None;
    }
    let step = CycleStep::from_cycle(billing_cycle)?;

    // Walk forward from start_date one cycle at a time until the next
    // boundary would pass `today`. Bounded by the number of cycles
    // between the two dates plus a small margin, so it always terminates
    // even on clamped month math.
    let mut period_start = start_date;
    loop {
        let next = step.advance(period_start)?;
        if next <= period_start {
            // Overflow / non-advancing guard: stop walking.
            return None;
        }
        if next > today {
            // `period_end` is the day before the next period starts.
            let period_end = next.pred_opt().unwrap_or(next);
            return Some((period_start, period_end));
        }
        period_start = next;
    }
}

/// PMS-933, rewritten for PMS-944: why a company's time did not produce an
/// invoice.
///
/// Counted only when the eligible set came back empty, to turn "none found"
/// into a statement that is true and that names somebody's next action.
///
/// The three states are split because they are three different answers to the
/// same question, and the same sentence would be wrong for two of them. Time
/// logged as non-billable is a decision somebody made, and the fix is to change
/// it. Time already on an invoice is not missing at all, and telling that user
/// to go and log hours would have them bill the same work twice. Time that is
/// billable and uninvoiced but not armed should not exist since PMS-944 arms an
/// entry at creation and migration 121 armed the rest, so it is reported rather
/// than denied: the one thing PMS-933 forbids is answering "there is none" when
/// there is some.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct UninvoiceableTime {
    /// Client entries that are billable and uninvoiced but not `ready_to_bill`.
    pub not_ready: i64,
    /// Minutes across those.
    pub not_ready_minutes: i64,
    /// Client entries logged as non-billable.
    pub non_billable: i64,
    /// Minutes across those, so the message can state the size of what was
    /// written off.
    pub non_billable_minutes: i64,
    /// Client entries that were billable and are already on an invoice.
    pub already_invoiced: i64,
}

impl UninvoiceableTime {
    /// Hours as somebody would say them: 120 minutes is "2 hours", not "2.00",
    /// and 60 minutes is "1 hour", not "1 hours". The plural is on the number
    /// being exactly one, so 1.5 and 0.75 both stay plural.
    fn hours(minutes: i64) -> String {
        let hours = (Decimal::from(minutes) / Decimal::from(60))
            .round_dp(2)
            .normalize();
        if hours == Decimal::ONE {
            "1 hour".to_string()
        } else {
            format!("{hours} hours")
        }
    }

    /// `n` of `noun`, pluralised. "1 time entries" in an error the user is
    /// already suspicious of reads as a second bug.
    fn count_of(n: i64, singular: &str, plural: &str) -> String {
        if n == 1 {
            format!("1 {singular}")
        } else {
            format!("{n} {plural}")
        }
    }

    /// The sentence the caller returns as a 400.
    ///
    /// Nothing logged at all means the original message, which is the one case
    /// it was ever true in.
    fn into_message(self) -> String {
        // Ordered by how much the reader needs it. An unarmed entry is the
        // surprising one and comes first; already-invoiced is the reassuring
        // one and comes last.
        let mut parts: Vec<String> = Vec::new();
        if self.not_ready > 0 {
            let hours = Self::hours(self.not_ready_minutes);
            // Verb agreement as well as noun agreement: "1 entry that are not
            // marked" reads as a second bug in a message the reader is already
            // suspicious of, having just been told something was missing.
            let is_are = if self.not_ready == 1 { "is" } else { "are" };
            parts.push(format!(
                "{} ({hours}) that {is_are} not marked ready to bill",
                Self::count_of(
                    self.not_ready,
                    "billable time entry",
                    "billable time entries"
                )
            ));
        }
        if self.non_billable > 0 {
            let hours = Self::hours(self.non_billable_minutes);
            parts.push(format!(
                "{} ({hours}) logged as non-billable",
                Self::count_of(self.non_billable, "time entry", "time entries")
            ));
        }
        if self.already_invoiced > 0 {
            parts.push(format!(
                "{} already on an invoice",
                Self::count_of(
                    self.already_invoiced,
                    "billable time entry",
                    "billable time entries"
                )
            ));
        }

        let Some(next) = self.next_step() else {
            return "No billable time or mileage entries found for this company".to_string();
        };

        // "a, b and c" rather than "a, b, c", because this is a sentence.
        let what = match parts.len() {
            1 => parts.remove(0),
            _ => {
                let last = parts.pop().unwrap_or_default();
                format!("{} and {last}", parts.join(", "))
            }
        };
        format!("This company has no time to invoice right now. It has {what}. {next}")
    }

    /// The action to name, chosen by the same priority the parts are listed in,
    /// so the sentence ends by telling one person to do one thing. `None` means
    /// the company genuinely has nothing logged.
    fn next_step(&self) -> Option<&'static str> {
        if self.not_ready > 0 {
            return Some("Re-save them and they become invoiceable.");
        }
        if self.non_billable > 0 {
            return Some(
                "Mark them billable if they should be charged, then generate the invoice again.",
            );
        }
        if self.already_invoiced > 0 {
            return Some("There is nothing new to bill for this company.");
        }
        None
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

/// PMS-315: mileage entry projection for the invoice builder.
#[derive(sqlx::FromRow)]
struct MileageBillingRow {
    id: Uuid,
    distance_miles: Decimal,
    rate_per_mile: Option<Decimal>,
    total_amount: Option<Decimal>,
    ticket_id: Option<Uuid>,
    start_address: Option<String>,
    end_address: Option<String>,
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
    config_encrypted: Option<String>,
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
            invoice_number: None,
            company_id: r.company_id,
            company_name: None,
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
    product_id: Option<Uuid>,
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
            product_id: r.product_id,
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
    payment_term_id: Option<Uuid>,
    subtotal: Decimal,
    tax_amount: Decimal,
    discount_amount: Decimal,
    total: Decimal,
    amount_paid: Decimal,
    amount_credited: Decimal,
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
            company_name: None,
            billing_contact_id: r.billing_contact_id,
            contract_id: r.contract_id,
            status: InvoiceStatus::from_str(&r.status).unwrap_or(InvoiceStatus::Draft),
            invoice_date: r.invoice_date,
            due_date: r.due_date,
            payment_terms: r.payment_terms,
            payment_term_id: r.payment_term_id,
            payment_term_name: None,
            subtotal: r.subtotal,
            tax_amount: r.tax_amount,
            discount_amount: r.discount_amount,
            total: r.total,
            amount_paid: r.amount_paid,
            amount_credited: r.amount_credited,
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

#[derive(sqlx::FromRow)]
struct PaymentTermRow {
    id: Uuid,
    name: String,
    is_default: Option<bool>,
    is_active: Option<bool>,
    sort_order: Option<i32>,
    net_days: Option<i32>,
}

impl From<PaymentTermRow> for PaymentTermResponse {
    fn from(r: PaymentTermRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            is_default: r.is_default.unwrap_or(false),
            is_active: r.is_active.unwrap_or(true),
            sort_order: r.sort_order.unwrap_or(0),
            net_days: r.net_days,
        }
    }
}

#[cfg(test)]
mod pms944_uninvoiceable_time_tests {
    use super::UninvoiceableTime;

    fn why(
        non_billable: i64,
        non_billable_minutes: i64,
        already_invoiced: i64,
    ) -> UninvoiceableTime {
        UninvoiceableTime {
            not_ready: 0,
            not_ready_minutes: 0,
            non_billable,
            non_billable_minutes,
            already_invoiced,
        }
    }

    fn not_ready(count: i64, minutes: i64) -> UninvoiceableTime {
        UninvoiceableTime {
            not_ready: count,
            not_ready_minutes: minutes,
            ..UninvoiceableTime::default()
        }
    }

    /// The one case the original sentence was ever true in. PMS-933 kept it for
    /// the same reason: a company that really has logged nothing should be told
    /// exactly that.
    #[test]
    fn nothing_logged_keeps_the_original_message() {
        assert_eq!(
            why(0, 0, 0).into_message(),
            "No billable time or mileage entries found for this company"
        );
    }

    /// PMS-933's requirement, restated against the rule PMS-944 leaves behind:
    /// the message must never deny the existence of data that is there.
    #[test]
    fn time_that_exists_is_never_reported_as_missing() {
        for msg in [
            why(1, 60, 0).into_message(),
            why(0, 0, 1).into_message(),
            why(2, 120, 3).into_message(),
            not_ready(1, 60).into_message(),
        ] {
            assert!(
                !msg.contains("No billable time"),
                "it must not claim there is none: {msg}"
            );
        }
    }

    /// Written-off time is a decision somebody made when logging it, so the
    /// message names that decision and how to change it.
    #[test]
    fn non_billable_time_says_so_and_names_the_step() {
        let msg = why(1, 90, 0).into_message();
        assert!(
            msg.contains("1 time entry (1.5 hours) logged as non-billable"),
            "{msg}"
        );
        assert!(msg.contains("Mark them billable"), "{msg}");
    }

    /// Already invoiced is the opposite problem. Telling this user to go and
    /// log hours would have them bill the same work twice, so it gets its own
    /// sentence and no call to action.
    #[test]
    fn already_invoiced_time_does_not_ask_for_more_hours() {
        let msg = why(0, 0, 2).into_message();
        assert!(
            msg.contains("2 billable time entries already on an invoice"),
            "{msg}"
        );
        assert!(msg.contains("nothing new to bill"), "{msg}");
        assert!(!msg.contains("Mark them billable"), "{msg}");
    }

    /// Both at once is a real case - part of a job written off, the rest
    /// already billed - and naming only one sends the user looking for the
    /// other.
    #[test]
    fn a_mix_names_both() {
        let msg = why(2, 120, 3).into_message();
        assert!(
            msg.contains("2 time entries (2 hours) logged as non-billable"),
            "{msg}"
        );
        assert!(
            msg.contains("3 billable time entries already on an invoice"),
            "{msg}"
        );
    }

    /// Hours are what a person bills in, not minutes, and a whole number should
    /// not arrive as "2.00 hours".
    #[test]
    fn hours_read_the_way_somebody_would_say_them() {
        assert!(why(1, 120, 0).into_message().contains("2 hours"));
        assert!(why(1, 90, 0).into_message().contains("1.5 hours"));
        assert!(why(1, 45, 0).into_message().contains("0.75 hours"));
        // Exactly one is the only singular; a fraction near it is not.
        assert!(why(1, 60, 0).into_message().contains("(1 hour)"));
        // Not exactly representable in quarters; rounded rather than printed to
        // fifteen decimal places.
        assert!(why(1, 50, 0).into_message().contains("0.83 hours"));
    }

    /// Singular and plural, because "1 time entries" in an error the user is
    /// already suspicious of reads as a second bug.
    #[test]
    fn one_entry_is_singular() {
        assert!(why(1, 60, 0).into_message().contains("1 time entry ("));
        assert!(why(2, 60, 0).into_message().contains("2 time entries ("));
        assert!(why(0, 0, 1)
            .into_message()
            .contains("1 billable time entry already"));
        assert!(why(0, 0, 2)
            .into_message()
            .contains("2 billable time entries already"));
    }

    /// The state that should not exist. PMS-944 arms an entry at creation and
    /// migration 121 armed the rest, so a billable uninvoiced entry that is not
    /// `ready_to_bill` means something wrote the row directly. Reporting it is
    /// the whole point: the one answer PMS-933 forbids is "there is none" when
    /// there is some.
    #[test]
    fn an_unarmed_entry_is_reported_rather_than_denied() {
        let msg = not_ready(2, 180).into_message();
        assert!(
            msg.contains("2 billable time entries (3 hours) that are not marked ready to bill"),
            "{msg}"
        );
        assert!(!msg.contains("No billable time"), "{msg}");
    }

    /// Three at once still reads as a sentence, and the action named is the one
    /// for the state that comes first.
    #[test]
    fn every_state_at_once_reads_as_one_sentence() {
        let msg = UninvoiceableTime {
            not_ready: 1,
            not_ready_minutes: 60,
            non_billable: 2,
            non_billable_minutes: 120,
            already_invoiced: 3,
        }
        .into_message();
        assert!(msg.contains("1 billable time entry (1 hour) that is not marked ready to bill, 2 time entries (2 hours) logged as non-billable and 3 billable time entries already on an invoice"), "{msg}");
        assert!(
            msg.ends_with("Re-save them and they become invoiceable."),
            "{msg}"
        );
    }

    /// The message must not mention approval. Approval no longer gates billing,
    /// so naming it would send the user to a screen that cannot help - which is
    /// the exact failure MAPPS-598 reported, pointing the other way.
    #[test]
    fn the_message_never_blames_approval() {
        for msg in [
            why(1, 60, 0).into_message(),
            why(0, 0, 1).into_message(),
            why(2, 120, 3).into_message(),
            not_ready(1, 60).into_message(),
        ] {
            assert!(!msg.contains("approv"), "{msg}");
            assert!(!msg.contains("timesheet"), "{msg}");
        }
    }
}

/// PMS-953: one credit-note row, joined to the names a client would otherwise
/// have to fetch separately.
#[derive(sqlx::FromRow)]
struct CreditNoteRow {
    id: Uuid,
    tenant_id: Uuid,
    credit_note_number: String,
    company_id: Uuid,
    company_name: Option<String>,
    invoice_id: Uuid,
    invoice_number: Option<String>,
    status: String,
    issue_date: chrono::NaiveDate,
    reason: String,
    subtotal: Decimal,
    tax_amount: Decimal,
    total: Decimal,
    currency: Option<String>,
    notes: Option<String>,
    created_by_id: Option<Uuid>,
    voided_at: Option<chrono::DateTime<Utc>>,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
}

impl From<CreditNoteRow> for CreditNoteResponse {
    fn from(r: CreditNoteRow) -> Self {
        Self {
            id: r.id,
            tenant_id: r.tenant_id,
            credit_note_number: r.credit_note_number,
            company_id: r.company_id,
            company_name: r.company_name,
            invoice_id: r.invoice_id,
            invoice_number: r.invoice_number,
            // An unrecognised value can only come from a row this build did not
            // write, and reading it as `Issued` would count it against an
            // invoice. `Void` is the reading that cannot overstate a credit.
            status: CreditNoteStatus::from_str(&r.status).unwrap_or(CreditNoteStatus::Void),
            issue_date: r.issue_date,
            reason: r.reason,
            subtotal: r.subtotal,
            tax_amount: r.tax_amount,
            total: r.total,
            currency: r.currency,
            notes: r.notes,
            created_by_id: r.created_by_id,
            voided_at: r.voided_at,
            created_at: r.created_at,
            updated_at: r.updated_at,
            lines: None,
        }
    }
}

#[derive(sqlx::FromRow)]
struct CreditNoteLineRow {
    id: Uuid,
    line_type: String,
    description: String,
    quantity: Decimal,
    unit_price: Decimal,
    total: Decimal,
    sort_order: Option<i32>,
}

impl From<CreditNoteLineRow> for CreditNoteLineResponse {
    fn from(r: CreditNoteLineRow) -> Self {
        Self {
            id: r.id,
            line_type: InvoiceLineType::from_str(&r.line_type).unwrap_or(InvoiceLineType::Service),
            description: r.description,
            quantity: r.quantity,
            unit_price: r.unit_price,
            total: r.total,
            sort_order: r.sort_order.unwrap_or(0),
        }
    }
}

// ---- PMS-954: statement row types ------------------------------------------

#[derive(sqlx::FromRow)]
struct StatementInvoiceRow {
    id: Uuid,
    invoice_number: String,
    invoice_date: chrono::NaiveDate,
    due_date: chrono::NaiveDate,
    status: String,
    total: Decimal,
}

impl From<StatementInvoiceRow> for StatementInvoiceLine {
    fn from(r: StatementInvoiceRow) -> Self {
        Self {
            invoice_id: r.id,
            invoice_number: r.invoice_number,
            invoice_date: r.invoice_date,
            due_date: r.due_date,
            status: InvoiceStatus::from_str(&r.status).unwrap_or(InvoiceStatus::Draft),
            total: r.total,
        }
    }
}

#[derive(sqlx::FromRow)]
struct StatementPaymentRow {
    id: Uuid,
    payment_date: chrono::NaiveDate,
    amount: Decimal,
    payment_method: String,
    reference_number: Option<String>,
    invoice_number: Option<String>,
}

impl From<StatementPaymentRow> for StatementPaymentLine {
    fn from(r: StatementPaymentRow) -> Self {
        Self {
            payment_id: r.id,
            payment_date: r.payment_date,
            amount: r.amount,
            payment_method: PaymentMethod::from_str(&r.payment_method)
                .unwrap_or(PaymentMethod::Other),
            reference_number: r.reference_number,
            invoice_number: r.invoice_number,
        }
    }
}

#[derive(sqlx::FromRow)]
struct StatementRefundRow {
    id: Uuid,
    refund_date: chrono::NaiveDate,
    amount: Decimal,
    invoice_number: Option<String>,
}

impl From<StatementRefundRow> for StatementRefundLine {
    fn from(r: StatementRefundRow) -> Self {
        Self {
            refund_id: r.id,
            refund_date: r.refund_date,
            amount: r.amount,
            invoice_number: r.invoice_number,
        }
    }
}

#[derive(sqlx::FromRow)]
struct StatementCreditRow {
    id: Uuid,
    credit_note_number: String,
    issue_date: chrono::NaiveDate,
    total: Decimal,
    reason: String,
    invoice_number: Option<String>,
}

impl From<StatementCreditRow> for StatementCreditLine {
    fn from(r: StatementCreditRow) -> Self {
        Self {
            credit_note_id: r.id,
            credit_note_number: r.credit_note_number,
            issue_date: r.issue_date,
            total: r.total,
            reason: r.reason,
            invoice_number: r.invoice_number,
        }
    }
}

// ---- PMS-955: product catalog row type -------------------------------------

#[derive(sqlx::FromRow)]
struct ProductRow {
    id: Uuid,
    sku: Option<String>,
    name: String,
    description: Option<String>,
    unit_price: Decimal,
    unit: String,
    is_taxable: bool,
    is_active: bool,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
}

impl From<ProductRow> for ProductResponse {
    fn from(r: ProductRow) -> Self {
        Self {
            id: r.id,
            sku: r.sku,
            name: r.name,
            description: r.description,
            unit_price: r.unit_price,
            unit: r.unit,
            is_taxable: r.is_taxable,
            is_active: r.is_active,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[cfg(test)]
mod gateway_resolution {
    use super::*;

    fn row(provider: &str) -> (String, Option<String>) {
        (
            provider.to_string(),
            Some(format!("ciphertext-for-{provider}")),
        )
    }

    /// The property that makes PMS-966 a refactor rather than a change: a
    /// tenant with a stored `authorize_net` row was invisible behind the old
    /// `provider = 'stripe'` literal, and must stay invisible now that the
    /// literal is gone. (PMS-966 used `paypal` as the example; PMS-969 made
    /// that one serveable, so the example moved to the provider that still is
    /// not.)
    #[test]
    fn an_unserveable_row_is_skipped_exactly_as_the_literal_skipped_it() {
        let picked = BillingService::select_serveable(vec![row("authorize_net"), row("stripe")])
            .expect("one serveable row resolves");
        assert_eq!(picked.map(|(id, _)| id), Some("stripe".to_string()));

        let none = BillingService::select_serveable(vec![row("authorize_net")])
            .expect("no serveable row is not an error");
        assert!(
            none.is_none(),
            "a tenant with only unserveable gateways resolves to None, not an error"
        );
    }

    /// No active rows at all is the ordinary unconfigured tenant.
    #[test]
    fn no_rows_resolves_to_none() {
        let none = BillingService::select_serveable(Vec::new()).expect("no rows is fine");
        assert!(none.is_none());
    }

    /// Two serveable gateways is a question the database cannot answer, so it
    /// is refused rather than resolved. `UNIQUE (tenant_id, provider)` permits
    /// one active row per provider, so this becomes reachable the moment a
    /// second provider is implemented (PMS-969); picking one would route a
    /// customer's payment at whichever row the planner happened to return.
    #[test]
    fn two_serveable_gateways_is_refused_and_not_picked_between() {
        // Constructed from `SUPPORTED` rather than from two hard-coded names,
        // so this keeps testing the ambiguity once a second provider lands
        // instead of quietly becoming unreachable.
        let mut rows: Vec<(String, Option<String>)> =
            provider::SUPPORTED.iter().map(|p| row(p)).collect();
        if rows.len() < 2 {
            rows.push(row(provider::SUPPORTED[0]));
        }
        match BillingService::select_serveable(rows) {
            Err(AppError::Configuration(message)) => {
                assert!(
                    message.contains("exactly one may be active"),
                    "refused for the wrong reason: {message}"
                );
            }
            Err(other) => panic!("expected a Configuration error, got {other:?}"),
            Ok(_) => panic!("two serveable gateways must not resolve to one"),
        }
    }
}
