//! Quotes service (PMS-672).
//!
//! Every method takes `tenant_id` explicitly and opens its transaction
//! with [`Database::begin_with_tenant`], so RLS scopes the statements.
//! This repo has no middleware-level tenant scoping (see
//! `docs/dev-docs/codebase-state.md` cross-cutting issue #8), so the
//! discipline is deliberate rather than incidental.

use chrono::Utc;
use rust_decimal::Decimal;
use uuid::Uuid;

use crate::db::Database;
use crate::modules::audit::{audit_write, AuditAction, AuditCtx};
use crate::modules::auth::TenantId;
use crate::utils::error::{AppError, AppResult};
use crate::utils::pagination::PaginationParams;

use super::models::*;

/// Quote operations: the sales document, its line items, and the
/// server-side totals derived from them.
#[derive(Clone)]
pub struct QuotesService {
    db: Database,
}

impl QuotesService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Allocate the next gapless, per-tenant quote number inside the
    /// caller's transaction.
    ///
    /// Atomically bumps `quote_sequences.last_number`; the row lock
    /// serialises concurrent creates so numbers stay dense and unique,
    /// and living in the caller's `tx` means a rollback restores the
    /// sequence too. Mirrors `BillingService::next_invoice_number`.
    async fn next_quote_number(
        tx: &mut sqlx::PgConnection,
        tenant_id: TenantId,
    ) -> AppResult<String> {
        let seq_row: Option<(i32, Option<String>)> = sqlx::query_as(
            r#"
            UPDATE quote_sequences
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
                // First quote for this tenant: seed the sequence row.
                sqlx::query("INSERT INTO quote_sequences (tenant_id, last_number) VALUES ($1, 1)")
                    .bind(tenant_id)
                    .execute(&mut *tx)
                    .await?;
                (1, Some("QUO-".to_string()))
            }
        };
        Ok(format!(
            "{}{:06}",
            prefix.unwrap_or_else(|| "QUO-".to_string()),
            next_number
        ))
    }

    /// Validate that `company_id` names a company in the caller's tenant.
    ///
    /// The FK on `quotes.company_id` alone is not enough: foreign-key
    /// checks bypass RLS, so a caller passing another tenant's company id
    /// would otherwise get a row that silently links across tenants.
    /// Same guard, same reason, as
    /// `BillingService::assert_payment_term_in_tenant` (PMS-333).
    async fn assert_company_in_tenant(
        tx: &mut sqlx::PgConnection,
        tenant_id: TenantId,
        company_id: Uuid,
    ) -> AppResult<()> {
        let exists: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM companies WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(company_id)
                .fetch_optional(&mut *tx)
                .await?;
        exists
            .map(|_| ())
            .ok_or_else(|| AppError::BadRequest(format!("unknown company {company_id}")))
    }

    /// Same cross-tenant guard for the billing contact.
    async fn assert_contact_in_tenant(
        tx: &mut sqlx::PgConnection,
        tenant_id: TenantId,
        contact_id: Uuid,
    ) -> AppResult<()> {
        let exists: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM contacts WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(contact_id)
                .fetch_optional(&mut *tx)
                .await?;
        exists
            .map(|_| ())
            .ok_or_else(|| AppError::BadRequest(format!("unknown contact {contact_id}")))
    }

    /// Resolve company ids to display names so responses never carry a
    /// bare UUID. Mirrors `BillingService::company_name_map`.
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

    async fn enrich_quotes(
        &self,
        tenant_id: TenantId,
        quotes: &mut [QuoteResponse],
    ) -> AppResult<()> {
        let ids: Vec<Uuid> = quotes.iter().map(|q| q.company_id).collect();
        let names = self.company_name_map(tenant_id, &ids).await?;
        for q in quotes.iter_mut() {
            q.company_name = names.get(&q.company_id).cloned();
        }
        Ok(())
    }

    /// Recompute `subtotal` / `total` from the quote's line rows and
    /// write them back.
    ///
    /// The single place totals are derived. Every mutating path funnels
    /// through here rather than trusting a caller-supplied figure, so a
    /// quote's stored total always equals the sum of its lines plus tax.
    async fn recompute_totals(
        tx: &mut sqlx::PgConnection,
        tenant_id: TenantId,
        quote_id: Uuid,
    ) -> AppResult<()> {
        // COALESCE so a quote with no lines settles at 0 rather than NULL.
        let subtotal: Decimal = sqlx::query_scalar(
            "SELECT COALESCE(SUM(total), 0) FROM quote_lines WHERE quote_id = $1",
        )
        .bind(quote_id)
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query(
            r#"
            UPDATE quotes
            SET subtotal = $3, total = $3 + tax_amount
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(quote_id)
        .bind(subtotal)
        .execute(&mut *tx)
        .await?;
        Ok(())
    }

    /// Load a quote's status, or 404. Used by the mutating paths to
    /// enforce the freeze rules before doing any work.
    async fn status_of(
        tx: &mut sqlx::PgConnection,
        tenant_id: TenantId,
        quote_id: Uuid,
    ) -> AppResult<QuoteStatus> {
        let raw: Option<String> =
            sqlx::query_scalar("SELECT status FROM quotes WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(quote_id)
                .fetch_optional(&mut *tx)
                .await?;
        let raw = raw.ok_or_else(|| AppError::NotFound("Quote".to_string()))?;
        Ok(QuoteStatus::from_str(&raw).unwrap_or(QuoteStatus::Draft))
    }

    /// Reject a content mutation when the quote is past the point where
    /// its figures may change.
    fn assert_content_editable(status: QuoteStatus) -> AppResult<()> {
        if !status.allows_content_edit() {
            return Err(AppError::Conflict(format!(
                "Quote in status '{}' cannot be edited",
                status.as_str()
            )));
        }
        Ok(())
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_quotes(
        &self,
        tenant_id: TenantId,
        filter: &QuoteFilter,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<QuoteResponse>, u64)> {
        let offset = pagination.offset() as i64;
        let limit = pagination.limit() as i64;

        // Parallel WHERE clauses so the data and count queries each get
        // correctly numbered placeholders: data has $1 tenant + $2 limit +
        // $3 offset so filters start at $4; count has $1 tenant only so
        // filters start at $2. Mirrors `list_invoices`.
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
        if filter.q.is_some() {
            data_conds.push(format!(
                "(title ILIKE ${data_idx} OR quote_number ILIKE ${data_idx})"
            ));
            count_conds.push(format!(
                "(title ILIKE ${count_idx} OR quote_number ILIKE ${count_idx})"
            ));
        }

        let data_where = data_conds.join(" AND ");
        let count_where = count_conds.join(" AND ");
        // Bare column: `order_by` appends the direction itself.
        let order_by = pagination.order_by(
            "created_at",
            &["created_at", "valid_until", "total", "title"],
        );
        let query = format!(
            r#"
            SELECT {QUOTE_COLUMNS}
            FROM quotes
            WHERE {data_where}
            ORDER BY {order_by}
            LIMIT $2 OFFSET $3
            "#
        );
        let count_query = format!("SELECT COUNT(*) FROM quotes WHERE {count_where}");

        let mut q = sqlx::query_as::<_, QuoteRow>(&query)
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
        if let Some(ref s) = filter.q {
            let pattern = format!("%{s}%");
            q = q.bind(pattern.clone());
            cq = cq.bind(pattern);
        }

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows = q.fetch_all(&mut *tx).await?;
        let total = cq.fetch_one(&mut *tx).await?;
        drop(tx);
        let mut resp: Vec<QuoteResponse> = rows.into_iter().map(Into::into).collect();
        self.enrich_quotes(tenant_id, &mut resp).await?;
        Ok((resp, total as u64))
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_quote(&self, tenant_id: TenantId, quote_id: Uuid) -> AppResult<QuoteResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row = sqlx::query_as::<_, QuoteRow>(&format!(
            "SELECT {QUOTE_COLUMNS} FROM quotes WHERE tenant_id = $1 AND id = $2"
        ))
        .bind(tenant_id)
        .bind(quote_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::NotFound("Quote".to_string()))?;

        let line_rows = sqlx::query_as::<_, QuoteLineRow>(
            r#"
            SELECT id, line_type, description, quantity, unit_price, total, sort_order
            FROM quote_lines
            WHERE quote_id = $1
            ORDER BY sort_order, created_at
            "#,
        )
        .bind(quote_id)
        .fetch_all(&mut *tx)
        .await?;
        drop(tx);

        let mut resp: QuoteResponse = row.into();
        resp.lines = Some(line_rows.into_iter().map(Into::into).collect());
        self.enrich_quotes(tenant_id, std::slice::from_mut(&mut resp))
            .await?;
        Ok(resp)
    }

    /// Create a quote and its lines in one transaction.
    ///
    /// Allocates the human-readable quote number from the per-tenant
    /// sequence, then derives `subtotal` from the supplied lines and
    /// `total` as `subtotal + tax_amount`. The request carries no total
    /// field at all, so there is nothing to ignore.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_quote(
        &self,
        tenant_id: TenantId,
        requested_by_id: Uuid,
        request: &CreateQuoteRequest,
        ctx: &AuditCtx,
    ) -> AppResult<QuoteResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;

        Self::assert_company_in_tenant(&mut tx, tenant_id, request.company_id).await?;
        if let Some(contact_id) = request.billing_contact_id {
            Self::assert_contact_in_tenant(&mut tx, tenant_id, contact_id).await?;
        }

        let quote_number = Self::next_quote_number(&mut tx, tenant_id).await?;

        let subtotal: Decimal = request
            .lines
            .iter()
            .map(|l| l.quantity * l.unit_price)
            .sum();
        let tax = request.tax_amount.unwrap_or(Decimal::ZERO);
        let total = subtotal + tax;

        let quote_id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO quotes (
                id, tenant_id, quote_number, company_id, billing_contact_id,
                title, summary, description, status, valid_until,
                subtotal, tax_amount, total, currency, requested_by_id
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'draft', $9, $10, $11, $12, $13, $14)
            "#,
        )
        .bind(quote_id)
        .bind(tenant_id)
        .bind(&quote_number)
        .bind(request.company_id)
        .bind(request.billing_contact_id)
        .bind(&request.title)
        .bind(&request.summary)
        .bind(&request.description)
        .bind(request.valid_until)
        .bind(subtotal)
        .bind(tax)
        .bind(total)
        .bind(request.currency.as_deref().unwrap_or("USD"))
        .bind(requested_by_id)
        .execute(&mut *tx)
        .await?;

        for line in &request.lines {
            Self::insert_line(&mut tx, quote_id, line).await?;
        }

        let after: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT to_jsonb(t) FROM quotes t WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(quote_id)
                .fetch_optional(&mut *tx)
                .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Create,
            "quotes",
            Some(quote_id),
            None,
            after,
        )
        .await?;

        tx.commit().await?;
        self.get_quote(tenant_id, quote_id).await
    }

    async fn insert_line(
        tx: &mut sqlx::PgConnection,
        quote_id: Uuid,
        line: &QuoteLineRequest,
    ) -> AppResult<Uuid> {
        let id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO quote_lines (
                id, quote_id, line_type, description, quantity, unit_price, total, sort_order
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
        )
        .bind(id)
        .bind(quote_id)
        .bind(line.line_type.as_str())
        .bind(&line.description)
        .bind(line.quantity)
        .bind(line.unit_price)
        .bind(line.quantity * line.unit_price)
        .bind(line.sort_order)
        .execute(&mut *tx)
        .await?;
        Ok(id)
    }

    /// Update header fields, and optionally replace the whole line set.
    ///
    /// Rejects any write to a frozen quote, and any CONTENT change once
    /// the quote has left `draft` / `rejected`; a status-only transition
    /// is still allowed so the internal workflow can advance.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_quote(
        &self,
        tenant_id: TenantId,
        quote_id: Uuid,
        request: &UpdateQuoteRequest,
        ctx: &AuditCtx,
    ) -> AppResult<QuoteResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let current = Self::status_of(&mut tx, tenant_id, quote_id).await?;

        if current.is_frozen() {
            return Err(AppError::Conflict(format!(
                "Quote in status '{}' cannot be edited",
                current.as_str()
            )));
        }

        let changes_content = request.billing_contact_id.is_some()
            || request.title.is_some()
            || request.summary.is_some()
            || request.description.is_some()
            || request.valid_until.is_some()
            || request.currency.is_some()
            || request.tax_amount.is_some()
            || request.lines.is_some();
        if changes_content {
            Self::assert_content_editable(current)?;
        }

        if let Some(next) = request.status {
            if !next.is_staff_settable() {
                return Err(AppError::Conflict(format!(
                    "Status '{}' is not settable here; it is written by the send, portal, or convert route",
                    next.as_str()
                )));
            }
        }

        if let Some(contact_id) = request.billing_contact_id {
            Self::assert_contact_in_tenant(&mut tx, tenant_id, contact_id).await?;
        }

        let before: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT to_jsonb(t) FROM quotes t WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(quote_id)
                .fetch_optional(&mut *tx)
                .await?;

        // COALESCE keeps every omitted field at its current value, so the
        // handler does not have to read-modify-write the whole row.
        sqlx::query(
            r#"
            UPDATE quotes
            SET billing_contact_id = COALESCE($3, billing_contact_id),
                title              = COALESCE($4, title),
                summary            = COALESCE($5, summary),
                description        = COALESCE($6, description),
                valid_until        = COALESCE($7, valid_until),
                currency           = COALESCE($8, currency),
                tax_amount         = COALESCE($9, tax_amount),
                status             = COALESCE($10, status)
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(quote_id)
        .bind(request.billing_contact_id)
        .bind(&request.title)
        .bind(&request.summary)
        .bind(&request.description)
        .bind(request.valid_until)
        .bind(request.currency.as_deref())
        .bind(request.tax_amount)
        .bind(request.status.map(|s| s.as_str()))
        .execute(&mut *tx)
        .await?;

        // Replace the line set wholesale when supplied, then recompute so
        // the header totals match the new lines.
        if let Some(lines) = &request.lines {
            sqlx::query("DELETE FROM quote_lines WHERE quote_id = $1")
                .bind(quote_id)
                .execute(&mut *tx)
                .await?;
            for line in lines {
                Self::insert_line(&mut tx, quote_id, line).await?;
            }
        }
        // Always recompute: `tax_amount` alone changes `total` even when
        // the lines are untouched.
        Self::recompute_totals(&mut tx, tenant_id, quote_id).await?;

        let after: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT to_jsonb(t) FROM quotes t WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(quote_id)
                .fetch_optional(&mut *tx)
                .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Update,
            "quotes",
            Some(quote_id),
            before,
            after,
        )
        .await?;

        tx.commit().await?;
        self.get_quote(tenant_id, quote_id).await
    }

    /// Cancel a quote.
    ///
    /// Modelled as a `cancelled` transition rather than a row delete: a
    /// quote that was sent to a customer is a commercial record, and the
    /// approvals rows referencing it (`target='quote'`) would be orphaned
    /// by a hard delete. `quotes` has no `deleted_at`, so the lifecycle
    /// status is the soft-delete.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn cancel_quote(
        &self,
        tenant_id: TenantId,
        quote_id: Uuid,
        ctx: &AuditCtx,
    ) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let current = Self::status_of(&mut tx, tenant_id, quote_id).await?;
        if current.is_frozen() {
            return Err(AppError::Conflict(format!(
                "Quote in status '{}' cannot be cancelled",
                current.as_str()
            )));
        }

        let before: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT to_jsonb(t) FROM quotes t WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(quote_id)
                .fetch_optional(&mut *tx)
                .await?;

        sqlx::query("UPDATE quotes SET status = 'cancelled' WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(quote_id)
            .execute(&mut *tx)
            .await?;

        let after: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT to_jsonb(t) FROM quotes t WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(quote_id)
                .fetch_optional(&mut *tx)
                .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Delete,
            "quotes",
            Some(quote_id),
            before,
            after,
        )
        .await?;

        tx.commit().await?;
        Ok(())
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn add_line(
        &self,
        tenant_id: TenantId,
        quote_id: Uuid,
        line: &QuoteLineRequest,
    ) -> AppResult<QuoteResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let current = Self::status_of(&mut tx, tenant_id, quote_id).await?;
        Self::assert_content_editable(current)?;

        Self::insert_line(&mut tx, quote_id, line).await?;
        Self::recompute_totals(&mut tx, tenant_id, quote_id).await?;
        tx.commit().await?;
        self.get_quote(tenant_id, quote_id).await
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_line(
        &self,
        tenant_id: TenantId,
        quote_id: Uuid,
        line_id: Uuid,
        line: &QuoteLineRequest,
    ) -> AppResult<QuoteResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let current = Self::status_of(&mut tx, tenant_id, quote_id).await?;
        Self::assert_content_editable(current)?;

        // Scoped by quote_id as well as line id: the parent lookup above
        // is what proves tenancy, so a line from another quote must not be
        // reachable through this path.
        let affected = sqlx::query(
            r#"
            UPDATE quote_lines
            SET line_type = $3, description = $4, quantity = $5,
                unit_price = $6, total = $5 * $6, sort_order = $7
            WHERE id = $1 AND quote_id = $2
            "#,
        )
        .bind(line_id)
        .bind(quote_id)
        .bind(line.line_type.as_str())
        .bind(&line.description)
        .bind(line.quantity)
        .bind(line.unit_price)
        .bind(line.sort_order)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if affected == 0 {
            return Err(AppError::NotFound("Quote line".to_string()));
        }

        Self::recompute_totals(&mut tx, tenant_id, quote_id).await?;
        tx.commit().await?;
        self.get_quote(tenant_id, quote_id).await
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_line(
        &self,
        tenant_id: TenantId,
        quote_id: Uuid,
        line_id: Uuid,
    ) -> AppResult<QuoteResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let current = Self::status_of(&mut tx, tenant_id, quote_id).await?;
        Self::assert_content_editable(current)?;

        let affected = sqlx::query("DELETE FROM quote_lines WHERE id = $1 AND quote_id = $2")
            .bind(line_id)
            .bind(quote_id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if affected == 0 {
            return Err(AppError::NotFound("Quote line".to_string()));
        }

        Self::recompute_totals(&mut tx, tenant_id, quote_id).await?;
        tx.commit().await?;
        self.get_quote(tenant_id, quote_id).await
    }
}

/// Shared column list so the list and detail reads cannot drift apart.
const QUOTE_COLUMNS: &str = r#"id, tenant_id, quote_number, company_id, billing_contact_id,
       title, summary, description, status, valid_until,
       subtotal, tax_amount, total, currency, requested_by_id,
       sent_at, decided_at, decided_by_contact_id, decision_notes,
       converted_project_id, created_at, updated_at"#;

#[derive(sqlx::FromRow)]
struct QuoteLineRow {
    id: Uuid,
    line_type: String,
    description: String,
    quantity: Decimal,
    unit_price: Decimal,
    total: Decimal,
    sort_order: Option<i32>,
}

impl From<QuoteLineRow> for QuoteLineResponse {
    fn from(r: QuoteLineRow) -> Self {
        Self {
            id: r.id,
            line_type: QuoteLineType::from_str(&r.line_type).unwrap_or(QuoteLineType::Service),
            description: r.description,
            quantity: r.quantity,
            unit_price: r.unit_price,
            total: r.total,
            sort_order: r.sort_order.unwrap_or(0),
        }
    }
}

#[derive(sqlx::FromRow)]
struct QuoteRow {
    id: Uuid,
    tenant_id: Uuid,
    quote_number: Option<String>,
    company_id: Uuid,
    billing_contact_id: Option<Uuid>,
    title: String,
    summary: Option<String>,
    description: Option<String>,
    status: String,
    valid_until: Option<chrono::NaiveDate>,
    subtotal: Decimal,
    tax_amount: Decimal,
    total: Decimal,
    currency: Option<String>,
    requested_by_id: Option<Uuid>,
    sent_at: Option<chrono::DateTime<Utc>>,
    decided_at: Option<chrono::DateTime<Utc>>,
    decided_by_contact_id: Option<Uuid>,
    decision_notes: Option<String>,
    converted_project_id: Option<Uuid>,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
}

impl From<QuoteRow> for QuoteResponse {
    fn from(r: QuoteRow) -> Self {
        Self {
            id: r.id,
            tenant_id: r.tenant_id,
            quote_number: r.quote_number,
            company_id: r.company_id,
            company_name: None,
            billing_contact_id: r.billing_contact_id,
            title: r.title,
            summary: r.summary,
            description: r.description,
            status: QuoteStatus::from_str(&r.status).unwrap_or(QuoteStatus::Draft),
            valid_until: r.valid_until,
            subtotal: r.subtotal,
            tax_amount: r.tax_amount,
            total: r.total,
            currency: r.currency,
            requested_by_id: r.requested_by_id,
            sent_at: r.sent_at,
            decided_at: r.decided_at,
            decided_by_contact_id: r.decided_by_contact_id,
            decision_notes: r.decision_notes,
            converted_project_id: r.converted_project_id,
            created_at: r.created_at,
            updated_at: r.updated_at,
            lines: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_covers_issued_and_terminal_states() {
        // Everything from `sent` onwards is a decision or a record, not a
        // draft, so no staff write may touch it.
        for s in [
            QuoteStatus::Sent,
            QuoteStatus::Accepted,
            QuoteStatus::Declined,
            QuoteStatus::Expired,
            QuoteStatus::Converted,
            QuoteStatus::Cancelled,
        ] {
            assert!(s.is_frozen(), "{} should be frozen", s.as_str());
        }
        for s in [
            QuoteStatus::Draft,
            QuoteStatus::Submitted,
            QuoteStatus::Approved,
            QuoteStatus::Rejected,
        ] {
            assert!(!s.is_frozen(), "{} should not be frozen", s.as_str());
        }
    }

    #[test]
    fn content_edits_confined_to_draft_and_rejected() {
        // `submitted` / `approved` are not frozen (the workflow still has
        // to advance them) but their figures must not move underneath an
        // approver.
        assert!(QuoteStatus::Draft.allows_content_edit());
        assert!(QuoteStatus::Rejected.allows_content_edit());
        assert!(!QuoteStatus::Submitted.allows_content_edit());
        assert!(!QuoteStatus::Approved.allows_content_edit());
        assert!(!QuoteStatus::Sent.allows_content_edit());
    }

    #[test]
    fn staff_cannot_set_client_or_route_owned_statuses() {
        // Guards against forging a client's acceptance through a plain
        // header update.
        for s in [
            QuoteStatus::Sent,
            QuoteStatus::Accepted,
            QuoteStatus::Declined,
            QuoteStatus::Expired,
            QuoteStatus::Converted,
        ] {
            assert!(
                !s.is_staff_settable(),
                "{} must not be settable",
                s.as_str()
            );
        }
        for s in [
            QuoteStatus::Draft,
            QuoteStatus::Submitted,
            QuoteStatus::Approved,
            QuoteStatus::Rejected,
            QuoteStatus::Cancelled,
        ] {
            assert!(s.is_staff_settable(), "{} should be settable", s.as_str());
        }
    }

    #[test]
    fn status_round_trips_through_str() {
        for s in [
            QuoteStatus::Draft,
            QuoteStatus::Submitted,
            QuoteStatus::Approved,
            QuoteStatus::Rejected,
            QuoteStatus::Sent,
            QuoteStatus::Accepted,
            QuoteStatus::Declined,
            QuoteStatus::Expired,
            QuoteStatus::Converted,
            QuoteStatus::Cancelled,
        ] {
            assert_eq!(QuoteStatus::from_str(s.as_str()), Some(s));
        }
        assert_eq!(QuoteStatus::from_str("nonsense"), None);
    }

    #[test]
    fn line_type_round_trips_through_str() {
        for t in [
            QuoteLineType::Service,
            QuoteLineType::Product,
            QuoteLineType::Labour,
            QuoteLineType::Expense,
            QuoteLineType::Adjustment,
            QuoteLineType::Discount,
        ] {
            assert_eq!(QuoteLineType::from_str(t.as_str()), Some(t));
        }
        assert_eq!(QuoteLineType::from_str("nonsense"), None);
    }
}
