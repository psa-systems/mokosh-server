//! Quotes service (PMS-672).
//!
//! Every method takes `tenant_id` explicitly and opens its transaction
//! with [`Database::begin_with_tenant`], so RLS scopes the statements.
//! This repo has no middleware-level tenant scoping (see
//! `docs/dev-docs/codebase-state.md` cross-cutting issue #8), so the
//! discipline is deliberate rather than incidental.

use std::sync::Arc;

use chrono::{NaiveDate, Utc};
use rust_decimal::Decimal;
use uuid::Uuid;

use crate::db::Database;
use crate::modules::audit::{audit_write, AuditAction, AuditCtx};
use crate::modules::auth::TenantId;
use crate::modules::notifications::NotificationsService;
use crate::utils::email::Mailer;
use crate::utils::error::{AppError, AppResult};
use crate::utils::pagination::PaginationParams;

use super::models::*;

/// Quote operations: the sales document, its line items, and the
/// server-side totals derived from them.
#[derive(Clone)]
pub struct QuotesService {
    db: Database,
    /// Mailer used to send the client their sign-off link (PMS-673).
    /// `None` for the plain `new()` constructor so non-production callers
    /// and unit tests stay compilable; sending then skips the mail and
    /// still performs the state transition, matching how `TicketService`
    /// treats its optional dispatcher.
    mailer: Option<Arc<dyn Mailer>>,
    /// Rule-driven fanout used to tell the quote's owner that the client
    /// decided. Optional for the same reason as `mailer`.
    notifications: Option<NotificationsService>,
    /// Base origin of the client portal, used to build the sign-off link
    /// in the outbound mail.
    portal_origin: String,
}

impl QuotesService {
    pub fn new(db: Database) -> Self {
        Self {
            db,
            mailer: None,
            notifications: None,
            portal_origin: String::new(),
        }
    }

    /// Full constructor used by `create_api_router`: adds the mailer that
    /// carries the sign-off link to the client, the notifications
    /// dispatcher that tells staff about the client's decision, and the
    /// portal origin those links are built from.
    pub fn with_delivery(
        db: Database,
        mailer: Arc<dyn Mailer>,
        notifications: NotificationsService,
        portal_origin: String,
    ) -> Self {
        Self {
            db,
            mailer: Some(mailer),
            notifications: Some(notifications),
            portal_origin,
        }
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
            .ok_or_else(|| AppError::BadRequest(format!("Unknown company {company_id}")))
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
            .ok_or_else(|| AppError::BadRequest(format!("Unknown contact {contact_id}")))
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
        let order_by = pagination.order_by("created_at", mokosh_types::sort::QUOTES)?;
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

    // ========================================================================
    // PMS-673: issue to the client, and the client's sign-off.
    // ========================================================================

    /// Send an approved quote to the client.
    ///
    /// Allowed only from `approved`: internal sign-off is the gate, and it
    /// runs on the existing polymorphic approvals surface
    /// (`/quotes/{id}/approvals`), which this method deliberately does not
    /// touch. Moves the quote to `sent`, stamps `sent_at`, and emails the
    /// billing contact a link to the portal view where they accept or
    /// decline.
    ///
    /// The mail is sent AFTER the transaction commits. A mail failure must
    /// not roll back a transition the customer may already have been told
    /// about out of band, and the reverse (committing a `sent` quote whose
    /// mail silently vanished) is recoverable by resending, so the
    /// transition is the durable half.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn send_quote(
        &self,
        tenant_id: TenantId,
        quote_id: Uuid,
        ctx: &AuditCtx,
    ) -> AppResult<QuoteResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let current = Self::status_of(&mut tx, tenant_id, quote_id).await?;
        if current != QuoteStatus::Approved {
            return Err(AppError::Conflict(format!(
                "Quote in status '{}' cannot be sent; it must be internally approved first",
                current.as_str()
            )));
        }

        let before: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT to_jsonb(t) FROM quotes t WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(quote_id)
                .fetch_optional(&mut *tx)
                .await?;

        sqlx::query(
            "UPDATE quotes SET status = 'sent', sent_at = NOW() WHERE tenant_id = $1 AND id = $2",
        )
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
            AuditAction::Update,
            "quotes",
            Some(quote_id),
            before,
            after,
        )
        .await?;
        tx.commit().await?;

        let quote = self.get_quote(tenant_id, quote_id).await?;
        self.mail_quote_to_client(tenant_id, &quote).await;
        Ok(quote)
    }

    /// Best-effort delivery of the sign-off link.
    ///
    /// Swallows its errors on purpose: the quote is already `sent` and a
    /// bounced mail must not surface as a 500 that makes the caller retry
    /// a transition that already happened. Failures are logged so a
    /// missing mail is diagnosable.
    async fn mail_quote_to_client(&self, tenant_id: TenantId, quote: &QuoteResponse) {
        let Some(mailer) = self.mailer.as_ref() else {
            return;
        };
        let Some(contact_id) = quote.billing_contact_id else {
            tracing::info!(
                quote_id = %quote.id,
                "quote sent with no billing contact; no client mail dispatched"
            );
            return;
        };

        let email: Option<String> = match self.db.begin_with_tenant(tenant_id).await {
            Ok(mut tx) => {
                sqlx::query_scalar("SELECT email FROM contacts WHERE tenant_id = $1 AND id = $2")
                    .bind(tenant_id)
                    .bind(contact_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .ok()
                    .flatten()
            }
            Err(e) => {
                tracing::warn!(error = %e, "could not open tx to resolve quote billing contact");
                None
            }
        };
        let Some(email) = email.filter(|e| !e.is_empty()) else {
            tracing::info!(
                quote_id = %quote.id,
                "quote billing contact has no email; no client mail dispatched"
            );
            return;
        };

        let link = format!(
            "{}/portal/quotes/{}",
            self.portal_origin.trim_end_matches('/'),
            quote.id
        );
        let number = quote.quote_number.as_deref().unwrap_or("(unnumbered)");
        let valid_until = quote.valid_until.map(|d| d.to_string());

        // PMS-761: the client is being asked to approve spend, so the message
        // says who is asking. A failure to read the identity is not a reason to
        // withhold the quote, but it IS a reason not to send an anonymous one,
        // so the send is skipped and logged rather than degraded.
        let org = match crate::modules::tenants::OrgIdentity::load(&self.db, tenant_id).await {
            Ok(org) => org,
            Err(e) => {
                tracing::warn!(
                    error = %e, quote_id = %quote.id,
                    "could not read the organisation identity; quote sign-off mail not sent",
                );
                return;
            }
        };
        let contact_line = org.contact_line("Questions about this quote?", None);
        let from = crate::utils::email::SenderIdentity {
            org_name: org.name(),
            contact_line: &contact_line,
        };

        if let Err(e) = mailer
            .send_quote_ready(
                &email,
                from,
                crate::utils::email::QuoteReady {
                    quote_number: number,
                    title: &quote.title,
                    total: &quote.total.to_string(),
                    valid_until: valid_until.as_deref(),
                    portal_link: &link,
                },
            )
            .await
        {
            tracing::warn!(error = %e, quote_id = %quote.id, "quote sign-off mail failed to send");
        }
    }

    /// List the quotes a portal contact's company may see.
    ///
    /// Scoped by BOTH the contact's tenant and their company, and further
    /// restricted to the statuses that have actually been issued. A
    /// `draft`, `submitted`, `approved`, or `rejected` quote is internal
    /// working state and must never reach a customer; `cancelled` is
    /// withdrawn and equally not theirs to see.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_quotes_for_company(
        &self,
        tenant_id: TenantId,
        company_id: Uuid,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<QuoteResponse>, u64)> {
        let offset = pagination.offset() as i64;
        let limit = pagination.limit() as i64;
        let order_by = pagination.order_by("created_at", mokosh_types::sort::QUOTE_REQUESTS)?;

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows = sqlx::query_as::<_, QuoteRow>(&format!(
            r#"
            SELECT {QUOTE_COLUMNS}
            FROM quotes
            WHERE tenant_id = $1 AND company_id = $4 AND status = ANY($5)
            ORDER BY {order_by}
            LIMIT $2 OFFSET $3
            "#
        ))
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .bind(company_id)
        .bind(CLIENT_VISIBLE_STATUSES)
        .fetch_all(&mut *tx)
        .await?;
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM quotes WHERE tenant_id = $1 AND company_id = $2 AND status = ANY($3)",
        )
        .bind(tenant_id)
        .bind(company_id)
        .bind(CLIENT_VISIBLE_STATUSES)
        .fetch_one(&mut *tx)
        .await?;
        drop(tx);

        let mut resp: Vec<QuoteResponse> = rows.into_iter().map(Into::into).collect();
        self.enrich_quotes(tenant_id, &mut resp).await?;
        Ok((resp, total as u64))
    }

    /// Fetch one quote for a portal contact.
    ///
    /// Returns 404 rather than 403 when the quote belongs to another
    /// company or has not been issued, so the portal never confirms the
    /// existence of a quote the caller may not see. Mirrors the portal
    /// invoice route's posture.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_quote_for_company(
        &self,
        tenant_id: TenantId,
        company_id: Uuid,
        quote_id: Uuid,
    ) -> AppResult<QuoteResponse> {
        let quote = self.get_quote(tenant_id, quote_id).await?;
        if quote.company_id != company_id || !quote.status.is_client_visible() {
            return Err(AppError::NotFound("Quote".to_string()));
        }
        Ok(quote)
    }

    /// Record the client's accept / decline decision.
    ///
    /// Valid only from `sent`: an already-decided quote 409s, so a
    /// double-click or a stale browser tab cannot flip a decision, and an
    /// expired quote cannot be accepted at all.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn decide_quote(
        &self,
        tenant_id: TenantId,
        quote_id: Uuid,
        decision: &ClientDecision,
        ctx: &AuditCtx,
    ) -> AppResult<QuoteResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;

        // Company scope first, and as a 404: a contact must not be able to
        // learn that another company's quote exists by watching the error
        // change from 404 to 409.
        let row: Option<(Uuid, String, Option<NaiveDate>)> = sqlx::query_as(
            "SELECT company_id, status, valid_until FROM quotes WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(quote_id)
        .fetch_optional(&mut *tx)
        .await?;
        let (row_company, raw_status, valid_until) =
            row.ok_or_else(|| AppError::NotFound("Quote".to_string()))?;
        let stored = QuoteStatus::from_str(&raw_status).unwrap_or(QuoteStatus::Draft);
        if row_company != decision.company_id || !stored.is_client_visible() {
            return Err(AppError::NotFound("Quote".to_string()));
        }

        // Read-time expiry: a quote past `valid_until` is treated as
        // expired without a sweeper having to have run.
        let effective = effective_status(stored, valid_until, Utc::now().date_naive());
        if effective != QuoteStatus::Sent {
            return Err(AppError::Conflict(format!(
                "Quote in status '{}' can no longer be decided",
                effective.as_str()
            )));
        }

        let before: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT to_jsonb(t) FROM quotes t WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(quote_id)
                .fetch_optional(&mut *tx)
                .await?;

        let next = if decision.accept {
            QuoteStatus::Accepted
        } else {
            QuoteStatus::Declined
        };
        sqlx::query(
            r#"
            UPDATE quotes
            SET status = $3, decided_at = NOW(),
                decided_by_contact_id = $4, decision_notes = $5
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(quote_id)
        .bind(next.as_str())
        .bind(decision.contact_id)
        .bind(decision.notes.as_deref())
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
            AuditAction::Update,
            "quotes",
            Some(quote_id),
            before,
            after,
        )
        .await?;
        tx.commit().await?;

        let quote = self.get_quote(tenant_id, quote_id).await?;
        self.notify_owner_of_decision(tenant_id, &quote, next).await;
        Ok(quote)
    }

    /// Best-effort "your client decided" fanout to the quote's owner.
    /// Errors are logged, never surfaced: the decision is committed and
    /// must not be undone by a notification failure.
    async fn notify_owner_of_decision(
        &self,
        tenant_id: TenantId,
        quote: &QuoteResponse,
        outcome: QuoteStatus,
    ) {
        let Some(notifications) = self.notifications.as_ref() else {
            return;
        };
        let event_type = match outcome {
            QuoteStatus::Accepted => "quote.accepted",
            _ => "quote.declined",
        };
        let context = serde_json::json!({
            "quote_id": quote.id,
            "quote_number": quote.quote_number,
            "title": quote.title,
            "total": quote.total.to_string(),
            "company_id": quote.company_id,
            "company_name": quote.company_name,
            "decision_notes": quote.decision_notes,
            "recipient_user_id": quote.requested_by_id,
        });
        if let Err(e) = notifications
            .dispatch(tenant_id, event_type, &context)
            .await
        {
            tracing::warn!(error = %e, quote_id = %quote.id, "quote decision notification failed");
        }
    }

    // ========================================================================
    // PMS-674: convert an accepted quote into a Project.
    // ========================================================================

    /// Turn an accepted quote into a Project, in one transaction.
    ///
    /// This is the "upon approval, it becomes a project" step: the quote
    /// supplies the client, the name, the scope, and the budget, and the
    /// request supplies only what a quote cannot know (who runs it, when,
    /// and how it bills).
    ///
    /// **Idempotent.** The quote row is taken with `SELECT ... FOR UPDATE`
    /// before anything is read off it, so a second concurrent request
    /// blocks until the first commits and then observes `converted` and
    /// returns the existing link instead of building a second project.
    /// The row lock, not the `UNIQUE (converted_project_id)` constraint,
    /// is what makes this safe: that constraint stops two quotes pointing
    /// at one project, which is a different failure. It remains as a
    /// backstop.
    ///
    /// **Atomic.** The project insert and the quote's transition to
    /// `converted` share one transaction, so a failure on either leaves
    /// the quote exactly as it was rather than marked converted with no
    /// project behind it.
    ///
    /// Returns the updated quote rather than the project: every other
    /// route in this module returns a `QuoteResponse`, and the response
    /// carries `converted_project_id`, so a caller that wants the project
    /// has the id to fetch it.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn convert_quote(
        &self,
        tenant_id: TenantId,
        quote_id: Uuid,
        request: &ConvertQuoteRequest,
        ctx: &AuditCtx,
    ) -> AppResult<QuoteResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;

        // Serialise concurrent conversions of the same quote. Everything
        // below reads from this locked row.
        let row = sqlx::query_as::<_, QuoteForConversion>(
            r#"
            SELECT status, converted_project_id, company_id, title, description, total
            FROM quotes
            WHERE tenant_id = $1 AND id = $2
            FOR UPDATE
            "#,
        )
        .bind(tenant_id)
        .bind(quote_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::NotFound("Quote".to_string()))?;
        let status = QuoteStatus::from_str(&row.status).unwrap_or(QuoteStatus::Draft);

        // Already converted: return the existing link rather than 409ing.
        // A double-clicked Convert button is not an error, and the caller
        // gets the same `converted_project_id` either way.
        if status == QuoteStatus::Converted && row.converted_project_id.is_some() {
            drop(tx);
            return self.get_quote(tenant_id, quote_id).await;
        }

        if status != QuoteStatus::Accepted {
            return Err(AppError::Conflict(format!(
                "Quote in status '{}' cannot be converted; the client must accept it first",
                status.as_str()
            )));
        }

        let project_id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO projects (
                id, tenant_id, name, description, company_id,
                project_type, project_type_id, status, project_manager_id,
                start_date, target_end_date, budget_hours, budget_amount,
                billing_method, is_billable
            ) VALUES (
                $1, $2, $3, $4, $5,
                'client',
                -- Same lookup resolution `create_project` does (PMS-322);
                -- NULL when the tenant has no matching type row.
                (SELECT id FROM project_types WHERE tenant_id = $2 AND name = 'client'),
                'planning', $6, $7, $8, $9, $10, $11, TRUE
            )
            "#,
        )
        .bind(project_id)
        .bind(tenant_id)
        .bind(&row.title)
        .bind(&row.description)
        .bind(row.company_id)
        .bind(request.project_manager_id)
        .bind(request.start_date)
        .bind(request.target_end_date)
        .bind(request.budget_hours)
        .bind(row.total)
        .bind(request.billing_method.as_deref().unwrap_or("fixed_price"))
        .execute(&mut *tx)
        .await?;

        let before: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT to_jsonb(t) FROM quotes t WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(quote_id)
                .fetch_optional(&mut *tx)
                .await?;

        sqlx::query(
            r#"
            UPDATE quotes
            SET status = 'converted', converted_project_id = $3
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(quote_id)
        .bind(project_id)
        .execute(&mut *tx)
        .await?;

        let after: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT to_jsonb(t) FROM quotes t WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(quote_id)
                .fetch_optional(&mut *tx)
                .await?;

        // Two audit rows: the project came into existence, and the quote
        // changed state. Reading either entity's history alone should show
        // what happened to it.
        let project_after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM projects t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(project_id)
        .fetch_optional(&mut *tx)
        .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Create,
            "projects",
            Some(project_id),
            None,
            project_after,
        )
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

/// Statuses a portal contact may see, as the bind for `status = ANY($n)`.
/// Kept in step with [`QuoteStatus::is_client_visible`]; the unit tests
/// assert the two agree so a new status cannot be added to one and
/// forgotten in the other.
const CLIENT_VISIBLE_STATUSES: &[&str] = &["sent", "accepted", "declined", "expired", "converted"];

/// Derive the status a reader should see, applying expiry at read time.
///
/// A `sent` quote whose `valid_until` has passed reads as `expired`
/// without any sweeper having run. Doing it here rather than in a
/// scheduled job means there is no window in which an expired quote is
/// still acceptable, and no background machinery to operate; the cost is
/// that the stored status stays `sent` until something writes the row.
/// Only `sent` is reinterpreted: a quote already accepted or converted
/// does not expire retroactively just because its validity date passed.
fn effective_status(
    stored: QuoteStatus,
    valid_until: Option<NaiveDate>,
    today: NaiveDate,
) -> QuoteStatus {
    match (stored, valid_until) {
        (QuoteStatus::Sent, Some(until)) if until < today => QuoteStatus::Expired,
        _ => stored,
    }
}

/// Shared column list so the list and detail reads cannot drift apart.
const QUOTE_COLUMNS: &str = r#"id, tenant_id, quote_number, company_id, billing_contact_id,
       title, summary, description, status, valid_until,
       subtotal, tax_amount, total, currency, requested_by_id,
       sent_at, decided_at, decided_by_contact_id, decision_notes,
       converted_project_id, created_at, updated_at"#;

/// The fields `convert_quote` reads off the `FOR UPDATE`-locked quote
/// row. A named struct rather than a tuple so the field meanings survive
/// the trip to the INSERT below.
#[derive(sqlx::FromRow)]
struct QuoteForConversion {
    status: String,
    converted_project_id: Option<Uuid>,
    company_id: Uuid,
    title: String,
    description: Option<String>,
    total: Decimal,
}

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
            // Read-time expiry (PMS-673): a `sent` quote past its
            // `valid_until` reports as `expired` even though the stored
            // column still says `sent`. See `effective_status`.
            status: effective_status(
                QuoteStatus::from_str(&r.status).unwrap_or(QuoteStatus::Draft),
                r.valid_until,
                Utc::now().date_naive(),
            ),
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

    /// Every status, so the set-membership tests below cannot silently
    /// miss a variant added later.
    const ALL_STATUSES: [QuoteStatus; 10] = [
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
    ];

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
    fn client_visible_set_matches_the_sql_bind_list() {
        // `CLIENT_VISIBLE_STATUSES` is what the portal list query binds,
        // and `is_client_visible` is what the detail + decide paths check.
        // If the two ever disagree, a quote would be listable but not
        // openable (or worse). Pin them to each other.
        for s in ALL_STATUSES {
            assert_eq!(
                s.is_client_visible(),
                CLIENT_VISIBLE_STATUSES.contains(&s.as_str()),
                "{} disagrees between the predicate and the SQL bind list",
                s.as_str()
            );
        }
    }

    #[test]
    fn internal_states_are_never_client_visible() {
        // The customer must not learn that a quote was drafted, submitted,
        // internally rejected, or withdrawn.
        for s in [
            QuoteStatus::Draft,
            QuoteStatus::Submitted,
            QuoteStatus::Approved,
            QuoteStatus::Rejected,
            QuoteStatus::Cancelled,
        ] {
            assert!(!s.is_client_visible(), "{} must stay internal", s.as_str());
        }
    }

    #[test]
    fn expiry_is_applied_at_read_time_to_sent_quotes_only() {
        let today = NaiveDate::from_ymd_opt(2026, 7, 21).unwrap();
        let yesterday = NaiveDate::from_ymd_opt(2026, 7, 20).unwrap();
        let tomorrow = NaiveDate::from_ymd_opt(2026, 7, 22).unwrap();

        // A sent quote past its date reads as expired.
        assert_eq!(
            effective_status(QuoteStatus::Sent, Some(yesterday), today),
            QuoteStatus::Expired
        );
        // On the last valid day it is still live: `valid_until` is
        // inclusive, so a customer accepting on the deadline succeeds.
        assert_eq!(
            effective_status(QuoteStatus::Sent, Some(today), today),
            QuoteStatus::Sent
        );
        assert_eq!(
            effective_status(QuoteStatus::Sent, Some(tomorrow), today),
            QuoteStatus::Sent
        );
        // No expiry date means it never expires.
        assert_eq!(
            effective_status(QuoteStatus::Sent, None, today),
            QuoteStatus::Sent
        );
        // A decided quote does not expire retroactively just because the
        // validity date has since passed.
        for s in [
            QuoteStatus::Accepted,
            QuoteStatus::Declined,
            QuoteStatus::Converted,
            QuoteStatus::Draft,
        ] {
            assert_eq!(effective_status(s, Some(yesterday), today), s);
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
