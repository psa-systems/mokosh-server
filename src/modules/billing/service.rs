//! Billing service. Endpoints land incrementally across PMS-33.

use chrono::Utc;
use rust_decimal::Decimal;
use uuid::Uuid;

use crate::db::Database;
use crate::utils::error::{AppError, AppResult};
use crate::utils::pagination::PaginationParams;

use super::models::*;

/// Billing operations: invoices, payments, gateway configs, tax rates.
#[derive(Clone)]
pub struct BillingService {
    db: Database,
}

impl BillingService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// PMS-35: paginated + filterable invoice list. `lines` is left
    /// `None` on list rollups — the customer-facing UI fetches lines
    /// only when expanding a row.
    pub async fn list_invoices(
        &self,
        tenant_id: Uuid,
        filter: &InvoiceFilter,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<InvoiceResponse>, u64)> {
        let offset = pagination.offset() as i64;
        let limit = pagination.limit() as i64;

        let mut conditions = vec!["tenant_id = $1".to_string()];
        let mut param_idx = 4;
        if filter.company_id.is_some() {
            conditions.push(format!("company_id = ${param_idx}"));
            param_idx += 1;
        }
        if filter.status.is_some() {
            conditions.push(format!("status = ${param_idx}"));
            param_idx += 1;
        }
        if filter.contract_id.is_some() {
            conditions.push(format!("contract_id = ${param_idx}"));
            param_idx += 1;
        }
        if filter.q.is_some() {
            conditions.push(format!("(invoice_number ILIKE ${param_idx} OR po_number ILIKE ${param_idx})"));
        }

        let where_clause = conditions.join(" AND ");
        let order_by = pagination.order_by(
            "invoice_date DESC",
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
            WHERE {where_clause}
            ORDER BY {order_by}
            LIMIT $2 OFFSET $3
            "#
        );
        let count_query = format!("SELECT COUNT(*) FROM invoices WHERE {where_clause}");

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
    pub async fn create_invoice(
        &self,
        tenant_id: Uuid,
        request: &CreateInvoiceRequest,
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
        let invoice_number = format!("{}{:06}", prefix.unwrap_or_else(|| "INV-".to_string()), next_number);

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

        tx.commit().await?;
        self.get_invoice(tenant_id, invoice_id).await
    }

    /// PMS-38: update an invoice header and optionally replace its
    /// line items in one transaction. Rejects edits on
    /// `InvoiceStatus::is_frozen` invoices (sent, paid, partially paid,
    /// void, written off) - correction goes through a credit note,
    /// which is out of scope for this commit.
    pub async fn update_invoice(
        &self,
        tenant_id: Uuid,
        invoice_id: Uuid,
        request: &UpdateInvoiceRequest,
    ) -> AppResult<InvoiceResponse> {
        let current = self.get_invoice(tenant_id, invoice_id).await?;
        if current.status.is_frozen() {
            return Err(AppError::Conflict(format!(
                "Invoice in status '{}' cannot be edited",
                current.status.as_str()
            )));
        }

        let mut tx = self.db.pool().begin().await?;

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

        tx.commit().await?;
        self.get_invoice(tenant_id, invoice_id).await
    }

    /// PMS-36: read a single invoice with `lines` populated. 404 when
    /// the id is outside the tenant.
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
