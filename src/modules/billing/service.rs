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
