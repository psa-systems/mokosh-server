//! MAPPS-1100 Phases A + B: the writer for the Bills and Expenses
//! subsystem.
//!
//! Phase A shipped the leaf lookups (`vendors`, `expense_categories`).
//! Phase B shipped the bill + expense headers with their own lifecycle:
//! bills (`draft -> approved -> paid`, `void`) and expenses
//! (`draft -> submitted -> approved -> reimbursed`, `rejected`), each
//! atomic with its lines in one transaction. Delegation to Xero /
//! QuickBooks is Phase C: it builds on the OAuth + webhook infrastructure
//! MAPPS-1099 shipped, and has not yet been started.
//!
//! Every mutation runs inside `begin_with_tenant` and writes an
//! `audit_log` row in the same transaction, matching the billing
//! service's pattern.

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::FromRow;
use uuid::Uuid;
use validator::Validate;

use super::models::{
    Bill, BillFilter, BillLine, BillPayment, Expense, ExpenseCategory, ExpenseFilter, ExpenseLine,
    Vendor,
};
use crate::db::{Database, TenantTransaction};
use crate::modules::audit::{audit_write, AuditAction, AuditCtx};
use crate::modules::auth::TenantId;
use crate::utils::error::{AppError, AppResult, FieldError};
use crate::utils::pagination::PaginationParams;

fn field_error(field: &str, message: &str) -> AppError {
    AppError::Validation {
        message: message.to_string(),
        errors: vec![FieldError::new(field, message, "invalid")],
    }
}

/// Create / update body for a vendor. Name is required and bounded; the
/// optional fields mirror the schema columns one-to-one.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpsertVendorRequest {
    #[validate(length(min = 1, max = 200))]
    pub name: String,
    #[serde(default)]
    #[validate(length(max = 100))]
    pub account_number: Option<String>,
    /// ISO-4217 code the vendor bills in by default (optional). Capped so
    /// a mistyped free-text value cannot reach the ledger.
    #[serde(default)]
    #[validate(length(min = 3, max = 3))]
    pub default_currency: Option<String>,
    #[serde(default)]
    #[validate(length(max = 2000))]
    pub notes: Option<String>,
}

/// Create / update body for an expense category.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpsertExpenseCategoryRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    #[serde(default = "default_true")]
    pub is_active: bool,
}

fn default_true() -> bool {
    true
}

/// Response shape for an expense category. The row shape is also the
/// response because the schema has no fields the client should not see.
#[derive(Debug, Clone, Serialize, FromRow)]
pub struct ExpenseCategoryResponse {
    pub id: Uuid,
    pub name: String,
    pub is_active: bool,
}

impl From<ExpenseCategory> for ExpenseCategoryResponse {
    fn from(c: ExpenseCategory) -> Self {
        Self {
            id: c.id,
            name: c.name,
            is_active: c.is_active,
        }
    }
}

/// The one writer for the expenses subsystem.
#[derive(Clone)]
pub struct ExpensesService {
    db: Database,
    /// MAPPS-1155: the dispatcher that raises a bill in the provider a
    /// tenant delegated Bills and expenses to. `None` on every test
    /// harness and QA seeder, so a build that does not opt in keeps the
    /// local path byte for byte; wired on the serving instance after
    /// `IntegrationsService` is built.
    bill_dispatch:
        Option<std::sync::Arc<crate::modules::billing::invoice_issuer_dispatch::IssuerDispatcher>>,
}

impl ExpensesService {
    pub fn new(db: Database) -> Self {
        Self {
            db,
            bill_dispatch: None,
        }
    }

    /// Opt this instance into delegated bills (MAPPS-1155).
    ///
    /// The same shape `BillingService::with_invoice_dispatch` uses, for
    /// the same reason: an instance built without it runs the local path
    /// for every tenant, and one built with it still does until an
    /// operator flips `Feature::DelegatedBills` AND the tenant delegates.
    pub fn with_bill_dispatch(
        mut self,
        dispatcher: std::sync::Arc<
            crate::modules::billing::invoice_issuer_dispatch::IssuerDispatcher,
        >,
    ) -> Self {
        self.bill_dispatch = Some(dispatcher);
        self
    }

    // ── Vendors ──────────────────────────────────────────────────────────

    pub async fn list_vendors(
        &self,
        tenant_id: TenantId,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<Vendor>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vendors WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_one(&mut *tx)
            .await?;
        let rows: Vec<Vendor> = sqlx::query_as(
            r#"SELECT id, tenant_id, name, account_number, default_currency, notes,
                      created_at, updated_at
               FROM vendors
               WHERE tenant_id = $1
               ORDER BY lower(name)
               LIMIT $2 OFFSET $3"#,
        )
        .bind(tenant_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&mut *tx)
        .await?;
        Ok((rows, total as u64))
    }

    pub async fn get_vendor(&self, tenant_id: TenantId, id: Uuid) -> AppResult<Vendor> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: Option<Vendor> = sqlx::query_as(
            r#"SELECT id, tenant_id, name, account_number, default_currency, notes,
                      created_at, updated_at
               FROM vendors WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        row.ok_or_else(|| AppError::NotFound("Vendor".to_string()))
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_vendor(
        &self,
        tenant_id: TenantId,
        request: &UpsertVendorRequest,
        ctx: &AuditCtx,
    ) -> AppResult<Vendor> {
        let id = Uuid::new_v4();
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: Vendor = sqlx::query_as(
            r#"INSERT INTO vendors
                 (id, tenant_id, name, account_number, default_currency, notes)
               VALUES ($1, $2, $3, $4, $5, $6)
               RETURNING id, tenant_id, name, account_number, default_currency, notes,
                         created_at, updated_at"#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(request.name.trim())
        .bind(request.account_number.as_deref().map(str::trim))
        .bind(
            request
                .default_currency
                .as_deref()
                .map(|c| c.trim().to_ascii_uppercase()),
        )
        .bind(request.notes.as_deref())
        .fetch_one(&mut *tx)
        .await?;
        let after: Option<Value> = Some(serde_json::to_value(&row).unwrap_or(Value::Null));
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Create,
            "vendors",
            Some(id),
            None,
            after,
        )
        .await?;
        tx.commit().await?;
        Ok(row)
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, vendor_id = %id))]
    pub async fn update_vendor(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        request: &UpsertVendorRequest,
        ctx: &AuditCtx,
    ) -> AppResult<Vendor> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let before: Option<Value> = sqlx::query_scalar(
            "SELECT to_jsonb(v) FROM vendors v WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        if before.is_none() {
            return Err(AppError::NotFound("Vendor".to_string()));
        }
        let row: Vendor = sqlx::query_as(
            r#"UPDATE vendors
               SET name = $3,
                   account_number = $4,
                   default_currency = $5,
                   notes = $6,
                   updated_at = NOW()
               WHERE tenant_id = $1 AND id = $2
               RETURNING id, tenant_id, name, account_number, default_currency, notes,
                         created_at, updated_at"#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(request.name.trim())
        .bind(request.account_number.as_deref().map(str::trim))
        .bind(
            request
                .default_currency
                .as_deref()
                .map(|c| c.trim().to_ascii_uppercase()),
        )
        .bind(request.notes.as_deref())
        .fetch_one(&mut *tx)
        .await?;
        let after: Option<Value> = Some(serde_json::to_value(&row).unwrap_or(Value::Null));
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Update,
            "vendors",
            Some(id),
            before,
            after,
        )
        .await?;
        tx.commit().await?;
        Ok(row)
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, vendor_id = %id))]
    pub async fn delete_vendor(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        ctx: &AuditCtx,
    ) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let before: Option<Value> = sqlx::query_scalar(
            "SELECT to_jsonb(v) FROM vendors v WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        if before.is_none() {
            return Err(AppError::NotFound("Vendor".to_string()));
        }
        let result = sqlx::query("DELETE FROM vendors WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await;
        if let Err(e) = result {
            // A bill still references this vendor (FK 23503): 409 so the
            // caller sees a reason instead of a 500.
            if e.as_database_error().and_then(|d| d.code()).as_deref() == Some("23503") {
                return Err(AppError::Conflict(
                    "Cannot delete this vendor: it is still referenced by a bill".to_string(),
                ));
            }
            return Err(e.into());
        }
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Delete,
            "vendors",
            Some(id),
            before,
            None,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    // ── Expense categories ───────────────────────────────────────────────

    pub async fn list_expense_categories(
        &self,
        tenant_id: TenantId,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<ExpenseCategoryResponse>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM expense_categories WHERE tenant_id = $1")
                .bind(tenant_id)
                .fetch_one(&mut *tx)
                .await?;
        let rows: Vec<ExpenseCategoryResponse> = sqlx::query_as(
            r#"SELECT id, name, is_active
               FROM expense_categories
               WHERE tenant_id = $1
               ORDER BY lower(name)
               LIMIT $2 OFFSET $3"#,
        )
        .bind(tenant_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&mut *tx)
        .await?;
        Ok((rows, total as u64))
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_expense_category(
        &self,
        tenant_id: TenantId,
        request: &UpsertExpenseCategoryRequest,
        ctx: &AuditCtx,
    ) -> AppResult<ExpenseCategoryResponse> {
        let id = Uuid::new_v4();
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let insert = sqlx::query_as::<_, ExpenseCategoryResponse>(
            r#"INSERT INTO expense_categories (id, tenant_id, name, is_active)
               VALUES ($1, $2, $3, $4)
               RETURNING id, name, is_active"#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(request.name.trim())
        .bind(request.is_active)
        .fetch_one(&mut *tx)
        .await;
        let row = match insert {
            Ok(r) => r,
            Err(e) => {
                // (tenant_id, lower(name)) uniqueness collision.
                if e.as_database_error().and_then(|d| d.code()).as_deref() == Some("23505") {
                    return Err(AppError::Conflict(
                        "An expense category with that name already exists".to_string(),
                    ));
                }
                return Err(e.into());
            }
        };
        let after: Option<Value> = Some(serde_json::json!({
            "id": row.id,
            "name": row.name,
            "is_active": row.is_active,
        }));
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Create,
            "expense_categories",
            Some(id),
            None,
            after,
        )
        .await?;
        tx.commit().await?;
        Ok(row)
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, category_id = %id))]
    pub async fn update_expense_category(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        request: &UpsertExpenseCategoryRequest,
        ctx: &AuditCtx,
    ) -> AppResult<ExpenseCategoryResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let before: Option<Value> = sqlx::query_scalar(
            "SELECT to_jsonb(c) FROM expense_categories c WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        if before.is_none() {
            return Err(AppError::NotFound("Expense category".to_string()));
        }
        let update = sqlx::query_as::<_, ExpenseCategoryResponse>(
            r#"UPDATE expense_categories
               SET name = $3, is_active = $4
               WHERE tenant_id = $1 AND id = $2
               RETURNING id, name, is_active"#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(request.name.trim())
        .bind(request.is_active)
        .fetch_one(&mut *tx)
        .await;
        let row = match update {
            Ok(r) => r,
            Err(e) => {
                if e.as_database_error().and_then(|d| d.code()).as_deref() == Some("23505") {
                    return Err(AppError::Conflict(
                        "An expense category with that name already exists".to_string(),
                    ));
                }
                return Err(e.into());
            }
        };
        let after: Option<Value> = Some(serde_json::json!({
            "id": row.id,
            "name": row.name,
            "is_active": row.is_active,
        }));
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Update,
            "expense_categories",
            Some(id),
            before,
            after,
        )
        .await?;
        tx.commit().await?;
        Ok(row)
    }

    // ── Bills ────────────────────────────────────────────────────────────
    //
    // Bills are what the MSP owes a vendor. Lifecycle is
    // `draft -> approved -> paid`, with `void` as an off-ramp. A `draft`
    // bill is editable; everything after is immutable from this
    // service's write surface except for status transitions. Totals are
    // computed from the lines inside the create transaction so a
    // committed row's `subtotal_minor` / `tax_minor` / `total_minor`
    // match its line set exactly.

    /// Bills for this tenant, narrowed by status and by free text
    /// (PMS-1539).
    ///
    /// The count uses the same predicate as the page, so `total`
    /// describes the filtered set: a count over every bill beside a
    /// filtered page would page an operator into empty pages and
    /// misreport how many matched, which is why MAPPS-1167 could not do
    /// this client-side.
    ///
    /// `q` matches the bill's own number and the vendor's name. The
    /// invoices precedent searches `invoice_number` and `po_number`, the
    /// document's own identifiers; a bill's second identifier is who sent
    /// it, and that name lives on `vendors`, so it is reached through an
    /// EXISTS rather than a join, which keeps the count query and the
    /// page query the same shape.
    pub async fn list_bills(
        &self,
        tenant_id: TenantId,
        filter: &BillFilter,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<Bill>, u64)> {
        let status = filter
            .status
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let pattern = search_pattern(filter.q.as_deref());
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*) FROM bills
               WHERE tenant_id = $1
                 AND ($2::text IS NULL OR status = $2)
                 AND ($3::text IS NULL OR bill_number ILIKE $3 OR EXISTS (
                       SELECT 1 FROM vendors v
                       WHERE v.tenant_id = bills.tenant_id
                         AND v.id = bills.vendor_id
                         AND v.name ILIKE $3
                     ))"#,
        )
        .bind(tenant_id)
        .bind(status)
        .bind(pattern.as_deref())
        .fetch_one(&mut *tx)
        .await?;
        let rows: Vec<Bill> = sqlx::query_as(
            r#"SELECT id, tenant_id, vendor_id, bill_number, issue_date, due_date,
                      currency, subtotal_minor, tax_minor, total_minor, paid_minor,
                      status, notes, external_provider, external_bill_id,
                      created_at, updated_at
               FROM bills
               WHERE tenant_id = $1
                 AND ($2::text IS NULL OR status = $2)
                 AND ($3::text IS NULL OR bill_number ILIKE $3 OR EXISTS (
                       SELECT 1 FROM vendors v
                       WHERE v.tenant_id = bills.tenant_id
                         AND v.id = bills.vendor_id
                         AND v.name ILIKE $3
                     ))
               ORDER BY issue_date DESC, created_at DESC
               LIMIT $4 OFFSET $5"#,
        )
        .bind(tenant_id)
        .bind(status)
        .bind(pattern.as_deref())
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&mut *tx)
        .await?;
        Ok((rows, total as u64))
    }

    pub async fn get_bill(&self, tenant_id: TenantId, id: Uuid) -> AppResult<BillWithLines> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let bill: Bill = sqlx::query_as(
            r#"SELECT id, tenant_id, vendor_id, bill_number, issue_date, due_date,
                      currency, subtotal_minor, tax_minor, total_minor, paid_minor,
                      status, notes, external_provider, external_bill_id,
                      created_at, updated_at
               FROM bills WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::NotFound("Bill".to_string()))?;
        let lines: Vec<BillLine> = sqlx::query_as(
            r#"SELECT id, tenant_id, bill_id, category_id, description,
                      quantity_hundredths, unit_price_minor, tax_minor, total_minor,
                      position, created_at
               FROM bill_lines
               WHERE tenant_id = $1 AND bill_id = $2
               ORDER BY position, created_at"#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_all(&mut *tx)
        .await?;
        Ok(BillWithLines { bill, lines })
    }

    /// The vendor must belong to this tenant. FK + the RLS GUC enforce it,
    /// but the explicit lookup gives a clear 404 instead of a generic
    /// FK-violation 500 on a wrong id.
    async fn assert_vendor_exists(&self, tenant_id: TenantId, vendor_id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let found = sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM vendors WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(vendor_id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        found
            .map(|_| ())
            .ok_or_else(|| AppError::NotFound("Vendor".to_string()))
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_bill(
        &self,
        tenant_id: TenantId,
        request: &CreateBillRequest,
        ctx: &AuditCtx,
    ) -> AppResult<BillWithLines> {
        let currency = request.currency.trim().to_ascii_uppercase();
        if currency.len() != 3 {
            return Err(field_error(
                "currency",
                "currency is a 3-letter ISO-4217 code",
            ));
        }
        if request.lines.is_empty() {
            return Err(field_error("lines", "a bill needs at least one line"));
        }
        let totals = BillTotals::from_lines(&request.lines);
        let id = Uuid::new_v4();

        // MAPPS-1155: when the tenant has delegated Bills and expenses, the
        // provider holds the bill, and it is raised there BEFORE anything
        // local is written, so a provider that refuses leaves no row
        // behind. Outside the transaction for the reason MAPPS-1134 put
        // the invoice push outside its own: an HTTP round trip inside a
        // write transaction holds its locks for the length of somebody
        // else's outage.
        //
        // The pass is skipped entirely unless the deployment switch is on,
        // so a deployment that has not flipped it runs exactly the
        // statements it ran before.
        let external = match self.bill_dispatch.as_ref() {
            Some(dispatcher) if dispatcher.bills_delegation_enabled() => {
                use crate::modules::billing::invoice_issuer_dispatch::{
                    BillLineShape, BillPlan, CreateBillShape,
                };
                // The same lookup the write transaction does below, run
                // first on this path only. Without it an id that names no
                // vendor is refused as "not mapped to a Xero vendor",
                // which sends the reader to the mapping surface to map a
                // vendor that does not exist; the local path answers 404
                // and so should this one.
                self.assert_vendor_exists(tenant_id, request.vendor_id)
                    .await?;
                let lines: Vec<BillLineShape> = request
                    .lines
                    .iter()
                    .map(|l| BillLineShape {
                        category_id: l.category_id,
                        description: l.description.clone(),
                        quantity_hundredths: l.quantity_hundredths,
                        unit_price_minor: l.unit_price_minor,
                    })
                    .collect();
                let shape = CreateBillShape {
                    vendor_id: request.vendor_id,
                    issue_date: request.issue_date,
                    // A bill with no due date is due on issue as far as the
                    // provider is concerned; Mokosh keeps the NULL, which is
                    // "the vendor did not say".
                    due_date: request.due_date.unwrap_or(request.issue_date),
                    currency: &currency,
                    lines: &lines,
                };
                match dispatcher.plan_bill(tenant_id, &shape).await? {
                    BillPlan::Local => None,
                    BillPlan::Delegated(external) => Some(external),
                }
            }
            _ => None,
        };

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;

        // The vendor must belong to this tenant: FK + the RLS GUC enforce
        // it, but the explicit lookup gives a clear 404 instead of a
        // generic FK-violation 500 on a wrong id. Inside the transaction
        // that writes, so it holds for the row being written; the
        // delegated path checks it a second time before the push, where
        // no transaction is open yet.
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM vendors WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(request.vendor_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| AppError::NotFound("Vendor".to_string()))?;

        let bill: Bill = sqlx::query_as(
            r#"INSERT INTO bills
                 (id, tenant_id, vendor_id, bill_number, issue_date, due_date,
                  currency, subtotal_minor, tax_minor, total_minor, notes,
                  external_provider, external_bill_id)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
               RETURNING id, tenant_id, vendor_id, bill_number, issue_date, due_date,
                         currency, subtotal_minor, tax_minor, total_minor, paid_minor,
                         status, notes, external_provider, external_bill_id,
                         created_at, updated_at"#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(request.vendor_id)
        .bind(request.bill_number.as_deref().map(str::trim))
        .bind(request.issue_date)
        .bind(request.due_date)
        .bind(&currency)
        .bind(totals.subtotal_minor)
        .bind(totals.tax_minor)
        .bind(totals.total_minor)
        .bind(request.notes.as_deref())
        // MAPPS-1155: NULL on the local path, which is every row on a
        // deployment that has not delegated. The pair records who holds
        // the bill of record, and the local row keeps every other column
        // it already had: nothing about the Mokosh bill changes because a
        // provider also has it.
        .bind(external.as_ref().map(|e| e.provider.as_str()))
        .bind(external.as_ref().map(|e| e.external_bill_id.as_str()))
        .fetch_one(&mut *tx)
        .await?;

        let lines = insert_bill_lines(&mut tx, tenant_id, id, &request.lines).await?;

        let after: Option<Value> = Some(serde_json::to_value(&bill).unwrap_or(Value::Null));
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Create,
            "bills",
            Some(id),
            None,
            after,
        )
        .await?;
        tx.commit().await?;
        Ok(BillWithLines { bill, lines })
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, bill_id = %id))]
    pub async fn approve_bill(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        ctx: &AuditCtx,
    ) -> AppResult<Bill> {
        self.transition_bill(tenant_id, id, &["draft"], "approved", ctx)
            .await
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, bill_id = %id))]
    pub async fn void_bill(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        ctx: &AuditCtx,
    ) -> AppResult<Bill> {
        self.transition_bill(tenant_id, id, &["draft", "approved"], "void", ctx)
            .await
    }

    async fn transition_bill(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        allowed_from: &[&str],
        to: &str,
        ctx: &AuditCtx,
    ) -> AppResult<Bill> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let before: Bill = sqlx::query_as(
            r#"SELECT id, tenant_id, vendor_id, bill_number, issue_date, due_date,
                      currency, subtotal_minor, tax_minor, total_minor, paid_minor,
                      status, notes, external_provider, external_bill_id,
                      created_at, updated_at
               FROM bills WHERE tenant_id = $1 AND id = $2 FOR UPDATE"#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::NotFound("Bill".to_string()))?;
        if !allowed_from.iter().any(|s| *s == before.status) {
            return Err(AppError::Conflict(bill_transition_refusal(
                &before.status,
                to,
            )));
        }
        let after: Bill = sqlx::query_as(
            r#"UPDATE bills SET status = $3, updated_at = NOW()
               WHERE tenant_id = $1 AND id = $2
               RETURNING id, tenant_id, vendor_id, bill_number, issue_date, due_date,
                         currency, subtotal_minor, tax_minor, total_minor, paid_minor,
                         status, notes, external_provider, external_bill_id,
                         created_at, updated_at"#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(to)
        .fetch_one(&mut *tx)
        .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Update,
            "bills",
            Some(id),
            Some(serde_json::to_value(&before).unwrap_or(Value::Null)),
            Some(serde_json::to_value(&after).unwrap_or(Value::Null)),
        )
        .await?;
        tx.commit().await?;
        Ok(after)
    }

    /// Record one payment the MSP made against a bill (PMS-1536).
    ///
    /// The four refusals, each for its own reason:
    ///
    /// - a **draft** bill cannot be paid, because approval is the step
    ///   where somebody checks the bill against what was ordered, and
    ///   paying first makes that check decorative;
    /// - a **void** bill cannot be paid, and the refusal says it was
    ///   voided rather than leaving the reader to guess;
    /// - an amount **at or below zero** is not a payment. A refund from a
    ///   vendor is a credit they owe, which is a different document;
    ///   `bill_payments_amount_positive` is the floor under this.
    /// - an amount **over what remains** is refused, naming what remains.
    ///   A duplicate payment is a thing to fix with the vendor, not to
    ///   record as an overpayment that leaves `paid_minor > total_minor`
    ///   and `status` meaning neither one thing nor the other.
    ///
    /// The insert and the recompute share one transaction, so a reader can
    /// never see a payment row that `paid_minor` does not include.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, bill_id = %bill_id))]
    pub async fn record_bill_payment(
        &self,
        tenant_id: TenantId,
        bill_id: Uuid,
        request: &RecordBillPaymentRequest,
        ctx: &AuditCtx,
    ) -> AppResult<BillWithPayments> {
        if request.amount_minor <= 0 {
            return Err(field_error(
                "amount_minor",
                "a payment is an amount above zero; a vendor refund is a credit, not a negative payment",
            ));
        }
        let method = request.payment_method.trim().to_ascii_lowercase();
        if !BILL_PAYMENT_METHODS.contains(&method.as_str()) {
            return Err(field_error(
                "payment_method",
                "payment_method is one of check, credit_card, ach, wire, cash, other",
            ));
        }

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let bill: Bill = sqlx::query_as(
            r#"SELECT id, tenant_id, vendor_id, bill_number, issue_date, due_date,
                      currency, subtotal_minor, tax_minor, total_minor, paid_minor,
                      status, notes, external_provider, external_bill_id,
                      created_at, updated_at
               FROM bills WHERE tenant_id = $1 AND id = $2 FOR UPDATE"#,
        )
        .bind(tenant_id)
        .bind(bill_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::NotFound("Bill".to_string()))?;

        match bill.status.as_str() {
            "approved" | "paid" => {}
            "void" => {
                return Err(AppError::Conflict(
                    "This bill was voided, so there is nothing to pay.".to_string(),
                ))
            }
            other => {
                return Err(AppError::Conflict(format!(
                "A bill is paid after it is approved, and this one is {other}. Approve it first."
            )))
            }
        }

        let remaining = bill.total_minor.saturating_sub(bill.paid_minor);
        if request.amount_minor > remaining {
            return Err(AppError::Conflict(format!(
                "That is more than this bill has left to pay ({} remaining of {}). \
                 A duplicate payment is settled with the vendor, not recorded here.",
                remaining, bill.total_minor
            )));
        }

        let payment: BillPayment = sqlx::query_as(
            r#"INSERT INTO bill_payments
                 (tenant_id, bill_id, paid_on, amount_minor, payment_method, reference, notes)
               VALUES ($1, $2, $3, $4, $5, $6, $7)
               RETURNING id, tenant_id, bill_id, paid_on, amount_minor,
                         payment_method, reference, notes, created_at"#,
        )
        .bind(tenant_id)
        .bind(bill_id)
        .bind(request.paid_on)
        .bind(request.amount_minor)
        .bind(&method)
        .bind(request.reference.as_deref().map(str::trim))
        .bind(request.notes.as_deref().map(str::trim))
        .fetch_one(&mut *tx)
        .await?;

        let updated = recompute_bill_payment_state(&mut tx, tenant_id, bill_id).await?;

        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Create,
            "bill_payments",
            Some(payment.id),
            None,
            Some(serde_json::to_value(&payment).unwrap_or(Value::Null)),
        )
        .await?;
        tx.commit().await?;
        Ok(BillWithPayments {
            bill: updated,
            payments: vec![payment],
        })
    }

    /// The delegated bill one provider id names, for the webhook receiver
    /// (PMS-1543).
    ///
    /// The bill half of `BillingService::delegated_invoice`, and keyed the
    /// same way: tenant, provider and the provider's own id. Returns the
    /// three figures reconciliation needs rather than the whole row,
    /// because the receiver's job is arithmetic.
    pub async fn delegated_bill(
        &self,
        tenant_id: TenantId,
        provider: &str,
        external_bill_id: &str,
    ) -> AppResult<Option<DelegatedBillRow>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: Option<DelegatedBillRow> = sqlx::query_as(
            "SELECT id, status, total_minor, paid_minor, currency FROM bills \
             WHERE tenant_id = $1 AND external_provider = $2 AND external_bill_id = $3",
        )
        .bind(tenant_id)
        .bind(provider)
        .bind(external_bill_id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row)
    }

    /// Record what the provider says it has paid against a delegated bill
    /// (PMS-1543).
    ///
    /// Reconciles rather than appends: the caller passes the provider's
    /// RUNNING total, and this writes the difference against what Mokosh
    /// already holds. A redelivered webhook therefore records nothing
    /// because the difference is zero, which is idempotency by arithmetic
    /// rather than by a dedupe column somebody has to keep unique.
    ///
    /// Returns the payment it wrote, or `None` when there was nothing to
    /// write. Three ways to get `None`, all of them ordinary: the provider
    /// is level with Mokosh, the bill is already fully paid here, or the
    /// bill is in a state that cannot take a payment (a void bill whose
    /// provider copy was paid is a disagreement to surface, not one to
    /// paper over by writing anyway).
    ///
    /// An amount beyond the remaining balance is recorded UP TO the
    /// balance and the excess logged. The local refusal that
    /// `record_bill_payment` gives a human is the right answer when a
    /// person is typing; here the provider has already committed the
    /// payment, and refusing it would leave the two ledgers disagreeing,
    /// which is the thing this path exists to stop.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, external_bill_id = %report.external_bill_id))]
    pub async fn reconcile_external_bill_payment(
        &self,
        tenant_id: TenantId,
        report: &ExternalBillPaymentReport<'_>,
        ctx: &AuditCtx,
    ) -> AppResult<Option<BillPayment>> {
        let ExternalBillPaymentReport {
            provider,
            external_bill_id,
            provider_paid_minor,
            paid_on,
        } = *report;
        // The bill is resolved from the provider's id rather than passed
        // in: the caller holds only that id, and one that passed both could
        // pass a figure from one bill with the id of another.
        let Some(bill) = self
            .delegated_bill(tenant_id, provider, external_bill_id)
            .await?
        else {
            return Ok(None);
        };
        if bill.status != "approved" && bill.status != "paid" {
            tracing::warn!(
                status = %bill.status,
                "provider reports a payment against a bill this status cannot take; left for an operator"
            );
            return Ok(None);
        }
        let unrecorded = provider_paid_minor.saturating_sub(bill.paid_minor);
        if unrecorded <= 0 {
            return Ok(None);
        }
        let remaining = bill.total_minor.saturating_sub(bill.paid_minor);
        if remaining <= 0 {
            return Ok(None);
        }
        let amount_minor = unrecorded.min(remaining);
        if amount_minor < unrecorded {
            tracing::warn!(
                excess_minor = unrecorded - amount_minor,
                "provider reports more paid than this bill is for; recording the balance only"
            );
        }
        let payment = self
            .record_bill_payment(
                tenant_id,
                bill.id,
                &RecordBillPaymentRequest {
                    paid_on,
                    amount_minor,
                    // The CHECK set has no "the provider did it" value and
                    // inventing one would mean a migration plus every
                    // consumer that matches on it; `other` with the
                    // provider named in the reference says the same thing
                    // in the columns that already exist.
                    payment_method: "other".to_string(),
                    reference: Some(format!("{provider}:{external_bill_id}")),
                    notes: Some(format!(
                        "Recorded from {provider}, which reports {} paid against this bill.",
                        provider_paid_minor
                    )),
                },
                ctx,
            )
            .await?;
        Ok(payment.payments.into_iter().next())
    }

    /// Record a payment an operator is making, and tell the provider when
    /// it holds the bill (PMS-1545).
    ///
    /// The outer half of [`Self::record_bill_payment`], which stays the
    /// one writer and is deliberately NOT the thing that pushes. The
    /// inbound receiver calls the inner method (PMS-1543), so a payment
    /// that arrived FROM a provider can never be pushed back to it: the
    /// loop is prevented by which method each caller holds rather than by
    /// a flag somebody has to set correctly. A test asserts the inner one
    /// sends nothing even on a service that has a dispatcher.
    ///
    /// The push runs BEFORE the local write, like every other push in this
    /// subsystem: a provider that refuses leaves no local payment row, so
    /// the operator sees a failure and retries rather than ending up with
    /// a payment Mokosh believes in and the provider does not.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, bill_id = %bill_id))]
    pub async fn pay_bill(
        &self,
        tenant_id: TenantId,
        bill_id: Uuid,
        request: &RecordBillPaymentRequest,
        ctx: &AuditCtx,
    ) -> AppResult<BillWithPayments> {
        let delegated = match self.bill_dispatch.as_ref() {
            Some(dispatcher) if dispatcher.bills_delegation_enabled() => {
                // Read first so the push has the bill's provider pair and
                // its vendor, and so a bill in a state that cannot take a
                // payment is refused before any wire call. The inner
                // method checks the state again under its row lock, which
                // is what actually guards it.
                let bill = self.get_bill(tenant_id, bill_id).await?.bill;
                match (
                    bill.external_provider.as_deref(),
                    bill.external_bill_id.as_deref(),
                ) {
                    (Some(provider), Some(external_id)) => {
                        crate::modules::billing::invoice_issuer::InvoiceProviderKind::parse(
                            provider,
                        )
                        .map(|kind| (kind, external_id.to_string(), bill.vendor_id))
                    }
                    // A bill no provider holds: the local path unchanged,
                    // which is every bill on a deployment that has not
                    // delegated.
                    _ => None,
                }
            }
            _ => None,
        };

        let external_payment_id = match (delegated.as_ref(), self.bill_dispatch.as_ref()) {
            (Some((provider, external_id, vendor_id)), Some(dispatcher)) => Some(
                dispatcher
                    .pay_bill_in_provider(
                        tenant_id,
                        *provider,
                        external_id,
                        *vendor_id,
                        request.amount_minor,
                        request.paid_on,
                    )
                    .await?,
            ),
            _ => None,
        };

        // The provider's own payment id goes in the note rather than a
        // column of its own. PMS-1543 reconciles against the provider's
        // running total, so nothing keys on this id; what it is for is a
        // human holding two ledgers, and a migration for a value only a
        // person reads is a column every consumer then has to learn.
        let request = match external_payment_id.as_deref() {
            Some(id) => {
                let provider = delegated
                    .as_ref()
                    .map(|(kind, _, _)| kind.as_str())
                    .unwrap_or("the provider");
                let mut annotated = request.clone();
                annotated.notes = Some(match request.notes.as_deref() {
                    Some(note) if !note.trim().is_empty() => {
                        format!("{note}\n\nRecorded in {provider} as payment {id}.")
                    }
                    _ => format!("Recorded in {provider} as payment {id}."),
                });
                annotated
            }
            None => request.clone(),
        };
        self.record_bill_payment(tenant_id, bill_id, &request, ctx)
            .await
    }

    /// Every payment against one bill, newest first.
    pub async fn list_bill_payments(
        &self,
        tenant_id: TenantId,
        bill_id: Uuid,
    ) -> AppResult<Vec<BillPayment>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        // The bill itself is read first so an unknown id is a 404 rather
        // than an empty list, which would read as "paid nothing yet".
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM bills WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(bill_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| AppError::NotFound("Bill".to_string()))?;
        let rows: Vec<BillPayment> = sqlx::query_as(
            r#"SELECT id, tenant_id, bill_id, paid_on, amount_minor,
                      payment_method, reference, notes, created_at
               FROM bill_payments
               WHERE tenant_id = $1 AND bill_id = $2
               ORDER BY paid_on DESC, created_at DESC"#,
        )
        .bind(tenant_id)
        .bind(bill_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rows)
    }

    // ── Expenses ─────────────────────────────────────────────────────────
    //
    // Expenses are what an MSP's own people spent. Lifecycle is
    // `draft -> submitted -> approved -> reimbursed`, with `rejected`
    // as a terminal off-ramp from `submitted`. `reimbursed` is terminal
    // and immutable: a correction is a reversing expense per the
    // MAPPS-1100 scoping, mirroring the invoice amendment pattern in
    // PMS-1334.

    /// Claims for this tenant, or for one submitter within it
    /// (PMS-1535).
    ///
    /// `submitter` is `None` for a caller who may see everyone's claims
    /// and `Some(user_id)` for everyone else. The filter is a parameter
    /// rather than two methods because the count and the page have to
    /// agree: a total over every claim beside a page of one person's
    /// would page a technician through claims they cannot read.
    /// Claims for this tenant or for one submitter, narrowed by status and
    /// by free text (PMS-1539).
    ///
    /// `q` matches the claim's notes and its lines' descriptions, because
    /// a claim has no number of its own: what somebody remembers is what
    /// it was for, and that is written on the lines. The submitter scope
    /// from PMS-1535 applies first, so a filter can only narrow what that
    /// caller could already see.
    pub async fn list_expenses(
        &self,
        tenant_id: TenantId,
        submitter: Option<Uuid>,
        filter: &ExpenseFilter,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<Expense>, u64)> {
        let status = filter
            .status
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let pattern = search_pattern(filter.q.as_deref());
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*) FROM expenses
               WHERE tenant_id = $1
                 AND ($2::uuid IS NULL OR user_id = $2)
                 AND ($3::text IS NULL OR status = $3)
                 AND ($4::text IS NULL OR notes ILIKE $4 OR EXISTS (
                       SELECT 1 FROM expense_lines el
                       WHERE el.tenant_id = expenses.tenant_id
                         AND el.expense_id = expenses.id
                         AND el.description ILIKE $4
                     ))"#,
        )
        .bind(tenant_id)
        .bind(submitter)
        .bind(status)
        .bind(pattern.as_deref())
        .fetch_one(&mut *tx)
        .await?;
        let rows: Vec<Expense> = sqlx::query_as(
            r#"SELECT id, tenant_id, user_id, incurred_on, currency,
                      subtotal_minor, tax_minor, total_minor, status,
                      approver_id, approved_at, reimbursed_at, notes,
                      external_provider, external_expense_id,
                      created_at, updated_at
               FROM expenses
               WHERE tenant_id = $1
                 AND ($2::uuid IS NULL OR user_id = $2)
                 AND ($3::text IS NULL OR status = $3)
                 AND ($4::text IS NULL OR notes ILIKE $4 OR EXISTS (
                       SELECT 1 FROM expense_lines el
                       WHERE el.tenant_id = expenses.tenant_id
                         AND el.expense_id = expenses.id
                         AND el.description ILIKE $4
                     ))
               ORDER BY incurred_on DESC, created_at DESC
               LIMIT $5 OFFSET $6"#,
        )
        .bind(tenant_id)
        .bind(submitter)
        .bind(status)
        .bind(pattern.as_deref())
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&mut *tx)
        .await?;
        Ok((rows, total as u64))
    }

    pub async fn get_expense(&self, tenant_id: TenantId, id: Uuid) -> AppResult<ExpenseWithLines> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let expense: Expense = sqlx::query_as(
            r#"SELECT id, tenant_id, user_id, incurred_on, currency,
                      subtotal_minor, tax_minor, total_minor, status,
                      approver_id, approved_at, reimbursed_at, notes,
                      external_provider, external_expense_id,
                      created_at, updated_at
               FROM expenses WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::NotFound("Expense".to_string()))?;
        let lines: Vec<ExpenseLine> = sqlx::query_as(
            r#"SELECT id, tenant_id, expense_id, category_id, description,
                      amount_minor, tax_minor, position, created_at
               FROM expense_lines
               WHERE tenant_id = $1 AND expense_id = $2
               ORDER BY position, created_at"#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_all(&mut *tx)
        .await?;
        Ok(ExpenseWithLines { expense, lines })
    }

    /// A new expense always lands as `draft` and belongs to `user_id`
    /// (the submitter). Approval and reimbursement are later transitions.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, user_id = %user_id))]
    pub async fn create_expense(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        request: &CreateExpenseRequest,
        ctx: &AuditCtx,
    ) -> AppResult<ExpenseWithLines> {
        let currency = request.currency.trim().to_ascii_uppercase();
        if currency.len() != 3 {
            return Err(field_error(
                "currency",
                "currency is a 3-letter ISO-4217 code",
            ));
        }
        if request.lines.is_empty() {
            return Err(field_error("lines", "an expense needs at least one line"));
        }
        let totals = ExpenseTotals::from_lines(&request.lines);
        let id = Uuid::new_v4();
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let expense: Expense = sqlx::query_as(
            r#"INSERT INTO expenses
                 (id, tenant_id, user_id, incurred_on, currency,
                  subtotal_minor, tax_minor, total_minor, notes)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
               RETURNING id, tenant_id, user_id, incurred_on, currency,
                         subtotal_minor, tax_minor, total_minor, status,
                         approver_id, approved_at, reimbursed_at, notes,
                         external_provider, external_expense_id,
                         created_at, updated_at"#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(user_id)
        .bind(request.incurred_on)
        .bind(&currency)
        .bind(totals.subtotal_minor)
        .bind(totals.tax_minor)
        .bind(totals.total_minor)
        .bind(request.notes.as_deref())
        .fetch_one(&mut *tx)
        .await?;
        let lines = insert_expense_lines(&mut tx, tenant_id, id, &request.lines).await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Create,
            "expenses",
            Some(id),
            None,
            Some(serde_json::to_value(&expense).unwrap_or(Value::Null)),
        )
        .await?;
        tx.commit().await?;
        Ok(ExpenseWithLines { expense, lines })
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, expense_id = %id))]
    pub async fn submit_expense(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        ctx: &AuditCtx,
    ) -> AppResult<Expense> {
        self.transition_expense(
            tenant_id,
            id,
            &["draft"],
            "submitted",
            None,
            false,
            None,
            ctx,
        )
        .await
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, expense_id = %id))]
    pub async fn approve_expense(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        approver_id: Uuid,
        ctx: &AuditCtx,
    ) -> AppResult<Expense> {
        self.transition_expense(
            tenant_id,
            id,
            &["submitted"],
            "approved",
            Some(approver_id),
            false,
            None,
            ctx,
        )
        .await
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, expense_id = %id))]
    pub async fn reject_expense(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        ctx: &AuditCtx,
    ) -> AppResult<Expense> {
        self.transition_expense(
            tenant_id,
            id,
            &["submitted"],
            "rejected",
            None,
            false,
            None,
            ctx,
        )
        .await
    }

    /// `reimbursed` is terminal and immutable: `transition_expense`
    /// refuses every outbound move from it.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, expense_id = %id))]
    /// Mark a claim paid back, and record it in the provider when the
    /// tenant delegated Bills and expenses (PMS-1541).
    ///
    /// The push happens here and not on create, because a claim becomes
    /// the MSP's money LEAVING when it is paid back: a draft or submitted
    /// claim is an internal document the provider has no business holding,
    /// and a rejected one must never reach the ledger at all.
    ///
    /// Before the write transaction, for the reason MAPPS-1134 put the
    /// invoice push outside its own: a provider that refuses leaves the
    /// claim `approved`, which is the state somebody can retry from, and
    /// an HTTP round trip inside a write transaction holds its locks for
    /// the length of somebody else's outage.
    pub async fn reimburse_expense(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        ctx: &AuditCtx,
    ) -> AppResult<Expense> {
        let external = match self.bill_dispatch.as_ref() {
            Some(dispatcher) if dispatcher.bills_delegation_enabled() => {
                use crate::modules::billing::invoice_issuer_dispatch::{
                    ExpenseLineShape, ExpensePlan, ReimburseExpenseShape,
                };
                // Lock the row and assert the status under that lock, in
                // our own transaction committed immediately after, before
                // the wire call. A concurrent caller's own call to this
                // same helper then blocks on this row: it either finds the
                // lock free with the status unchanged, or (once
                // `transition_expense` has taken it and committed) finds
                // the status no longer `approved` and refuses before ever
                // reaching the external call (PMS-1547). Committing right
                // away, rather than holding this lock across the wire call
                // below, is what keeps that call off the row lock.
                let mut lock_tx = self.db.begin_with_tenant(tenant_id).await?;
                self.lock_and_assert_status(
                    &mut lock_tx,
                    tenant_id,
                    id,
                    &["approved"],
                    "reimbursed",
                )
                .await?;
                lock_tx.commit().await?;
                let claim = self.get_expense(tenant_id, id).await?;
                let lines: Vec<ExpenseLineShape> = claim
                    .lines
                    .iter()
                    .map(|l| ExpenseLineShape {
                        category_id: l.category_id,
                        description: l.description.clone(),
                        amount_minor: l.amount_minor,
                    })
                    .collect();
                let shape = ReimburseExpenseShape {
                    user_id: claim.expense.user_id,
                    // Today, not `incurred_on`: what the provider is being
                    // told about is the money leaving the MSP's account
                    // now, not when the person spent theirs.
                    paid_on: Utc::now().date_naive(),
                    currency: &claim.expense.currency,
                    lines: &lines,
                };
                match dispatcher.plan_expense(tenant_id, &shape).await? {
                    ExpensePlan::Local => None,
                    ExpensePlan::Delegated(external) => Some(external),
                }
            }
            _ => None,
        };
        self.transition_expense(
            tenant_id,
            id,
            &["approved"],
            "reimbursed",
            None,
            true,
            external.as_ref(),
            ctx,
        )
        .await
    }

    /// Lock the expense row `FOR UPDATE` and assert its current status is
    /// one of `allowed_from`, returning the locked row. Shared by
    /// `transition_expense`'s own check and by `reimburse_expense`'s
    /// earlier pre-check, so the two cannot drift and so a lock taken here
    /// is what a concurrent caller's own call to this helper blocks on
    /// (PMS-1547), not a plain unlocked read that could still see the
    /// pre-transition status.
    async fn lock_and_assert_status(
        &self,
        tx: &mut TenantTransaction<'_>,
        tenant_id: TenantId,
        id: Uuid,
        allowed_from: &[&str],
        to: &str,
    ) -> AppResult<Expense> {
        let before: Expense = sqlx::query_as(
            r#"SELECT id, tenant_id, user_id, incurred_on, currency,
                      subtotal_minor, tax_minor, total_minor, status,
                      approver_id, approved_at, reimbursed_at, notes,
                      external_provider, external_expense_id,
                      created_at, updated_at
               FROM expenses WHERE tenant_id = $1 AND id = $2 FOR UPDATE"#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| AppError::NotFound("Expense".to_string()))?;
        if before.status == "reimbursed" {
            // Checked before `allowed_from` because it holds for every
            // target, including one a future transition might allow. The
            // wording comes from the shared function so this branch and
            // the generic one cannot drift (PMS-1538).
            return Err(AppError::Conflict(expense_transition_refusal(
                &before.status,
                to,
            )));
        }
        if !allowed_from.iter().any(|s| *s == before.status) {
            return Err(AppError::Conflict(expense_transition_refusal(
                &before.status,
                to,
            )));
        }
        Ok(before)
    }

    #[allow(clippy::too_many_arguments)]
    async fn transition_expense(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        allowed_from: &[&str],
        to: &str,
        set_approver: Option<Uuid>,
        reimbursing: bool,
        external: Option<&crate::modules::billing::invoice_issuer::ExternalExpenseRef>,
        ctx: &AuditCtx,
    ) -> AppResult<Expense> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let before = self
            .lock_and_assert_status(&mut tx, tenant_id, id, allowed_from, to)
            .await?;
        let now: DateTime<Utc> = Utc::now();
        let approver_val = set_approver.or(before.approver_id);
        let approved_at = if to == "approved" {
            Some(now)
        } else {
            before.approved_at
        };
        let reimbursed_at = if reimbursing {
            Some(now)
        } else {
            before.reimbursed_at
        };
        let after: Expense = sqlx::query_as(
            r#"UPDATE expenses
               SET status = $3, approver_id = $4, approved_at = $5, reimbursed_at = $6,
                   external_provider = COALESCE($7, external_provider),
                   external_expense_id = COALESCE($8, external_expense_id),
                   updated_at = NOW()
               WHERE tenant_id = $1 AND id = $2
               RETURNING id, tenant_id, user_id, incurred_on, currency,
                         subtotal_minor, tax_minor, total_minor, status,
                         approver_id, approved_at, reimbursed_at, notes,
                         external_provider, external_expense_id,
                         created_at, updated_at"#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(to)
        .bind(approver_val)
        .bind(approved_at)
        .bind(reimbursed_at)
        // PMS-1541: COALESCE rather than a plain assignment, so the four
        // transitions that are not a reimbursement cannot blank a pair
        // somebody else wrote. NULL on every local path, which is every
        // claim on a deployment that has not delegated.
        .bind(external.map(|e| e.provider.as_str()))
        .bind(external.map(|e| e.external_expense_id.as_str()))
        .fetch_one(&mut *tx)
        .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Update,
            "expenses",
            Some(id),
            Some(serde_json::to_value(&before).unwrap_or(Value::Null)),
            Some(serde_json::to_value(&after).unwrap_or(Value::Null)),
        )
        .await?;
        tx.commit().await?;
        Ok(after)
    }
}

// ── Bill + Expense request/response shapes ──────────────────────────────

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateBillRequest {
    pub vendor_id: Uuid,
    #[serde(default)]
    #[validate(length(max = 100))]
    pub bill_number: Option<String>,
    pub issue_date: NaiveDate,
    #[serde(default)]
    pub due_date: Option<NaiveDate>,
    #[validate(length(min = 3, max = 3))]
    pub currency: String,
    #[serde(default)]
    #[validate(length(max = 2000))]
    pub notes: Option<String>,
    #[validate(length(min = 1, max = 200))]
    #[validate(nested)]
    pub lines: Vec<BillLineInput>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct BillLineInput {
    #[serde(default)]
    pub category_id: Option<Uuid>,
    #[validate(length(min = 1, max = 500))]
    pub description: String,
    /// Quantity in hundredths, matching the schema and the invoice-line
    /// convention (so 1.25 = 125). A non-positive quantity is degenerate
    /// (PMS-1550).
    #[validate(range(min = 1))]
    pub quantity_hundredths: i64,
    #[validate(range(min = 0))]
    pub unit_price_minor: i64,
    #[serde(default)]
    #[validate(range(min = 0))]
    pub tax_minor: i64,
    #[serde(default)]
    pub position: i32,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateExpenseRequest {
    pub incurred_on: NaiveDate,
    #[validate(length(min = 3, max = 3))]
    pub currency: String,
    #[serde(default)]
    #[validate(length(max = 2000))]
    pub notes: Option<String>,
    #[validate(length(min = 1, max = 200))]
    #[validate(nested)]
    pub lines: Vec<ExpenseLineInput>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct ExpenseLineInput {
    #[serde(default)]
    pub category_id: Option<Uuid>,
    #[validate(length(min = 1, max = 500))]
    pub description: String,
    #[validate(range(min = 0))]
    pub amount_minor: i64,
    #[serde(default)]
    #[validate(range(min = 0))]
    pub tax_minor: i64,
    #[serde(default)]
    pub position: i32,
}

/// What a provider says it has paid against one delegated bill
/// (PMS-1543).
///
/// A named value rather than four parameters: the running total and the id
/// it belongs to have to travel together, and a caller passing them
/// separately could pass a figure from one bill with the id of another.
#[derive(Debug, Clone, Copy)]
pub struct ExternalBillPaymentReport<'a> {
    pub provider: &'a str,
    pub external_bill_id: &'a str,
    /// The provider's RUNNING total, not one payment: the difference
    /// against `bills.paid_minor` is what has not been recorded here.
    pub provider_paid_minor: i64,
    pub paid_on: NaiveDate,
}

/// The three figures the webhook receiver reconciles against (PMS-1543).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DelegatedBillRow {
    pub id: Uuid,
    pub status: String,
    pub total_minor: i64,
    pub paid_minor: i64,
    pub currency: String,
}

/// `POST /bills/{id}/payments` (PMS-1536).
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct RecordBillPaymentRequest {
    pub paid_on: NaiveDate,
    /// Minor units, like every other amount on a bill. Validated in the
    /// service rather than by `validator`, because the useful message
    /// names what a vendor refund is instead of saying "must be > 0".
    pub amount_minor: i64,
    #[validate(length(min = 1, max = 20))]
    pub payment_method: String,
    #[serde(default)]
    #[validate(length(max = 100))]
    pub reference: Option<String>,
    #[serde(default)]
    #[validate(length(max = 2000))]
    pub notes: Option<String>,
}

/// What recording a payment answers with: the bill as it now stands, and
/// the payment just written.
///
/// Flattened like [`BillWithLines`], so a caller reads the bill's own
/// fields at the top level either way.
#[derive(Debug, Clone, Serialize)]
pub struct BillWithPayments {
    #[serde(flatten)]
    pub bill: Bill,
    pub payments: Vec<BillPayment>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BillWithLines {
    #[serde(flatten)]
    pub bill: Bill,
    pub lines: Vec<BillLine>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExpenseWithLines {
    #[serde(flatten)]
    pub expense: Expense,
    pub lines: Vec<ExpenseLine>,
}

/// Why a bill cannot make this move, and what to do instead (PMS-1538).
///
/// PMS-977's rule for every refusal on this surface: "cannot be moved"
/// leaves the operator holding a document and no next step. The sibling
/// invoice-amendment path distinguishes its terminal states the same way,
/// and the `reimbursed` branch in `transition_expense` already did.
///
/// Pure and shared, so the one other place that pre-checks this state
/// (`reimburse_expense`, before it reaches a provider) cannot drift into a
/// second wording.
fn bill_transition_refusal(from: &str, to: &str) -> String {
    match from {
        // Both terminal, and for different reasons, so they get different
        // remedies: a paid bill is a settled fact to correct with another
        // document, where a void one never settled anything.
        "paid" => "This bill has already been paid, so moving it would misstate what was \
                   settled. Issue a credit or adjustment instead."
            .to_string(),
        "void" => "This bill is void, so there is nothing left to move. Raise a new bill instead."
            .to_string(),
        status if status == to => format!("This bill is already '{to}'."),
        "draft" if to == "paid" => "This bill has not been approved yet, so paying it would \
                                    skip the check that it matches what was ordered. Approve \
                                    it first."
            .to_string(),
        status => format!(
            "This bill is '{status}', so it cannot move to '{to}'. No remedy is defined yet \
             for this transition."
        ),
    }
}

/// Why a claim cannot make this move, and what to do instead (PMS-1538).
///
/// Each arm names the step that is missing rather than the step that
/// failed, because the caller is holding a claim and wants to know what to
/// press next.
fn expense_transition_refusal(from: &str, to: &str) -> String {
    match from {
        "rejected" => {
            "This expense was rejected, which is terminal. File a new expense instead.".to_string()
        }
        "reimbursed" => {
            "A reimbursed expense is immutable. File a reversing expense instead.".to_string()
        }
        status if status == to => format!("This expense is already '{to}'."),
        "draft" => format!(
            "This expense has not been submitted yet, so it cannot move to '{to}'. Submit it \
             first."
        ),
        // The pair the salvaged work left to the fallback, which is the one
        // somebody actually hits: finance opens a submitted claim and tries
        // to pay it back before anybody approved it.
        "submitted" if to == "reimbursed" => {
            "This expense has not been approved yet, so there is nothing to pay back. Approve \
             it first."
                .to_string()
        }
        "approved" if to == "submitted" => {
            "This expense is already approved, which is past submission. There is nothing to \
             submit."
                .to_string()
        }
        status => format!(
            "This expense is '{status}', so it cannot move to '{to}'. No remedy is defined yet \
             for this transition."
        ),
    }
}

/// A `%q%` pattern for an ILIKE, or `None` when nothing was typed
/// (PMS-1539).
///
/// Blank and whitespace-only collapse to `None` rather than to `%%`: a
/// `q=` left on the URL by a cleared search box would otherwise be a
/// filter that matches everything by accident, and the first wildcard
/// somebody escapes would change that silently.
fn search_pattern(q: Option<&str>) -> Option<String> {
    let q = q?.trim();
    if q.is_empty() {
        None
    } else {
        Some(format!("%{q}%"))
    }
}

/// The payment methods `bill_payments`' CHECK allows, in one place so the
/// service refuses a bad one with a message instead of a 23514.
const BILL_PAYMENT_METHODS: [&str; 6] = ["check", "credit_card", "ach", "wire", "cash", "other"];

/// The ONE writer of `bills.paid_minor` and of `bills.status` on the paid
/// edge (PMS-1536, the rule PMS-953 states for invoices).
///
/// Derives both from the payment rows rather than adjusting a counter: a
/// running total nudged by each caller drifts the first time one of them
/// fails halfway, and the sum is the answer the rows already hold.
///
/// `paid` once the total is covered, and nothing else is reached from
/// here. A part-paid bill stays `approved`, because the bills CHECK has no
/// `partially_paid` and `total_minor - paid_minor` answers "what do we
/// owe" without one; adding a status value is a migration plus every
/// consumer that matches on it.
async fn recompute_bill_payment_state(
    conn: &mut sqlx::PgConnection,
    tenant_id: TenantId,
    bill_id: Uuid,
) -> AppResult<Bill> {
    let bill: Bill = sqlx::query_as(
        r#"UPDATE bills SET
             paid_minor = COALESCE((
                 SELECT SUM(amount_minor) FROM bill_payments
                 WHERE tenant_id = $1 AND bill_id = $2
             ), 0),
             status = CASE
                 WHEN COALESCE((
                     SELECT SUM(amount_minor) FROM bill_payments
                     WHERE tenant_id = $1 AND bill_id = $2
                 ), 0) >= total_minor THEN 'paid'
                 ELSE status
             END,
             updated_at = NOW()
           WHERE tenant_id = $1 AND id = $2
           RETURNING id, tenant_id, vendor_id, bill_number, issue_date, due_date,
                     currency, subtotal_minor, tax_minor, total_minor, paid_minor,
                     status, notes, external_provider, external_bill_id,
                     created_at, updated_at"#,
    )
    .bind(tenant_id)
    .bind(bill_id)
    .fetch_one(conn)
    .await?;
    Ok(bill)
}

struct BillTotals {
    subtotal_minor: i64,
    tax_minor: i64,
    total_minor: i64,
}

impl BillTotals {
    /// Totals from a bill's lines. Each line's `total_minor` is
    /// `unit_price_minor * quantity_hundredths / 100` (truncated), the
    /// same per-line rounding the invoice path uses so a bill mirrors
    /// what a vendor's own invoice would print.
    fn from_lines(lines: &[BillLineInput]) -> Self {
        let mut subtotal: i64 = 0;
        let mut tax: i64 = 0;
        for line in lines {
            let line_total = line
                .unit_price_minor
                .saturating_mul(line.quantity_hundredths)
                / 100;
            subtotal = subtotal.saturating_add(line_total);
            tax = tax.saturating_add(line.tax_minor);
        }
        Self {
            subtotal_minor: subtotal,
            tax_minor: tax,
            total_minor: subtotal.saturating_add(tax),
        }
    }
}

struct ExpenseTotals {
    subtotal_minor: i64,
    tax_minor: i64,
    total_minor: i64,
}

impl ExpenseTotals {
    fn from_lines(lines: &[ExpenseLineInput]) -> Self {
        let mut subtotal: i64 = 0;
        let mut tax: i64 = 0;
        for line in lines {
            subtotal = subtotal.saturating_add(line.amount_minor);
            tax = tax.saturating_add(line.tax_minor);
        }
        Self {
            subtotal_minor: subtotal,
            tax_minor: tax,
            total_minor: subtotal.saturating_add(tax),
        }
    }
}

async fn insert_bill_lines(
    conn: &mut sqlx::PgConnection,
    tenant_id: TenantId,
    bill_id: Uuid,
    inputs: &[BillLineInput],
) -> AppResult<Vec<BillLine>> {
    let mut rows = Vec::with_capacity(inputs.len());
    for (idx, line) in inputs.iter().enumerate() {
        let line_total = line
            .unit_price_minor
            .saturating_mul(line.quantity_hundredths)
            / 100;
        let total_with_tax = line_total.saturating_add(line.tax_minor);
        let row: BillLine = sqlx::query_as(
            r#"INSERT INTO bill_lines
                 (tenant_id, bill_id, category_id, description,
                  quantity_hundredths, unit_price_minor, tax_minor, total_minor, position)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
               RETURNING id, tenant_id, bill_id, category_id, description,
                         quantity_hundredths, unit_price_minor, tax_minor, total_minor,
                         position, created_at"#,
        )
        .bind(tenant_id)
        .bind(bill_id)
        .bind(line.category_id)
        .bind(line.description.trim())
        .bind(line.quantity_hundredths)
        .bind(line.unit_price_minor)
        .bind(line.tax_minor)
        .bind(total_with_tax)
        .bind(if line.position == 0 {
            idx as i32
        } else {
            line.position
        })
        .fetch_one(&mut *conn)
        .await?;
        rows.push(row);
    }
    Ok(rows)
}

async fn insert_expense_lines(
    conn: &mut sqlx::PgConnection,
    tenant_id: TenantId,
    expense_id: Uuid,
    inputs: &[ExpenseLineInput],
) -> AppResult<Vec<ExpenseLine>> {
    let mut rows = Vec::with_capacity(inputs.len());
    for (idx, line) in inputs.iter().enumerate() {
        let row: ExpenseLine = sqlx::query_as(
            r#"INSERT INTO expense_lines
                 (tenant_id, expense_id, category_id, description,
                  amount_minor, tax_minor, position)
               VALUES ($1, $2, $3, $4, $5, $6, $7)
               RETURNING id, tenant_id, expense_id, category_id, description,
                         amount_minor, tax_minor, position, created_at"#,
        )
        .bind(tenant_id)
        .bind(expense_id)
        .bind(line.category_id)
        .bind(line.description.trim())
        .bind(line.amount_minor)
        .bind(line.tax_minor)
        .bind(if line.position == 0 {
            idx as i32
        } else {
            line.position
        })
        .fetch_one(&mut *conn)
        .await?;
        rows.push(row);
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::{bill_transition_refusal, expense_transition_refusal};

    /// Every refusal names a next step, which is what PMS-977 asks of this
    /// surface: a message that only says "cannot" leaves the operator
    /// holding a document and nothing to press.
    ///
    /// Asserted as a property over every pair the two state machines can
    /// refuse, rather than one case per arm, because the arm somebody adds
    /// later is the one that will forget.
    #[test]
    fn every_refusal_names_a_next_step_or_says_none_is_defined() {
        let bill_statuses = ["draft", "approved", "paid", "void"];
        for from in bill_statuses {
            for to in ["approved", "void", "paid"] {
                let message = bill_transition_refusal(from, to);
                assert!(
                    message.contains("instead")
                        || message.contains("first")
                        || message.contains("already")
                        || message.contains("No remedy is defined yet"),
                    "bill {from} -> {to}: {message}"
                );
                assert!(
                    !message.starts_with("Cannot move"),
                    "and never the bare shape: {message}"
                );
            }
        }
        let expense_statuses = ["draft", "submitted", "approved", "reimbursed", "rejected"];
        for from in expense_statuses {
            for to in ["submitted", "approved", "rejected", "reimbursed"] {
                let message = expense_transition_refusal(from, to);
                assert!(
                    message.contains("instead")
                        || message.contains("first")
                        || message.contains("already")
                        || message.contains("nothing to submit")
                        || message.contains("No remedy is defined yet"),
                    "expense {from} -> {to}: {message}"
                );
                assert!(!message.starts_with("Cannot move"), "{message}");
            }
        }
    }

    /// The two terminal bill states get different remedies, because they
    /// are terminal for different reasons: a paid bill settled something
    /// and a void one never did.
    #[test]
    fn a_paid_bill_and_a_void_bill_are_told_different_things() {
        let paid = bill_transition_refusal("paid", "void");
        assert!(paid.contains("credit or adjustment"), "{paid}");
        let void = bill_transition_refusal("void", "approved");
        assert!(void.contains("Raise a new bill"), "{void}");
        assert_ne!(paid, void);
    }

    /// The pair somebody actually hits: finance opens a submitted claim
    /// and tries to pay it back before anybody approved it.
    #[test]
    fn paying_back_an_unapproved_claim_says_to_approve_it() {
        let message = expense_transition_refusal("submitted", "reimbursed");
        assert!(message.contains("Approve it first"), "{message}");
        assert!(
            !message.contains("No remedy is defined yet"),
            "this one has an obvious remedy and had fallen through to the fallback"
        );
    }

    /// Paying an unapproved bill says the same thing, for the same reason:
    /// approval is where the bill is checked against what was ordered.
    #[test]
    fn paying_an_unapproved_bill_says_to_approve_it() {
        let message = bill_transition_refusal("draft", "paid");
        assert!(message.contains("Approve it first"), "{message}");
    }

    /// A reimbursed claim keeps the wording it already had (PMS-1538's
    /// third criterion), and now keeps it from one place.
    #[test]
    fn the_reimbursed_message_is_unchanged_and_shared() {
        for to in ["submitted", "approved", "rejected", "reimbursed"] {
            assert_eq!(
                expense_transition_refusal("reimbursed", to),
                "A reimbursed expense is immutable. File a reversing expense instead.",
                "{to}"
            );
        }
    }

    /// A redundant move says so rather than reciting both halves.
    #[test]
    fn a_move_to_the_state_it_is_in_says_already() {
        assert_eq!(
            bill_transition_refusal("approved", "approved"),
            "This bill is already 'approved'."
        );
        assert_eq!(
            expense_transition_refusal("submitted", "submitted"),
            "This expense is already 'submitted'."
        );
    }
}
