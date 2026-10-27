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

use super::models::{Bill, BillLine, Expense, ExpenseCategory, ExpenseLine, Vendor};
use crate::db::Database;
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

    pub async fn list_bills(
        &self,
        tenant_id: TenantId,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<Bill>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM bills WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_one(&mut *tx)
            .await?;
        let rows: Vec<Bill> = sqlx::query_as(
            r#"SELECT id, tenant_id, vendor_id, bill_number, issue_date, due_date,
                      currency, subtotal_minor, tax_minor, total_minor, paid_minor,
                      status, notes, external_provider, external_bill_id,
                      created_at, updated_at
               FROM bills
               WHERE tenant_id = $1
               ORDER BY issue_date DESC, created_at DESC
               LIMIT $2 OFFSET $3"#,
        )
        .bind(tenant_id)
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
            return Err(AppError::Conflict(format!(
                "Cannot move bill from {} to {to}.",
                before.status
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
    pub async fn list_expenses(
        &self,
        tenant_id: TenantId,
        submitter: Option<Uuid>,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<Expense>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM expenses              WHERE tenant_id = $1 AND ($2::uuid IS NULL OR user_id = $2)",
        )
        .bind(tenant_id)
        .bind(submitter)
        .fetch_one(&mut *tx)
        .await?;
        let rows: Vec<Expense> = sqlx::query_as(
            r#"SELECT id, tenant_id, user_id, incurred_on, currency,
                      subtotal_minor, tax_minor, total_minor, status,
                      approver_id, approved_at, reimbursed_at, notes,
                      external_provider, external_expense_id,
                      created_at, updated_at
               FROM expenses
               WHERE tenant_id = $1 AND ($2::uuid IS NULL OR user_id = $2)
               ORDER BY incurred_on DESC, created_at DESC
               LIMIT $3 OFFSET $4"#,
        )
        .bind(tenant_id)
        .bind(submitter)
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
        self.transition_expense(tenant_id, id, &["draft"], "submitted", None, false, ctx)
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
        self.transition_expense(tenant_id, id, &["submitted"], "rejected", None, false, ctx)
            .await
    }

    /// `reimbursed` is terminal and immutable: `transition_expense`
    /// refuses every outbound move from it.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, expense_id = %id))]
    pub async fn reimburse_expense(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        ctx: &AuditCtx,
    ) -> AppResult<Expense> {
        self.transition_expense(tenant_id, id, &["approved"], "reimbursed", None, true, ctx)
            .await
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
        ctx: &AuditCtx,
    ) -> AppResult<Expense> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
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
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::NotFound("Expense".to_string()))?;
        if before.status == "reimbursed" {
            return Err(AppError::Conflict(
                "A reimbursed expense is immutable. File a reversing expense instead.".to_string(),
            ));
        }
        if !allowed_from.iter().any(|s| *s == before.status) {
            return Err(AppError::Conflict(format!(
                "Cannot move expense from {} to {to}.",
                before.status
            )));
        }
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
    pub lines: Vec<BillLineInput>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct BillLineInput {
    #[serde(default)]
    pub category_id: Option<Uuid>,
    #[validate(length(min = 1, max = 500))]
    pub description: String,
    /// Quantity in hundredths, matching the schema and the invoice-line
    /// convention (so 1.25 = 125).
    pub quantity_hundredths: i64,
    pub unit_price_minor: i64,
    #[serde(default)]
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
    pub lines: Vec<ExpenseLineInput>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct ExpenseLineInput {
    #[serde(default)]
    pub category_id: Option<Uuid>,
    #[validate(length(min = 1, max = 500))]
    pub description: String,
    pub amount_minor: i64,
    #[serde(default)]
    pub tax_minor: i64,
    #[serde(default)]
    pub position: i32,
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
