//! MAPPS-1100 Phase A: the writer for the Bills and Expenses subsystem.
//!
//! Only the leaf lookups (`vendors`, `expense_categories`) are wired in
//! this slice because they are prerequisites for the bills/expenses
//! headers themselves. The headers land in a follow-up PR with their
//! own routes; mounting empty `/api/v1/bills` and `/api/v1/expenses`
//! endpoints that return `NotImplemented` is the "advertises what the
//! build cannot deliver" anti-pattern MAPPS-1098 and MAPPS-1102 enforce
//! against.
//!
//! Every mutation runs inside `begin_with_tenant` and writes an
//! `audit_log` row in the same transaction, matching the billing
//! service's pattern.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::FromRow;
use uuid::Uuid;
use validator::Validate;

use super::models::{ExpenseCategory, Vendor};
use crate::db::Database;
use crate::modules::audit::{audit_write, AuditAction, AuditCtx};
use crate::modules::auth::TenantId;
use crate::utils::error::{AppError, AppResult};
use crate::utils::pagination::PaginationParams;

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
}

impl ExpensesService {
    pub fn new(db: Database) -> Self {
        Self { db }
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
}
