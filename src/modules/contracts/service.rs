//! Contracts service.

use crate::modules::auth::TenantId;
use chrono::{DateTime, Datelike, Days, Months, NaiveDate, Utc};
use rust_decimal::Decimal;
use uuid::Uuid;

use crate::db::Database;
use crate::modules::audit::{audit_write, AuditAction, AuditCtx};
use crate::utils::error::{AppError, AppResult};
use crate::utils::pagination::PaginationParams;

use super::models::*;

/// Max contracts processed per transaction in [`ContractsService::expire_due_contracts`].
/// Bounds the row-lock footprint and audit-row count per commit so the
/// lifecycle sweep never holds a long table-wide lock (PMS-194).
const EXPIRE_BATCH: i64 = 200;

/// One billing-period step, expressed in the unit the cycle requires
/// (PMS-404). Sub-month cycles (`weekly`, `bi_weekly`) advance by whole
/// days; month-or-longer cycles advance by whole months so end-of-month
/// overflow clamps (e.g. Jan 31 + 1 month -> Feb 28/29).
///
/// Shared by both period calculators that anchor on a contract's
/// `start_date`: [`ContractsService::period_for`] (hour-balance windows)
/// and `current_billing_period` in the billing service (invoice anchors).
#[derive(Clone, Copy)]
pub(crate) enum CycleStep {
    Days(u64),
    Months(u32),
}

impl CycleStep {
    /// Map a `billing_cycle` token to its recurring step. Returns `None`
    /// for `one_time` and any unknown value, which callers treat as
    /// non-recurring.
    pub(crate) fn from_cycle(billing_cycle: &str) -> Option<Self> {
        match billing_cycle {
            "weekly" => Some(CycleStep::Days(7)),
            "bi_weekly" => Some(CycleStep::Days(14)),
            "monthly" => Some(CycleStep::Months(1)),
            "quarterly" => Some(CycleStep::Months(3)),
            "annually" => Some(CycleStep::Months(12)),
            _ => None,
        }
    }

    /// Advance `date` by one step, returning `None` on date overflow.
    pub(crate) fn advance(self, date: NaiveDate) -> Option<NaiveDate> {
        match self {
            CycleStep::Days(d) => date.checked_add_days(Days::new(d)),
            CycleStep::Months(m) => date.checked_add_months(Months::new(m)),
        }
    }
}

#[derive(Clone)]
pub struct ContractsService {
    db: Database,
}

impl ContractsService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    // PMS-66 contracts CRUD ---------------------------------------------------
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_contracts(
        &self,
        tenant_id: TenantId,
        filter: &ContractFilter,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<ContractResponse>, u64)> {
        let mut conditions = vec!["tenant_id = $1".to_string()];
        let mut idx = 2;
        if filter.company_id.is_some() {
            conditions.push(format!("company_id = ${idx}"));
            idx += 1;
        }
        if filter.contract_type.is_some() {
            conditions.push(format!("contract_type = ${idx}"));
            idx += 1;
        }
        if filter.status.is_some() {
            conditions.push(format!("status = ${idx}"));
            idx += 1;
        }
        let where_clause = conditions.join(" AND ");

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let count_query = format!("SELECT COUNT(*) FROM contracts WHERE {where_clause}");
        let mut count_q = sqlx::query_scalar::<_, i64>(&count_query).bind(tenant_id);
        if let Some(v) = filter.company_id {
            count_q = count_q.bind(v);
        }
        if let Some(v) = &filter.contract_type {
            count_q = count_q.bind(v);
        }
        if let Some(v) = &filter.status {
            count_q = count_q.bind(v);
        }
        let total: i64 = count_q.fetch_one(&mut *tx).await?;

        let query = format!(
            r#"SELECT id, contract_number, name, company_id, contract_type, status,
                      start_date, end_date, auto_renew, billing_cycle, billing_amount,
                      sla_id, signed_date, signed_by_contact_id, notes, created_at, updated_at
               FROM contracts WHERE {where_clause}
               ORDER BY start_date DESC
               LIMIT ${} OFFSET ${}"#,
            idx,
            idx + 1
        );
        let mut q = sqlx::query_as::<_, ContractRow>(&query).bind(tenant_id);
        if let Some(v) = filter.company_id {
            q = q.bind(v);
        }
        if let Some(v) = &filter.contract_type {
            q = q.bind(v);
        }
        if let Some(v) = &filter.status {
            q = q.bind(v);
        }
        q = q
            .bind(pagination.limit() as i64)
            .bind(pagination.offset() as i64);
        let rows = q.fetch_all(&mut *tx).await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_contract(
        &self,
        tenant_id: TenantId,
        request: &CreateContractRequest,
        ctx: &AuditCtx,
    ) -> AppResult<ContractResponse> {
        let id = Uuid::new_v4();
        // Mutation + audit row in one transaction. CREATE: old = None,
        // after captured by the new contract id. PMS-117.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            r#"INSERT INTO contracts (
                id, tenant_id, contract_number, name, company_id, contract_type, status,
                start_date, end_date, auto_renew, billing_cycle, billing_amount, sla_id,
                signed_date, signed_by_contact_id, notes
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)"#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&request.contract_number)
        .bind(&request.name)
        .bind(request.company_id)
        .bind(&request.contract_type)
        .bind(&request.status)
        .bind(request.start_date)
        .bind(request.end_date)
        .bind(request.auto_renew)
        .bind(&request.billing_cycle)
        .bind(request.billing_amount)
        .bind(request.sla_id)
        .bind(request.signed_date)
        .bind(request.signed_by_contact_id)
        .bind(&request.notes)
        .execute(&mut *tx)
        .await?;

        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM contracts t WHERE tenant_id = $1 AND id = $2",
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
            "contracts",
            Some(id),
            None,
            after,
        )
        .await?;
        tx.commit().await?;
        self.get_contract(tenant_id, id).await
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_contract(&self, tenant_id: TenantId, id: Uuid) -> AppResult<ContractResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row = sqlx::query_as::<_, ContractRow>(
            r#"SELECT id, contract_number, name, company_id, contract_type, status,
                      start_date, end_date, auto_renew, billing_cycle, billing_amount,
                      sla_id, signed_date, signed_by_contact_id, notes, created_at, updated_at
               FROM contracts WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::NotFound("Contract".to_string()))?;
        Ok(row.into())
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_contract(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        request: &UpdateContractRequest,
        ctx: &AuditCtx,
    ) -> AppResult<ContractResponse> {
        // Mutation + audit row in one transaction: snapshot before and
        // after, write the audit entry on the same tx. PMS-117.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let before: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM contracts t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;

        let n = sqlx::query(
            r#"UPDATE contracts SET
                contract_number = COALESCE($3, contract_number),
                name = COALESCE($4, name),
                status = COALESCE($5, status),
                end_date = COALESCE($6, end_date),
                auto_renew = COALESCE($7, auto_renew),
                billing_cycle = COALESCE($8, billing_cycle),
                billing_amount = COALESCE($9, billing_amount),
                sla_id = COALESCE($10, sla_id),
                signed_date = COALESCE($11, signed_date),
                signed_by_contact_id = COALESCE($12, signed_by_contact_id),
                notes = COALESCE($13, notes),
                updated_at = NOW()
               WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(&request.contract_number)
        .bind(&request.name)
        .bind(&request.status)
        .bind(request.end_date)
        .bind(request.auto_renew)
        .bind(&request.billing_cycle)
        .bind(request.billing_amount)
        .bind(request.sla_id)
        .bind(request.signed_date)
        .bind(request.signed_by_contact_id)
        .bind(&request.notes)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("Contract".to_string()));
        }

        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM contracts t WHERE tenant_id = $1 AND id = $2",
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
            "contracts",
            Some(id),
            before,
            after,
        )
        .await?;
        tx.commit().await?;
        self.get_contract(tenant_id, id).await
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_contract(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        ctx: &AuditCtx,
    ) -> AppResult<()> {
        // Mutation + audit row in one transaction. DELETE: snapshot
        // before, old = before, after = None. PMS-117.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let before: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM contracts t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        let n = sqlx::query("DELETE FROM contracts WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("Contract".to_string()));
        }
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Delete,
            "contracts",
            Some(id),
            before,
            None,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    // PMS-67 contract items ---------------------------------------------------
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_contract_items(
        &self,
        tenant_id: TenantId,
        contract_id: Uuid,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<ContractItemResponse>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM contract_items WHERE tenant_id = $1 AND contract_id = $2",
        )
        .bind(tenant_id)
        .bind(contract_id)
        .fetch_one(&mut *tx)
        .await?;

        let rows = sqlx::query_as::<_, ContractItemRow>(
            r#"SELECT id, contract_id, name, description, item_type, quantity, unit_price,
                      total_price, billing_frequency, work_type_id, included_hours,
                      overage_rate, rollover_enabled, max_rollover_hours, sort_order
               FROM contract_items WHERE tenant_id = $1 AND contract_id = $2
               ORDER BY sort_order
               LIMIT $3 OFFSET $4"#,
        )
        .bind(tenant_id)
        .bind(contract_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&mut *tx)
        .await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_contract_item(
        &self,
        tenant_id: TenantId,
        contract_id: Uuid,
        request: &UpsertContractItemRequest,
        ctx: &AuditCtx,
    ) -> AppResult<ContractItemResponse> {
        let total = request.quantity * request.unit_price;
        let id = Uuid::new_v4();
        // Mutation + audit row in one transaction. CREATE: old = None,
        // after captured by the new item id. PMS-117.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            r#"INSERT INTO contract_items (id, tenant_id, contract_id, name, description, item_type,
                                            quantity, unit_price, total_price, billing_frequency, work_type_id,
                                            included_hours, overage_rate, rollover_enabled,
                                            max_rollover_hours, sort_order)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)"#,
        )
        .bind(id).bind(tenant_id).bind(contract_id)
        .bind(&request.name).bind(&request.description).bind(&request.item_type)
        .bind(request.quantity).bind(request.unit_price).bind(total)
        .bind(&request.billing_frequency).bind(request.work_type_id)
        .bind(request.included_hours).bind(request.overage_rate)
        .bind(request.rollover_enabled).bind(request.max_rollover_hours).bind(request.sort_order)
        .execute(&mut *tx).await?;

        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM contract_items t WHERE tenant_id = $1 AND id = $2",
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
            "contract_items",
            Some(id),
            None,
            after,
        )
        .await?;
        tx.commit().await?;
        Ok(ContractItemResponse {
            id,
            contract_id,
            name: request.name.clone(),
            description: request.description.clone(),
            item_type: request.item_type.clone(),
            quantity: request.quantity,
            unit_price: request.unit_price,
            total_price: total,
            billing_frequency: request.billing_frequency.clone(),
            work_type_id: request.work_type_id,
            included_hours: request.included_hours,
            overage_rate: request.overage_rate,
            rollover_enabled: request.rollover_enabled,
            max_rollover_hours: request.max_rollover_hours,
            sort_order: request.sort_order,
        })
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_contract_item(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        request: &UpsertContractItemRequest,
        ctx: &AuditCtx,
    ) -> AppResult<ContractItemResponse> {
        let total = request.quantity * request.unit_price;
        // Mutation + audit row in one transaction: snapshot before and
        // after, write the audit entry on the same tx. PMS-117.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let before: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM contract_items t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        let contract_id: Option<Uuid> = sqlx::query_scalar(
            r#"UPDATE contract_items SET
                name=$3, description=$4, item_type=$5, quantity=$6, unit_price=$7,
                total_price=$8, billing_frequency=$9, work_type_id=$10, included_hours=$11,
                overage_rate=$12, rollover_enabled=$13, max_rollover_hours=$14,
                sort_order=$15, updated_at = NOW()
               WHERE tenant_id = $1 AND id = $2 RETURNING contract_id"#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(&request.name)
        .bind(&request.description)
        .bind(&request.item_type)
        .bind(request.quantity)
        .bind(request.unit_price)
        .bind(total)
        .bind(&request.billing_frequency)
        .bind(request.work_type_id)
        .bind(request.included_hours)
        .bind(request.overage_rate)
        .bind(request.rollover_enabled)
        .bind(request.max_rollover_hours)
        .bind(request.sort_order)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(cid) = contract_id else {
            return Err(AppError::NotFound("Contract item".to_string()));
        };

        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM contract_items t WHERE tenant_id = $1 AND id = $2",
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
            "contract_items",
            Some(id),
            before,
            after,
        )
        .await?;
        tx.commit().await?;
        Ok(ContractItemResponse {
            id,
            contract_id: cid,
            name: request.name.clone(),
            description: request.description.clone(),
            item_type: request.item_type.clone(),
            quantity: request.quantity,
            unit_price: request.unit_price,
            total_price: total,
            billing_frequency: request.billing_frequency.clone(),
            work_type_id: request.work_type_id,
            included_hours: request.included_hours,
            overage_rate: request.overage_rate,
            rollover_enabled: request.rollover_enabled,
            max_rollover_hours: request.max_rollover_hours,
            sort_order: request.sort_order,
        })
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_contract_item(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        ctx: &AuditCtx,
    ) -> AppResult<()> {
        // Mutation + audit row in one transaction. DELETE: snapshot
        // before, old = before, after = None. PMS-117.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let before: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM contract_items t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        let n = sqlx::query("DELETE FROM contract_items WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("Contract item".to_string()));
        }
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Delete,
            "contract_items",
            Some(id),
            before,
            None,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    // PMS-68 hour balances ----------------------------------------------------
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_hour_balance(
        &self,
        tenant_id: TenantId,
        contract_id: Uuid,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<ContractHourBalanceResponse>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM contract_hour_balances WHERE tenant_id = $1 AND contract_id = $2",
        )
        .bind(tenant_id)
        .bind(contract_id)
        .fetch_one(&mut *tx)
        .await?;

        let rows = sqlx::query_as::<_, BalanceRow>(
            r#"SELECT id, contract_id, contract_item_id, period_start, period_end,
                      hours_included, hours_used, hours_remaining, rollover_hours
               FROM contract_hour_balances WHERE tenant_id = $1 AND contract_id = $2
               ORDER BY period_start
               LIMIT $3 OFFSET $4"#,
        )
        .bind(tenant_id)
        .bind(contract_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&mut *tx)
        .await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    // PMS-69 rate cards -------------------------------------------------------
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_rate_cards(
        &self,
        tenant_id: TenantId,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<RateCardResponse>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rate_cards WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_one(&mut *tx)
            .await?;

        let rows = sqlx::query_as::<_, RateCardRow>(
            r#"SELECT id, name, description, is_default, default_per_mile_rate
               FROM rate_cards WHERE tenant_id = $1
               ORDER BY is_default DESC, name
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
    pub async fn get_rate_card(
        &self,
        tenant_id: TenantId,
        id: Uuid,
    ) -> AppResult<RateCardResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row = sqlx::query_as::<_, RateCardRow>(
            r#"SELECT id, name, description, is_default, default_per_mile_rate
               FROM rate_cards WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::NotFound("Rate card".to_string()))?;
        Ok(row.into())
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_rate_card(
        &self,
        tenant_id: TenantId,
        request: &UpsertRateCardRequest,
        ctx: &AuditCtx,
    ) -> AppResult<RateCardResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        if request.is_default {
            sqlx::query("UPDATE rate_cards SET is_default = FALSE WHERE tenant_id = $1")
                .bind(tenant_id)
                .execute(&mut *tx)
                .await?;
        }
        let id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO rate_cards (id, tenant_id, name, description, is_default, default_per_mile_rate)
               VALUES ($1, $2, $3, $4, $5, $6)"#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&request.name)
        .bind(&request.description)
        .bind(request.is_default)
        .bind(request.default_per_mile_rate)
        .execute(&mut *tx)
        .await?;

        // Audit row in the same transaction. CREATE: old = None, after
        // captured by the new rate-card id. PMS-117.
        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM rate_cards t WHERE tenant_id = $1 AND id = $2",
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
            "rate_cards",
            Some(id),
            None,
            after,
        )
        .await?;
        tx.commit().await?;
        Ok(RateCardResponse {
            id,
            name: request.name.clone(),
            description: request.description.clone(),
            is_default: request.is_default,
            default_per_mile_rate: request.default_per_mile_rate,
        })
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_rate_card(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        request: &UpsertRateCardRequest,
        ctx: &AuditCtx,
    ) -> AppResult<RateCardResponse> {
        // Mutation + audit row in one transaction. UPDATE: snapshot
        // before, then after. PMS-117 / PMS-194.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let before: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM rate_cards t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        if request.is_default {
            sqlx::query(
                "UPDATE rate_cards SET is_default = FALSE WHERE tenant_id = $1 AND id <> $2",
            )
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await?;
        }
        let n = sqlx::query(
            r#"UPDATE rate_cards SET name = $3, description = $4, is_default = $5,
                   default_per_mile_rate = $6, updated_at = NOW()
               WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(&request.name)
        .bind(&request.description)
        .bind(request.is_default)
        .bind(request.default_per_mile_rate)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("Rate card".to_string()));
        }
        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM rate_cards t WHERE tenant_id = $1 AND id = $2",
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
            "rate_cards",
            Some(id),
            before,
            after,
        )
        .await?;
        tx.commit().await?;
        Ok(RateCardResponse {
            id,
            name: request.name.clone(),
            description: request.description.clone(),
            is_default: request.is_default,
            default_per_mile_rate: request.default_per_mile_rate,
        })
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_rate_card(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        ctx: &AuditCtx,
    ) -> AppResult<()> {
        // Mutation + audit row in one transaction. DELETE: snapshot
        // before, old = before, after = None. PMS-117.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let before: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM rate_cards t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        let n = sqlx::query("DELETE FROM rate_cards WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("Rate card".to_string()));
        }
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Delete,
            "rate_cards",
            Some(id),
            before,
            None,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    // PMS-70 rate card items --------------------------------------------------
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_rate_card_items(
        &self,
        tenant_id: TenantId,
        rate_card_id: Uuid,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<RateCardItemResponse>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*)
               FROM rate_card_items rci
               INNER JOIN rate_cards rc ON rci.rate_card_id = rc.id
               WHERE rc.tenant_id = $1 AND rci.rate_card_id = $2"#,
        )
        .bind(tenant_id)
        .bind(rate_card_id)
        .fetch_one(&mut *tx)
        .await?;

        let rows = sqlx::query_as::<_, RateCardItemRow>(
            r#"SELECT rci.id, rci.rate_card_id, rci.work_type_id, rci.hourly_rate,
                      rci.after_hours_rate, rci.emergency_rate
               FROM rate_card_items rci
               INNER JOIN rate_cards rc ON rci.rate_card_id = rc.id
               WHERE rc.tenant_id = $1 AND rci.rate_card_id = $2
               LIMIT $3 OFFSET $4"#,
        )
        .bind(tenant_id)
        .bind(rate_card_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&mut *tx)
        .await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn upsert_rate_card_item(
        &self,
        tenant_id: TenantId,
        rate_card_id: Uuid,
        request: &UpsertRateCardItemRequest,
        ctx: &AuditCtx,
    ) -> AppResult<RateCardItemResponse> {
        // Verify rate card belongs to tenant first.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM rate_cards WHERE id = $1 AND tenant_id = $2)",
        )
        .bind(rate_card_id)
        .bind(tenant_id)
        .fetch_one(&mut *tx)
        .await?;
        if !exists {
            return Err(AppError::NotFound("Rate card".to_string()));
        }

        // Mutation + audit row in one transaction. PMS-117.
        // `rate_card_items` has no `tenant_id` column (it is tenant-scoped
        // through its parent `rate_cards` row, validated above), so the
        // snapshot predicates key on the natural `(rate_card_id,
        // work_type_id)` unique pair for `before` and on the returned `id`
        // for `after`. This is an INSERT .. ON CONFLICT upsert, so the
        // action is Update when a row already existed (the `before`
        // snapshot doubles as the existence check) else Create.
        let before: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM rate_card_items t \
             WHERE t.rate_card_id = $1 AND t.work_type_id = $2",
        )
        .bind(rate_card_id)
        .bind(request.work_type_id)
        .fetch_optional(&mut *tx)
        .await?;
        let action = if before.is_some() {
            AuditAction::Update
        } else {
            AuditAction::Create
        };

        let id: Uuid = sqlx::query_scalar(
            r#"INSERT INTO rate_card_items
               (rate_card_id, work_type_id, hourly_rate, after_hours_rate, emergency_rate)
               VALUES ($1, $2, $3, $4, $5)
               ON CONFLICT (rate_card_id, work_type_id) DO UPDATE SET
                 hourly_rate = EXCLUDED.hourly_rate,
                 after_hours_rate = EXCLUDED.after_hours_rate,
                 emergency_rate = EXCLUDED.emergency_rate,
                 updated_at = NOW()
               RETURNING id"#,
        )
        .bind(rate_card_id)
        .bind(request.work_type_id)
        .bind(request.hourly_rate)
        .bind(request.after_hours_rate)
        .bind(request.emergency_rate)
        .fetch_one(&mut *tx)
        .await?;

        let after: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT to_jsonb(t) FROM rate_card_items t WHERE t.id = $1")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            action,
            "rate_card_items",
            Some(id),
            before,
            after,
        )
        .await?;
        tx.commit().await?;
        Ok(RateCardItemResponse {
            id,
            rate_card_id,
            work_type_id: request.work_type_id,
            hourly_rate: request.hourly_rate,
            after_hours_rate: request.after_hours_rate,
            emergency_rate: request.emergency_rate,
        })
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_rate_card_item(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        ctx: &AuditCtx,
    ) -> AppResult<()> {
        // Mutation + audit row in one transaction. DELETE: snapshot
        // before, old = before, after = None. PMS-117 / PMS-194.
        // `rate_card_items` has no `tenant_id` column; it is tenant-scoped
        // through its parent `rate_cards` row, so the snapshot joins on it.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let before: Option<serde_json::Value> = sqlx::query_scalar(
            r#"SELECT to_jsonb(rci) FROM rate_card_items rci
               INNER JOIN rate_cards rc ON rci.rate_card_id = rc.id
               WHERE rc.tenant_id = $1 AND rci.id = $2"#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        let n = sqlx::query(
            r#"DELETE FROM rate_card_items rci USING rate_cards rc
               WHERE rci.rate_card_id = rc.id AND rc.tenant_id = $1 AND rci.id = $2"#,
        )
        .bind(tenant_id)
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("Rate card item".to_string()));
        }
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Delete,
            "rate_card_items",
            Some(id),
            before,
            None,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    // PMS-64 hour consumption -------------------------------------------------

    /// Draw `hours` against a contract's block-hours allotment for the
    /// period covering `when`, returning how much landed inside the
    /// included allotment versus overage.
    ///
    /// Runs in a single transaction:
    ///   1. Resolve the contract's `block_hours` `contract_item` to read
    ///      `included_hours` / `overage_rate`.
    ///   2. Find (or lazily create) the `contract_hour_balances` row whose
    ///      `[period_start, period_end]` range contains `when`. The period
    ///      is derived from the contract's `billing_cycle` and `start_date`
    ///      (see [`Self::period_for`]); the lazily-created row seeds
    ///      `hours_included` from the item (plus any prior rollover that a
    ///      preceding [`Self::roll_to_next_period`] wrote) and
    ///      `hours_remaining` to match.
    ///   3. Split the request: the part that fits in `hours_remaining` is
    ///      `hours_applied` and decrements the balance; the rest is
    ///      `overage_hours`, billed at `overage_rate`.
    ///
    /// All queries are tenant-scoped. `hours` must be non-negative.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, contract_id = %contract_id))]
    pub async fn consume_hours(
        &self,
        tenant_id: TenantId,
        contract_id: Uuid,
        hours: Decimal,
        when: DateTime<Utc>,
    ) -> AppResult<ConsumeOutcome> {
        if hours < Decimal::ZERO {
            return Err(AppError::BadRequest(
                "consume_hours: hours must be non-negative".to_string(),
            ));
        }

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;

        // 1. block-hours contract item + the contract's billing cycle / start.
        let item = sqlx::query_as::<_, BlockItemRow>(
            r#"SELECT ci.id, ci.included_hours, ci.overage_rate,
                      ci.rollover_enabled, ci.max_rollover_hours,
                      c.billing_cycle, c.start_date
               FROM contract_items ci
               INNER JOIN contracts c ON c.id = ci.contract_id
               WHERE ci.tenant_id = $1 AND ci.contract_id = $2
                 AND ci.item_type = 'block_hours'
               ORDER BY ci.sort_order
               LIMIT 1"#,
        )
        .bind(tenant_id)
        .bind(contract_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::NotFound("Block hours contract item".to_string()))?;

        let included = item.included_hours.unwrap_or(Decimal::ZERO);
        let overage_rate = item.overage_rate.unwrap_or(Decimal::ZERO);
        let billing_cycle = item.billing_cycle.as_deref().unwrap_or("monthly");
        let when_date = when.date_naive();
        let (period_start, period_end) =
            Self::period_for(item.start_date, billing_cycle, when_date);

        // 2. find or create the balance row for this period.
        let existing = sqlx::query_as::<_, BalanceMutRow>(
            r#"SELECT id, hours_used, hours_remaining
               FROM contract_hour_balances
               WHERE tenant_id = $1 AND contract_id = $2 AND contract_item_id = $3
                 AND period_start = $4 AND period_end = $5
               FOR UPDATE"#,
        )
        .bind(tenant_id)
        .bind(contract_id)
        .bind(item.id)
        .bind(period_start)
        .bind(period_end)
        .fetch_optional(&mut *tx)
        .await?;

        let balance = match existing {
            Some(b) => b,
            None => {
                // Seed a fresh period. `hours_included` is the item's
                // included hours (rollover from a closed prior period is
                // applied separately by roll_to_next_period, which seeds
                // the row up-front; if no such row exists we start clean).
                let id = Uuid::new_v4();
                sqlx::query(
                    r#"INSERT INTO contract_hour_balances
                       (id, tenant_id, contract_id, contract_item_id, period_start, period_end,
                        hours_included, hours_used, hours_remaining, rollover_hours)
                       VALUES ($1,$2,$3,$4,$5,$6,$7,0,$7,0)"#,
                )
                .bind(id)
                .bind(tenant_id)
                .bind(contract_id)
                .bind(item.id)
                .bind(period_start)
                .bind(period_end)
                .bind(included)
                .execute(&mut *tx)
                .await?;
                BalanceMutRow {
                    id,
                    hours_used: Some(Decimal::ZERO),
                    hours_remaining: included,
                }
            }
        };

        // 3. split request into applied (against remaining) + overage.
        let remaining = balance.hours_remaining.max(Decimal::ZERO);
        let hours_applied = hours.min(remaining);
        let overage_hours = hours - hours_applied;
        let overage_amount = overage_hours * overage_rate;

        let used = balance.hours_used.unwrap_or(Decimal::ZERO);
        sqlx::query(
            r#"UPDATE contract_hour_balances
               SET hours_used = $2,
                   hours_remaining = $3,
                   updated_at = NOW()
               WHERE id = $1"#,
        )
        .bind(balance.id)
        .bind(used + hours_applied)
        .bind(remaining - hours_applied)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(ConsumeOutcome {
            hours_applied,
            overage_hours,
            overage_amount,
            balance_id: balance.id,
        })
    }

    /// Roll the unused hours of the period ending `closing_period_end`
    /// into the next period's balance row, capped at the item's
    /// `max_rollover_hours`. No-op (returns `Decimal::ZERO`) when the
    /// item has `rollover_enabled = false`.
    ///
    /// Idempotency: the next-period row is UPSERTed. If it does not exist
    /// it is created with `hours_included = included + rolled` and the
    /// matching `hours_remaining`; if it already exists its
    /// `rollover_hours` / `hours_included` / `hours_remaining` are bumped
    /// by the rolled amount. Returns the number of hours actually rolled.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, contract_id = %contract_id))]
    pub async fn roll_to_next_period(
        &self,
        tenant_id: TenantId,
        contract_id: Uuid,
        closing_period_end: NaiveDate,
    ) -> AppResult<Decimal> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;

        let item = sqlx::query_as::<_, BlockItemRow>(
            r#"SELECT ci.id, ci.included_hours, ci.overage_rate,
                      ci.rollover_enabled, ci.max_rollover_hours,
                      c.billing_cycle, c.start_date
               FROM contract_items ci
               INNER JOIN contracts c ON c.id = ci.contract_id
               WHERE ci.tenant_id = $1 AND ci.contract_id = $2
                 AND ci.item_type = 'block_hours'
               ORDER BY ci.sort_order
               LIMIT 1"#,
        )
        .bind(tenant_id)
        .bind(contract_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::NotFound("Block hours contract item".to_string()))?;

        if !item.rollover_enabled.unwrap_or(false) {
            tx.commit().await?;
            return Ok(Decimal::ZERO);
        }

        // Unused hours from the closing period.
        let closing = sqlx::query_as::<_, BalanceMutRow>(
            r#"SELECT id, hours_used, hours_remaining
               FROM contract_hour_balances
               WHERE tenant_id = $1 AND contract_id = $2 AND contract_item_id = $3
                 AND period_end = $4
               FOR UPDATE"#,
        )
        .bind(tenant_id)
        .bind(contract_id)
        .bind(item.id)
        .bind(closing_period_end)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::NotFound("closing-period balance".to_string()))?;

        let unused = closing.hours_remaining.max(Decimal::ZERO);
        let cap = item.max_rollover_hours.unwrap_or(unused);
        let rolled = unused.min(cap);
        if rolled <= Decimal::ZERO {
            tx.commit().await?;
            return Ok(Decimal::ZERO);
        }

        let included = item.included_hours.unwrap_or(Decimal::ZERO);
        let billing_cycle = item.billing_cycle.as_deref().unwrap_or("monthly");
        // Next period starts the day after the closing period ends.
        let next_start = closing_period_end.succ_opt().unwrap_or(closing_period_end);
        let (period_start, period_end) =
            Self::period_for(item.start_date, billing_cycle, next_start);

        let id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO contract_hour_balances
               (id, tenant_id, contract_id, contract_item_id, period_start, period_end,
                hours_included, hours_used, hours_remaining, rollover_hours)
               VALUES ($1,$2,$3,$4,$5,$6,$7,0,$7,$8)
               ON CONFLICT (tenant_id, contract_id, contract_item_id, period_start, period_end)
               DO UPDATE SET
                   hours_included = contract_hour_balances.hours_included + EXCLUDED.rollover_hours,
                   hours_remaining = contract_hour_balances.hours_remaining + EXCLUDED.rollover_hours,
                   rollover_hours = contract_hour_balances.rollover_hours + EXCLUDED.rollover_hours,
                   updated_at = NOW()"#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(contract_id)
        .bind(item.id)
        .bind(period_start)
        .bind(period_end)
        .bind(included + rolled)
        .bind(rolled)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(rolled)
    }

    /// Derive the `[period_start, period_end]` inclusive date range that
    /// contains `when`, anchored on the contract's `start_date` and
    /// stepped by `billing_cycle`.
    ///
    /// Periods are contiguous, non-overlapping windows of the cycle
    /// length starting at `anchor`:
    ///   * `weekly`    -> 7-day windows
    ///   * `bi_weekly` -> 14-day windows
    ///   * `monthly`   -> 1-month windows
    ///   * `quarterly` -> 3-month windows
    ///   * `annually`  -> 12-month windows
    ///   * `one_time` (and any unknown value) -> a single open window
    ///     starting at `anchor` and ending far in the future, so a
    ///     one-shot block draws from one balance row forever.
    ///
    /// Sub-month cycles (`weekly`/`bi_weekly`) step by whole days via
    /// [`chrono::Days`]; month-or-longer cycles step via
    /// [`chrono::Months`] so end-of-month overflow clamps (PMS-404).
    ///
    /// `period_end` is the last day of the window (the day before the
    /// next window's start), matching the DATE columns' inclusive
    /// `period_start`/`period_end` semantics.
    fn period_for(
        anchor: NaiveDate,
        billing_cycle: &str,
        when: NaiveDate,
    ) -> (NaiveDate, NaiveDate) {
        let step = match CycleStep::from_cycle(billing_cycle) {
            Some(step) => step,
            // one_time / unknown: a single window from the anchor.
            None => {
                let end = NaiveDate::from_ymd_opt(9999, 12, 31).unwrap_or(anchor);
                return (anchor, end);
            }
        };

        // Walk windows forward from the anchor until one contains `when`.
        // `when` before the anchor falls back to the first window so the
        // caller still gets a deterministic, anchored range.
        let mut start = anchor;
        loop {
            let next = step.advance(start).unwrap_or(start);
            if next <= start {
                // Overflow guard: stop walking, treat as open window.
                let end = NaiveDate::from_ymd_opt(9999, 12, 31).unwrap_or(start);
                return (start, end);
            }
            if when < next {
                let end = next.pred_opt().unwrap_or(next);
                return (start, end);
            }
            start = next;
        }
    }

    // PMS-64 rate resolution --------------------------------------------------

    /// Resolve the effective hourly rate for a `work_type` on a rate card.
    ///
    /// Precedence: `emergency` wins, then `after_hours`, else the base
    /// `hourly_rate`. When the chosen tier is NULL the method falls back
    /// to `hourly_rate` (the only non-null column), so an
    /// `after_hours`/`emergency` request still returns a usable rate.
    /// Tenant-scoped through the parent `rate_cards` row.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, rate_card_id = %rate_card_id))]
    pub async fn resolve_rate(
        &self,
        tenant_id: TenantId,
        rate_card_id: Uuid,
        work_type_id: Uuid,
        after_hours: bool,
        emergency: bool,
    ) -> AppResult<Decimal> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row = sqlx::query_as::<_, RateTierRow>(
            r#"SELECT rci.hourly_rate, rci.after_hours_rate, rci.emergency_rate
               FROM rate_card_items rci
               INNER JOIN rate_cards rc ON rci.rate_card_id = rc.id
               WHERE rc.tenant_id = $1 AND rci.rate_card_id = $2 AND rci.work_type_id = $3"#,
        )
        .bind(tenant_id)
        .bind(rate_card_id)
        .bind(work_type_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::NotFound("Rate card item".to_string()))?;

        let rate = if emergency {
            row.emergency_rate.unwrap_or(row.hourly_rate)
        } else if after_hours {
            row.after_hours_rate.unwrap_or(row.hourly_rate)
        } else {
            row.hourly_rate
        };
        Ok(rate)
    }

    // PMS-64 lifecycle --------------------------------------------------------

    /// Transition `active` contracts whose `end_date` has passed as of
    /// `now`:
    ///   * `auto_renew = true` with a non-empty `renewal_terms` (or a
    ///     derivable term) -> status stays `active` conceptually but is
    ///     stamped `renewed` for the closing term, and `start_date` /
    ///     `end_date` are advanced by the renewal length. The renewal
    ///     length is taken from `renewal_terms->>'term_months'` when
    ///     present, else the span of the current term (end - start).
    ///   * otherwise -> status set to `expired`.
    ///
    /// Returns `(renewed_count, expired_count)`. The sweep runs across all
    /// tenants (the worker owns the cadence), but processes each tenant in
    /// its own series of bounded transactions rather than one table-wide
    /// lock: it resolves the tenants with due contracts up front, then
    /// drains each tenant a [`EXPIRE_BATCH`]-sized batch at a time,
    /// committing after every batch so the row-lock footprint stays small
    /// on large datasets (PMS-194). Each renew/expire writes a per-contract
    /// audit row in the same transaction via `audit_write(AuditCtx::system)`
    /// (PMS-117). Pass a specific `now` for deterministic tests.
    #[tracing::instrument(skip_all)]
    pub async fn expire_due_contracts(&self, now: DateTime<Utc>) -> AppResult<(u64, u64)> {
        let today = now.date_naive();

        // SAFETY (PMS-285): the contract-lifecycle sweep runs across EVERY
        // tenant's `contracts` (the worker owns the cadence), so it cannot set a
        // single tenant GUC and runs on the migrator (BYPASSRLS) pool. The
        // per-tenant drain below preserves PMS-194's bounded transactions while
        // routing every statement through that pool.
        // Tenants with at least one due contract. Resolved up front so the
        // per-tenant drain below never holds a lock spanning all tenants.
        let tenants: Vec<Uuid> = sqlx::query_scalar(
            r#"SELECT DISTINCT tenant_id
               FROM contracts
               WHERE status = 'active' AND end_date IS NOT NULL AND end_date < $1"#,
        )
        .bind(today)
        .fetch_all(self.db.migrator_pool())
        .await?;

        let mut renewed = 0u64;
        let mut expired = 0u64;

        for tenant_id in tenants {
            let tid = TenantId::from_trusted(tenant_id);
            let ctx = AuditCtx::system(tenant_id);

            // Drain this tenant's due contracts a batch at a time. Each
            // processed row leaves the predicate (status moves off
            // 'active'), so a batch returning no rows means the tenant is
            // done and the loop terminates.
            loop {
                let mut tx = self.db.migrator_pool().begin().await?;
                let due = sqlx::query_as::<_, DueContractRow>(
                    r#"SELECT id, start_date, end_date, auto_renew, renewal_terms
                       FROM contracts
                       WHERE tenant_id = $1 AND status = 'active'
                         AND end_date IS NOT NULL AND end_date < $2
                       ORDER BY id
                       LIMIT $3
                       FOR UPDATE"#,
                )
                .bind(tenant_id)
                .bind(today)
                .bind(EXPIRE_BATCH)
                .fetch_all(&mut *tx)
                .await?;

                if due.is_empty() {
                    tx.commit().await?;
                    break;
                }

                for c in due {
                    let end_date = match c.end_date {
                        Some(d) => d,
                        None => continue,
                    };

                    let before: Option<serde_json::Value> =
                        sqlx::query_scalar("SELECT to_jsonb(t) FROM contracts t WHERE id = $1")
                            .bind(c.id)
                            .fetch_optional(&mut *tx)
                            .await?;

                    if c.auto_renew.unwrap_or(false) {
                        // Renewal length: explicit term_months override, else
                        // the span of the closing term in whole months (>= 1).
                        let term_months = c
                            .renewal_terms
                            .as_ref()
                            .and_then(|v| v.get("term_months"))
                            .and_then(|v| v.as_u64())
                            .map(|m| m as u32)
                            .unwrap_or_else(|| months_between(c.start_date, end_date).max(1));

                        let new_start = end_date.succ_opt().unwrap_or(end_date);
                        let new_end = new_start
                            .checked_add_months(Months::new(term_months))
                            .and_then(|d| d.pred_opt())
                            .unwrap_or(new_start);

                        sqlx::query(
                            r#"UPDATE contracts
                               SET status = 'renewed',
                                   start_date = $2,
                                   end_date = $3,
                                   updated_at = NOW()
                               WHERE id = $1"#,
                        )
                        .bind(c.id)
                        .bind(new_start)
                        .bind(new_end)
                        .execute(&mut *tx)
                        .await?;
                        renewed += 1;
                    } else {
                        sqlx::query(
                            r#"UPDATE contracts
                               SET status = 'expired', updated_at = NOW()
                               WHERE id = $1"#,
                        )
                        .bind(c.id)
                        .execute(&mut *tx)
                        .await?;
                        expired += 1;
                    }

                    let after: Option<serde_json::Value> =
                        sqlx::query_scalar("SELECT to_jsonb(t) FROM contracts t WHERE id = $1")
                            .bind(c.id)
                            .fetch_optional(&mut *tx)
                            .await?;

                    audit_write(
                        &mut *tx,
                        tid,
                        &ctx,
                        AuditAction::Update,
                        "contracts",
                        Some(c.id),
                        before,
                        after,
                    )
                    .await?;
                }

                tx.commit().await?;
            }
        }

        Ok((renewed, expired))
    }

    // PMS-33 billing feed -----------------------------------------------------

    /// Return a contract's recurring billing line items (the
    /// `recurring_service` / `retainer` items that carry a billing
    /// frequency) for the downstream billing engine (PMS-33) to turn
    /// into invoice lines. Tenant-scoped.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, contract_id = %contract_id))]
    pub async fn list_recurring_items(
        &self,
        tenant_id: TenantId,
        contract_id: Uuid,
    ) -> AppResult<Vec<ContractItemResponse>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows = sqlx::query_as::<_, ContractItemRow>(
            r#"SELECT id, contract_id, name, description, item_type, quantity, unit_price,
                      total_price, billing_frequency, work_type_id, included_hours,
                      overage_rate, rollover_enabled, max_rollover_hours, sort_order
               FROM contract_items
               WHERE tenant_id = $1 AND contract_id = $2
                 AND item_type IN ('recurring_service', 'retainer')
               ORDER BY sort_order"#,
        )
        .bind(tenant_id)
        .bind(contract_id)
        .fetch_all(&mut *tx)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }
}

/// Whole-month span between two dates (used to derive a renewal term
/// length when `renewal_terms` carries no explicit `term_months`).
fn months_between(start: NaiveDate, end: NaiveDate) -> u32 {
    let years = end.year() - start.year();
    let months = end.month() as i32 - start.month() as i32;
    (years * 12 + months).max(0) as u32
}

#[derive(sqlx::FromRow)]
struct ContractRow {
    id: Uuid,
    contract_number: Option<String>,
    name: String,
    company_id: Uuid,
    contract_type: String,
    status: Option<String>,
    start_date: chrono::NaiveDate,
    end_date: Option<chrono::NaiveDate>,
    auto_renew: Option<bool>,
    billing_cycle: Option<String>,
    billing_amount: Option<Decimal>,
    sla_id: Option<Uuid>,
    signed_date: Option<chrono::NaiveDate>,
    signed_by_contact_id: Option<Uuid>,
    notes: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<ContractRow> for ContractResponse {
    fn from(r: ContractRow) -> Self {
        Self {
            id: r.id,
            contract_number: r.contract_number,
            name: r.name,
            company_id: r.company_id,
            contract_type: r.contract_type,
            status: r.status.unwrap_or_else(|| "draft".into()),
            start_date: r.start_date,
            end_date: r.end_date,
            auto_renew: r.auto_renew.unwrap_or(false),
            billing_cycle: r.billing_cycle.unwrap_or_else(|| "monthly".into()),
            billing_amount: r.billing_amount,
            sla_id: r.sla_id,
            signed_date: r.signed_date,
            signed_by_contact_id: r.signed_by_contact_id,
            notes: r.notes,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct ContractItemRow {
    id: Uuid,
    contract_id: Uuid,
    name: String,
    description: Option<String>,
    item_type: String,
    quantity: Decimal,
    unit_price: Decimal,
    total_price: Decimal,
    billing_frequency: Option<String>,
    work_type_id: Option<Uuid>,
    included_hours: Option<Decimal>,
    overage_rate: Option<Decimal>,
    rollover_enabled: Option<bool>,
    max_rollover_hours: Option<Decimal>,
    sort_order: Option<i32>,
}

impl From<ContractItemRow> for ContractItemResponse {
    fn from(r: ContractItemRow) -> Self {
        Self {
            id: r.id,
            contract_id: r.contract_id,
            name: r.name,
            description: r.description,
            item_type: r.item_type,
            quantity: r.quantity,
            unit_price: r.unit_price,
            total_price: r.total_price,
            billing_frequency: r.billing_frequency.unwrap_or_else(|| "monthly".into()),
            work_type_id: r.work_type_id,
            included_hours: r.included_hours,
            overage_rate: r.overage_rate,
            rollover_enabled: r.rollover_enabled.unwrap_or(false),
            max_rollover_hours: r.max_rollover_hours,
            sort_order: r.sort_order.unwrap_or(0),
        }
    }
}

#[derive(sqlx::FromRow)]
struct BalanceRow {
    id: Uuid,
    contract_id: Uuid,
    contract_item_id: Uuid,
    period_start: chrono::NaiveDate,
    period_end: chrono::NaiveDate,
    hours_included: Decimal,
    hours_used: Option<Decimal>,
    hours_remaining: Decimal,
    rollover_hours: Option<Decimal>,
}

impl From<BalanceRow> for ContractHourBalanceResponse {
    fn from(r: BalanceRow) -> Self {
        Self {
            id: r.id,
            contract_id: r.contract_id,
            contract_item_id: r.contract_item_id,
            period_start: r.period_start,
            period_end: r.period_end,
            hours_included: r.hours_included,
            hours_used: r.hours_used.unwrap_or(Decimal::ZERO),
            hours_remaining: r.hours_remaining,
            rollover_hours: r.rollover_hours.unwrap_or(Decimal::ZERO),
        }
    }
}

#[derive(sqlx::FromRow)]
struct RateCardRow {
    id: Uuid,
    name: String,
    description: Option<String>,
    is_default: Option<bool>,
    default_per_mile_rate: Option<Decimal>,
}

impl From<RateCardRow> for RateCardResponse {
    fn from(r: RateCardRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            description: r.description,
            is_default: r.is_default.unwrap_or(false),
            default_per_mile_rate: r.default_per_mile_rate,
        }
    }
}

#[derive(sqlx::FromRow)]
struct RateCardItemRow {
    id: Uuid,
    rate_card_id: Uuid,
    work_type_id: Uuid,
    hourly_rate: Decimal,
    after_hours_rate: Option<Decimal>,
    emergency_rate: Option<Decimal>,
}

impl From<RateCardItemRow> for RateCardItemResponse {
    fn from(r: RateCardItemRow) -> Self {
        Self {
            id: r.id,
            rate_card_id: r.rate_card_id,
            work_type_id: r.work_type_id,
            hourly_rate: r.hourly_rate,
            after_hours_rate: r.after_hours_rate,
            emergency_rate: r.emergency_rate,
        }
    }
}

/// Block-hours contract item + its parent contract's cycle anchor,
/// joined for hour-consumption / rollover math.
#[derive(sqlx::FromRow)]
struct BlockItemRow {
    id: Uuid,
    included_hours: Option<Decimal>,
    overage_rate: Option<Decimal>,
    rollover_enabled: Option<bool>,
    max_rollover_hours: Option<Decimal>,
    billing_cycle: Option<String>,
    start_date: chrono::NaiveDate,
}

/// Minimal mutable view of a `contract_hour_balances` row used when
/// debiting / rolling hours.
#[derive(sqlx::FromRow)]
struct BalanceMutRow {
    id: Uuid,
    hours_used: Option<Decimal>,
    hours_remaining: Decimal,
}

/// The three rate tiers of a `rate_card_items` row for [`ContractsService::resolve_rate`].
#[derive(sqlx::FromRow)]
struct RateTierRow {
    hourly_rate: Decimal,
    after_hours_rate: Option<Decimal>,
    emergency_rate: Option<Decimal>,
}

/// Contract fields needed by the lifecycle sweep.
#[derive(sqlx::FromRow)]
struct DueContractRow {
    id: Uuid,
    start_date: chrono::NaiveDate,
    end_date: Option<chrono::NaiveDate>,
    auto_renew: Option<bool>,
    renewal_terms: Option<serde_json::Value>,
}
