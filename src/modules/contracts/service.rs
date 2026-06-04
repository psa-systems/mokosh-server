//! Contracts service.

use rust_decimal::Decimal;
use uuid::Uuid;

use crate::db::Database;
use crate::utils::error::{AppError, AppResult};

use super::models::*;

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
        tenant_id: Uuid,
        filter: &ContractFilter,
    ) -> AppResult<Vec<ContractResponse>> {
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
        }
        let where_clause = conditions.join(" AND ");
        let query = format!(
            r#"SELECT id, contract_number, name, company_id, contract_type, status,
                      start_date, end_date, auto_renew, billing_cycle, billing_amount,
                      sla_id, signed_date, signed_by_contact_id, notes, created_at, updated_at
               FROM contracts WHERE {where_clause} ORDER BY start_date DESC"#
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
        let rows = q.fetch_all(self.db.pool()).await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_contract(
        &self,
        tenant_id: Uuid,
        request: &CreateContractRequest,
    ) -> AppResult<ContractResponse> {
        let id = Uuid::new_v4();
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
        .execute(self.db.pool())
        .await?;
        self.get_contract(tenant_id, id).await
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_contract(&self, tenant_id: Uuid, id: Uuid) -> AppResult<ContractResponse> {
        let row = sqlx::query_as::<_, ContractRow>(
            r#"SELECT id, contract_number, name, company_id, contract_type, status,
                      start_date, end_date, auto_renew, billing_cycle, billing_amount,
                      sla_id, signed_date, signed_by_contact_id, notes, created_at, updated_at
               FROM contracts WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(self.db.pool())
        .await?
        .ok_or_else(|| AppError::NotFound("Contract".to_string()))?;
        Ok(row.into())
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_contract(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        request: &UpdateContractRequest,
    ) -> AppResult<ContractResponse> {
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
        .execute(self.db.pool())
        .await?
        .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("Contract".to_string()));
        }
        self.get_contract(tenant_id, id).await
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_contract(&self, tenant_id: Uuid, id: Uuid) -> AppResult<()> {
        let n = sqlx::query("DELETE FROM contracts WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(self.db.pool())
            .await?
            .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("Contract".to_string()));
        }
        Ok(())
    }

    // PMS-67 contract items ---------------------------------------------------
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_contract_items(
        &self,
        tenant_id: Uuid,
        contract_id: Uuid,
    ) -> AppResult<Vec<ContractItemResponse>> {
        let rows = sqlx::query_as::<_, ContractItemRow>(
            r#"SELECT id, contract_id, name, description, item_type, quantity, unit_price,
                      total_price, billing_frequency, work_type_id, included_hours,
                      overage_rate, rollover_enabled, max_rollover_hours, sort_order
               FROM contract_items WHERE tenant_id = $1 AND contract_id = $2
               ORDER BY sort_order"#,
        )
        .bind(tenant_id)
        .bind(contract_id)
        .fetch_all(self.db.pool())
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_contract_item(
        &self,
        tenant_id: Uuid,
        contract_id: Uuid,
        request: &UpsertContractItemRequest,
    ) -> AppResult<ContractItemResponse> {
        let total = request.quantity * request.unit_price;
        let id = Uuid::new_v4();
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
        .execute(self.db.pool()).await?;
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
        tenant_id: Uuid,
        id: Uuid,
        request: &UpsertContractItemRequest,
    ) -> AppResult<ContractItemResponse> {
        let total = request.quantity * request.unit_price;
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
        .fetch_optional(self.db.pool())
        .await?;
        let Some(cid) = contract_id else {
            return Err(AppError::NotFound("ContractItem".to_string()));
        };
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
    pub async fn delete_contract_item(&self, tenant_id: Uuid, id: Uuid) -> AppResult<()> {
        let n = sqlx::query("DELETE FROM contract_items WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(self.db.pool())
            .await?
            .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("ContractItem".to_string()));
        }
        Ok(())
    }

    // PMS-68 hour balances ----------------------------------------------------
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_hour_balance(
        &self,
        tenant_id: Uuid,
        contract_id: Uuid,
    ) -> AppResult<Vec<ContractHourBalanceResponse>> {
        let rows = sqlx::query_as::<_, BalanceRow>(
            r#"SELECT id, contract_id, contract_item_id, period_start, period_end,
                      hours_included, hours_used, hours_remaining, rollover_hours
               FROM contract_hour_balances WHERE tenant_id = $1 AND contract_id = $2
               ORDER BY period_start"#,
        )
        .bind(tenant_id)
        .bind(contract_id)
        .fetch_all(self.db.pool())
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    // PMS-69 rate cards -------------------------------------------------------
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_rate_cards(&self, tenant_id: Uuid) -> AppResult<Vec<RateCardResponse>> {
        let rows = sqlx::query_as::<_, RateCardRow>(
            r#"SELECT id, name, description, is_default
               FROM rate_cards WHERE tenant_id = $1 ORDER BY is_default DESC, name"#,
        )
        .bind(tenant_id)
        .fetch_all(self.db.pool())
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_rate_card(
        &self,
        tenant_id: Uuid,
        request: &UpsertRateCardRequest,
    ) -> AppResult<RateCardResponse> {
        let mut tx = self.db.pool().begin().await?;
        if request.is_default {
            sqlx::query("UPDATE rate_cards SET is_default = FALSE WHERE tenant_id = $1")
                .bind(tenant_id)
                .execute(&mut *tx)
                .await?;
        }
        let id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO rate_cards (id, tenant_id, name, description, is_default)
               VALUES ($1, $2, $3, $4, $5)"#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&request.name)
        .bind(&request.description)
        .bind(request.is_default)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(RateCardResponse {
            id,
            name: request.name.clone(),
            description: request.description.clone(),
            is_default: request.is_default,
        })
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_rate_card(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        request: &UpsertRateCardRequest,
    ) -> AppResult<RateCardResponse> {
        let mut tx = self.db.pool().begin().await?;
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
            r#"UPDATE rate_cards SET name = $3, description = $4, is_default = $5, updated_at = NOW()
               WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id).bind(id).bind(&request.name).bind(&request.description).bind(request.is_default)
        .execute(&mut *tx).await?.rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("RateCard".to_string()));
        }
        tx.commit().await?;
        Ok(RateCardResponse {
            id,
            name: request.name.clone(),
            description: request.description.clone(),
            is_default: request.is_default,
        })
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_rate_card(&self, tenant_id: Uuid, id: Uuid) -> AppResult<()> {
        let n = sqlx::query("DELETE FROM rate_cards WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(self.db.pool())
            .await?
            .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("RateCard".to_string()));
        }
        Ok(())
    }

    // PMS-70 rate card items --------------------------------------------------
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_rate_card_items(
        &self,
        tenant_id: Uuid,
        rate_card_id: Uuid,
    ) -> AppResult<Vec<RateCardItemResponse>> {
        let rows = sqlx::query_as::<_, RateCardItemRow>(
            r#"SELECT rci.id, rci.rate_card_id, rci.work_type_id, rci.hourly_rate,
                      rci.after_hours_rate, rci.emergency_rate
               FROM rate_card_items rci
               INNER JOIN rate_cards rc ON rci.rate_card_id = rc.id
               WHERE rc.tenant_id = $1 AND rci.rate_card_id = $2"#,
        )
        .bind(tenant_id)
        .bind(rate_card_id)
        .fetch_all(self.db.pool())
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn upsert_rate_card_item(
        &self,
        tenant_id: Uuid,
        rate_card_id: Uuid,
        request: &UpsertRateCardItemRequest,
    ) -> AppResult<RateCardItemResponse> {
        // Verify rate card belongs to tenant first.
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM rate_cards WHERE id = $1 AND tenant_id = $2)",
        )
        .bind(rate_card_id)
        .bind(tenant_id)
        .fetch_one(self.db.pool())
        .await?;
        if !exists {
            return Err(AppError::NotFound("RateCard".to_string()));
        }

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
        .fetch_one(self.db.pool())
        .await?;
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
    pub async fn delete_rate_card_item(&self, tenant_id: Uuid, id: Uuid) -> AppResult<()> {
        let n = sqlx::query(
            r#"DELETE FROM rate_card_items rci USING rate_cards rc
               WHERE rci.rate_card_id = rc.id AND rc.tenant_id = $1 AND rci.id = $2"#,
        )
        .bind(tenant_id)
        .bind(id)
        .execute(self.db.pool())
        .await?
        .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("RateCardItem".to_string()));
        }
        Ok(())
    }
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
}

impl From<RateCardRow> for RateCardResponse {
    fn from(r: RateCardRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            description: r.description,
            is_default: r.is_default.unwrap_or(false),
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
