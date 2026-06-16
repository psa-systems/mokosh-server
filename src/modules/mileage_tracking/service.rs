//! Mileage-tracking service (PMS-315). Mirrors `TimeTrackingService` for the
//! time-entry CRUD path, swapping the hours axis for a distance axis.

use rust_decimal::Decimal;
use uuid::Uuid;

use crate::db::Database;
use crate::modules::auth::TenantId;
use crate::utils::error::{AppError, AppResult};
use crate::utils::pagination::PaginationParams;

use super::models::*;
use mokosh_types::tickets::BillingStatus;
use mokosh_types::time_tracking::ApprovalStatus;

#[derive(Clone)]
pub struct MileageTrackingService {
    db: Database,
}

impl MileageTrackingService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_mileage_entries(
        &self,
        tenant_id: TenantId,
        filter: &MileageEntryFilter,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<MileageEntryResponse>, u64)> {
        let offset = pagination.offset() as i64;
        let limit = pagination.limit() as i64;
        // Data and count queries bind a different number of leading params
        // (data: $1 tenant, $2 limit, $3 offset -> filters from $4; count: $1
        // tenant -> filters from $2), so each needs its OWN placeholder
        // numbering. Mirrors time_tracking::list_time_entries.
        let mut data_conds = vec!["me.tenant_id = $1".to_string()];
        let mut count_conds = vec!["tenant_id = $1".to_string()];
        let mut data_idx = 4;
        let mut count_idx = 2;
        let mut push_filter = |col: &str, op: &str| {
            data_conds.push(format!("me.{col} {op} ${data_idx}"));
            count_conds.push(format!("{col} {op} ${count_idx}"));
            data_idx += 1;
            count_idx += 1;
        };
        if filter.user_id.is_some() {
            push_filter("user_id", "=");
        }
        if filter.ticket_id.is_some() {
            push_filter("ticket_id", "=");
        }
        if filter.project_id.is_some() {
            push_filter("project_id", "=");
        }
        if filter.date_from.is_some() {
            push_filter("date", ">=");
        }
        if filter.date_to.is_some() {
            push_filter("date", "<=");
        }
        let data_where = data_conds.join(" AND ");
        let count_where = count_conds.join(" AND ");
        let order_by = pagination.order_by("date", &["date", "distance_miles", "created_at"]);
        let order_by = format!("me.{order_by}");
        let query = format!(
            r#"
            SELECT me.id, me.user_id, me.date, me.distance_miles, me.start_address, me.end_address,
                   me.ticket_id, me.project_id, me.task_id, me.company_id, me.contract_id, me.notes,
                   me.is_billable, me.billing_status, me.rate_per_mile, me.total_amount,
                   me.approval_status, me.created_at, me.updated_at,
                   tk.ticket_number, tk.title AS ticket_title,
                   pr.name AS project_name, ta.title AS task_title
            FROM mileage_entries me
            LEFT JOIN tickets  tk ON tk.id = me.ticket_id
            LEFT JOIN projects pr ON pr.id = me.project_id
            LEFT JOIN tasks    ta ON ta.id = me.task_id
            WHERE {data_where}
            ORDER BY {order_by}
            LIMIT $2 OFFSET $3
            "#
        );
        let count_query = format!("SELECT COUNT(*) FROM mileage_entries WHERE {count_where}");
        let mut q = sqlx::query_as::<_, MileageEntryRow>(&query)
            .bind(tenant_id)
            .bind(limit)
            .bind(offset);
        let mut cq = sqlx::query_scalar::<_, i64>(&count_query).bind(tenant_id);
        if let Some(v) = filter.user_id {
            q = q.bind(v);
            cq = cq.bind(v);
        }
        if let Some(v) = filter.ticket_id {
            q = q.bind(v);
            cq = cq.bind(v);
        }
        if let Some(v) = filter.project_id {
            q = q.bind(v);
            cq = cq.bind(v);
        }
        if let Some(v) = filter.date_from {
            q = q.bind(v);
            cq = cq.bind(v);
        }
        if let Some(v) = filter.date_to {
            q = q.bind(v);
            cq = cq.bind(v);
        }
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows = q.fetch_all(&mut *tx).await?;
        let total = cq.fetch_one(&mut *tx).await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_mileage_entry(
        &self,
        tenant_id: TenantId,
        request: &CreateMileageEntryRequest,
    ) -> AppResult<MileageEntryResponse> {
        if request.distance_miles <= Decimal::ZERO {
            return Err(AppError::BadRequest(
                "distance_miles must be greater than 0".to_string(),
            ));
        }
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        // Write-side tenant validation: FKs check existence, not ownership, so
        // a request body could otherwise attach mileage to another tenant's
        // company / ticket.
        assert_company_in_tenant(&mut *tx, tenant_id, request.company_id).await?;
        if let Some(ticket_id) = request.ticket_id {
            assert_ticket_in_tenant(&mut *tx, tenant_id, ticket_id).await?;
        }

        // Rate precedence: explicit request rate > tenant default rate card's
        // per-mile rate > None. total_amount only for billable entries.
        let rate = match request.rate_per_mile {
            Some(r) => Some(r),
            None => default_rate_card_per_mile(&mut *tx, tenant_id).await?,
        };
        let total = if request.is_billable {
            rate.map(|r| r * request.distance_miles)
        } else {
            None
        };
        // Mileage has no timesheet-approval gate (unlike time entries, whose
        // weekly approval flips them to ready_to_bill). A billable mileage
        // entry is therefore ready to bill on creation; the invoice builder
        // uses the same `ready_to_bill` predicate for both kinds.
        let billing_status = if request.is_billable {
            "ready_to_bill"
        } else {
            "not_billed"
        };

        let id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO mileage_entries (
                id, tenant_id, user_id, date, distance_miles, start_address,
                end_address, ticket_id, project_id, task_id, company_id,
                contract_id, notes, is_billable, rate_per_mile, total_amount,
                billing_status
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
                      $14, $15, $16, $17)
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(request.user_id)
        .bind(request.date)
        .bind(request.distance_miles)
        .bind(&request.start_address)
        .bind(&request.end_address)
        .bind(request.ticket_id)
        .bind(request.project_id)
        .bind(request.task_id)
        .bind(request.company_id)
        .bind(request.contract_id)
        .bind(&request.notes)
        .bind(request.is_billable)
        .bind(rate)
        .bind(total)
        .bind(billing_status)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        self.get_mileage_entry(tenant_id, id).await
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_mileage_entry(
        &self,
        tenant_id: TenantId,
        id: Uuid,
    ) -> AppResult<MileageEntryResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row = sqlx::query_as::<_, MileageEntryRow>(
            r#"
            SELECT me.id, me.user_id, me.date, me.distance_miles, me.start_address, me.end_address,
                   me.ticket_id, me.project_id, me.task_id, me.company_id, me.contract_id, me.notes,
                   me.is_billable, me.billing_status, me.rate_per_mile, me.total_amount,
                   me.approval_status, me.created_at, me.updated_at,
                   tk.ticket_number, tk.title AS ticket_title,
                   pr.name AS project_name, ta.title AS task_title
            FROM mileage_entries me
            LEFT JOIN tickets  tk ON tk.id = me.ticket_id
            LEFT JOIN projects pr ON pr.id = me.project_id
            LEFT JOIN tasks    ta ON ta.id = me.task_id
            WHERE me.tenant_id = $1 AND me.id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::NotFound("MileageEntry".to_string()))?;
        Ok(row.into())
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_mileage_entry(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        request: &UpdateMileageEntryRequest,
    ) -> AppResult<MileageEntryResponse> {
        let current = self.get_mileage_entry(tenant_id, id).await?;
        let distance = request.distance_miles.unwrap_or(current.distance_miles);
        if distance <= Decimal::ZERO {
            return Err(AppError::BadRequest(
                "distance_miles must be greater than 0".to_string(),
            ));
        }
        let is_billable = request.is_billable.unwrap_or(current.is_billable);
        let rate = request.rate_per_mile.or(current.rate_per_mile);
        let total = if is_billable {
            rate.map(|r| r * distance)
        } else {
            None
        };

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let affected = sqlx::query(
            r#"
            UPDATE mileage_entries SET
                date          = COALESCE($3, date),
                distance_miles = $4,
                start_address = COALESCE($5, start_address),
                end_address   = COALESCE($6, end_address),
                ticket_id     = $7,
                project_id    = $8,
                notes         = COALESCE($9, notes),
                is_billable   = $10,
                rate_per_mile = $11,
                total_amount  = $12,
                task_id       = COALESCE($13, task_id),
                updated_at    = NOW()
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(request.date)
        .bind(distance)
        .bind(&request.start_address)
        .bind(&request.end_address)
        .bind(request.ticket_id)
        .bind(request.project_id)
        .bind(&request.notes)
        .bind(is_billable)
        .bind(rate)
        .bind(total)
        .bind(request.task_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if affected == 0 {
            return Err(AppError::NotFound("MileageEntry".to_string()));
        }
        tx.commit().await?;
        self.get_mileage_entry(tenant_id, id).await
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_mileage_entry(&self, tenant_id: TenantId, id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let affected = sqlx::query("DELETE FROM mileage_entries WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if affected == 0 {
            return Err(AppError::NotFound("MileageEntry".to_string()));
        }
        tx.commit().await?;
        Ok(())
    }
}

// ============================================================================
// Shared resolve helpers (tenant validation + default rate lookup)
// ============================================================================

/// The tenant default rate card's per-mile rate, if a default card exists and
/// carries one. `None` => the entry is unpriced unless an explicit rate is set.
async fn default_rate_card_per_mile<'e, E>(
    exec: E,
    tenant_id: TenantId,
) -> AppResult<Option<Decimal>>
where
    E: sqlx::PgExecutor<'e>,
{
    let row: Option<Option<Decimal>> = sqlx::query_scalar(
        r#"
        SELECT default_per_mile_rate
        FROM rate_cards
        WHERE tenant_id = $1 AND is_default = TRUE
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(exec)
    .await?;
    Ok(row.flatten())
}

/// Assert a ticket belongs to the tenant. `NotFound` cross-tenant.
async fn assert_ticket_in_tenant<'e, E>(
    exec: E,
    tenant_id: TenantId,
    ticket_id: Uuid,
) -> AppResult<()>
where
    E: sqlx::PgExecutor<'e>,
{
    let found: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM tickets WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(ticket_id)
            .fetch_optional(exec)
            .await?;
    found
        .map(|_| ())
        .ok_or_else(|| AppError::NotFound("Ticket".to_string()))
}

/// Assert a company belongs to the tenant. `NotFound` cross-tenant.
async fn assert_company_in_tenant<'e, E>(
    exec: E,
    tenant_id: TenantId,
    company_id: Uuid,
) -> AppResult<()>
where
    E: sqlx::PgExecutor<'e>,
{
    let found: Option<i32> =
        sqlx::query_scalar("SELECT 1 FROM companies WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(company_id)
            .fetch_optional(exec)
            .await?;
    found
        .map(|_| ())
        .ok_or_else(|| AppError::NotFound("Company".to_string()))
}

#[derive(sqlx::FromRow)]
struct MileageEntryRow {
    id: Uuid,
    user_id: Uuid,
    date: chrono::NaiveDate,
    distance_miles: Decimal,
    start_address: Option<String>,
    end_address: Option<String>,
    ticket_id: Option<Uuid>,
    project_id: Option<Uuid>,
    task_id: Option<Uuid>,
    company_id: Uuid,
    contract_id: Option<Uuid>,
    notes: Option<String>,
    is_billable: Option<bool>,
    billing_status: Option<String>,
    rate_per_mile: Option<Decimal>,
    total_amount: Option<Decimal>,
    approval_status: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
    ticket_number: Option<String>,
    ticket_title: Option<String>,
    project_name: Option<String>,
    task_title: Option<String>,
}

impl From<MileageEntryRow> for MileageEntryResponse {
    fn from(r: MileageEntryRow) -> Self {
        Self {
            id: r.id,
            user_id: r.user_id,
            date: r.date,
            distance_miles: r.distance_miles,
            start_address: r.start_address,
            end_address: r.end_address,
            ticket_id: r.ticket_id,
            project_id: r.project_id,
            task_id: r.task_id,
            company_id: r.company_id,
            contract_id: r.contract_id,
            notes: r.notes,
            is_billable: r.is_billable.unwrap_or(true),
            billing_status: r
                .billing_status
                .as_deref()
                .and_then(BillingStatus::from_str)
                .unwrap_or_default(),
            rate_per_mile: r.rate_per_mile,
            total_amount: r.total_amount,
            approval_status: r
                .approval_status
                .as_deref()
                .and_then(ApprovalStatus::from_str)
                .unwrap_or_default(),
            created_at: r.created_at,
            updated_at: r.updated_at,
            ticket_number: r.ticket_number,
            ticket_title: r.ticket_title,
            project_name: r.project_name,
            task_title: r.task_title,
        }
    }
}
