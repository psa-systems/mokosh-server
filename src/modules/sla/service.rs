//! SLA service.

use chrono::{DateTime, Duration, Utc};
use rust_decimal::Decimal;
use uuid::Uuid;

use crate::db::Database;
use crate::utils::error::{AppError, AppResult};

use super::models::*;

#[derive(Clone)]
pub struct SlaService {
    db: Database,
}

impl SlaService {
    pub fn new(db: Database) -> Self { Self { db } }

    // PMS-108 policies --------------------------------------------------------
    pub async fn list_policies(&self, tenant_id: Uuid) -> AppResult<Vec<SlaPolicyResponse>> {
        let rows = sqlx::query_as::<_, PolicyRow>(
            r#"SELECT id, name, description, business_hours_id, is_default
               FROM sla_policies WHERE tenant_id = $1 ORDER BY is_default DESC, name"#,
        ).bind(tenant_id).fetch_all(self.db.pool()).await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn create_policy(
        &self, tenant_id: Uuid, request: &UpsertSlaPolicyRequest,
    ) -> AppResult<SlaPolicyResponse> {
        let mut tx = self.db.pool().begin().await?;
        if request.is_default {
            sqlx::query("UPDATE sla_policies SET is_default = FALSE WHERE tenant_id = $1")
                .bind(tenant_id).execute(&mut *tx).await?;
        }
        let id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO sla_policies (id, tenant_id, name, description, business_hours_id, is_default)
               VALUES ($1, $2, $3, $4, $5, $6)"#,
        )
        .bind(id).bind(tenant_id)
        .bind(&request.name).bind(&request.description).bind(request.business_hours_id).bind(request.is_default)
        .execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(SlaPolicyResponse {
            id, name: request.name.clone(), description: request.description.clone(),
            business_hours_id: request.business_hours_id, is_default: request.is_default,
        })
    }

    pub async fn get_policy(&self, tenant_id: Uuid, id: Uuid) -> AppResult<SlaPolicyResponse> {
        let row = sqlx::query_as::<_, PolicyRow>(
            r#"SELECT id, name, description, business_hours_id, is_default
               FROM sla_policies WHERE tenant_id = $1 AND id = $2"#,
        ).bind(tenant_id).bind(id).fetch_optional(self.db.pool()).await?
        .ok_or_else(|| AppError::NotFound("SlaPolicy".to_string()))?;
        Ok(row.into())
    }

    pub async fn update_policy(
        &self, tenant_id: Uuid, id: Uuid, request: &UpsertSlaPolicyRequest,
    ) -> AppResult<SlaPolicyResponse> {
        let mut tx = self.db.pool().begin().await?;
        if request.is_default {
            sqlx::query("UPDATE sla_policies SET is_default = FALSE WHERE tenant_id = $1 AND id <> $2")
                .bind(tenant_id).bind(id).execute(&mut *tx).await?;
        }
        let n = sqlx::query(
            r#"UPDATE sla_policies SET name = $3, description = $4, business_hours_id = $5,
                   is_default = $6, updated_at = NOW()
               WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id).bind(id)
        .bind(&request.name).bind(&request.description).bind(request.business_hours_id).bind(request.is_default)
        .execute(&mut *tx).await?.rows_affected();
        if n == 0 { return Err(AppError::NotFound("SlaPolicy".to_string())); }
        tx.commit().await?;
        Ok(SlaPolicyResponse {
            id, name: request.name.clone(), description: request.description.clone(),
            business_hours_id: request.business_hours_id, is_default: request.is_default,
        })
    }

    pub async fn delete_policy(&self, tenant_id: Uuid, id: Uuid) -> AppResult<()> {
        let n = sqlx::query("DELETE FROM sla_policies WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id).bind(id).execute(self.db.pool()).await?.rows_affected();
        if n == 0 { return Err(AppError::NotFound("SlaPolicy".to_string())); }
        Ok(())
    }

    // PMS-109 targets ---------------------------------------------------------
    pub async fn list_targets(&self, tenant_id: Uuid, policy_id: Uuid) -> AppResult<Vec<SlaTargetResponse>> {
        // Tenant scoping via the policy join so a caller cannot list another tenant's targets.
        let rows = sqlx::query_as::<_, TargetRow>(
            r#"SELECT t.id, t.sla_policy_id, t.priority_id, t.first_response_hours,
                      t.resolution_hours, t.operational_hours
               FROM sla_targets t
               INNER JOIN sla_policies p ON t.sla_policy_id = p.id
               WHERE p.tenant_id = $1 AND p.id = $2"#,
        ).bind(tenant_id).bind(policy_id).fetch_all(self.db.pool()).await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn upsert_target(
        &self, tenant_id: Uuid, policy_id: Uuid, request: &UpsertSlaTargetRequest,
    ) -> AppResult<SlaTargetResponse> {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM sla_policies WHERE id = $1 AND tenant_id = $2)",
        ).bind(policy_id).bind(tenant_id).fetch_one(self.db.pool()).await?;
        if !exists { return Err(AppError::NotFound("SlaPolicy".to_string())); }
        let id: Uuid = sqlx::query_scalar(
            r#"INSERT INTO sla_targets
               (sla_policy_id, priority_id, first_response_hours, resolution_hours, operational_hours)
               VALUES ($1, $2, $3, $4, $5)
               ON CONFLICT (sla_policy_id, priority_id) DO UPDATE SET
                 first_response_hours = EXCLUDED.first_response_hours,
                 resolution_hours = EXCLUDED.resolution_hours,
                 operational_hours = EXCLUDED.operational_hours,
                 updated_at = NOW()
               RETURNING id"#,
        )
        .bind(policy_id).bind(request.priority_id)
        .bind(request.first_response_hours).bind(request.resolution_hours)
        .bind(&request.operational_hours)
        .fetch_one(self.db.pool()).await?;
        Ok(SlaTargetResponse {
            id, sla_policy_id: policy_id, priority_id: request.priority_id,
            first_response_hours: request.first_response_hours,
            resolution_hours: request.resolution_hours,
            operational_hours: request.operational_hours.clone(),
        })
    }

    pub async fn delete_target(&self, tenant_id: Uuid, id: Uuid) -> AppResult<()> {
        let n = sqlx::query(
            r#"DELETE FROM sla_targets t USING sla_policies p
               WHERE t.sla_policy_id = p.id AND p.tenant_id = $1 AND t.id = $2"#,
        ).bind(tenant_id).bind(id).execute(self.db.pool()).await?.rows_affected();
        if n == 0 { return Err(AppError::NotFound("SlaTarget".to_string())); }
        Ok(())
    }

    // PMS-110 business hours --------------------------------------------------
    pub async fn list_business_hours(&self, tenant_id: Uuid) -> AppResult<Vec<BusinessHoursResponse>> {
        let rows = sqlx::query_as::<_, BhRow>(
            r#"SELECT id, name, timezone, schedule, is_default
               FROM business_hours WHERE tenant_id = $1 ORDER BY is_default DESC, name"#,
        ).bind(tenant_id).fetch_all(self.db.pool()).await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn create_business_hours(
        &self, tenant_id: Uuid, request: &UpsertBusinessHoursRequest,
    ) -> AppResult<BusinessHoursResponse> {
        let mut tx = self.db.pool().begin().await?;
        if request.is_default {
            sqlx::query("UPDATE business_hours SET is_default = FALSE WHERE tenant_id = $1")
                .bind(tenant_id).execute(&mut *tx).await?;
        }
        let id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO business_hours (id, tenant_id, name, timezone, schedule, is_default)
               VALUES ($1, $2, $3, $4, $5, $6)"#,
        )
        .bind(id).bind(tenant_id)
        .bind(&request.name).bind(&request.timezone).bind(&request.schedule).bind(request.is_default)
        .execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(BusinessHoursResponse {
            id, name: request.name.clone(), timezone: request.timezone.clone(),
            schedule: request.schedule.clone(), is_default: request.is_default,
        })
    }

    pub async fn update_business_hours(
        &self, tenant_id: Uuid, id: Uuid, request: &UpsertBusinessHoursRequest,
    ) -> AppResult<BusinessHoursResponse> {
        let n = sqlx::query(
            r#"UPDATE business_hours SET name = $3, timezone = $4, schedule = $5,
                   is_default = $6, updated_at = NOW()
               WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id).bind(id)
        .bind(&request.name).bind(&request.timezone).bind(&request.schedule).bind(request.is_default)
        .execute(self.db.pool()).await?.rows_affected();
        if n == 0 { return Err(AppError::NotFound("BusinessHours".to_string())); }
        Ok(BusinessHoursResponse {
            id, name: request.name.clone(), timezone: request.timezone.clone(),
            schedule: request.schedule.clone(), is_default: request.is_default,
        })
    }

    pub async fn delete_business_hours(&self, tenant_id: Uuid, id: Uuid) -> AppResult<()> {
        let n = sqlx::query("DELETE FROM business_hours WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id).bind(id).execute(self.db.pool()).await?.rows_affected();
        if n == 0 { return Err(AppError::NotFound("BusinessHours".to_string())); }
        Ok(())
    }

    // PMS-111 holiday calendars -----------------------------------------------
    pub async fn list_holiday_calendars(&self, tenant_id: Uuid) -> AppResult<Vec<HolidayCalendarResponse>> {
        let rows = sqlx::query_as::<_, HolidayRow>(
            r#"SELECT id, name, holidays FROM holiday_calendars
               WHERE tenant_id = $1 ORDER BY name"#,
        ).bind(tenant_id).fetch_all(self.db.pool()).await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn create_holiday_calendar(
        &self, tenant_id: Uuid, request: &UpsertHolidayCalendarRequest,
    ) -> AppResult<HolidayCalendarResponse> {
        let id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO holiday_calendars (id, tenant_id, name, holidays)
               VALUES ($1, $2, $3, $4)"#,
        )
        .bind(id).bind(tenant_id).bind(&request.name).bind(&request.holidays)
        .execute(self.db.pool()).await?;
        Ok(HolidayCalendarResponse {
            id, name: request.name.clone(), holidays: request.holidays.clone(),
        })
    }

    pub async fn update_holiday_calendar(
        &self, tenant_id: Uuid, id: Uuid, request: &UpsertHolidayCalendarRequest,
    ) -> AppResult<HolidayCalendarResponse> {
        let n = sqlx::query(
            r#"UPDATE holiday_calendars SET name = $3, holidays = $4, updated_at = NOW()
               WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id).bind(id).bind(&request.name).bind(&request.holidays)
        .execute(self.db.pool()).await?.rows_affected();
        if n == 0 { return Err(AppError::NotFound("HolidayCalendar".to_string())); }
        Ok(HolidayCalendarResponse {
            id, name: request.name.clone(), holidays: request.holidays.clone(),
        })
    }

    pub async fn delete_holiday_calendar(&self, tenant_id: Uuid, id: Uuid) -> AppResult<()> {
        let n = sqlx::query("DELETE FROM holiday_calendars WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id).bind(id).execute(self.db.pool()).await?.rows_affected();
        if n == 0 { return Err(AppError::NotFound("HolidayCalendar".to_string())); }
        Ok(())
    }

    // PMS-112 evaluator -------------------------------------------------------
    /// Compute and persist `tickets.first_response_due`, `resolution_due`,
    /// `sla_due_date` for the ticket based on its priority's targets in
    /// its assigned SLA policy. v1 treats every target's window as
    /// 24x7 hours (ignores `business_hours` schedules); business-hours
    /// awareness lands as a follow-up once a Postgres function or
    /// in-process date arithmetic helper is bench-tested.
    pub async fn evaluate_for_ticket(
        &self, tenant_id: Uuid, ticket_id: Uuid,
    ) -> AppResult<()> {
        let row: Option<(Option<Uuid>, Uuid, DateTime<Utc>)> = sqlx::query_as(
            r#"SELECT sla_id, priority_id, created_at FROM tickets
               WHERE tenant_id = $1 AND id = $2"#,
        ).bind(tenant_id).bind(ticket_id).fetch_optional(self.db.pool()).await?;
        let Some((sla_id, priority_id, created_at)) = row else { return Ok(()); };
        let policy_id = match sla_id {
            Some(p) => p,
            None => match sqlx::query_scalar::<_, Uuid>(
                "SELECT id FROM sla_policies WHERE tenant_id = $1 AND is_default = TRUE LIMIT 1",
            ).bind(tenant_id).fetch_optional(self.db.pool()).await? {
                Some(p) => p,
                None => return Ok(()), // no policy configured; nothing to evaluate
            },
        };
        let target: Option<(Option<Decimal>, Option<Decimal>)> = sqlx::query_as(
            r#"SELECT first_response_hours, resolution_hours FROM sla_targets
               WHERE sla_policy_id = $1 AND priority_id = $2"#,
        ).bind(policy_id).bind(priority_id).fetch_optional(self.db.pool()).await?;
        let Some((fr, res)) = target else { return Ok(()); };

        let fr_due = fr.and_then(|h| h.to_string().parse::<f64>().ok())
            .map(|h| created_at + Duration::milliseconds((h * 3_600_000.0) as i64));
        let res_due = res.and_then(|h| h.to_string().parse::<f64>().ok())
            .map(|h| created_at + Duration::milliseconds((h * 3_600_000.0) as i64));

        sqlx::query(
            r#"UPDATE tickets SET first_response_due = $3, resolution_due = $4,
                   sla_due_date = $4, updated_at = NOW()
               WHERE tenant_id = $1 AND id = $2"#,
        ).bind(tenant_id).bind(ticket_id).bind(fr_due).bind(res_due)
        .execute(self.db.pool()).await?;
        Ok(())
    }
}

#[derive(sqlx::FromRow)]
struct PolicyRow {
    id: Uuid, name: String, description: Option<String>,
    business_hours_id: Option<Uuid>, is_default: Option<bool>,
}

impl From<PolicyRow> for SlaPolicyResponse {
    fn from(r: PolicyRow) -> Self {
        Self {
            id: r.id, name: r.name, description: r.description,
            business_hours_id: r.business_hours_id,
            is_default: r.is_default.unwrap_or(false),
        }
    }
}

#[derive(sqlx::FromRow)]
struct TargetRow {
    id: Uuid, sla_policy_id: Uuid, priority_id: Uuid,
    first_response_hours: Option<Decimal>, resolution_hours: Option<Decimal>,
    operational_hours: Option<String>,
}

impl From<TargetRow> for SlaTargetResponse {
    fn from(r: TargetRow) -> Self {
        Self {
            id: r.id, sla_policy_id: r.sla_policy_id, priority_id: r.priority_id,
            first_response_hours: r.first_response_hours,
            resolution_hours: r.resolution_hours,
            operational_hours: r.operational_hours.unwrap_or_else(|| "business_hours".into()),
        }
    }
}

#[derive(sqlx::FromRow)]
struct BhRow {
    id: Uuid, name: String, timezone: String,
    schedule: serde_json::Value, is_default: Option<bool>,
}

impl From<BhRow> for BusinessHoursResponse {
    fn from(r: BhRow) -> Self {
        Self {
            id: r.id, name: r.name, timezone: r.timezone, schedule: r.schedule,
            is_default: r.is_default.unwrap_or(false),
        }
    }
}

#[derive(sqlx::FromRow)]
struct HolidayRow {
    id: Uuid, name: String, holidays: serde_json::Value,
}

impl From<HolidayRow> for HolidayCalendarResponse {
    fn from(r: HolidayRow) -> Self {
        Self { id: r.id, name: r.name, holidays: r.holidays }
    }
}
