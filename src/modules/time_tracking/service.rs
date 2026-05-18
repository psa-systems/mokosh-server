//! Time-tracking service. Endpoints land incrementally across PMS-42.

use chrono::{Datelike, NaiveDate, Utc};
use rust_decimal::Decimal;
use uuid::Uuid;

use crate::db::Database;
use crate::utils::error::{AppError, AppResult};
use crate::utils::pagination::PaginationParams;

use super::models::*;

#[derive(Clone)]
pub struct TimeTrackingService {
    db: Database,
}

impl TimeTrackingService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    // ========================================================================
    // PMS-50 work types
    // ========================================================================

    pub async fn list_work_types(&self, tenant_id: Uuid) -> AppResult<Vec<WorkTypeResponse>> {
        let rows = sqlx::query_as::<_, WorkTypeRow>(
            r#"
            SELECT id, name, description, default_billable, default_rate,
                   is_active, sort_order
            FROM work_types
            WHERE tenant_id = $1
            ORDER BY sort_order, name
            "#,
        )
        .bind(tenant_id)
        .fetch_all(self.db.pool())
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn create_work_type(
        &self,
        tenant_id: Uuid,
        request: &UpsertWorkTypeRequest,
    ) -> AppResult<WorkTypeResponse> {
        let id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO work_types
                (tenant_id, name, description, default_billable, default_rate,
                 is_active, sort_order)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id
            "#,
        )
        .bind(tenant_id)
        .bind(&request.name)
        .bind(&request.description)
        .bind(request.default_billable)
        .bind(request.default_rate)
        .bind(request.is_active)
        .bind(request.sort_order)
        .fetch_one(self.db.pool())
        .await?;
        Ok(WorkTypeResponse {
            id,
            name: request.name.clone(),
            description: request.description.clone(),
            default_billable: request.default_billable,
            default_rate: request.default_rate,
            is_active: request.is_active,
            sort_order: request.sort_order,
        })
    }

    pub async fn update_work_type(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        request: &UpsertWorkTypeRequest,
    ) -> AppResult<WorkTypeResponse> {
        let affected = sqlx::query(
            r#"
            UPDATE work_types SET
                name = $3, description = $4, default_billable = $5,
                default_rate = $6, is_active = $7, sort_order = $8,
                updated_at = NOW()
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(&request.name)
        .bind(&request.description)
        .bind(request.default_billable)
        .bind(request.default_rate)
        .bind(request.is_active)
        .bind(request.sort_order)
        .execute(self.db.pool())
        .await?
        .rows_affected();
        if affected == 0 {
            return Err(AppError::NotFound("WorkType".to_string()));
        }
        Ok(WorkTypeResponse {
            id,
            name: request.name.clone(),
            description: request.description.clone(),
            default_billable: request.default_billable,
            default_rate: request.default_rate,
            is_active: request.is_active,
            sort_order: request.sort_order,
        })
    }

    pub async fn delete_work_type(&self, tenant_id: Uuid, id: Uuid) -> AppResult<()> {
        let affected = sqlx::query("DELETE FROM work_types WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(self.db.pool())
            .await?
            .rows_affected();
        if affected == 0 {
            return Err(AppError::NotFound("WorkType".to_string()));
        }
        Ok(())
    }

    // ========================================================================
    // PMS-44 / PMS-45 time entries
    // ========================================================================

    /// Compute duration_minutes from start/end if not supplied.
    fn compute_minutes(request: &CreateTimeEntryRequest) -> AppResult<i32> {
        if let Some(m) = request.duration_minutes {
            return Ok(m);
        }
        if let (Some(s), Some(e)) = (request.start_time, request.end_time) {
            let secs = (e - s).num_minutes();
            if secs < 0 {
                return Err(AppError::BadRequest(
                    "end_time must be after start_time".to_string(),
                ));
            }
            return Ok(secs as i32);
        }
        Err(AppError::BadRequest(
            "Either duration_minutes or (start_time, end_time) must be supplied".to_string(),
        ))
    }

    pub async fn list_time_entries(
        &self,
        tenant_id: Uuid,
        filter: &TimeEntryFilter,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<TimeEntryResponse>, u64)> {
        let offset = pagination.offset() as i64;
        let limit = pagination.limit() as i64;
        let mut conditions = vec!["tenant_id = $1".to_string()];
        let mut idx = 4;
        if filter.user_id.is_some() {
            conditions.push(format!("user_id = ${idx}"));
            idx += 1;
        }
        if filter.ticket_id.is_some() {
            conditions.push(format!("ticket_id = ${idx}"));
            idx += 1;
        }
        if filter.project_id.is_some() {
            conditions.push(format!("project_id = ${idx}"));
            idx += 1;
        }
        if filter.date_from.is_some() {
            conditions.push(format!("date >= ${idx}"));
            idx += 1;
        }
        if filter.date_to.is_some() {
            conditions.push(format!("date <= ${idx}"));
        }
        let where_clause = conditions.join(" AND ");
        let order_by =
            pagination.order_by("date DESC, start_time DESC", &["date", "duration_minutes", "created_at"]);
        let query = format!(
            r#"
            SELECT id, user_id, date, start_time, end_time, duration_minutes,
                   work_type_id, ticket_id, project_id, company_id, notes,
                   is_billable, billing_status, hourly_rate, total_amount,
                   approval_status, created_at, updated_at
            FROM time_entries
            WHERE {where_clause}
            ORDER BY {order_by}
            LIMIT $2 OFFSET $3
            "#
        );
        let count_query = format!("SELECT COUNT(*) FROM time_entries WHERE {where_clause}");
        let mut q = sqlx::query_as::<_, TimeEntryRow>(&query)
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
        let rows = q.fetch_all(self.db.pool()).await?;
        let total = cq.fetch_one(self.db.pool()).await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    pub async fn create_time_entry(
        &self,
        tenant_id: Uuid,
        request: &CreateTimeEntryRequest,
    ) -> AppResult<TimeEntryResponse> {
        let duration = Self::compute_minutes(request)?;
        let total = request
            .hourly_rate
            .map(|r| r * Decimal::from(duration) / Decimal::from(60));
        let id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO time_entries (
                id, tenant_id, user_id, date, start_time, end_time,
                duration_minutes, work_type_id, ticket_id, project_id,
                company_id, notes, is_billable, hourly_rate, total_amount
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(request.user_id)
        .bind(request.date)
        .bind(request.start_time)
        .bind(request.end_time)
        .bind(duration)
        .bind(request.work_type_id)
        .bind(request.ticket_id)
        .bind(request.project_id)
        .bind(request.company_id)
        .bind(&request.notes)
        .bind(request.is_billable)
        .bind(request.hourly_rate)
        .bind(total)
        .execute(self.db.pool())
        .await?;
        self.get_time_entry(tenant_id, id).await
    }

    pub async fn get_time_entry(&self, tenant_id: Uuid, id: Uuid) -> AppResult<TimeEntryResponse> {
        let row = sqlx::query_as::<_, TimeEntryRow>(
            r#"
            SELECT id, user_id, date, start_time, end_time, duration_minutes,
                   work_type_id, ticket_id, project_id, company_id, notes,
                   is_billable, billing_status, hourly_rate, total_amount,
                   approval_status, created_at, updated_at
            FROM time_entries
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(self.db.pool())
        .await?
        .ok_or_else(|| AppError::NotFound("TimeEntry".to_string()))?;
        Ok(row.into())
    }

    pub async fn update_time_entry(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        request: &UpdateTimeEntryRequest,
    ) -> AppResult<TimeEntryResponse> {
        let current = self.get_time_entry(tenant_id, id).await?;
        let start = request.start_time.or(current.start_time);
        let end = request.end_time.or(current.end_time);
        let duration = if let Some(d) = request.duration_minutes {
            d
        } else if let (Some(s), Some(e)) = (start, end) {
            let m = (e - s).num_minutes();
            if m < 0 {
                return Err(AppError::BadRequest("end_time must be after start_time".to_string()));
            }
            m as i32
        } else {
            current.duration_minutes
        };
        let hourly_rate = request.hourly_rate.or(current.hourly_rate);
        let total = hourly_rate.map(|r| r * Decimal::from(duration) / Decimal::from(60));

        let affected = sqlx::query(
            r#"
            UPDATE time_entries SET
                date              = COALESCE($3, date),
                start_time        = $4,
                end_time          = $5,
                duration_minutes  = $6,
                work_type_id      = COALESCE($7, work_type_id),
                ticket_id         = $8,
                project_id        = $9,
                notes             = COALESCE($10, notes),
                is_billable       = COALESCE($11, is_billable),
                hourly_rate       = $12,
                total_amount      = $13,
                updated_at        = NOW()
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(request.date)
        .bind(start)
        .bind(end)
        .bind(duration)
        .bind(request.work_type_id)
        .bind(request.ticket_id)
        .bind(request.project_id)
        .bind(&request.notes)
        .bind(request.is_billable)
        .bind(hourly_rate)
        .bind(total)
        .execute(self.db.pool())
        .await?
        .rows_affected();
        if affected == 0 {
            return Err(AppError::NotFound("TimeEntry".to_string()));
        }
        self.get_time_entry(tenant_id, id).await
    }

    pub async fn delete_time_entry(&self, tenant_id: Uuid, id: Uuid) -> AppResult<()> {
        let affected = sqlx::query("DELETE FROM time_entries WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(self.db.pool())
            .await?
            .rows_affected();
        if affected == 0 {
            return Err(AppError::NotFound("TimeEntry".to_string()));
        }
        Ok(())
    }

    // ========================================================================
    // PMS-46 timesheets (aggregate over time_entries)
    // ========================================================================

    pub async fn list_timesheets(
        &self,
        tenant_id: Uuid,
        filter: &TimesheetFilter,
    ) -> AppResult<Vec<TimesheetSummaryResponse>> {
        // Anchor week_start to Monday. Postgres DATE_TRUNC('week', ...)
        // does ISO week (Monday-start) by default.
        let mut conditions = vec!["tenant_id = $1".to_string()];
        let mut idx = 2;
        if filter.user_id.is_some() {
            conditions.push(format!("user_id = ${idx}"));
            idx += 1;
        }
        if filter.week.is_some() {
            conditions.push(format!(
                "date >= DATE_TRUNC('week', ${idx}::date)::date \
                 AND date < (DATE_TRUNC('week', ${idx}::date) + INTERVAL '7 days')::date"
            ));
        }
        let where_clause = conditions.join(" AND ");
        let query = format!(
            r#"
            SELECT
                user_id,
                DATE_TRUNC('week', date)::date AS week_start,
                SUM(duration_minutes)::bigint AS total_minutes,
                SUM(CASE WHEN is_billable THEN duration_minutes ELSE 0 END)::bigint
                    AS billable_minutes,
                COUNT(*)::bigint AS entry_count
            FROM time_entries
            WHERE {where_clause}
            GROUP BY user_id, DATE_TRUNC('week', date)
            ORDER BY week_start DESC, user_id
            "#
        );
        let mut q = sqlx::query_as::<_, TimesheetRow>(&query).bind(tenant_id);
        if let Some(uid) = filter.user_id {
            q = q.bind(uid);
        }
        if let Some(w) = filter.week {
            q = q.bind(w);
        }
        let rows = q.fetch_all(self.db.pool()).await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    // ========================================================================
    // PMS-47 timesheet submit (state transition over the week's entries)
    // ========================================================================

    /// `timesheet_id` is interpreted as a `(user_id, week_start)` pair
    /// composite via two query params; for the path-based endpoint the
    /// route handler unpacks `user_id_week-anchor` into the pair.
    pub async fn submit_timesheet(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        week_start: NaiveDate,
    ) -> AppResult<TimesheetSummaryResponse> {
        // Anchor to Monday (ISO week start).
        let anchor = week_start - chrono::Duration::days(week_start.weekday().num_days_from_monday() as i64);
        let week_end = anchor + chrono::Duration::days(7);

        let affected = sqlx::query(
            r#"
            UPDATE time_entries
            SET approval_status = 'pending',
                updated_at      = NOW()
            WHERE tenant_id = $1
              AND user_id   = $2
              AND date     >= $3
              AND date      < $4
              AND approval_status NOT IN ('approved')
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(anchor)
        .bind(week_end)
        .execute(self.db.pool())
        .await?
        .rows_affected();

        if affected == 0 {
            return Err(AppError::NotFound(
                "Timesheet (no editable entries in that week)".to_string(),
            ));
        }

        // Return the recomputed week summary.
        let filter = TimesheetFilter {
            user_id: Some(user_id),
            week: Some(anchor),
        };
        let summaries = self.list_timesheets(tenant_id, &filter).await?;
        summaries
            .into_iter()
            .find(|s| s.user_id == user_id && s.week_start == anchor)
            .ok_or_else(|| AppError::NotFound("Timesheet".to_string()))
    }

    // ========================================================================
    // PMS-48 active timers
    // ========================================================================

    pub async fn list_active_timers(
        &self,
        tenant_id: Uuid,
        user_id: Option<Uuid>,
    ) -> AppResult<Vec<ActiveTimerResponse>> {
        let (sql, has_user) = if user_id.is_some() {
            (
                "SELECT id, user_id, ticket_id, project_id, company_id, work_type_id, notes, started_at \
                 FROM active_timers WHERE tenant_id = $1 AND user_id = $2",
                true,
            )
        } else {
            (
                "SELECT id, user_id, ticket_id, project_id, company_id, work_type_id, notes, started_at \
                 FROM active_timers WHERE tenant_id = $1",
                false,
            )
        };
        let mut q = sqlx::query_as::<_, ActiveTimerRow>(sql).bind(tenant_id);
        if has_user {
            q = q.bind(user_id.unwrap());
        }
        let rows = q.fetch_all(self.db.pool()).await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn start_timer(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        request: &StartTimerRequest,
    ) -> AppResult<ActiveTimerResponse> {
        // UNIQUE(user_id) on active_timers means we either upsert or
        // reject. We reject so the user explicitly stops + re-starts;
        // silent replacement loses the prior elapsed time.
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM active_timers WHERE user_id = $1)",
        )
        .bind(user_id)
        .fetch_one(self.db.pool())
        .await?;
        if exists {
            return Err(AppError::Conflict(
                "User already has an active timer; stop it first".to_string(),
            ));
        }

        let id = Uuid::new_v4();
        let started_at: chrono::DateTime<Utc> = sqlx::query_scalar(
            r#"
            INSERT INTO active_timers
                (id, tenant_id, user_id, ticket_id, project_id, company_id,
                 work_type_id, notes)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING started_at
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(user_id)
        .bind(request.ticket_id)
        .bind(request.project_id)
        .bind(request.company_id)
        .bind(request.work_type_id)
        .bind(&request.notes)
        .fetch_one(self.db.pool())
        .await?;

        Ok(ActiveTimerResponse {
            id,
            user_id,
            ticket_id: request.ticket_id,
            project_id: request.project_id,
            company_id: request.company_id,
            work_type_id: request.work_type_id,
            notes: request.notes.clone(),
            started_at,
        })
    }

    /// Stop a timer: removes the `active_timers` row and creates a
    /// `time_entries` row covering the elapsed window.
    pub async fn stop_timer(&self, tenant_id: Uuid, timer_id: Uuid) -> AppResult<TimeEntryResponse> {
        let mut tx = self.db.pool().begin().await?;
        let timer: Option<ActiveTimerRow> = sqlx::query_as(
            "SELECT id, user_id, ticket_id, project_id, company_id, work_type_id, notes, started_at \
             FROM active_timers WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(timer_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(timer) = timer else {
            return Err(AppError::NotFound("ActiveTimer".to_string()));
        };

        let now = Utc::now();
        let duration = (now - timer.started_at).num_minutes().max(1) as i32;

        // Active timer might not carry work_type_id / company_id; the
        // schema requires both on time_entries. Fall back to first
        // active work type and first company on the timer user's tenant.
        let work_type_id = match timer.work_type_id {
            Some(v) => v,
            None => sqlx::query_scalar::<_, Uuid>(
                "SELECT id FROM work_types WHERE tenant_id = $1 AND is_active = TRUE ORDER BY sort_order LIMIT 1",
            )
            .bind(tenant_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| {
                AppError::Configuration(
                    "Cannot stop timer: tenant has no active work_types and timer set none"
                        .to_string(),
                )
            })?,
        };
        let company_id = match timer.company_id {
            Some(v) => v,
            None => sqlx::query_scalar::<_, Uuid>(
                "SELECT company_id FROM tickets WHERE id = $1",
            )
            .bind(timer.ticket_id.unwrap_or(Uuid::nil()))
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| {
                AppError::BadRequest(
                    "Cannot stop timer without an inferable company_id".to_string(),
                )
            })?,
        };

        let entry_id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO time_entries (
                id, tenant_id, user_id, date, start_time, end_time,
                duration_minutes, work_type_id, ticket_id, project_id,
                company_id, notes, is_billable
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, TRUE
            )
            "#,
        )
        .bind(entry_id)
        .bind(tenant_id)
        .bind(timer.user_id)
        .bind(now.date_naive())
        .bind(timer.started_at.time())
        .bind(now.time())
        .bind(duration)
        .bind(work_type_id)
        .bind(timer.ticket_id)
        .bind(timer.project_id)
        .bind(company_id)
        .bind(&timer.notes)
        .execute(&mut *tx)
        .await?;

        sqlx::query("DELETE FROM active_timers WHERE id = $1")
            .bind(timer_id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        self.get_time_entry(tenant_id, entry_id).await
    }

    // ========================================================================
    // PMS-49 time rounding rules
    // ========================================================================

    pub async fn list_rounding_rules(
        &self,
        tenant_id: Uuid,
    ) -> AppResult<Vec<TimeRoundingRuleResponse>> {
        let rows = sqlx::query_as::<_, RoundingRuleRow>(
            r#"
            SELECT id, name, increment_minutes, rounding_method, minimum_minutes, is_default
            FROM time_rounding_rules
            WHERE tenant_id = $1
            ORDER BY is_default DESC, name
            "#,
        )
        .bind(tenant_id)
        .fetch_all(self.db.pool())
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn create_rounding_rule(
        &self,
        tenant_id: Uuid,
        request: &UpsertTimeRoundingRuleRequest,
    ) -> AppResult<TimeRoundingRuleResponse> {
        Self::validate_rounding_method(&request.rounding_method)?;
        let mut tx = self.db.pool().begin().await?;
        if request.is_default {
            sqlx::query("UPDATE time_rounding_rules SET is_default = FALSE WHERE tenant_id = $1")
                .bind(tenant_id)
                .execute(&mut *tx)
                .await?;
        }
        let id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO time_rounding_rules
                (tenant_id, name, increment_minutes, rounding_method,
                 minimum_minutes, is_default)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id
            "#,
        )
        .bind(tenant_id)
        .bind(&request.name)
        .bind(request.increment_minutes)
        .bind(&request.rounding_method)
        .bind(request.minimum_minutes)
        .bind(request.is_default)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(TimeRoundingRuleResponse {
            id,
            name: request.name.clone(),
            increment_minutes: request.increment_minutes,
            rounding_method: request.rounding_method.clone(),
            minimum_minutes: request.minimum_minutes,
            is_default: request.is_default,
        })
    }

    pub async fn update_rounding_rule(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        request: &UpsertTimeRoundingRuleRequest,
    ) -> AppResult<TimeRoundingRuleResponse> {
        Self::validate_rounding_method(&request.rounding_method)?;
        let mut tx = self.db.pool().begin().await?;
        if request.is_default {
            sqlx::query(
                "UPDATE time_rounding_rules SET is_default = FALSE WHERE tenant_id = $1 AND id <> $2",
            )
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await?;
        }
        let affected = sqlx::query(
            r#"
            UPDATE time_rounding_rules SET
                name = $3, increment_minutes = $4, rounding_method = $5,
                minimum_minutes = $6, is_default = $7, updated_at = NOW()
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(&request.name)
        .bind(request.increment_minutes)
        .bind(&request.rounding_method)
        .bind(request.minimum_minutes)
        .bind(request.is_default)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if affected == 0 {
            return Err(AppError::NotFound("TimeRoundingRule".to_string()));
        }
        tx.commit().await?;
        Ok(TimeRoundingRuleResponse {
            id,
            name: request.name.clone(),
            increment_minutes: request.increment_minutes,
            rounding_method: request.rounding_method.clone(),
            minimum_minutes: request.minimum_minutes,
            is_default: request.is_default,
        })
    }

    pub async fn delete_rounding_rule(&self, tenant_id: Uuid, id: Uuid) -> AppResult<()> {
        let affected =
            sqlx::query("DELETE FROM time_rounding_rules WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(id)
                .execute(self.db.pool())
                .await?
                .rows_affected();
        if affected == 0 {
            return Err(AppError::NotFound("TimeRoundingRule".to_string()));
        }
        Ok(())
    }

    fn validate_rounding_method(method: &str) -> AppResult<()> {
        match method {
            "up" | "down" | "nearest" => Ok(()),
            other => Err(AppError::BadRequest(format!(
                "rounding_method {other:?} invalid; expected up | down | nearest"
            ))),
        }
    }
}

#[derive(sqlx::FromRow)]
struct WorkTypeRow {
    id: Uuid,
    name: String,
    description: Option<String>,
    default_billable: bool,
    default_rate: Option<Decimal>,
    is_active: bool,
    sort_order: i32,
}

impl From<WorkTypeRow> for WorkTypeResponse {
    fn from(r: WorkTypeRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            description: r.description,
            default_billable: r.default_billable,
            default_rate: r.default_rate,
            is_active: r.is_active,
            sort_order: r.sort_order,
        }
    }
}

#[derive(sqlx::FromRow)]
struct TimeEntryRow {
    id: Uuid,
    user_id: Uuid,
    date: chrono::NaiveDate,
    start_time: Option<chrono::NaiveTime>,
    end_time: Option<chrono::NaiveTime>,
    duration_minutes: i32,
    work_type_id: Uuid,
    ticket_id: Option<Uuid>,
    project_id: Option<Uuid>,
    company_id: Uuid,
    notes: Option<String>,
    is_billable: Option<bool>,
    billing_status: Option<String>,
    hourly_rate: Option<Decimal>,
    total_amount: Option<Decimal>,
    approval_status: Option<String>,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
}

impl From<TimeEntryRow> for TimeEntryResponse {
    fn from(r: TimeEntryRow) -> Self {
        Self {
            id: r.id,
            user_id: r.user_id,
            date: r.date,
            start_time: r.start_time,
            end_time: r.end_time,
            duration_minutes: r.duration_minutes,
            work_type_id: r.work_type_id,
            ticket_id: r.ticket_id,
            project_id: r.project_id,
            company_id: r.company_id,
            notes: r.notes,
            is_billable: r.is_billable.unwrap_or(true),
            billing_status: r.billing_status.unwrap_or_else(|| "not_billed".to_string()),
            hourly_rate: r.hourly_rate,
            total_amount: r.total_amount,
            approval_status: r.approval_status.unwrap_or_else(|| "pending".to_string()),
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct TimesheetRow {
    user_id: Uuid,
    week_start: chrono::NaiveDate,
    total_minutes: i64,
    billable_minutes: i64,
    entry_count: i64,
}

impl From<TimesheetRow> for TimesheetSummaryResponse {
    fn from(r: TimesheetRow) -> Self {
        Self {
            user_id: r.user_id,
            week_start: r.week_start,
            total_minutes: r.total_minutes,
            billable_minutes: r.billable_minutes,
            entry_count: r.entry_count,
        }
    }
}

#[derive(sqlx::FromRow)]
struct ActiveTimerRow {
    id: Uuid,
    user_id: Uuid,
    ticket_id: Option<Uuid>,
    project_id: Option<Uuid>,
    company_id: Option<Uuid>,
    work_type_id: Option<Uuid>,
    notes: Option<String>,
    started_at: chrono::DateTime<Utc>,
}

impl From<ActiveTimerRow> for ActiveTimerResponse {
    fn from(r: ActiveTimerRow) -> Self {
        Self {
            id: r.id,
            user_id: r.user_id,
            ticket_id: r.ticket_id,
            project_id: r.project_id,
            company_id: r.company_id,
            work_type_id: r.work_type_id,
            notes: r.notes,
            started_at: r.started_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct RoundingRuleRow {
    id: Uuid,
    name: String,
    increment_minutes: i32,
    rounding_method: String,
    minimum_minutes: Option<i32>,
    is_default: Option<bool>,
}

impl From<RoundingRuleRow> for TimeRoundingRuleResponse {
    fn from(r: RoundingRuleRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            increment_minutes: r.increment_minutes,
            rounding_method: r.rounding_method,
            minimum_minutes: r.minimum_minutes.unwrap_or(0),
            is_default: r.is_default.unwrap_or(false),
        }
    }
}
