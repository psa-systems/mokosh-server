//! Calendar / scheduling service. Stateless except for the DB handle.

use chrono::{Datelike, Utc};
use uuid::Uuid;

use crate::db::Database;
use crate::utils::error::{AppError, AppResult};
use crate::utils::pagination::PaginationParams;

use super::models::*;

#[derive(Clone)]
pub struct CalendarService {
    db: Database,
}

impl CalendarService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Reject a foreign id that does not belong to this tenant, so a request
    /// body cannot link a row to another tenant's data. `table` is a
    /// compile-time constant, never user input.
    async fn validate_fk(&self, tenant_id: Uuid, table: &'static str, id: Uuid) -> AppResult<()> {
        let exists: bool = sqlx::query_scalar(&format!(
            "SELECT EXISTS(SELECT 1 FROM {table} WHERE tenant_id = $1 AND id = $2)"
        ))
        .bind(tenant_id)
        .bind(id)
        .fetch_one(self.db.pool())
        .await?;
        if exists {
            Ok(())
        } else {
            Err(AppError::BadRequest(format!(
                "Referenced {table} not found in this tenant"
            )))
        }
    }

    async fn validate_fk_opt(
        &self,
        tenant_id: Uuid,
        table: &'static str,
        id: Option<Uuid>,
    ) -> AppResult<()> {
        match id {
            Some(id) => self.validate_fk(tenant_id, table, id).await,
            None => Ok(()),
        }
    }

    // ========================================================================
    // PMS-60 appointments
    // ========================================================================

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_appointments(
        &self,
        tenant_id: Uuid,
        filter: &AppointmentFilter,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<AppointmentResponse>, u64)> {
        let mut conditions = vec!["tenant_id = $1".to_string()];
        let mut idx = 2;
        if filter.user_id.is_some() {
            conditions.push(format!("assigned_to_id = ${idx}"));
            idx += 1;
        }
        if filter.appointment_type.is_some() {
            conditions.push(format!("appointment_type = ${idx}"));
            idx += 1;
        }
        if filter.from.is_some() {
            conditions.push(format!("end_time >= ${idx}"));
            idx += 1;
        }
        if filter.to.is_some() {
            conditions.push(format!("start_time <= ${idx}"));
            idx += 1;
        }
        let where_clause = conditions.join(" AND ");
        let limit_placeholder = idx;
        let offset_placeholder = idx + 1;
        let query = format!(
            r#"SELECT id, title, description, appointment_type, ticket_id, project_id,
                      task_id, company_id, contact_id, site_id, assigned_to_id,
                      start_time, end_time, all_day, timezone, status, location,
                      created_at, updated_at
               FROM appointments WHERE {where_clause}
               ORDER BY start_time
               LIMIT ${limit_placeholder} OFFSET ${offset_placeholder}"#
        );
        let count_query = format!("SELECT COUNT(*) FROM appointments WHERE {where_clause}");
        let mut q = sqlx::query_as::<_, AppointmentRow>(&query).bind(tenant_id);
        let mut cq = sqlx::query_scalar::<_, i64>(&count_query).bind(tenant_id);
        if let Some(v) = filter.user_id {
            q = q.bind(v);
            cq = cq.bind(v);
        }
        if let Some(v) = &filter.appointment_type {
            q = q.bind(v);
            cq = cq.bind(v);
        }
        if let Some(v) = filter.from {
            q = q.bind(v);
            cq = cq.bind(v);
        }
        if let Some(v) = filter.to {
            q = q.bind(v);
            cq = cq.bind(v);
        }
        let rows = q
            .bind(pagination.limit() as i64)
            .bind(pagination.offset() as i64)
            .fetch_all(self.db.pool())
            .await?;
        let total = cq.fetch_one(self.db.pool()).await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_appointment(
        &self,
        tenant_id: Uuid,
        request: &CreateAppointmentRequest,
    ) -> AppResult<AppointmentResponse> {
        if request.end_time < request.start_time {
            return Err(AppError::BadRequest(
                "end_time must be >= start_time".to_string(),
            ));
        }
        // PSA audit: every foreign id from the request body must belong to
        // this tenant before it is linked.
        self.validate_fk(tenant_id, "users", request.assigned_to_id)
            .await?;
        self.validate_fk_opt(tenant_id, "companies", request.company_id)
            .await?;
        self.validate_fk_opt(tenant_id, "contacts", request.contact_id)
            .await?;
        self.validate_fk_opt(tenant_id, "sites", request.site_id)
            .await?;
        self.validate_fk_opt(tenant_id, "tickets", request.ticket_id)
            .await?;
        self.validate_fk_opt(tenant_id, "projects", request.project_id)
            .await?;
        self.validate_fk_opt(tenant_id, "tasks", request.task_id)
            .await?;
        let id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO appointments (
                id, tenant_id, title, description, appointment_type, ticket_id, project_id,
                task_id, company_id, contact_id, site_id, assigned_to_id,
                start_time, end_time, all_day, timezone, location
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)"#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&request.title)
        .bind(&request.description)
        .bind(&request.appointment_type)
        .bind(request.ticket_id)
        .bind(request.project_id)
        .bind(request.task_id)
        .bind(request.company_id)
        .bind(request.contact_id)
        .bind(request.site_id)
        .bind(request.assigned_to_id)
        .bind(request.start_time)
        .bind(request.end_time)
        .bind(request.all_day)
        .bind(&request.timezone)
        .bind(&request.location)
        .execute(self.db.pool())
        .await?;
        self.get_appointment(tenant_id, id).await
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_appointment(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> AppResult<AppointmentResponse> {
        let row = sqlx::query_as::<_, AppointmentRow>(
            r#"SELECT id, title, description, appointment_type, ticket_id, project_id,
                      task_id, company_id, contact_id, site_id, assigned_to_id,
                      start_time, end_time, all_day, timezone, status, location,
                      created_at, updated_at
               FROM appointments WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(self.db.pool())
        .await?
        .ok_or_else(|| AppError::NotFound("Appointment".to_string()))?;
        Ok(row.into())
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_appointment(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        request: &UpdateAppointmentRequest,
    ) -> AppResult<AppointmentResponse> {
        // PSA audit: validate the foreign id being set so an update cannot
        // re-link this appointment to another tenant's user.
        self.validate_fk_opt(tenant_id, "users", request.assigned_to_id)
            .await?;
        let n = sqlx::query(
            r#"UPDATE appointments SET
                title = COALESCE($3, title),
                description = COALESCE($4, description),
                appointment_type = COALESCE($5, appointment_type),
                assigned_to_id = COALESCE($6, assigned_to_id),
                start_time = COALESCE($7, start_time),
                end_time = COALESCE($8, end_time),
                all_day = COALESCE($9, all_day),
                timezone = COALESCE($10, timezone),
                status = COALESCE($11, status),
                location = COALESCE($12, location),
                updated_at = NOW()
               WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(&request.title)
        .bind(&request.description)
        .bind(&request.appointment_type)
        .bind(request.assigned_to_id)
        .bind(request.start_time)
        .bind(request.end_time)
        .bind(request.all_day)
        .bind(&request.timezone)
        .bind(&request.status)
        .bind(&request.location)
        .execute(self.db.pool())
        .await?
        .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("Appointment".to_string()));
        }
        self.get_appointment(tenant_id, id).await
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_appointment(&self, tenant_id: Uuid, id: Uuid) -> AppResult<()> {
        let n = sqlx::query("DELETE FROM appointments WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(self.db.pool())
            .await?
            .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("Appointment".to_string()));
        }
        Ok(())
    }

    // ========================================================================
    // PMS-61 user availability
    // ========================================================================

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_user_availability(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<UserAvailabilityResponse>, u64)> {
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM user_availability WHERE tenant_id = $1 AND user_id = $2",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_one(self.db.pool())
        .await?;

        let rows = sqlx::query_as::<_, AvailRow>(
            r#"SELECT id, user_id, day_of_week, start_time, end_time, is_available
               FROM user_availability WHERE tenant_id = $1 AND user_id = $2
               ORDER BY day_of_week, start_time
               LIMIT $3 OFFSET $4"#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(self.db.pool())
        .await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    /// PUT semantics: replace the entire availability set for a user
    /// in one transaction. Partial updates are an explicit non-goal -
    /// the calendar UI typically presents the whole week as one form,
    /// so atomic replacement matches the user workflow.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn replace_user_availability(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        request: &ReplaceAvailabilityRequest,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<UserAvailabilityResponse>, u64)> {
        let mut tx = self.db.pool().begin().await?;
        sqlx::query("DELETE FROM user_availability WHERE tenant_id = $1 AND user_id = $2")
            .bind(tenant_id)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        for w in &request.windows {
            if w.end_time <= w.start_time {
                return Err(AppError::BadRequest(
                    "end_time must be after start_time".to_string(),
                ));
            }
            sqlx::query(
                r#"INSERT INTO user_availability
                   (id, tenant_id, user_id, day_of_week, start_time, end_time, is_available)
                   VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
            )
            .bind(Uuid::new_v4())
            .bind(tenant_id)
            .bind(user_id)
            .bind(w.day_of_week)
            .bind(w.start_time)
            .bind(w.end_time)
            .bind(w.is_available)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        self.get_user_availability(tenant_id, user_id, pagination)
            .await
    }

    // ========================================================================
    // PMS-62 time off
    // ========================================================================

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_time_off(
        &self,
        tenant_id: Uuid,
        filter: &TimeOffFilter,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<TimeOffResponse>, u64)> {
        let mut conditions = vec!["tenant_id = $1".to_string()];
        let mut idx = 2;
        if filter.user_id.is_some() {
            conditions.push(format!("user_id = ${idx}"));
            idx += 1;
        }
        if filter.status.is_some() {
            conditions.push(format!("status = ${idx}"));
            idx += 1;
        }
        if filter.from.is_some() {
            conditions.push(format!("end_date >= ${idx}"));
            idx += 1;
        }
        if filter.to.is_some() {
            conditions.push(format!("start_date <= ${idx}"));
            idx += 1;
        }
        let where_clause = conditions.join(" AND ");
        let limit_placeholder = idx;
        let offset_placeholder = idx + 1;
        let query = format!(
            r#"SELECT id, user_id, start_date, end_date, type, status, approved_by_id, notes, created_at
               FROM time_off WHERE {where_clause}
               ORDER BY start_date DESC
               LIMIT ${limit_placeholder} OFFSET ${offset_placeholder}"#
        );
        let count_query = format!("SELECT COUNT(*) FROM time_off WHERE {where_clause}");
        let mut q = sqlx::query_as::<_, TimeOffRow>(&query).bind(tenant_id);
        let mut cq = sqlx::query_scalar::<_, i64>(&count_query).bind(tenant_id);
        if let Some(v) = filter.user_id {
            q = q.bind(v);
            cq = cq.bind(v);
        }
        if let Some(v) = &filter.status {
            q = q.bind(v);
            cq = cq.bind(v);
        }
        if let Some(v) = filter.from {
            q = q.bind(v);
            cq = cq.bind(v);
        }
        if let Some(v) = filter.to {
            q = q.bind(v);
            cq = cq.bind(v);
        }
        let rows = q
            .bind(pagination.limit() as i64)
            .bind(pagination.offset() as i64)
            .fetch_all(self.db.pool())
            .await?;
        let total = cq.fetch_one(self.db.pool()).await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_time_off(
        &self,
        tenant_id: Uuid,
        request: &CreateTimeOffRequest,
    ) -> AppResult<TimeOffResponse> {
        if request.end_date < request.start_date {
            return Err(AppError::BadRequest(
                "end_date must be >= start_date".to_string(),
            ));
        }
        let id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO time_off (id, tenant_id, user_id, start_date, end_date, type, notes)
               VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(request.user_id)
        .bind(request.start_date)
        .bind(request.end_date)
        .bind(&request.kind)
        .bind(&request.notes)
        .execute(self.db.pool())
        .await?;
        self.get_time_off(tenant_id, id).await
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_time_off(&self, tenant_id: Uuid, id: Uuid) -> AppResult<TimeOffResponse> {
        let row = sqlx::query_as::<_, TimeOffRow>(
            r#"SELECT id, user_id, start_date, end_date, type, status, approved_by_id, notes, created_at
               FROM time_off WHERE tenant_id = $1 AND id = $2"#,
        ).bind(tenant_id).bind(id).fetch_optional(self.db.pool()).await?
        .ok_or_else(|| AppError::NotFound("TimeOff".to_string()))?;
        Ok(row.into())
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn approve_time_off(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        approver_id: Uuid,
        status: &str,
    ) -> AppResult<TimeOffResponse> {
        if !matches!(status, "approved" | "rejected") {
            return Err(AppError::BadRequest(format!(
                "status must be approved | rejected; got {status:?}"
            )));
        }
        let n = sqlx::query(
            r#"UPDATE time_off SET status = $3, approved_by_id = $4, updated_at = NOW()
               WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(status)
        .bind(approver_id)
        .execute(self.db.pool())
        .await?
        .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("TimeOff".to_string()));
        }
        self.get_time_off(tenant_id, id).await
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_time_off(&self, tenant_id: Uuid, id: Uuid) -> AppResult<()> {
        let n = sqlx::query("DELETE FROM time_off WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(self.db.pool())
            .await?
            .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("TimeOff".to_string()));
        }
        Ok(())
    }

    // ========================================================================
    // PMS-63 on-call schedules
    // ========================================================================

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_on_call_schedules(
        &self,
        tenant_id: Uuid,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<OnCallScheduleResponse>, u64)> {
        let total: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM on_call_schedules WHERE tenant_id = $1")
                .bind(tenant_id)
                .fetch_one(self.db.pool())
                .await?;

        let rows = sqlx::query_as::<_, OnCallRow>(
            r#"SELECT id, name, team_id, rotation_type, rotation_config, is_active
               FROM on_call_schedules WHERE tenant_id = $1
               ORDER BY name
               LIMIT $2 OFFSET $3"#,
        )
        .bind(tenant_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(self.db.pool())
        .await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_on_call_schedule(
        &self,
        tenant_id: Uuid,
        request: &UpsertOnCallScheduleRequest,
    ) -> AppResult<OnCallScheduleResponse> {
        let id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO on_call_schedules
               (id, tenant_id, name, team_id, rotation_type, rotation_config, is_active)
               VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&request.name)
        .bind(request.team_id)
        .bind(&request.rotation_type)
        .bind(&request.rotation_config)
        .bind(request.is_active)
        .execute(self.db.pool())
        .await?;
        Ok(OnCallScheduleResponse {
            id,
            name: request.name.clone(),
            team_id: request.team_id,
            rotation_type: request.rotation_type.clone(),
            rotation_config: request.rotation_config.clone(),
            is_active: request.is_active,
        })
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_on_call_schedule(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        request: &UpsertOnCallScheduleRequest,
    ) -> AppResult<OnCallScheduleResponse> {
        let n = sqlx::query(
            r#"UPDATE on_call_schedules SET
                  name = $3, team_id = $4, rotation_type = $5,
                  rotation_config = $6, is_active = $7, updated_at = NOW()
               WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(&request.name)
        .bind(request.team_id)
        .bind(&request.rotation_type)
        .bind(&request.rotation_config)
        .bind(request.is_active)
        .execute(self.db.pool())
        .await?
        .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("OnCallSchedule".to_string()));
        }
        Ok(OnCallScheduleResponse {
            id,
            name: request.name.clone(),
            team_id: request.team_id,
            rotation_type: request.rotation_type.clone(),
            rotation_config: request.rotation_config.clone(),
            is_active: request.is_active,
        })
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_on_call_schedule(&self, tenant_id: Uuid, id: Uuid) -> AppResult<()> {
        let n = sqlx::query("DELETE FROM on_call_schedules WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(self.db.pool())
            .await?
            .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("OnCallSchedule".to_string()));
        }
        Ok(())
    }

    /// Resolve who's on call right now. v1 picks the first user from
    /// `rotation_config.user_ids[]` per active schedule; weekly /
    /// daily / custom rotation math arrives in a follow-up. Returns
    /// one entry per active schedule.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn on_call_now(&self, tenant_id: Uuid) -> AppResult<Vec<OnCallNowResponse>> {
        let rows = sqlx::query_as::<_, OnCallRow>(
            r#"SELECT id, name, team_id, rotation_type, rotation_config, is_active
               FROM on_call_schedules WHERE tenant_id = $1 AND is_active = TRUE"#,
        )
        .bind(tenant_id)
        .fetch_all(self.db.pool())
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let users = r
                .rotation_config
                .get("user_ids")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let on_call_user_id = match (users.first(), r.rotation_type.as_str(), Utc::now()) {
                (Some(v), "weekly", now) => {
                    // weekly: index = ISO week mod len(users).
                    let _ = v;
                    let week = now.iso_week().week() as usize;
                    let len = users.len();
                    if len == 0 {
                        None
                    } else {
                        users[week % len]
                            .as_str()
                            .and_then(|s| Uuid::parse_str(s).ok())
                    }
                }
                (Some(v), "daily", now) => {
                    let _ = v;
                    let day = now.ordinal() as usize;
                    let len = users.len();
                    if len == 0 {
                        None
                    } else {
                        users[day % len]
                            .as_str()
                            .and_then(|s| Uuid::parse_str(s).ok())
                    }
                }
                (Some(v), _, _) => v.as_str().and_then(|s| Uuid::parse_str(s).ok()),
                _ => None,
            };
            out.push(OnCallNowResponse {
                schedule_id: r.id,
                schedule_name: r.name,
                on_call_user_id,
            });
        }
        Ok(out)
    }
}

#[derive(sqlx::FromRow)]
struct AppointmentRow {
    id: Uuid,
    title: String,
    description: Option<String>,
    appointment_type: Option<String>,
    ticket_id: Option<Uuid>,
    project_id: Option<Uuid>,
    task_id: Option<Uuid>,
    company_id: Option<Uuid>,
    contact_id: Option<Uuid>,
    site_id: Option<Uuid>,
    assigned_to_id: Uuid,
    start_time: chrono::DateTime<Utc>,
    end_time: chrono::DateTime<Utc>,
    all_day: Option<bool>,
    timezone: Option<String>,
    status: Option<String>,
    location: Option<String>,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
}

impl From<AppointmentRow> for AppointmentResponse {
    fn from(r: AppointmentRow) -> Self {
        Self {
            id: r.id,
            title: r.title,
            description: r.description,
            appointment_type: r.appointment_type.unwrap_or_else(|| "other".into()),
            ticket_id: r.ticket_id,
            project_id: r.project_id,
            task_id: r.task_id,
            company_id: r.company_id,
            contact_id: r.contact_id,
            site_id: r.site_id,
            assigned_to_id: r.assigned_to_id,
            start_time: r.start_time,
            end_time: r.end_time,
            all_day: r.all_day.unwrap_or(false),
            timezone: r.timezone.unwrap_or_else(|| "UTC".into()),
            status: r.status.unwrap_or_else(|| "scheduled".into()),
            location: r.location,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct AvailRow {
    id: Uuid,
    user_id: Uuid,
    day_of_week: i32,
    start_time: chrono::NaiveTime,
    end_time: chrono::NaiveTime,
    is_available: Option<bool>,
}

impl From<AvailRow> for UserAvailabilityResponse {
    fn from(r: AvailRow) -> Self {
        Self {
            id: r.id,
            user_id: r.user_id,
            day_of_week: r.day_of_week,
            start_time: r.start_time,
            end_time: r.end_time,
            is_available: r.is_available.unwrap_or(true),
        }
    }
}

#[derive(sqlx::FromRow)]
struct TimeOffRow {
    id: Uuid,
    user_id: Uuid,
    start_date: chrono::NaiveDate,
    end_date: chrono::NaiveDate,
    r#type: String,
    status: Option<String>,
    approved_by_id: Option<Uuid>,
    notes: Option<String>,
    created_at: chrono::DateTime<Utc>,
}

impl From<TimeOffRow> for TimeOffResponse {
    fn from(r: TimeOffRow) -> Self {
        Self {
            id: r.id,
            user_id: r.user_id,
            start_date: r.start_date,
            end_date: r.end_date,
            kind: r.r#type,
            status: r.status.unwrap_or_else(|| "pending".into()),
            approved_by_id: r.approved_by_id,
            notes: r.notes,
            created_at: r.created_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct OnCallRow {
    id: Uuid,
    name: String,
    team_id: Option<Uuid>,
    rotation_type: String,
    rotation_config: serde_json::Value,
    is_active: Option<bool>,
}

impl From<OnCallRow> for OnCallScheduleResponse {
    fn from(r: OnCallRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            team_id: r.team_id,
            rotation_type: r.rotation_type,
            rotation_config: r.rotation_config,
            is_active: r.is_active.unwrap_or(true),
        }
    }
}
