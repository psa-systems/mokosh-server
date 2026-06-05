//! Calendar / scheduling service. Stateless except for the DB handle
//! (plus an optional notifications dispatcher used by the reminder
//! worker, mirroring `AuthService::with_dispatcher`).

use chrono::{DateTime, Datelike, Utc};
use uuid::Uuid;

use crate::db::Database;
use crate::modules::notifications::NotificationsService;
use crate::utils::error::{AppError, AppResult};
use crate::utils::pagination::PaginationParams;

use super::models::*;

/// Hard ceiling on how many occurrences a single recurring series may
/// expand to in one range query. RRULEs without `COUNT` / `UNTIL` are
/// infinite; `rrule::RRuleSet::all` requires a `u16` limit, and we
/// additionally clip to the requested `to` bound. This cap is the
/// belt-and-braces guard so a pathological rule (e.g. `FREQ=SECONDLY`)
/// over a wide range cannot blow up memory.
const MAX_OCCURRENCES_PER_SERIES: u16 = 1000;

#[derive(Clone)]
pub struct CalendarService {
    db: Database,
    /// When `Some`, the appointment-reminder worker
    /// ([`CalendarReminderWorker`](super::worker::CalendarReminderWorker))
    /// dispatches `appointment.reminder` events through the notifications
    /// queue. `None` for the plain CRUD construction used by the API
    /// router's calendar routes and by older test fixtures that never
    /// run the reminder worker. Mirrors `AuthService::with_dispatcher`.
    notifications: Option<NotificationsService>,
}

impl CalendarService {
    pub fn new(db: Database) -> Self {
        Self {
            db,
            notifications: None,
        }
    }

    /// Like [`Self::new`] but additionally wires the notifications
    /// dispatcher so the reminder worker can fan out
    /// `appointment.reminder` events. The server uses this constructor in
    /// `create_api_router` so the single `CalendarService` shared by the
    /// calendar routes and the reminder worker carries the handle.
    pub fn with_dispatcher(db: Database, notifications: NotificationsService) -> Self {
        Self {
            db,
            notifications: Some(notifications),
        }
    }

    /// Borrow the wired notifications dispatcher, if any. The reminder
    /// worker uses this to fan out `appointment.reminder` events; absent
    /// a dispatcher the worker tick is a no-op.
    pub(crate) fn notifications(&self) -> Option<&NotificationsService> {
        self.notifications.as_ref()
    }

    /// Connection-pool accessor for the reminder worker, which writes the
    /// `appointment_reminders` dedupe ledger directly.
    pub(crate) fn pool(&self) -> &sqlx::PgPool {
        self.db.pool()
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
        // Bounded range query (both ends supplied) => expand recurring
        // series in-memory and paginate the expanded set. Recurrence has
        // no meaning without an upper bound, so the unbounded path below
        // stays a plain SQL-paginated list of stored rows (master rows
        // included, occurrences not expanded). `appointment_type` is not
        // a dimension of the range/dispatch view, so it is honoured only
        // on the unbounded path.
        if let (Some(from), Some(to), None) =
            (filter.from, filter.to, filter.appointment_type.as_ref())
        {
            let all = self
                .appointments_in_range(tenant_id, from, to, filter.user_id)
                .await?;
            let total = all.len() as u64;
            let start = pagination.offset() as usize;
            let page: Vec<AppointmentResponse> = all
                .into_iter()
                .skip(start)
                .take(pagination.limit() as usize)
                .collect();
            return Ok((page, total));
        }
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
                      recurrence_rule, recurrence_parent_id,
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

    /// Range query with in-memory recurrence expansion (PMS-58).
    ///
    /// Returns every appointment instance that overlaps `[from, to]`,
    /// sorted by start. Non-recurring rows pass through unchanged; rows
    /// carrying a `recurrence_rule` are expanded to concrete occurrence
    /// instances bounded by the window (the master row itself is NOT
    /// emitted - its occurrences are). Expansion happens here at read
    /// time; no occurrence rows are ever written to the DB.
    ///
    /// `assigned_to_id` optionally narrows to one technician. The window
    /// is required: an unbounded recurring series has no natural end, so
    /// the caller must supply both bounds.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn appointments_in_range(
        &self,
        tenant_id: Uuid,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        assigned_to_id: Option<Uuid>,
    ) -> AppResult<Vec<AppointmentResponse>> {
        // Non-recurring rows overlapping the window. The recurring
        // masters are fetched separately (next query) WITHOUT a time
        // filter, because a series that started before `from` can still
        // produce occurrences inside the window.
        let mut conditions = vec![
            "tenant_id = $1".to_string(),
            "recurrence_rule IS NULL".to_string(),
        ];
        let mut idx = 2;
        if assigned_to_id.is_some() {
            conditions.push(format!("assigned_to_id = ${idx}"));
            idx += 1;
        }
        let from_ph = idx;
        let to_ph = idx + 1;
        // overlap: end >= from AND start <= to
        conditions.push(format!("end_time >= ${from_ph}"));
        conditions.push(format!("start_time <= ${to_ph}"));
        let where_clause = conditions.join(" AND ");
        let plain_query = format!(
            r#"SELECT id, title, description, appointment_type, ticket_id, project_id,
                      task_id, company_id, contact_id, site_id, assigned_to_id,
                      start_time, end_time, all_day, timezone, status, location,
                      recurrence_rule, recurrence_parent_id,
                      created_at, updated_at
               FROM appointments WHERE {where_clause}
               ORDER BY start_time"#
        );
        let mut q = sqlx::query_as::<_, AppointmentRow>(&plain_query).bind(tenant_id);
        if let Some(v) = assigned_to_id {
            q = q.bind(v);
        }
        let plain_rows = q.bind(from).bind(to).fetch_all(self.db.pool()).await?;

        // Recurring masters: no time filter (the rule decides which
        // occurrences land in the window).
        let mut rconditions = vec![
            "tenant_id = $1".to_string(),
            "recurrence_rule IS NOT NULL".to_string(),
        ];
        if assigned_to_id.is_some() {
            rconditions.push("assigned_to_id = $2".to_string());
        }
        let rwhere = rconditions.join(" AND ");
        let recurring_query = format!(
            r#"SELECT id, title, description, appointment_type, ticket_id, project_id,
                      task_id, company_id, contact_id, site_id, assigned_to_id,
                      start_time, end_time, all_day, timezone, status, location,
                      recurrence_rule, recurrence_parent_id,
                      created_at, updated_at
               FROM appointments WHERE {rwhere}
               ORDER BY start_time"#
        );
        let mut rq = sqlx::query_as::<_, AppointmentRow>(&recurring_query).bind(tenant_id);
        if let Some(v) = assigned_to_id {
            rq = rq.bind(v);
        }
        let recurring_rows = rq.fetch_all(self.db.pool()).await?;

        let mut out: Vec<AppointmentResponse> = plain_rows.into_iter().map(Into::into).collect();
        for row in recurring_rows {
            let base: AppointmentResponse = row.into();
            out.extend(expand_recurrence(&base, from, to));
        }
        out.sort_by_key(|a| a.start_time);
        Ok(out)
    }

    /// Enumerate concrete appointment occurrences (across all tenants)
    /// whose reminder fire-time has arrived but whose start is still in
    /// the future, for the reminder worker (PMS-58 follow-up).
    ///
    /// Only appointments carrying a non-empty `reminder_minutes` are
    /// considered. The scan window is `[now, now + max_offset]` where
    /// `max_offset` is the largest reminder offset present in the table:
    /// any occurrence that could currently owe a reminder starts inside
    /// that window (`now < occurrence_start <= now + offset <= now +
    /// max_offset`), so a wider window would only add work. Recurring
    /// masters are expanded in-memory via [`expand_recurrence`] exactly
    /// like the dispatch/range view; non-recurring rows pass through.
    ///
    /// Returns one [`ReminderCandidate`] per (occurrence, offset) pair.
    /// The worker is responsible for the per-pair dedupe against the
    /// `appointment_reminders` ledger and for firing the actual
    /// dispatch; this method only computes which reminders are due.
    #[tracing::instrument(skip_all)]
    pub async fn due_reminders(&self, now: DateTime<Utc>) -> AppResult<Vec<ReminderCandidate>> {
        // Largest configured offset across the whole table bounds the
        // expansion window. NULL (no appointment has reminders) => no work.
        let max_offset_min: Option<i32> = sqlx::query_scalar(
            r#"SELECT MAX(m) FROM appointments a, unnest(a.reminder_minutes) AS m
               WHERE a.reminder_minutes IS NOT NULL"#,
        )
        .fetch_one(self.db.pool())
        .await?;
        let Some(max_offset_min) = max_offset_min else {
            return Ok(Vec::new());
        };
        // Negative / zero offsets cannot produce a future-start reminder
        // window; clamp at 0 so the window is never inverted.
        let window_end = now + chrono::Duration::minutes(max_offset_min.max(0) as i64);

        // Pull every appointment with reminders. Non-recurring rows are
        // pre-filtered to those whose start can still fall in the window
        // (start > now AND start <= window_end). Recurring masters carry
        // no time filter - the rule decides which occurrences land in
        // range, same as `appointments_in_range`.
        let rows = sqlx::query_as::<_, ReminderRow>(
            r#"SELECT id, tenant_id, assigned_to_id, start_time, end_time,
                      recurrence_rule, reminder_minutes
               FROM appointments
               WHERE reminder_minutes IS NOT NULL
                 AND array_length(reminder_minutes, 1) > 0
                 AND (
                   recurrence_rule IS NOT NULL
                   OR (start_time > $1 AND start_time <= $2)
                 )"#,
        )
        .bind(now)
        .bind(window_end)
        .fetch_all(self.db.pool())
        .await?;

        let mut out: Vec<ReminderCandidate> = Vec::new();
        for row in rows {
            // Occurrence starts this row contributes inside the window.
            let occ_starts: Vec<DateTime<Utc>> = if row.recurrence_rule.is_some() {
                // Reuse the proven expander. It needs an AppointmentResponse
                // shape; only the recurrence-relevant fields matter here.
                let base = row.to_response();
                expand_recurrence(&base, now, window_end)
                    .into_iter()
                    .map(|occ| occ.start_time)
                    .collect()
            } else {
                vec![row.start_time]
            };

            for occ_start in occ_starts {
                // Past-start occurrences never owe a reminder (don't
                // remind for events that already began).
                if occ_start <= now {
                    continue;
                }
                for &offset in &row.reminder_minutes {
                    if offset < 0 {
                        continue;
                    }
                    let fire_at = occ_start - chrono::Duration::minutes(offset as i64);
                    // Due iff the fire-time has arrived. The start-future
                    // check above already holds.
                    if fire_at <= now {
                        out.push(ReminderCandidate {
                            tenant_id: row.tenant_id,
                            appointment_id: row.id,
                            assigned_to_id: row.assigned_to_id,
                            occurrence_start: occ_start,
                            reminder_minutes: offset,
                        });
                    }
                }
            }
        }
        Ok(out)
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_appointment(
        &self,
        tenant_id: Uuid,
        request: &CreateAppointmentRequest,
    ) -> AppResult<AppointmentResponse> {
        if request.end_time <= request.start_time {
            return Err(AppError::BadRequest(
                "end_time must be after start_time".to_string(),
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
                start_time, end_time, all_day, timezone, location, recurrence_rule
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)"#,
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
        .bind(&request.recurrence_rule)
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
                      recurrence_rule, recurrence_parent_id,
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

    // ========================================================================
    // PMS-58 dispatch view
    // ========================================================================

    /// Aggregated dispatch board for `[from, to]`. Combines the four
    /// scheduling surfaces a dispatcher needs:
    ///   * appointments overlapping the window (recurring series expanded)
    ///   * weekly availability windows (all users, or one when
    ///     `assigned_to_id` is set)
    ///   * approved time off overlapping the window
    ///   * current on-call coverage
    ///
    /// Availability is week-relative (`day_of_week` + start/end TIME), so
    /// it is returned as-is rather than projected onto the range; the UI
    /// overlays it against each day in the window.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn dispatch_view(
        &self,
        tenant_id: Uuid,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        assigned_to_id: Option<Uuid>,
    ) -> AppResult<DispatchResponse> {
        let appointments = self
            .appointments_in_range(tenant_id, from, to, assigned_to_id)
            .await?;

        // Availability: optionally scoped to one technician.
        let avail_rows = if let Some(uid) = assigned_to_id {
            sqlx::query_as::<_, AvailRow>(
                r#"SELECT id, user_id, day_of_week, start_time, end_time, is_available
                   FROM user_availability WHERE tenant_id = $1 AND user_id = $2
                   ORDER BY user_id, day_of_week, start_time"#,
            )
            .bind(tenant_id)
            .bind(uid)
            .fetch_all(self.db.pool())
            .await?
        } else {
            sqlx::query_as::<_, AvailRow>(
                r#"SELECT id, user_id, day_of_week, start_time, end_time, is_available
                   FROM user_availability WHERE tenant_id = $1
                   ORDER BY user_id, day_of_week, start_time"#,
            )
            .bind(tenant_id)
            .fetch_all(self.db.pool())
            .await?
        };
        let availability: Vec<UserAvailabilityResponse> =
            avail_rows.into_iter().map(Into::into).collect();

        // Approved time off overlapping the window. time_off is DATE
        // granularity, so compare against the date components of the
        // range bounds.
        let from_date = from.date_naive();
        let to_date = to.date_naive();
        let time_off_rows = if let Some(uid) = assigned_to_id {
            sqlx::query_as::<_, TimeOffRow>(
                r#"SELECT id, user_id, start_date, end_date, type, status, approved_by_id, notes, created_at
                   FROM time_off
                   WHERE tenant_id = $1 AND status = 'approved'
                     AND user_id = $4
                     AND end_date >= $2 AND start_date <= $3
                   ORDER BY start_date"#,
            )
            .bind(tenant_id)
            .bind(from_date)
            .bind(to_date)
            .bind(uid)
            .fetch_all(self.db.pool())
            .await?
        } else {
            sqlx::query_as::<_, TimeOffRow>(
                r#"SELECT id, user_id, start_date, end_date, type, status, approved_by_id, notes, created_at
                   FROM time_off
                   WHERE tenant_id = $1 AND status = 'approved'
                     AND end_date >= $2 AND start_date <= $3
                   ORDER BY start_date"#,
            )
            .bind(tenant_id)
            .bind(from_date)
            .bind(to_date)
            .fetch_all(self.db.pool())
            .await?
        };
        let time_off: Vec<TimeOffResponse> = time_off_rows.into_iter().map(Into::into).collect();

        let on_call = self.on_call_now(tenant_id).await?;

        Ok(DispatchResponse {
            appointments,
            availability,
            time_off,
            on_call,
        })
    }
}

/// Expand a recurring appointment master into concrete occurrence
/// instances overlapping `[from, to]`.
///
/// The stored `recurrence_rule` is an RFC 5545 RRULE value (e.g.
/// `FREQ=DAILY;COUNT=3`). The series is anchored on the master's
/// `start_time` (a `DTSTART` is synthesised from it; any `DTSTART` /
/// `RRULE:` prefix already present in the stored value is normalised
/// away). Each occurrence keeps the master's duration; `start_time` /
/// `end_time` are shifted to the occurrence and `recurrence_parent_id`
/// is set to the master id so a client can tell a virtual instance from
/// a stored row. The master row itself is NOT emitted - its first
/// occurrence stands in for it.
///
/// Bounding is twofold: `rrule`'s `before`/`after` clip the walk to the
/// window (widened by 1s so boundary occurrences are included, then
/// re-filtered inclusively in Rust), and [`MAX_OCCURRENCES_PER_SERIES`]
/// caps a pathological infinite rule. A rule that fails to parse yields
/// no instances (logged at warn) rather than failing the whole query.
fn expand_recurrence(
    base: &AppointmentResponse,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
) -> Vec<AppointmentResponse> {
    use rrule::{RRuleSet, Tz};

    let Some(rule_raw) = base.recurrence_rule.as_deref() else {
        return Vec::new();
    };
    // Normalise: drop any DTSTART line the caller stored (we anchor on
    // the appointment's start_time) and any leading `RRULE:` token, then
    // rebuild a canonical `DTSTART:...\nRRULE:...` document.
    let rule_body = rule_raw
        .lines()
        .map(str::trim)
        .find(|l| {
            let upper = l.to_uppercase();
            !upper.starts_with("DTSTART") && !l.is_empty()
        })
        .map(|l| {
            l.strip_prefix("RRULE:")
                .or_else(|| l.strip_prefix("rrule:"))
                .unwrap_or(l)
        })
        .unwrap_or(rule_raw);

    let dtstart = base.start_time.format("%Y%m%dT%H%M%SZ");
    let ical = format!("DTSTART:{dtstart}\nRRULE:{rule_body}");

    let set: RRuleSet = match ical.parse() {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                appointment_id = %base.id,
                rule = %rule_raw,
                error = %e,
                "skipping appointment with unparseable recurrence_rule",
            );
            return Vec::new();
        }
    };

    let duration = base.end_time - base.start_time;
    // Widen the rrule bounds by 1s so an occurrence landing exactly on a
    // bound is not dropped by the exclusive before/after; re-filter
    // inclusively below.
    let epsilon = chrono::Duration::seconds(1);
    let after = (from - epsilon).with_timezone(&Tz::UTC);
    let before = (to + epsilon).with_timezone(&Tz::UTC);

    let result = set
        .after(after)
        .before(before)
        .all(MAX_OCCURRENCES_PER_SERIES);
    if result.limited {
        tracing::warn!(
            appointment_id = %base.id,
            cap = MAX_OCCURRENCES_PER_SERIES,
            "recurrence expansion hit the per-series occurrence cap; results truncated",
        );
    }

    result
        .dates
        .into_iter()
        .map(|occ| occ.with_timezone(&Utc))
        .filter(|start| *start >= from && *start <= to)
        .map(|start| AppointmentResponse {
            start_time: start,
            end_time: start + duration,
            recurrence_parent_id: Some(base.id),
            // The instance carries no rule of its own; only the master
            // does. Clearing it keeps the wire shape unambiguous.
            recurrence_rule: None,
            ..base.clone()
        })
        .collect()
}

/// One due appointment reminder, as computed by
/// [`CalendarService::due_reminders`]: a concrete occurrence start paired
/// with one reminder offset whose fire-time has arrived. The worker
/// dedupes each candidate against the `appointment_reminders` ledger
/// before dispatching.
#[derive(Clone, Debug)]
pub struct ReminderCandidate {
    pub tenant_id: Uuid,
    pub appointment_id: Uuid,
    pub assigned_to_id: Uuid,
    /// Concrete occurrence start (the master start for a one-off, or an
    /// expanded instance start for a recurring series).
    pub occurrence_start: DateTime<Utc>,
    /// Minutes-before offset that fired this candidate. Matches one
    /// element of the appointment's `reminder_minutes[]` and is the
    /// third component of the ledger's unique key.
    pub reminder_minutes: i32,
}

/// Slim projection of `appointments` for the reminder scan: only the
/// columns the offset/occurrence math needs. Avoids widening the public
/// `AppointmentResponse` with `reminder_minutes`.
#[derive(sqlx::FromRow)]
struct ReminderRow {
    id: Uuid,
    tenant_id: Uuid,
    assigned_to_id: Uuid,
    start_time: DateTime<Utc>,
    end_time: DateTime<Utc>,
    recurrence_rule: Option<String>,
    reminder_minutes: Vec<i32>,
}

impl ReminderRow {
    /// Adapt to the `AppointmentResponse` shape `expand_recurrence`
    /// consumes. Only the recurrence-relevant fields (id, start/end,
    /// recurrence_rule) carry meaning for expansion; the rest are
    /// placeholder values that the expander never reads.
    fn to_response(&self) -> AppointmentResponse {
        AppointmentResponse {
            id: self.id,
            title: String::new(),
            description: None,
            appointment_type: "other".into(),
            ticket_id: None,
            project_id: None,
            task_id: None,
            company_id: None,
            contact_id: None,
            site_id: None,
            assigned_to_id: self.assigned_to_id,
            start_time: self.start_time,
            end_time: self.end_time,
            all_day: false,
            timezone: "UTC".into(),
            status: "scheduled".into(),
            location: None,
            recurrence_rule: self.recurrence_rule.clone(),
            recurrence_parent_id: None,
            created_at: self.start_time,
            updated_at: self.start_time,
        }
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
    recurrence_rule: Option<String>,
    recurrence_parent_id: Option<Uuid>,
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
            recurrence_rule: r.recurrence_rule,
            recurrence_parent_id: r.recurrence_parent_id,
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
