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
        let order_by = pagination.order_by(
            "date DESC, start_time DESC",
            &["date", "duration_minutes", "created_at"],
        );
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
        let pool = self.db.pool();
        // Write-side tenant validation: FKs check existence, not ownership,
        // so a request body could otherwise attach time to another tenant's
        // work type / ticket / company.
        let defaults = fetch_work_type_defaults(pool, tenant_id, request.work_type_id).await?;
        assert_company_in_tenant(pool, tenant_id, request.company_id).await?;
        if let Some(ticket_id) = request.ticket_id {
            assert_ticket_in_tenant(pool, tenant_id, ticket_id).await?;
        }

        let raw = Self::compute_minutes(request)?;
        let duration = match default_rounding_rule(pool, tenant_id).await? {
            Some(rule) => apply_rounding(raw, &rule),
            None => raw,
        };
        let (hourly_rate, total) = resolve_billing(
            request.hourly_rate,
            request.is_billable,
            &defaults,
            duration,
        );
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
        .bind(hourly_rate)
        .bind(total)
        .execute(pool)
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
                return Err(AppError::BadRequest(
                    "end_time must be after start_time".to_string(),
                ));
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
                COUNT(*)::bigint AS entry_count,
                CASE
                    WHEN BOOL_OR(approval_status = 'rejected') THEN 'rejected'
                    WHEN BOOL_AND(approval_status = 'approved') THEN 'approved'
                    ELSE 'pending'
                END AS approval_status
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
        let anchor = monday_anchor(week_start);
        let week_end = anchor + chrono::Duration::days(7);

        // Move every non-approved entry in the week to 'pending'. An empty or
        // already-approved week is not an error (decision: zeroed-summary
        // everywhere); we just return the current week summary.
        sqlx::query(
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
        .await?;

        self.week_summary(tenant_id, user_id, anchor).await
    }

    /// Approve every pending entry in the user's week. Manager+ only
    /// (enforced at the route). Idempotent: re-approving an approved week is
    /// a no-op that returns the same summary.
    pub async fn approve_timesheet(
        &self,
        tenant_id: Uuid,
        approver_id: Uuid,
        user_id: Uuid,
        week_start: NaiveDate,
    ) -> AppResult<TimesheetSummaryResponse> {
        let anchor = monday_anchor(week_start);
        let week_end = anchor + chrono::Duration::days(7);
        sqlx::query(
            r#"
            UPDATE time_entries
            SET approval_status = 'approved',
                approved_by_id  = $5,
                approved_at     = NOW(),
                updated_at      = NOW()
            WHERE tenant_id = $1
              AND user_id   = $2
              AND date     >= $3
              AND date      < $4
              AND approval_status = 'pending'
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(anchor)
        .bind(week_end)
        .bind(approver_id)
        .execute(self.db.pool())
        .await?;
        self.week_summary(tenant_id, user_id, anchor).await
    }

    /// Reject every pending entry in the user's week with a reason. Manager+
    /// only (enforced at the route).
    pub async fn reject_timesheet(
        &self,
        tenant_id: Uuid,
        reviewer_id: Uuid,
        user_id: Uuid,
        week_start: NaiveDate,
        reason: &str,
    ) -> AppResult<TimesheetSummaryResponse> {
        let anchor = monday_anchor(week_start);
        let week_end = anchor + chrono::Duration::days(7);
        // approved_by_id here records the LAST REVIEWER, not "the approver".
        // No consumer reads time_entries.approved_by_id as an approval flag
        // (verified: only calendar.time_off reads a column of that name), so
        // setting it on a rejection is safe and captures who reviewed.
        sqlx::query(
            r#"
            UPDATE time_entries
            SET approval_status  = 'rejected',
                rejection_reason = $5,
                approved_by_id   = $6,
                approved_at      = NOW(),
                updated_at       = NOW()
            WHERE tenant_id = $1
              AND user_id   = $2
              AND date     >= $3
              AND date      < $4
              AND approval_status = 'pending'
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(anchor)
        .bind(week_end)
        .bind(reason)
        .bind(reviewer_id)
        .execute(self.db.pool())
        .await?;
        self.week_summary(tenant_id, user_id, anchor).await
    }

    /// Current week summary for a user, or a zeroed `pending` summary when the
    /// week has no entries. Keeps submit/approve/reject responses consistent
    /// on empty weeks (no 404s).
    async fn week_summary(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        anchor: NaiveDate,
    ) -> AppResult<TimesheetSummaryResponse> {
        let filter = TimesheetFilter {
            user_id: Some(user_id),
            week: Some(anchor),
        };
        let summaries = self.list_timesheets(tenant_id, &filter).await?;
        Ok(summaries
            .into_iter()
            .find(|s| s.user_id == user_id && s.week_start == anchor)
            .unwrap_or_else(|| TimesheetSummaryResponse {
                user_id,
                week_start: anchor,
                total_minutes: 0,
                billable_minutes: 0,
                entry_count: 0,
                approval_status: "pending".to_string(),
            }))
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
        let pool = self.db.pool();
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM active_timers WHERE tenant_id = $1 AND user_id = $2)",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_one(pool)
        .await?;
        if exists {
            return Err(AppError::Conflict(
                "User already has an active timer; stop it first".to_string(),
            ));
        }

        // Validate any supplied references belong to the tenant before we
        // persist a timer that points at them.
        if let Some(ticket_id) = request.ticket_id {
            assert_ticket_in_tenant(pool, tenant_id, ticket_id).await?;
        }
        if let Some(company_id) = request.company_id {
            assert_company_in_tenant(pool, tenant_id, company_id).await?;
        }
        if let Some(work_type_id) = request.work_type_id {
            fetch_work_type_defaults(pool, tenant_id, work_type_id).await?;
        }

        let id = Uuid::new_v4();
        let started_at: chrono::DateTime<Utc> = match sqlx::query_scalar(
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
        .fetch_one(pool)
        .await
        {
            Ok(ts) => ts,
            // TOCTOU: another request may have inserted between the exists
            // check above and here. UNIQUE(user_id) backs us; surface the
            // race as a clean Conflict instead of a raw 500.
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
                return Err(AppError::Conflict(
                    "User already has an active timer; stop it first".to_string(),
                ));
            }
            Err(e) => return Err(e.into()),
        };

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
    pub async fn stop_timer(
        &self,
        tenant_id: Uuid,
        timer_id: Uuid,
    ) -> AppResult<TimeEntryResponse> {
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
        let raw = (now - timer.started_at).num_minutes().max(1) as i32;

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
                "SELECT company_id FROM tickets WHERE tenant_id = $1 AND id = $2",
            )
            .bind(tenant_id)
            .bind(timer.ticket_id.unwrap_or(Uuid::nil()))
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| {
                AppError::BadRequest(
                    "Cannot stop timer without an inferable company_id".to_string(),
                )
            })?,
        };

        // Derive billing from the resolved, tenant-scoped work type and apply
        // the tenant default rounding rule to the elapsed minutes, so a
        // stopped timer is priced consistently with a manual entry.
        let defaults = fetch_work_type_defaults(&mut *tx, tenant_id, work_type_id).await?;
        let duration = match default_rounding_rule(&mut *tx, tenant_id).await? {
            Some(rule) => apply_rounding(raw, &rule),
            None => raw,
        };
        let (hourly_rate, total) =
            resolve_billing(None, defaults.default_billable, &defaults, duration);

        let entry_id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO time_entries (
                id, tenant_id, user_id, date, start_time, end_time,
                duration_minutes, work_type_id, ticket_id, project_id,
                company_id, notes, is_billable, hourly_rate, total_amount
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
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
        .bind(defaults.default_billable)
        .bind(hourly_rate)
        .bind(total)
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

// ============================================================================
// Shared resolve helpers (tenant validation + billing derivation + rounding)
// ============================================================================

struct WorkTypeDefaults {
    default_rate: Option<Decimal>,
    default_billable: bool,
}

/// Tenant-scoped work-type fetch returning its billing defaults. `NotFound`
/// when the work type does not belong to `tenant_id` - this doubles as
/// write-side tenant validation, closing the cross-tenant attach vector
/// (FKs check existence, not ownership).
async fn fetch_work_type_defaults<'e, E>(
    exec: E,
    tenant_id: Uuid,
    work_type_id: Uuid,
) -> AppResult<WorkTypeDefaults>
where
    E: sqlx::PgExecutor<'e>,
{
    let row: Option<(Option<Decimal>, bool)> = sqlx::query_as::<_, (Option<Decimal>, bool)>(
        r#"
        SELECT default_rate, COALESCE(default_billable, TRUE) AS default_billable
        FROM work_types
        WHERE tenant_id = $1 AND id = $2
        "#,
    )
    .bind(tenant_id)
    .bind(work_type_id)
    .fetch_optional(exec)
    .await?;
    let (default_rate, default_billable) =
        row.ok_or_else(|| AppError::NotFound("WorkType".to_string()))?;
    Ok(WorkTypeDefaults {
        default_rate,
        default_billable,
    })
}

/// Assert a ticket belongs to the tenant; return its `company_id` so the
/// caller can both validate and infer company. `NotFound` cross-tenant.
async fn assert_ticket_in_tenant<'e, E>(
    exec: E,
    tenant_id: Uuid,
    ticket_id: Uuid,
) -> AppResult<Uuid>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_scalar::<_, Uuid>("SELECT company_id FROM tickets WHERE tenant_id = $1 AND id = $2")
        .bind(tenant_id)
        .bind(ticket_id)
        .fetch_optional(exec)
        .await?
        .ok_or_else(|| AppError::NotFound("Ticket".to_string()))
}

/// Assert a company belongs to the tenant. `NotFound` cross-tenant.
async fn assert_company_in_tenant<'e, E>(
    exec: E,
    tenant_id: Uuid,
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

/// Anchor a date to the Monday of its ISO week.
fn monday_anchor(d: NaiveDate) -> NaiveDate {
    d - chrono::Duration::days(d.weekday().num_days_from_monday() as i64)
}

struct RoundingParams {
    increment_minutes: i32,
    minimum_minutes: i32,
    method: String,
}

/// Apply a tenant rounding rule to a raw duration.
///
/// BILLING-CRITICAL: the order below is load-bearing. Once entries are billed
/// against it, changing this re-prices every entry billed after the change.
/// Do not reorder without a re-pricing migration.
///
/// 1. Floor to `minimum_minutes` first (a 3-min call on a 15-min floor
///    bills 15).
/// 2. Round the floored value to `increment_minutes` per `method`.
///
/// Tie-break: an exact midpoint rounds UP (bill-favorable, MSP convention).
/// `increment_minutes <= 0` is treated as no increment rounding (floor only).
fn apply_rounding(raw_minutes: i32, rule: &RoundingParams) -> i32 {
    let floored = raw_minutes.max(rule.minimum_minutes);
    let inc = rule.increment_minutes;
    if inc <= 0 {
        return floored;
    }
    let r = floored % inc;
    if r == 0 {
        return floored;
    }
    let down = floored - r;
    match rule.method.as_str() {
        "down" => down,
        "up" => down + inc,
        // `r * 2 >= inc` makes an exact midpoint round up.
        "nearest" => {
            if r * 2 >= inc {
                down + inc
            } else {
                down
            }
        }
        // Unreachable: method validated at rule-write (validate_rounding_method).
        _ => floored,
    }
}

/// Tenant default rounding rule, if one is configured. `None` => identity
/// (raw minutes, no rounding). Missing-rule = identity is a deliberate M1
/// choice; tracked as debt, not a silent gap.
async fn default_rounding_rule<'e, E>(exec: E, tenant_id: Uuid) -> AppResult<Option<RoundingParams>>
where
    E: sqlx::PgExecutor<'e>,
{
    let row: Option<(i32, i32, String)> = sqlx::query_as::<_, (i32, i32, String)>(
        r#"
        SELECT increment_minutes, COALESCE(minimum_minutes, 0), rounding_method
        FROM time_rounding_rules
        WHERE tenant_id = $1 AND is_default = TRUE
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(exec)
    .await?;
    Ok(row.map(
        |(increment_minutes, minimum_minutes, method)| RoundingParams {
            increment_minutes,
            minimum_minutes,
            method,
        },
    ))
}

/// Resolve the billable rate and total for an entry.
///
/// Rate precedence (locked, documented so an edited rate is never silently
/// overwritten by the derive step):
///   explicit request hourly_rate  >  work_type.default_rate  >  None
/// `total_amount` is computed only when the entry is billable.
fn resolve_billing(
    explicit_rate: Option<Decimal>,
    is_billable: bool,
    defaults: &WorkTypeDefaults,
    minutes: i32,
) -> (Option<Decimal>, Option<Decimal>) {
    let rate = explicit_rate.or(defaults.default_rate);
    let total = if is_billable {
        rate.map(|r| r * Decimal::from(minutes) / Decimal::from(60))
    } else {
        None
    };
    (rate, total)
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
    approval_status: String,
}

impl From<TimesheetRow> for TimesheetSummaryResponse {
    fn from(r: TimesheetRow) -> Self {
        Self {
            user_id: r.user_id,
            week_start: r.week_start,
            total_minutes: r.total_minutes,
            billable_minutes: r.billable_minutes,
            entry_count: r.entry_count,
            approval_status: r.approval_status,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(increment_minutes: i32, minimum_minutes: i32, method: &str) -> RoundingParams {
        RoundingParams {
            increment_minutes,
            minimum_minutes,
            method: method.to_string(),
        }
    }

    #[test]
    fn rounding_floor_applies_before_increment() {
        // 3 raw minutes, 15-min floor, round up to 15-min increment -> 15.
        assert_eq!(apply_rounding(3, &rule(15, 15, "up")), 15);
        // Floor alone lifts a sub-minimum value even with method "down".
        assert_eq!(apply_rounding(3, &rule(15, 15, "down")), 15);
    }

    #[test]
    fn rounding_up_rounds_partial_increment_up() {
        assert_eq!(apply_rounding(16, &rule(15, 0, "up")), 30);
        // Exact multiples are untouched.
        assert_eq!(apply_rounding(30, &rule(15, 0, "up")), 30);
    }

    #[test]
    fn rounding_down_truncates_to_increment() {
        assert_eq!(apply_rounding(29, &rule(15, 0, "down")), 15);
        assert_eq!(apply_rounding(14, &rule(15, 0, "down")), 0);
    }

    #[test]
    fn rounding_nearest_midpoint_rounds_up() {
        // Exact midpoint (7.5 of 15) rounds UP per the locked tie-break.
        assert_eq!(apply_rounding(8, &rule(15, 0, "nearest")), 15);
        // Just below midpoint rounds down.
        assert_eq!(apply_rounding(7, &rule(15, 0, "nearest")), 0);
        // Just above midpoint rounds up.
        assert_eq!(apply_rounding(23, &rule(15, 0, "nearest")), 30);
    }

    #[test]
    fn rounding_zero_increment_is_floor_only() {
        assert_eq!(apply_rounding(7, &rule(0, 15, "up")), 15);
        assert_eq!(apply_rounding(40, &rule(0, 15, "up")), 40);
    }

    #[test]
    fn resolve_billing_rate_precedence() {
        let defaults = WorkTypeDefaults {
            default_rate: Some(Decimal::from(100)),
            default_billable: true,
        };
        // Explicit rate wins over the work-type default.
        let (rate, total) = resolve_billing(Some(Decimal::from(150)), true, &defaults, 60);
        assert_eq!(rate, Some(Decimal::from(150)));
        assert_eq!(total, Some(Decimal::from(150)));
        // Falls back to the work-type default when no explicit rate.
        let (rate, total) = resolve_billing(None, true, &defaults, 30);
        assert_eq!(rate, Some(Decimal::from(100)));
        assert_eq!(total, Some(Decimal::from(50)));
        // Non-billable never produces a total, even with a known rate.
        let (rate, total) = resolve_billing(None, false, &defaults, 60);
        assert_eq!(rate, Some(Decimal::from(100)));
        assert_eq!(total, None);
    }
}
