//! Projects service.

use chrono::Utc;
use rust_decimal::Decimal;
use uuid::Uuid;

use crate::db::Database;
use crate::modules::audit::{audit_write, AuditAction, AuditCtx};
use crate::modules::auth::TenantId;
use crate::utils::error::{AppError, AppResult};
use crate::utils::pagination::PaginationParams;

use super::models::*;

#[derive(Clone)]
pub struct ProjectsService {
    db: Database,
}

impl ProjectsService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    // ========================================================================
    // PMS-53 projects CRUD
    // ========================================================================

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    /// PMS-894: tenant-wide project totals in one round trip.
    ///
    /// Two aggregates over the same table, kept in one transaction so the
    /// counts and the sum describe the same instant - a client rendering them
    /// side by side should not be able to show a budget that includes a
    /// project the counts do not.
    // SPEC-7.452: counts_by_status and total_budget are computed in one transaction, so both describe the same instant
    // SPEC-7.1057: counts per status present, plus the string sum of budget_amount (0 when none)
    pub async fn project_summary(&self, tenant_id: TenantId) -> AppResult<ProjectSummaryResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;

        let rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT status, COUNT(*) FROM projects WHERE tenant_id = $1 GROUP BY status",
        )
        .bind(tenant_id.get())
        .fetch_all(&mut *tx)
        .await?;

        // COALESCE so an empty tenant sums to 0 rather than NULL. `Decimal`
        // all the way out: the column is numeric, and rounding it through an
        // f64 on the way to a client is how a budget total ends in .9999999.
        let total: rust_decimal::Decimal = sqlx::query_scalar(
            "SELECT COALESCE(SUM(budget_amount), 0) FROM projects WHERE tenant_id = $1",
        )
        .bind(tenant_id.get())
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(ProjectSummaryResponse {
            counts_by_status: rows.into_iter().collect(),
            total_budget: total.to_string(),
        })
    }

    pub async fn list_projects(
        &self,
        tenant_id: TenantId,
        filter: &ProjectFilter,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<ProjectResponse>, u64)> {
        let offset = pagination.offset() as i64;
        let limit = pagination.limit() as i64;
        // Parallel WHERE clauses so the data and count queries each get
        // correctly numbered placeholders. The data query has $1 tenant +
        // $2 limit + $3 offset, so filters bind at $4+; the count query has
        // $1 tenant only, so filters bind at $2+. (Sharing one clause made
        // the count query reference $4/$5 with only 3 binds -> 500. Same
        // bug class as PMS-145.)
        // SPEC-7.410: both data and count queries scope to tenant_id = $1
        // SPEC-7.443: independently-numbered placeholders per query, so an added filter never reuses an index between the two
        let mut data_conds = vec!["tenant_id = $1".to_string()];
        let mut count_conds = vec!["tenant_id = $1".to_string()];
        let mut data_idx = 4;
        let mut count_idx = 2;
        if filter.company_id.is_some() {
            data_conds.push(format!("company_id = ${data_idx}"));
            count_conds.push(format!("company_id = ${count_idx}"));
            data_idx += 1;
            count_idx += 1;
        }
        if filter.status.is_some() {
            data_conds.push(format!("status = ${data_idx}"));
            count_conds.push(format!("status = ${count_idx}"));
            data_idx += 1;
            count_idx += 1;
        }
        if filter.project_manager_id.is_some() {
            data_conds.push(format!("project_manager_id = ${data_idx}"));
            count_conds.push(format!("project_manager_id = ${count_idx}"));
            data_idx += 1;
            count_idx += 1;
        }
        // PMS-895: name search. Last, so the placeholder numbering above is
        // untouched; the binds below go in this same order, which is the
        // invariant this whole parallel-clause dance exists to hold.
        // SPEC-7.445: q filters name ILIKE '%<q>%', applied as the last optional condition in both queries
        if filter.q.is_some() {
            data_conds.push(format!("name ILIKE ${data_idx}"));
            count_conds.push(format!("name ILIKE ${count_idx}"));
        }
        let where_clause = data_conds.join(" AND ");
        let count_where = count_conds.join(" AND ");
        // Bare column only (order_by appends the direction); "created_at DESC"
        // produced "... DESC DESC" -> 500 (PMS-145).
        // SPEC-7.444: default sort is created_at; order_by rejects any key outside mokosh_types::sort::PROJECTS
        let order_by = pagination.order_by("created_at", mokosh_types::sort::PROJECTS)?;
        let query = format!(
            r#"
            SELECT id, name, description, project_number, company_id,
                   -- SPEC-7.438: company_name via tenant-scoped correlated subquery; NULL if no company_id or the company row is gone
                   (SELECT co.name FROM companies co
                     WHERE co.id = projects.company_id
                       AND co.tenant_id = projects.tenant_id) AS company_name,
                   contract_id,
                   project_type, project_type_id, status, project_manager_id,
                   -- SPEC-7.439: project_manager_name via tenant-scoped correlated subquery, NULLIF(TRIM(...), '')
                   (SELECT NULLIF(TRIM(CONCAT(u.first_name, ' ', u.last_name)), '')
                      FROM users u
                     WHERE u.id = projects.project_manager_id
                       AND u.tenant_id = projects.tenant_id) AS project_manager_name,
                   start_date,
                   target_end_date, actual_end_date, budget_hours, budget_amount,
                   -- PMS-944: see the note on the task query. Approval is no
                   -- longer the gate on anything, so a project's actuals count
                   -- every live entry rather than only countersigned ones.
                   -- SPEC-7.440: actual_hours sums duration_minutes/60.0 over non-rejected time entries
                   COALESCE((SELECT SUM(te.duration_minutes) FROM time_entries te
                             WHERE te.project_id = projects.id
                               AND te.approval_status <> 'rejected'), 0)::numeric / 60.0
                       AS actual_hours,
                   -- SPEC-7.441: actual_amount sums total_amount over the same non-rejected entry set
                   COALESCE((SELECT SUM(te.total_amount) FROM time_entries te
                             WHERE te.project_id = projects.id
                               AND te.approval_status <> 'rejected'), 0) AS actual_amount,
                   billing_method, hourly_rate, is_billable, default_due_business_days,
                   created_at, updated_at
            FROM projects WHERE {where_clause}
            ORDER BY {order_by} LIMIT $2 OFFSET $3
"#
        );
        let count_query = format!("SELECT COUNT(*) FROM projects WHERE {count_where}");
        let mut q = sqlx::query_as::<_, ProjectRow>(&query)
            .bind(tenant_id)
            .bind(limit)
            .bind(offset);
        let mut cq = sqlx::query_scalar::<_, i64>(&count_query).bind(tenant_id);
        if let Some(v) = filter.company_id {
            q = q.bind(v);
            cq = cq.bind(v);
        }
        if let Some(v) = &filter.status {
            q = q.bind(v);
            cq = cq.bind(v);
        }
        if let Some(v) = filter.project_manager_id {
            q = q.bind(v);
            cq = cq.bind(v);
        }
        if let Some(v) = &filter.q {
            let pattern = format!("%{v}%");
            q = q.bind(pattern.clone());
            cq = cq.bind(pattern);
        }
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows = q.fetch_all(&mut *tx).await?;
        let total = cq.fetch_one(&mut *tx).await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_project(
        &self,
        tenant_id: TenantId,
        request: &CreateProjectRequest,
        ctx: &AuditCtx,
    ) -> AppResult<ProjectResponse> {
        let id = Uuid::new_v4();
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        // SPEC-7.1056: status and billing_method are not checked here; the DB CHECK answers a bad value with a 500
        sqlx::query(
            r#"
            INSERT INTO projects (
                id, tenant_id, name, description, project_number, company_id,
                contract_id, project_type, project_type_id, status, project_manager_id, start_date,
                target_end_date, actual_end_date, budget_hours, budget_amount, billing_method,
                hourly_rate, is_billable, default_due_business_days
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8,
                -- Resolve the lookup id from the legacy string so new rows
                -- carry project_type_id too (PMS-322); NULL if the tenant has
                -- no matching type row.
                -- SPEC-7.435: project_type_id is resolved from the legacy project_type string, NULL if no matching project_types row
                (SELECT id FROM project_types WHERE tenant_id = $2 AND name = $8),
                $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19
            )
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&request.name)
        .bind(&request.description)
        .bind(&request.project_number)
        .bind(request.company_id)
        .bind(request.contract_id)
        .bind(&request.project_type)
        .bind(&request.status)
        .bind(request.project_manager_id)
        .bind(request.start_date)
        .bind(request.target_end_date)
        .bind(request.actual_end_date)
        .bind(request.budget_hours)
        .bind(request.budget_amount)
        .bind(&request.billing_method)
        .bind(request.hourly_rate)
        .bind(request.is_billable)
        .bind(request.default_due_business_days)
        .execute(&mut *tx)
        .await?;
        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM projects t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        // SPEC-7.436: the Create audit row is written in the same transaction as the INSERT, before = NULL
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Create,
            "projects",
            Some(id),
            None,
            after,
        )
        .await?;
        tx.commit().await?;
        // SPEC-7.437: the create response is the freshly re-read project, so derived fields are populated, not reconstructed
        self.get_project(tenant_id, id).await
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_project(&self, tenant_id: TenantId, id: Uuid) -> AppResult<ProjectResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row = sqlx::query_as::<_, ProjectRow>(
            r#"
            SELECT id, name, description, project_number, company_id,
                   (SELECT co.name FROM companies co
                     WHERE co.id = projects.company_id
                       AND co.tenant_id = projects.tenant_id) AS company_name,
                   contract_id,
                   project_type, project_type_id, status, project_manager_id,
                   (SELECT NULLIF(TRIM(CONCAT(u.first_name, ' ', u.last_name)), '')
                      FROM users u
                     WHERE u.id = projects.project_manager_id
                       AND u.tenant_id = projects.tenant_id) AS project_manager_name,
                   start_date,
                   target_end_date, actual_end_date, budget_hours, budget_amount,
                   -- PMS-944: see the note on the task query. Approval is no
                   -- longer the gate on anything, so a project's actuals count
                   -- every live entry rather than only countersigned ones.
                   COALESCE((SELECT SUM(te.duration_minutes) FROM time_entries te
                             WHERE te.project_id = projects.id
                               AND te.approval_status <> 'rejected'), 0)::numeric / 60.0
                       AS actual_hours,
                   COALESCE((SELECT SUM(te.total_amount) FROM time_entries te
                             WHERE te.project_id = projects.id
                               AND te.approval_status <> 'rejected'), 0) AS actual_amount,
                   billing_method, hourly_rate, is_billable, default_due_business_days,
                   created_at, updated_at
            FROM projects WHERE tenant_id = $1 AND id = $2
"#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        // SPEC-7.442: a missing or foreign-tenant project id 404s
        .ok_or_else(|| AppError::NotFound("Project".to_string()))?;
        Ok(row.into())
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_project(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        request: &UpdateProjectRequest,
        ctx: &AuditCtx,
    ) -> AppResult<ProjectResponse> {
        // Mutation + audit row in one transaction (PMS-184), so the project
        // Overview's edits are captured in the change-history feed just like
        // tasks and tickets.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        // SPEC-7.446: before/after snapshots are taken inside one transaction, for the audit diff
        let before: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(p) FROM projects p WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;

        // SPEC-7.447: every field uses COALESCE($n, column), so an omitted field in the request leaves the stored value unchanged
        let affected = sqlx::query(
            r#"
            UPDATE projects SET
                name = COALESCE($3, name),
                description = COALESCE($4, description),
                status = COALESCE($5, status),
                project_manager_id = COALESCE($6, project_manager_id),
                start_date = COALESCE($7, start_date),
                target_end_date = COALESCE($8, target_end_date),
                actual_end_date = COALESCE($9, actual_end_date),
                budget_hours = COALESCE($10, budget_hours),
                budget_amount = COALESCE($11, budget_amount),
                billing_method = COALESCE($12, billing_method),
                hourly_rate = COALESCE($13, hourly_rate),
                is_billable = COALESCE($14, is_billable),
                default_due_business_days = COALESCE($15, default_due_business_days),
                updated_at = NOW()
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(&request.name)
        .bind(&request.description)
        .bind(&request.status)
        .bind(request.project_manager_id)
        .bind(request.start_date)
        .bind(request.target_end_date)
        .bind(request.actual_end_date)
        .bind(request.budget_hours)
        .bind(request.budget_amount)
        .bind(&request.billing_method)
        .bind(request.hourly_rate)
        .bind(request.is_billable)
        .bind(request.default_due_business_days)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        // SPEC-7.448: zero rows affected (missing or foreign-tenant id) 404s
        if affected == 0 {
            return Err(AppError::NotFound("Project".to_string()));
        }

        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(p) FROM projects p WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;

        // PMS-139: audit_write is a cross-module hub still on Uuid (swept last);
        // unwrap the TenantId at the boundary.
        // PMS-349: skip the audit entry when the only change is task-list
        // checkbox flips in the description (a checklist toggle, not an edit).
        // SPEC-7.449: a description-only change that is purely a checklist checkbox toggle writes no audit row
        if !crate::modules::audit::is_task_marker_only_change(&before, &after) {
            audit_write(
                &mut *tx,
                tenant_id,
                ctx,
                AuditAction::Update,
                "projects",
                Some(id),
                before,
                after,
            )
            .await?;
        }
        tx.commit().await?;
        self.get_project(tenant_id, id).await
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_project(&self, tenant_id: TenantId, id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        // SPEC-7.451: deletes only the row matching both tenant_id and id; zero rows affected 404s
        let n = sqlx::query("DELETE FROM projects WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("Project".to_string()));
        }
        tx.commit().await?;
        Ok(())
    }

    // ========================================================================
    // PMS-54 project phases CRUD
    // ========================================================================

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    // SPEC-7.457: lists only phases scoped to tenant_id and project_id, ordered by sort_order, paginated
    pub async fn list_project_phases(
        &self,
        tenant_id: TenantId,
        project_id: Uuid,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<ProjectPhaseResponse>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM project_phases WHERE tenant_id = $1 AND project_id = $2",
        )
        .bind(tenant_id)
        .bind(project_id)
        .fetch_one(&mut *tx)
        .await?;

        let rows = sqlx::query_as::<_, PhaseRow>(
            r#"SELECT id, project_id, name, description, sort_order, start_date, end_date, status
               FROM project_phases WHERE tenant_id = $1 AND project_id = $2 ORDER BY sort_order
               LIMIT $3 OFFSET $4"#,
        )
        .bind(tenant_id)
        .bind(project_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&mut *tx)
        .await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    /// PMS-399: pre-flight guard for the child-create/attach paths. A task or
    /// phase must not be attached to a project whose `status = 'cancelled'`
    /// (British spelling, matching the migration 007 CHECK set). Runs inside
    /// the caller's tenant-scoped tx so the status read and the subsequent
    /// INSERT share one transaction (the RLS GUC is set for both). A missing
    /// row is a 404; a cancelled project is a 409.
    // SPEC-7.454,7.455,7.456: 404 if missing, 409 if cancelled, else attach; runs inside the
    // caller's tenant tx, shared with the subsequent INSERT.
    async fn ensure_project_open(
        &self,
        tx: &mut sqlx::PgConnection,
        tenant_id: TenantId,
        project_id: Uuid,
    ) -> AppResult<()> {
        let status: Option<String> =
            sqlx::query_scalar("SELECT status FROM projects WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(project_id)
                .fetch_optional(tx)
                .await?;
        match status {
            None => Err(AppError::NotFound("Project".to_string())),
            Some(s) if s == "cancelled" => Err(AppError::Conflict(
                "Cannot add items to a cancelled project".to_string(),
            )),
            Some(_) => Ok(()),
        }
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_project_phase(
        &self,
        tenant_id: TenantId,
        project_id: Uuid,
        request: &UpsertProjectPhaseRequest,
        ctx: &AuditCtx,
    ) -> AppResult<ProjectPhaseResponse> {
        let id = Uuid::new_v4();
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        self.ensure_project_open(&mut tx, tenant_id, project_id)
            .await?; // &mut tx auto-derefs to &mut PgConnection; SPEC-7.455: guard and insert share this transaction
                     // SPEC-7.460: audit row written in the same transaction, and the returned phase is built from the request, not re-read
        sqlx::query(
            r#"INSERT INTO project_phases (id, tenant_id, project_id, name, description, sort_order, start_date, end_date, status)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
        )
        .bind(id).bind(tenant_id).bind(project_id)
        .bind(&request.name).bind(&request.description).bind(request.sort_order)
        .bind(request.start_date).bind(request.end_date).bind(&request.status)
        .execute(&mut *tx).await?;
        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM project_phases t WHERE tenant_id = $1 AND id = $2",
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
            "project_phases",
            Some(id),
            None,
            after,
        )
        .await?;
        tx.commit().await?;
        Ok(ProjectPhaseResponse {
            id,
            project_id,
            name: request.name.clone(),
            description: request.description.clone(),
            sort_order: request.sort_order,
            start_date: request.start_date,
            end_date: request.end_date,
            status: request.status.clone(),
        })
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    // SPEC-7.1061: the response is the request plus the RETURNING project_id
    // SPEC-7.461: a full-field UPDATE (not COALESCE'd) scoped by tenant_id and id; no matching row 404s; no audit row is written on update
    // SPEC-7.462: does not call ensure_project_open, so a phase under a now-cancelled project can still be edited
    pub async fn update_project_phase(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        request: &UpsertProjectPhaseRequest,
    ) -> AppResult<ProjectPhaseResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let project_id: Option<Uuid> = sqlx::query_scalar(
            r#"UPDATE project_phases SET name = $3, description = $4, sort_order = $5,
                   start_date = $6, end_date = $7, status = $8, updated_at = NOW()
               WHERE tenant_id = $1 AND id = $2 RETURNING project_id"#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(&request.name)
        .bind(&request.description)
        .bind(request.sort_order)
        .bind(request.start_date)
        .bind(request.end_date)
        .bind(&request.status)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        let Some(project_id) = project_id else {
            return Err(AppError::NotFound("Project phase".to_string()));
        };
        Ok(ProjectPhaseResponse {
            id,
            project_id,
            name: request.name.clone(),
            description: request.description.clone(),
            sort_order: request.sort_order,
            start_date: request.start_date,
            end_date: request.end_date,
            status: request.status.clone(),
        })
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    // SPEC-7.463: deletes by tenant_id + id; zero rows affected 404s; no audit row is written on delete
    pub async fn delete_project_phase(&self, tenant_id: TenantId, id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let n = sqlx::query("DELETE FROM project_phases WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("Project phase".to_string()));
        }
        tx.commit().await?;
        Ok(())
    }

    // ========================================================================
    // PMS-55 task statuses
    // ========================================================================

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    // SPEC-7.464: lists rows scoped to tenant_id, ordered by sort_order, name, paginated
    pub async fn list_task_statuses(
        &self,
        tenant_id: TenantId,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<TaskStatusResponse>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM task_statuses WHERE tenant_id = $1")
                .bind(tenant_id)
                .fetch_one(&mut *tx)
                .await?;

        let rows = sqlx::query_as::<_, TaskStatusRow>(
            r#"SELECT id, name, color, is_completed, sort_order
               FROM task_statuses WHERE tenant_id = $1 ORDER BY sort_order, name
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
    pub async fn create_task_status(
        &self,
        tenant_id: TenantId,
        request: &UpsertTaskStatusRequest,
        ctx: &AuditCtx,
    ) -> AppResult<TaskStatusResponse> {
        let id = Uuid::new_v4();
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            r#"INSERT INTO task_statuses (id, tenant_id, name, color, is_completed, sort_order)
               VALUES ($1, $2, $3, $4, $5, $6)"#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&request.name)
        .bind(&request.color)
        .bind(request.is_completed)
        .bind(request.sort_order)
        .execute(&mut *tx)
        .await?;
        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM task_statuses t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        // SPEC-7.466: Create audit row written in the same transaction as the INSERT; response is built from the request, not re-read
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Create,
            "task_statuses",
            Some(id),
            None,
            after,
        )
        .await?;
        tx.commit().await?;
        Ok(TaskStatusResponse {
            id,
            name: request.name.clone(),
            color: request.color.clone(),
            is_completed: request.is_completed,
            sort_order: request.sort_order,
        })
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    // SPEC-7.467: a full-field UPDATE scoped by tenant_id + id; zero rows affected 404s; no audit row is written on update
    pub async fn update_task_status(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        request: &UpsertTaskStatusRequest,
    ) -> AppResult<TaskStatusResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let n = sqlx::query(
            r#"UPDATE task_statuses SET name = $3, color = $4, is_completed = $5,
                   sort_order = $6, updated_at = NOW()
               WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(&request.name)
        .bind(&request.color)
        .bind(request.is_completed)
        .bind(request.sort_order)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        tx.commit().await?;
        if n == 0 {
            return Err(AppError::NotFound("Task status".to_string()));
        }
        Ok(TaskStatusResponse {
            id,
            name: request.name.clone(),
            color: request.color.clone(),
            is_completed: request.is_completed,
            sort_order: request.sort_order,
        })
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    // SPEC-7.1063: a status still referenced by a task fails with an unmapped FK error (500)
    // SPEC-7.468: deletes by tenant_id + id; zero rows affected 404s; no audit row written, and no FK-violation mapping (contrast with delete_project_type)
    pub async fn delete_task_status(&self, tenant_id: TenantId, id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let n = sqlx::query("DELETE FROM task_statuses WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("Task status".to_string()));
        }
        tx.commit().await?;
        Ok(())
    }

    // ========================================================================
    // PMS-322 project types CRUD. Mirrors task_statuses, plus: one default per
    // tenant (setting a new default clears the prior in the same tx), system
    // rows cannot be deleted, and a delete blocked by a referencing project FK
    // surfaces as a 409 instead of a 500.
    // ========================================================================

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    // SPEC-7.469: lists rows scoped to tenant_id, ordered by sort_order, name, paginated
    pub async fn list_project_types(
        &self,
        tenant_id: TenantId,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<ProjectTypeResponse>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM project_types WHERE tenant_id = $1")
                .bind(tenant_id)
                .fetch_one(&mut *tx)
                .await?;

        let rows = sqlx::query_as::<_, ProjectTypeRow>(
            r#"SELECT id, name, is_default, is_active, sort_order, is_system
               FROM project_types WHERE tenant_id = $1 ORDER BY sort_order, name
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
    pub async fn create_project_type(
        &self,
        tenant_id: TenantId,
        request: &UpsertProjectTypeRequest,
        ctx: &AuditCtx,
    ) -> AppResult<ProjectTypeResponse> {
        let id = Uuid::new_v4();
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        // SPEC-7.1062: a failed request rolls back the is_default clearing
        // SPEC-7.471: creating a default clears is_default on every other tenant row first, in the same transaction
        if request.is_default {
            sqlx::query("UPDATE project_types SET is_default = FALSE, updated_at = NOW() WHERE tenant_id = $1 AND is_default = TRUE")
                .bind(tenant_id)
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query(
            r#"INSERT INTO project_types (id, tenant_id, name, is_default, is_active, sort_order)
               VALUES ($1, $2, $3, $4, $5, $6)"#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&request.name)
        .bind(request.is_default)
        .bind(request.is_active)
        .bind(request.sort_order)
        .execute(&mut *tx)
        .await?;
        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM project_types t WHERE tenant_id = $1 AND id = $2",
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
            "project_types",
            Some(id),
            None,
            after,
        )
        .await?;
        tx.commit().await?;
        // SPEC-7.473: a Create audit row is written; the new row's is_system is always false (API-created types are never system rows)
        Ok(ProjectTypeResponse {
            id,
            name: request.name.clone(),
            is_default: request.is_default,
            is_active: request.is_active,
            sort_order: request.sort_order,
            is_system: false,
        })
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_project_type(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        request: &UpsertProjectTypeRequest,
    ) -> AppResult<ProjectTypeResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        // SPEC-7.472: updating to is_default = true clears is_default on every other tenant row except the one being updated, in the same transaction
        if request.is_default {
            sqlx::query("UPDATE project_types SET is_default = FALSE, updated_at = NOW() WHERE tenant_id = $1 AND is_default = TRUE AND id <> $2")
                .bind(tenant_id)
                .bind(id)
                .execute(&mut *tx)
                .await?;
        }
        // RETURNING is_system so we echo the stored (read-only) flag rather than
        // guessing it.
        // SPEC-7.474: zero rows is 404 "Project type"; no audit row is written on update
        let row: Option<ProjectTypeRow> = sqlx::query_as(
            r#"UPDATE project_types
               SET name = $3, is_default = $4, is_active = $5, sort_order = $6, updated_at = NOW()
               WHERE tenant_id = $1 AND id = $2
               RETURNING id, name, is_default, is_active, sort_order, is_system"#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(&request.name)
        .bind(request.is_default)
        .bind(request.is_active)
        .bind(request.sort_order)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            return Err(AppError::NotFound("Project type".to_string()));
        };
        tx.commit().await?;
        Ok(row.into())
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_project_type(&self, tenant_id: TenantId, id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        // A system row (the seeded client/internal values the code still depends
        // on) cannot be deleted via the API. 404 first if the row is absent.
        let is_system: Option<bool> = sqlx::query_scalar(
            "SELECT is_system FROM project_types WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        // SPEC-7.475: a missing row 404s; a row with is_system = true 409s and the DELETE is never attempted
        match is_system {
            None => return Err(AppError::NotFound("Project type".to_string())),
            Some(true) => {
                return Err(AppError::Conflict(
                    "Cannot delete a system project type".to_string(),
                ))
            }
            Some(false) => {}
        }
        let result = sqlx::query("DELETE FROM project_types WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await;
        if let Err(e) = result {
            // SPEC-7.476: a foreign-key violation (23503, a project still references this type) maps to 409 instead of propagating a 500
            if e.as_database_error().and_then(|d| d.code()).as_deref() == Some("23503") {
                return Err(AppError::Conflict(
                    "Cannot delete this project type: it is still referenced by a project"
                        .to_string(),
                ));
            }
            return Err(e.into());
        }
        tx.commit().await?;
        Ok(())
    }

    // ========================================================================
    // PMS-56 tasks CRUD
    // ========================================================================

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_project_tasks(
        &self,
        tenant_id: TenantId,
        project_id: Uuid,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<TaskResponse>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM tasks WHERE tenant_id = $1 AND project_id = $2",
        )
        .bind(tenant_id)
        .bind(project_id)
        .fetch_one(&mut *tx)
        .await?;

        let rows = sqlx::query_as::<_, TaskRow>(
            r#"SELECT id, project_id, phase_id, parent_task_id, title, description, status_id,
                      -- SPEC-7.477: status_name and status_is_completed are resolved via a tenant-scoped correlated subquery against task_statuses, not a join
                      (SELECT ts.name FROM task_statuses ts
                        WHERE ts.id = tasks.status_id
                          AND ts.tenant_id = tasks.tenant_id) AS status_name,
                      (SELECT ts.is_completed FROM task_statuses ts
                        WHERE ts.id = tasks.status_id
                          AND ts.tenant_id = tasks.tenant_id) AS status_is_completed,
                      priority, assigned_to_id,
                      -- SPEC-7.487: assigned_to_name is a tenant-scoped correlated subquery against users, NULL when unassigned
                      (SELECT NULLIF(TRIM(CONCAT(u.first_name, ' ', u.last_name)), '')
                         FROM users u
                        WHERE u.id = tasks.assigned_to_id
                          AND u.tenant_id = tasks.tenant_id) AS assigned_to_name,
                      estimated_hours,
                      -- SPEC-7.488: actual_hours and logged_hours are computed identically, summing duration_minutes/60.0 for every time entry whose approval_status is not 'rejected' (PMS-944: approval state is not a fact about whether the work happened)
                      -- PMS-944: actual hours are the hours worked. They used
                      -- to count only `approved` time, which reads zero on a
                      -- tenant with timesheets off, because nothing there ever
                      -- reaches that state. `logged_hours` beside it always
                      -- used this predicate; the two now agree, which is the
                      -- point: approval is no longer a fact about the work.
                      COALESCE((SELECT SUM(te.duration_minutes) FROM time_entries te
                                WHERE te.task_id = tasks.id
                                  AND te.approval_status <> 'rejected'), 0)::numeric / 60.0
                          AS actual_hours,
                      COALESCE((SELECT SUM(te.duration_minutes) FROM time_entries te
                                WHERE te.task_id = tasks.id
                                  AND te.approval_status <> 'rejected'), 0)::numeric / 60.0
                          AS logged_hours,
                      start_date,
                      due_date, completed_at, sort_order
               FROM tasks WHERE tenant_id = $1 AND project_id = $2 ORDER BY sort_order, created_at
               LIMIT $3 OFFSET $4"#,
        )
        .bind(tenant_id)
        .bind(project_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&mut *tx)
        .await?;
        // SPEC-7.489: tasks are scoped to tenant_id and project_id, ordered by sort_order then created_at, paginated
        // SPEC-7.490: this query (and its row mapping) is identical to get_task's single-row query below
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_task(
        &self,
        tenant_id: TenantId,
        user_tz: &str,
        project_id: Uuid,
        request: &CreateTaskRequest,
        ctx: &AuditCtx,
    ) -> AppResult<TaskResponse> {
        let id = Uuid::new_v4();
        // SPEC-7.1064: today is the caller's own-timezone date and is computed before the project guard
        // SPEC-7.483: an omitted due_date defaults from today + N business days, where N is the project's default_due_business_days override (0 disables it) if set, else the tenant-wide scheduling default; a supplied due_date is used as-is
        // PMS-345: when no due date is given, fall back to the standard due
        // date (today + N business days; N = 0 disables it). The offset is
        // sourced from the project first - its `default_due_business_days`
        // override (where a value of 0 disables the default for this project)
        // wins; a NULL override inherits the tenant-wide
        // `scheduling/default_due_business_days` setting.
        let due_date = match request.due_date {
            Some(d) => Some(d),
            None => {
                let project_override: Option<i16> = {
                    let mut tx = self.db.begin_with_tenant(tenant_id).await?;
                    sqlx::query_scalar(
                        "SELECT default_due_business_days FROM projects WHERE tenant_id = $1 AND id = $2",
                    )
                    .bind(tenant_id)
                    .bind(project_id)
                    .fetch_optional(&mut *tx)
                    .await?
                    .flatten()
                };
                let n = match project_override {
                    Some(v) => v.max(0) as u32,
                    None => {
                        crate::modules::settings::read_default_due_business_days(
                            &self.db, tenant_id,
                        )
                        .await?
                    }
                };
                // PMS-1027: counted from today where the caller is, not the
                // UTC day.
                (n > 0).then(|| {
                    crate::utils::datetime::add_business_days(
                        mokosh_types::datetime::user_today(chrono::Utc::now(), user_tz),
                        n,
                    )
                })
            }
        };
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        // SPEC-7.484: creating a task shares the ensure_project_open guard from phase creation, so a task cannot be attached to a cancelled or missing project
        self.ensure_project_open(&mut tx, tenant_id, project_id)
            .await?; // &mut tx auto-derefs to &mut PgConnection
        sqlx::query(
            r#"INSERT INTO tasks (id, tenant_id, project_id, phase_id, parent_task_id, title,
                                  description, status_id, priority, assigned_to_id,
                                  estimated_hours, start_date, due_date, sort_order)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)"#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(project_id)
        .bind(request.phase_id)
        .bind(request.parent_task_id)
        .bind(&request.title)
        .bind(&request.description)
        .bind(request.status_id)
        .bind(&request.priority)
        .bind(request.assigned_to_id)
        .bind(request.estimated_hours)
        .bind(request.start_date)
        .bind(due_date)
        .bind(request.sort_order)
        .execute(&mut *tx)
        .await?;

        // SPEC-7.485: the Create audit row is written in the same transaction as the INSERT, before = NULL
        // PMS-318: emit the Create audit row inside the same tx as the INSERT
        // (mirrors update_task above and the PMS-117 create_user pattern) so the
        // task's change-history feed shows the create event, and a rollback
        // drops both the task and its audit row together. `before` is NULL on a
        // create; `after` snapshots the inserted row via to_jsonb.
        let after: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT to_jsonb(t) FROM tasks t WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Create,
            "tasks",
            Some(id),
            None,
            after,
        )
        .await?;
        tx.commit().await?;
        // SPEC-7.486: the create response is the freshly re-read task, so derived fields (status_name, assigned_to_name, actual_hours, logged_hours) are populated, not reconstructed
        self.get_task(tenant_id, id).await
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_task(&self, tenant_id: TenantId, id: Uuid) -> AppResult<TaskResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row = sqlx::query_as::<_, TaskRow>(
            r#"SELECT id, project_id, phase_id, parent_task_id, title, description, status_id,
                      (SELECT ts.name FROM task_statuses ts
                        WHERE ts.id = tasks.status_id
                          AND ts.tenant_id = tasks.tenant_id) AS status_name,
                      (SELECT ts.is_completed FROM task_statuses ts
                        WHERE ts.id = tasks.status_id
                          AND ts.tenant_id = tasks.tenant_id) AS status_is_completed,
                      priority, assigned_to_id,
                      (SELECT NULLIF(TRIM(CONCAT(u.first_name, ' ', u.last_name)), '')
                         FROM users u
                        WHERE u.id = tasks.assigned_to_id
                          AND u.tenant_id = tasks.tenant_id) AS assigned_to_name,
                      estimated_hours,
                      -- PMS-944: actual hours are the hours worked. They used
                      -- to count only `approved` time, which reads zero on a
                      -- tenant with timesheets off, because nothing there ever
                      -- reaches that state. `logged_hours` beside it always
                      -- used this predicate; the two now agree, which is the
                      -- point: approval is no longer a fact about the work.
                      COALESCE((SELECT SUM(te.duration_minutes) FROM time_entries te
                                WHERE te.task_id = tasks.id
                                  AND te.approval_status <> 'rejected'), 0)::numeric / 60.0
                          AS actual_hours,
                      COALESCE((SELECT SUM(te.duration_minutes) FROM time_entries te
                                WHERE te.task_id = tasks.id
                                  AND te.approval_status <> 'rejected'), 0)::numeric / 60.0
                          AS logged_hours,
                      start_date,
                      due_date, completed_at, sort_order
               FROM tasks WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        // SPEC-7.491: a missing or foreign-tenant task id 404s
        .ok_or_else(|| AppError::NotFound("Task".to_string()))?;
        Ok(row.into())
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_task(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        request: &UpdateTaskRequest,
        ctx: &AuditCtx,
    ) -> AppResult<TaskResponse> {
        // SPEC-7.492: before/after snapshots are taken inside one transaction, for the audit diff
        // Mutation + audit row in one transaction (PMS-184, mirrors the
        // tickets path): snapshot the row before and after with `to_jsonb`
        // so the change-history feed can diff which columns moved, and write
        // the audit entry on the same tx so a rollback drops both.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let before: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT to_jsonb(t) FROM tasks t WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;

        // SPEC-7.493: an effective start/due range combining the request's supplied fields with the stored row's existing values is validated before the UPDATE runs, so a partial PUT cannot invert the range against unsupplied stored dates
        // PMS-398: a partial PUT can invert the start/due range against the
        // stored row even when the request alone passes the per-request
        // validator (which only sees the fields the caller supplied). Combine
        // each requested value with the stored one (request wins, else the
        // `before` snapshot) and reject an inverted effective range before the
        // UPDATE runs, mirroring the appointment range guard (PMS-343).
        let stored_date = |key: &str| -> Option<chrono::NaiveDate> {
            before
                .as_ref()
                .and_then(|b| b.get(key))
                .and_then(|v| v.as_str())
                .and_then(|s| chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").ok())
        };
        // SPEC-7.1060: a stored-date inversion answers 400, a request-only inversion 422
        let effective_start = request.start_date.or_else(|| stored_date("start_date"));
        let effective_due = request.due_date.or_else(|| stored_date("due_date"));
        if !task_dates_ok(effective_start, effective_due) {
            return Err(AppError::BadRequest(
                "Due date must be on or after the start date".to_string(),
            ));
        }

        // SPEC-7.494: every field except completed_at uses COALESCE($n, column), so an omitted field in the request leaves the stored value unchanged
        // SPEC-7.495: completed_at is inferred from the supplied status_id's is_completed flag via a CASE, not a second read: moving to a completed status stamps it (if not already stamped), moving to a non-completed status clears it, and an omitted status_id leaves it untouched
        // When the new status is completed, stamp completed_at; clearing
        // back to non-completed clears it. Two reads (status flag check)
        // would be more correct but require a join; we instead infer
        // from the supplied status_id via a CASE in SQL.
        let n = sqlx::query(
            r#"UPDATE tasks SET
                  title = COALESCE($3, title),
                  description = COALESCE($4, description),
                  status_id = COALESCE($5, status_id),
                  phase_id = COALESCE($6, phase_id),
                  priority = COALESCE($7, priority),
                  assigned_to_id = COALESCE($8, assigned_to_id),
                  estimated_hours = COALESCE($9, estimated_hours),
                  start_date = COALESCE($10, start_date),
                  due_date = COALESCE($11, due_date),
                  sort_order = COALESCE($12, sort_order),
                  completed_at = CASE
                      WHEN $5::uuid IS NOT NULL AND EXISTS (
                          -- SPEC-7.496: completed_at only stamps NOW() the first time (COALESCE keeps an existing timestamp), so re-saving an already-completed task does not move its completion time
                          SELECT 1 FROM task_statuses ts
                          WHERE ts.id = $5 AND ts.is_completed = TRUE
                      ) THEN COALESCE(completed_at, NOW())
                      WHEN $5::uuid IS NOT NULL THEN NULL
                      ELSE completed_at
                  END,
                  updated_at = NOW()
              WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(&request.title)
        .bind(&request.description)
        .bind(request.status_id)
        .bind(request.phase_id)
        .bind(&request.priority)
        .bind(request.assigned_to_id)
        .bind(request.estimated_hours)
        .bind(request.start_date)
        .bind(request.due_date)
        .bind(request.sort_order)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        // SPEC-7.497: zero rows affected (missing or foreign-tenant id) 404s
        if n == 0 {
            return Err(AppError::NotFound("Task".to_string()));
        }

        let after: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT to_jsonb(t) FROM tasks t WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;

        // SPEC-7.498: unlike update_project's task-marker-only skip, every task update writes an audit row, with no equivalent description-only exemption
        // PMS-139: audit_write is a cross-module hub still on Uuid (swept last);
        // unwrap the TenantId at the boundary.
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Update,
            "tasks",
            Some(id),
            before,
            after,
        )
        .await?;
        tx.commit().await?;
        // SPEC-7.499: as with create, the update response is the freshly re-read task, not reconstructed from the request
        self.get_task(tenant_id, id).await
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_task(&self, tenant_id: TenantId, id: Uuid) -> AppResult<()> {
        // SPEC-7.500: deletes by tenant_id + id; zero rows affected 404s; no audit row is written on delete
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let n = sqlx::query("DELETE FROM tasks WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("Task".to_string()));
        }
        tx.commit().await?;
        Ok(())
    }

    // ========================================================================
    // PMS-57 task dependencies (with cycle detection)
    // ========================================================================

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn add_task_dependency(
        &self,
        tenant_id: TenantId,
        task_id: Uuid,
        depends_on: Uuid,
        ctx: &AuditCtx,
    ) -> AppResult<()> {
        // SPEC-7.502: a task cannot depend on itself; rejected before any transaction opens
        if task_id == depends_on {
            return Err(AppError::BadRequest(
                "Task cannot depend on itself".to_string(),
            ));
        }
        // SPEC-7.503: a recursive CTE walks the existing depends_on chain from the candidate dependency back toward the task; if task_id is already reachable, adding the edge would close a cycle and is rejected with 409
        // SPEC-7.508: the cycle check and the self-dependency check are the only guards; there is no FK existence pre-check for task_id or depends_on before the INSERT (a foreign-tenant or missing task id surfaces as a database FK error, not an AppError)
        // Reject if adding this edge would create a cycle: there must
        // not already be a path depends_on -> ... -> task_id.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let creates_cycle: bool = sqlx::query_scalar(
            r#"
            -- SPEC-7.504: the recursive chain and its join are scoped to tenant_id = $1 at every step, so a cross-tenant dependency chain can never mask or create a cycle
            WITH RECURSIVE chain AS (
                SELECT depends_on_task_id FROM task_dependencies
                WHERE tenant_id = $1 AND task_id = $2
                UNION
                SELECT td.depends_on_task_id FROM task_dependencies td
                INNER JOIN chain c ON td.task_id = c.depends_on_task_id
                WHERE td.tenant_id = $1
            )
            SELECT EXISTS(SELECT 1 FROM chain WHERE depends_on_task_id = $3)
            "#,
        )
        .bind(tenant_id)
        .bind(depends_on)
        .bind(task_id)
        .fetch_one(&mut *tx)
        .await?;
        if creates_cycle {
            return Err(AppError::Conflict(
                "Refusing: this edge would create a dependency cycle".to_string(),
            ));
        }
        let dep_id = Uuid::new_v4();
        // SPEC-7.505: ON CONFLICT DO NOTHING makes re-adding an existing (task_id, depends_on_task_id) edge a silent no-op rather than a duplicate row or an error
        sqlx::query(
            r#"INSERT INTO task_dependencies (id, tenant_id, task_id, depends_on_task_id)
               VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING"#,
        )
        .bind(dep_id)
        .bind(tenant_id)
        .bind(task_id)
        .bind(depends_on)
        .execute(&mut *tx)
        .await?;
        // SPEC-7.506: on the no-op path above, this re-read finds no row with the freshly generated dep_id (the existing row kept its own id), so `after` is None and a Create audit row is still written with before = after = None
        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM task_dependencies t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(dep_id)
        .fetch_optional(&mut *tx)
        .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Create,
            "task_dependencies",
            Some(dep_id),
            None,
            after,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn remove_task_dependency(
        &self,
        tenant_id: TenantId,
        task_id: Uuid,
        depends_on: Uuid,
    ) -> AppResult<()> {
        // SPEC-7.507: deletes the edge by tenant_id, task_id and depends_on_task_id; this is idempotent (no error, no audit row) whether or not the edge existed
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            "DELETE FROM task_dependencies WHERE tenant_id = $1 AND task_id = $2 AND depends_on_task_id = $3",
        )
        .bind(tenant_id).bind(task_id).bind(depends_on)
        .execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }
}

#[derive(sqlx::FromRow)]
struct ProjectRow {
    id: Uuid,
    name: String,
    description: Option<String>,
    project_number: Option<String>,
    company_id: Option<Uuid>,
    company_name: Option<String>,
    contract_id: Option<Uuid>,
    project_type: String,
    project_type_id: Option<Uuid>,
    status: String,
    project_manager_id: Option<Uuid>,
    project_manager_name: Option<String>,
    start_date: Option<chrono::NaiveDate>,
    target_end_date: Option<chrono::NaiveDate>,
    actual_end_date: Option<chrono::NaiveDate>,
    budget_hours: Option<Decimal>,
    budget_amount: Option<Decimal>,
    actual_hours: Decimal,
    actual_amount: Decimal,
    billing_method: Option<String>,
    hourly_rate: Option<Decimal>,
    is_billable: Option<bool>,
    default_due_business_days: Option<i16>,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
}

// SPEC-7.453: billing_method defaults to "time_and_materials" and is_billable defaults to true when the stored column is NULL (predating a NOT NULL default)
impl From<ProjectRow> for ProjectResponse {
    fn from(r: ProjectRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            description: r.description,
            project_number: r.project_number,
            company_id: r.company_id,
            company_name: r.company_name,
            contract_id: r.contract_id,
            project_type: r.project_type,
            project_type_id: r.project_type_id,
            status: r.status,
            project_manager_id: r.project_manager_id,
            project_manager_name: r.project_manager_name,
            start_date: r.start_date,
            target_end_date: r.target_end_date,
            actual_end_date: r.actual_end_date,
            budget_hours: r.budget_hours,
            budget_amount: r.budget_amount,
            actual_hours: r.actual_hours,
            actual_amount: r.actual_amount,
            billing_method: r
                .billing_method
                .unwrap_or_else(|| "time_and_materials".into()),
            hourly_rate: r.hourly_rate,
            is_billable: r.is_billable.unwrap_or(true),
            default_due_business_days: r.default_due_business_days,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct PhaseRow {
    id: Uuid,
    project_id: Uuid,
    name: String,
    description: Option<String>,
    sort_order: Option<i32>,
    start_date: Option<chrono::NaiveDate>,
    end_date: Option<chrono::NaiveDate>,
    status: Option<String>,
}

impl From<PhaseRow> for ProjectPhaseResponse {
    fn from(r: PhaseRow) -> Self {
        Self {
            id: r.id,
            project_id: r.project_id,
            name: r.name,
            description: r.description,
            sort_order: r.sort_order.unwrap_or(0),
            start_date: r.start_date,
            end_date: r.end_date,
            status: r.status.unwrap_or_else(|| "not_started".into()),
        }
    }
}

#[derive(sqlx::FromRow)]
struct TaskStatusRow {
    id: Uuid,
    name: String,
    color: String,
    is_completed: Option<bool>,
    sort_order: Option<i32>,
}

impl From<TaskStatusRow> for TaskStatusResponse {
    fn from(r: TaskStatusRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            color: r.color,
            is_completed: r.is_completed.unwrap_or(false),
            sort_order: r.sort_order.unwrap_or(0),
        }
    }
}

#[derive(sqlx::FromRow)]
struct ProjectTypeRow {
    id: Uuid,
    name: String,
    is_default: bool,
    is_active: bool,
    sort_order: i32,
    is_system: bool,
}

impl From<ProjectTypeRow> for ProjectTypeResponse {
    fn from(r: ProjectTypeRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            is_default: r.is_default,
            is_active: r.is_active,
            sort_order: r.sort_order,
            is_system: r.is_system,
        }
    }
}

#[derive(sqlx::FromRow)]
struct TaskRow {
    id: Uuid,
    project_id: Option<Uuid>,
    phase_id: Option<Uuid>,
    parent_task_id: Option<Uuid>,
    title: String,
    description: Option<String>,
    status_id: Uuid,
    status_name: Option<String>,
    status_is_completed: Option<bool>,
    priority: Option<String>,
    assigned_to_id: Option<Uuid>,
    assigned_to_name: Option<String>,
    estimated_hours: Option<Decimal>,
    actual_hours: Option<Decimal>,
    logged_hours: Option<Decimal>,
    start_date: Option<chrono::NaiveDate>,
    due_date: Option<chrono::NaiveDate>,
    completed_at: Option<chrono::DateTime<Utc>>,
    sort_order: Option<i32>,
}

// SPEC-7.501: priority defaults to "medium" and sort_order defaults to 0 when the stored column is NULL
impl From<TaskRow> for TaskResponse {
    fn from(r: TaskRow) -> Self {
        Self {
            id: r.id,
            project_id: r.project_id,
            phase_id: r.phase_id,
            parent_task_id: r.parent_task_id,
            title: r.title,
            description: r.description,
            status_id: r.status_id,
            status_name: r.status_name,
            status_is_completed: r.status_is_completed,
            priority: r.priority.unwrap_or_else(|| "medium".into()),
            assigned_to_id: r.assigned_to_id,
            assigned_to_name: r.assigned_to_name,
            estimated_hours: r.estimated_hours,
            actual_hours: r.actual_hours,
            logged_hours: r.logged_hours,
            start_date: r.start_date,
            due_date: r.due_date,
            completed_at: r.completed_at,
            sort_order: r.sort_order.unwrap_or(0),
        }
    }
}
