//! Projects service.

use chrono::Utc;
use rust_decimal::Decimal;
use uuid::Uuid;

use crate::db::Database;
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

    pub async fn list_projects(
        &self,
        tenant_id: Uuid,
        filter: &ProjectFilter,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<ProjectResponse>, u64)> {
        let offset = pagination.offset() as i64;
        let limit = pagination.limit() as i64;
        let mut conditions = vec!["tenant_id = $1".to_string()];
        let mut idx = 4;
        if filter.company_id.is_some() {
            conditions.push(format!("company_id = ${idx}"));
            idx += 1;
        }
        if filter.status.is_some() {
            conditions.push(format!("status = ${idx}"));
            idx += 1;
        }
        if filter.project_manager_id.is_some() {
            conditions.push(format!("project_manager_id = ${idx}"));
        }
        let where_clause = conditions.join(" AND ");
        let order_by = pagination.order_by("created_at DESC", &["name", "start_date", "created_at"]);
        let query = format!(
            r#"
            SELECT id, name, description, project_number, company_id, contract_id,
                   project_type, status, project_manager_id, start_date,
                   target_end_date, actual_end_date, budget_hours, budget_amount,
                   billing_method, hourly_rate, is_billable, created_at, updated_at
            FROM projects WHERE {where_clause}
            ORDER BY {order_by} LIMIT $2 OFFSET $3
            "#
        );
        let count_query = format!("SELECT COUNT(*) FROM projects WHERE {where_clause}");
        let mut q = sqlx::query_as::<_, ProjectRow>(&query)
            .bind(tenant_id).bind(limit).bind(offset);
        let mut cq = sqlx::query_scalar::<_, i64>(&count_query).bind(tenant_id);
        if let Some(v) = filter.company_id { q = q.bind(v); cq = cq.bind(v); }
        if let Some(v) = &filter.status { q = q.bind(v); cq = cq.bind(v); }
        if let Some(v) = filter.project_manager_id { q = q.bind(v); cq = cq.bind(v); }
        let rows = q.fetch_all(self.db.pool()).await?;
        let total = cq.fetch_one(self.db.pool()).await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    pub async fn create_project(
        &self, tenant_id: Uuid, request: &CreateProjectRequest,
    ) -> AppResult<ProjectResponse> {
        let id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO projects (
                id, tenant_id, name, description, project_number, company_id,
                contract_id, project_type, status, project_manager_id, start_date,
                target_end_date, budget_hours, budget_amount, billing_method,
                hourly_rate, is_billable
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
            "#,
        )
        .bind(id).bind(tenant_id)
        .bind(&request.name).bind(&request.description).bind(&request.project_number)
        .bind(request.company_id).bind(request.contract_id)
        .bind(&request.project_type).bind(&request.status)
        .bind(request.project_manager_id)
        .bind(request.start_date).bind(request.target_end_date)
        .bind(request.budget_hours).bind(request.budget_amount)
        .bind(&request.billing_method).bind(request.hourly_rate).bind(request.is_billable)
        .execute(self.db.pool()).await?;
        self.get_project(tenant_id, id).await
    }

    pub async fn get_project(&self, tenant_id: Uuid, id: Uuid) -> AppResult<ProjectResponse> {
        let row = sqlx::query_as::<_, ProjectRow>(
            r#"
            SELECT id, name, description, project_number, company_id, contract_id,
                   project_type, status, project_manager_id, start_date,
                   target_end_date, actual_end_date, budget_hours, budget_amount,
                   billing_method, hourly_rate, is_billable, created_at, updated_at
            FROM projects WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id).bind(id)
        .fetch_optional(self.db.pool()).await?
        .ok_or_else(|| AppError::NotFound("Project".to_string()))?;
        Ok(row.into())
    }

    pub async fn update_project(
        &self, tenant_id: Uuid, id: Uuid, request: &UpdateProjectRequest,
    ) -> AppResult<ProjectResponse> {
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
                updated_at = NOW()
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id).bind(id)
        .bind(&request.name).bind(&request.description).bind(&request.status)
        .bind(request.project_manager_id)
        .bind(request.start_date).bind(request.target_end_date).bind(request.actual_end_date)
        .bind(request.budget_hours).bind(request.budget_amount)
        .bind(&request.billing_method).bind(request.hourly_rate).bind(request.is_billable)
        .execute(self.db.pool()).await?.rows_affected();
        if affected == 0 { return Err(AppError::NotFound("Project".to_string())); }
        self.get_project(tenant_id, id).await
    }

    pub async fn delete_project(&self, tenant_id: Uuid, id: Uuid) -> AppResult<()> {
        let n = sqlx::query("DELETE FROM projects WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id).bind(id).execute(self.db.pool()).await?.rows_affected();
        if n == 0 { return Err(AppError::NotFound("Project".to_string())); }
        Ok(())
    }

    // ========================================================================
    // PMS-54 project phases CRUD
    // ========================================================================

    pub async fn list_project_phases(&self, tenant_id: Uuid, project_id: Uuid) -> AppResult<Vec<ProjectPhaseResponse>> {
        let rows = sqlx::query_as::<_, PhaseRow>(
            r#"SELECT id, project_id, name, description, sort_order, start_date, end_date, status
               FROM project_phases WHERE tenant_id = $1 AND project_id = $2 ORDER BY sort_order"#,
        ).bind(tenant_id).bind(project_id).fetch_all(self.db.pool()).await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn create_project_phase(
        &self, tenant_id: Uuid, project_id: Uuid, request: &UpsertProjectPhaseRequest,
    ) -> AppResult<ProjectPhaseResponse> {
        let id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO project_phases (id, tenant_id, project_id, name, description, sort_order, start_date, end_date, status)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
        )
        .bind(id).bind(tenant_id).bind(project_id)
        .bind(&request.name).bind(&request.description).bind(request.sort_order)
        .bind(request.start_date).bind(request.end_date).bind(&request.status)
        .execute(self.db.pool()).await?;
        Ok(ProjectPhaseResponse {
            id, project_id,
            name: request.name.clone(), description: request.description.clone(),
            sort_order: request.sort_order,
            start_date: request.start_date, end_date: request.end_date,
            status: request.status.clone(),
        })
    }

    pub async fn update_project_phase(
        &self, tenant_id: Uuid, id: Uuid, request: &UpsertProjectPhaseRequest,
    ) -> AppResult<ProjectPhaseResponse> {
        let project_id: Option<Uuid> = sqlx::query_scalar(
            r#"UPDATE project_phases SET name = $3, description = $4, sort_order = $5,
                   start_date = $6, end_date = $7, status = $8, updated_at = NOW()
               WHERE tenant_id = $1 AND id = $2 RETURNING project_id"#,
        )
        .bind(tenant_id).bind(id)
        .bind(&request.name).bind(&request.description).bind(request.sort_order)
        .bind(request.start_date).bind(request.end_date).bind(&request.status)
        .fetch_optional(self.db.pool()).await?;
        let Some(project_id) = project_id else { return Err(AppError::NotFound("ProjectPhase".to_string())); };
        Ok(ProjectPhaseResponse {
            id, project_id,
            name: request.name.clone(), description: request.description.clone(),
            sort_order: request.sort_order,
            start_date: request.start_date, end_date: request.end_date,
            status: request.status.clone(),
        })
    }

    pub async fn delete_project_phase(&self, tenant_id: Uuid, id: Uuid) -> AppResult<()> {
        let n = sqlx::query("DELETE FROM project_phases WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id).bind(id).execute(self.db.pool()).await?.rows_affected();
        if n == 0 { return Err(AppError::NotFound("ProjectPhase".to_string())); }
        Ok(())
    }

    // ========================================================================
    // PMS-55 task statuses
    // ========================================================================

    pub async fn list_task_statuses(&self, tenant_id: Uuid) -> AppResult<Vec<TaskStatusResponse>> {
        let rows = sqlx::query_as::<_, TaskStatusRow>(
            r#"SELECT id, name, color, is_completed, sort_order
               FROM task_statuses WHERE tenant_id = $1 ORDER BY sort_order, name"#,
        ).bind(tenant_id).fetch_all(self.db.pool()).await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn create_task_status(
        &self, tenant_id: Uuid, request: &UpsertTaskStatusRequest,
    ) -> AppResult<TaskStatusResponse> {
        let id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO task_statuses (id, tenant_id, name, color, is_completed, sort_order)
               VALUES ($1, $2, $3, $4, $5, $6)"#,
        )
        .bind(id).bind(tenant_id)
        .bind(&request.name).bind(&request.color).bind(request.is_completed).bind(request.sort_order)
        .execute(self.db.pool()).await?;
        Ok(TaskStatusResponse {
            id, name: request.name.clone(), color: request.color.clone(),
            is_completed: request.is_completed, sort_order: request.sort_order,
        })
    }

    pub async fn update_task_status(
        &self, tenant_id: Uuid, id: Uuid, request: &UpsertTaskStatusRequest,
    ) -> AppResult<TaskStatusResponse> {
        let n = sqlx::query(
            r#"UPDATE task_statuses SET name = $3, color = $4, is_completed = $5,
                   sort_order = $6, updated_at = NOW()
               WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id).bind(id)
        .bind(&request.name).bind(&request.color).bind(request.is_completed).bind(request.sort_order)
        .execute(self.db.pool()).await?.rows_affected();
        if n == 0 { return Err(AppError::NotFound("TaskStatus".to_string())); }
        Ok(TaskStatusResponse {
            id, name: request.name.clone(), color: request.color.clone(),
            is_completed: request.is_completed, sort_order: request.sort_order,
        })
    }

    pub async fn delete_task_status(&self, tenant_id: Uuid, id: Uuid) -> AppResult<()> {
        let n = sqlx::query("DELETE FROM task_statuses WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id).bind(id).execute(self.db.pool()).await?.rows_affected();
        if n == 0 { return Err(AppError::NotFound("TaskStatus".to_string())); }
        Ok(())
    }

    // ========================================================================
    // PMS-56 tasks CRUD
    // ========================================================================

    pub async fn list_project_tasks(&self, tenant_id: Uuid, project_id: Uuid) -> AppResult<Vec<TaskResponse>> {
        let rows = sqlx::query_as::<_, TaskRow>(
            r#"SELECT id, project_id, phase_id, parent_task_id, title, description, status_id,
                      priority, assigned_to_id, estimated_hours, actual_hours, start_date,
                      due_date, completed_at, sort_order
               FROM tasks WHERE tenant_id = $1 AND project_id = $2 ORDER BY sort_order, created_at"#,
        ).bind(tenant_id).bind(project_id).fetch_all(self.db.pool()).await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn create_task(
        &self, tenant_id: Uuid, project_id: Uuid, request: &CreateTaskRequest,
    ) -> AppResult<TaskResponse> {
        let id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO tasks (id, tenant_id, project_id, phase_id, parent_task_id, title,
                                  description, status_id, priority, assigned_to_id,
                                  estimated_hours, start_date, due_date, sort_order)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)"#,
        )
        .bind(id).bind(tenant_id).bind(project_id)
        .bind(request.phase_id).bind(request.parent_task_id)
        .bind(&request.title).bind(&request.description).bind(request.status_id)
        .bind(&request.priority).bind(request.assigned_to_id)
        .bind(request.estimated_hours).bind(request.start_date).bind(request.due_date)
        .bind(request.sort_order)
        .execute(self.db.pool()).await?;
        self.get_task(tenant_id, id).await
    }

    pub async fn get_task(&self, tenant_id: Uuid, id: Uuid) -> AppResult<TaskResponse> {
        let row = sqlx::query_as::<_, TaskRow>(
            r#"SELECT id, project_id, phase_id, parent_task_id, title, description, status_id,
                      priority, assigned_to_id, estimated_hours, actual_hours, start_date,
                      due_date, completed_at, sort_order
               FROM tasks WHERE tenant_id = $1 AND id = $2"#,
        ).bind(tenant_id).bind(id)
        .fetch_optional(self.db.pool()).await?
        .ok_or_else(|| AppError::NotFound("Task".to_string()))?;
        Ok(row.into())
    }

    pub async fn update_task(
        &self, tenant_id: Uuid, id: Uuid, request: &UpdateTaskRequest,
    ) -> AppResult<TaskResponse> {
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
                  actual_hours = COALESCE($10, actual_hours),
                  start_date = COALESCE($11, start_date),
                  due_date = COALESCE($12, due_date),
                  sort_order = COALESCE($13, sort_order),
                  completed_at = CASE
                      WHEN $5::uuid IS NOT NULL AND EXISTS (
                          SELECT 1 FROM task_statuses ts
                          WHERE ts.id = $5 AND ts.is_completed = TRUE
                      ) THEN COALESCE(completed_at, NOW())
                      WHEN $5::uuid IS NOT NULL THEN NULL
                      ELSE completed_at
                  END,
                  updated_at = NOW()
              WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id).bind(id)
        .bind(&request.title).bind(&request.description).bind(request.status_id)
        .bind(request.phase_id).bind(&request.priority).bind(request.assigned_to_id)
        .bind(request.estimated_hours).bind(request.actual_hours)
        .bind(request.start_date).bind(request.due_date).bind(request.sort_order)
        .execute(self.db.pool()).await?.rows_affected();
        if n == 0 { return Err(AppError::NotFound("Task".to_string())); }
        self.get_task(tenant_id, id).await
    }

    pub async fn delete_task(&self, tenant_id: Uuid, id: Uuid) -> AppResult<()> {
        let n = sqlx::query("DELETE FROM tasks WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id).bind(id).execute(self.db.pool()).await?.rows_affected();
        if n == 0 { return Err(AppError::NotFound("Task".to_string())); }
        Ok(())
    }

    // ========================================================================
    // PMS-57 task dependencies (with cycle detection)
    // ========================================================================

    pub async fn add_task_dependency(
        &self, tenant_id: Uuid, task_id: Uuid, depends_on: Uuid,
    ) -> AppResult<()> {
        if task_id == depends_on {
            return Err(AppError::BadRequest("Task cannot depend on itself".to_string()));
        }
        // Reject if adding this edge would create a cycle: there must
        // not already be a path depends_on -> ... -> task_id.
        let creates_cycle: bool = sqlx::query_scalar(
            r#"
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
        .bind(tenant_id).bind(depends_on).bind(task_id)
        .fetch_one(self.db.pool()).await?;
        if creates_cycle {
            return Err(AppError::Conflict(
                "Refusing: this edge would create a dependency cycle".to_string(),
            ));
        }
        sqlx::query(
            r#"INSERT INTO task_dependencies (id, tenant_id, task_id, depends_on_task_id)
               VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING"#,
        )
        .bind(Uuid::new_v4()).bind(tenant_id).bind(task_id).bind(depends_on)
        .execute(self.db.pool()).await?;
        Ok(())
    }

    pub async fn remove_task_dependency(
        &self, tenant_id: Uuid, task_id: Uuid, depends_on: Uuid,
    ) -> AppResult<()> {
        sqlx::query(
            "DELETE FROM task_dependencies WHERE tenant_id = $1 AND task_id = $2 AND depends_on_task_id = $3",
        )
        .bind(tenant_id).bind(task_id).bind(depends_on)
        .execute(self.db.pool()).await?;
        Ok(())
    }
}

#[derive(sqlx::FromRow)]
struct ProjectRow {
    id: Uuid, name: String, description: Option<String>, project_number: Option<String>,
    company_id: Option<Uuid>, contract_id: Option<Uuid>,
    project_type: String, status: String,
    project_manager_id: Option<Uuid>,
    start_date: Option<chrono::NaiveDate>, target_end_date: Option<chrono::NaiveDate>,
    actual_end_date: Option<chrono::NaiveDate>,
    budget_hours: Option<Decimal>, budget_amount: Option<Decimal>,
    billing_method: Option<String>, hourly_rate: Option<Decimal>,
    is_billable: Option<bool>,
    created_at: chrono::DateTime<Utc>, updated_at: chrono::DateTime<Utc>,
}

impl From<ProjectRow> for ProjectResponse {
    fn from(r: ProjectRow) -> Self {
        Self {
            id: r.id, name: r.name, description: r.description, project_number: r.project_number,
            company_id: r.company_id, contract_id: r.contract_id,
            project_type: r.project_type, status: r.status,
            project_manager_id: r.project_manager_id,
            start_date: r.start_date, target_end_date: r.target_end_date, actual_end_date: r.actual_end_date,
            budget_hours: r.budget_hours, budget_amount: r.budget_amount,
            billing_method: r.billing_method.unwrap_or_else(|| "time_and_materials".into()),
            hourly_rate: r.hourly_rate, is_billable: r.is_billable.unwrap_or(true),
            created_at: r.created_at, updated_at: r.updated_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct PhaseRow {
    id: Uuid, project_id: Uuid, name: String, description: Option<String>,
    sort_order: Option<i32>, start_date: Option<chrono::NaiveDate>, end_date: Option<chrono::NaiveDate>,
    status: Option<String>,
}

impl From<PhaseRow> for ProjectPhaseResponse {
    fn from(r: PhaseRow) -> Self {
        Self {
            id: r.id, project_id: r.project_id, name: r.name, description: r.description,
            sort_order: r.sort_order.unwrap_or(0),
            start_date: r.start_date, end_date: r.end_date,
            status: r.status.unwrap_or_else(|| "not_started".into()),
        }
    }
}

#[derive(sqlx::FromRow)]
struct TaskStatusRow {
    id: Uuid, name: String, color: String,
    is_completed: Option<bool>, sort_order: Option<i32>,
}

impl From<TaskStatusRow> for TaskStatusResponse {
    fn from(r: TaskStatusRow) -> Self {
        Self {
            id: r.id, name: r.name, color: r.color,
            is_completed: r.is_completed.unwrap_or(false),
            sort_order: r.sort_order.unwrap_or(0),
        }
    }
}

#[derive(sqlx::FromRow)]
struct TaskRow {
    id: Uuid, project_id: Option<Uuid>, phase_id: Option<Uuid>, parent_task_id: Option<Uuid>,
    title: String, description: Option<String>, status_id: Uuid,
    priority: Option<String>, assigned_to_id: Option<Uuid>,
    estimated_hours: Option<Decimal>, actual_hours: Option<Decimal>,
    start_date: Option<chrono::NaiveDate>, due_date: Option<chrono::NaiveDate>,
    completed_at: Option<chrono::DateTime<Utc>>, sort_order: Option<i32>,
}

impl From<TaskRow> for TaskResponse {
    fn from(r: TaskRow) -> Self {
        Self {
            id: r.id, project_id: r.project_id, phase_id: r.phase_id,
            parent_task_id: r.parent_task_id,
            title: r.title, description: r.description, status_id: r.status_id,
            priority: r.priority.unwrap_or_else(|| "medium".into()),
            assigned_to_id: r.assigned_to_id,
            estimated_hours: r.estimated_hours, actual_hours: r.actual_hours,
            start_date: r.start_date, due_date: r.due_date,
            completed_at: r.completed_at, sort_order: r.sort_order.unwrap_or(0),
        }
    }
}
