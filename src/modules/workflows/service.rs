//! PMS-448: workflow-rule CRUD service.

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use super::models::{
    CreateWorkflowRuleRequest, UpdateWorkflowRuleRequest, WorkflowRuleResponse,
    WorkflowRuleRunResponse, RECOGNISED_TRIGGERS,
};
use crate::db::Database;
use crate::utils::error::{AppError, AppResult};

#[derive(Debug, FromRow)]
struct RuleRow {
    id: Uuid,
    trigger_event: String,
    name: String,
    description: Option<String>,
    conditions: serde_json::Value,
    actions: serde_json::Value,
    priority: i32,
    is_active: bool,
    created_by_id: Uuid,
    created_by_name: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<RuleRow> for WorkflowRuleResponse {
    fn from(r: RuleRow) -> Self {
        Self {
            id: r.id,
            trigger_event: r.trigger_event,
            name: r.name,
            description: r.description,
            conditions: r.conditions,
            actions: r.actions,
            priority: r.priority,
            is_active: r.is_active,
            created_by_id: r.created_by_id,
            created_by_name: r.created_by_name,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(Debug, FromRow)]
struct RunRow {
    id: Uuid,
    rule_id: Uuid,
    rule_name: Option<String>,
    entity_type: String,
    entity_id: Uuid,
    applied_actions: serde_json::Value,
    error: Option<String>,
    ran_at: DateTime<Utc>,
}

impl From<RunRow> for WorkflowRuleRunResponse {
    fn from(r: RunRow) -> Self {
        Self {
            id: r.id,
            rule_id: r.rule_id,
            rule_name: r.rule_name,
            entity_type: r.entity_type,
            entity_id: r.entity_id,
            applied_actions: r.applied_actions,
            error: r.error,
            ran_at: r.ran_at,
        }
    }
}

const RULE_SELECT: &str = "
    r.id, r.trigger_event, r.name, r.description, r.conditions, r.actions,
    r.priority, r.is_active, r.created_by_id,
    NULLIF(TRIM(CONCAT(u.first_name, ' ', u.last_name)), '') AS created_by_name,
    r.created_at, r.updated_at
";

/// PMS-683: every query runs inside `Database::begin_with_tenant`, which sets
/// the `app.current_tenant` GUC transaction-locally, so `workflow_rules` and
/// `workflow_rule_runs` are safe under the fail-closed `tenant_isolation` RLS
/// policy (migration 095). The only other path to these tables is the
/// WorkflowExecutor, which reads `workflow_rules` and writes `workflow_rule_runs`
/// inside the ticket service's own `begin_with_tenant` transaction, so it is
/// GUC-safe too.
#[derive(Clone)]
pub struct WorkflowsService {
    db: Database,
}

impl WorkflowsService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    pub async fn list(&self, tenant_id: Uuid) -> AppResult<Vec<WorkflowRuleResponse>> {
        let sql = format!(
            "SELECT {RULE_SELECT} \
             FROM workflow_rules r \
             LEFT JOIN users u ON u.id = r.created_by_id \
             WHERE r.tenant_id = $1 \
             ORDER BY r.priority ASC, r.created_at ASC",
        );
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows = sqlx::query_as::<_, RuleRow>(&sql)
            .bind(tenant_id)
            .fetch_all(&mut *tx)
            .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn get(&self, tenant_id: Uuid, id: Uuid) -> AppResult<WorkflowRuleResponse> {
        let sql = format!(
            "SELECT {RULE_SELECT} \
             FROM workflow_rules r \
             LEFT JOIN users u ON u.id = r.created_by_id \
             WHERE r.tenant_id = $1 AND r.id = $2",
        );
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row = sqlx::query_as::<_, RuleRow>(&sql)
            .bind(tenant_id)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(AppError::NotFound("Workflow rule".into()))?;
        Ok(row.into())
    }

    pub async fn create(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        req: CreateWorkflowRuleRequest,
    ) -> AppResult<WorkflowRuleResponse> {
        // Reject unrecognised triggers so an operator does not
        // silently create a rule that never fires. The Phase 2
        // allow-list covers `ticket.created`, `ticket.status_changed`,
        // and `ticket.priority_changed`.
        if !RECOGNISED_TRIGGERS.contains(&req.trigger_event.as_str()) {
            return Err(AppError::BadRequest(format!(
                "Unsupported trigger_event='{}'. Recognised: {}",
                req.trigger_event,
                RECOGNISED_TRIGGERS.join(", "),
            )));
        }
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO workflow_rules \
                 (tenant_id, trigger_event, name, description, conditions, actions, \
                  priority, is_active, created_by_id) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             RETURNING id",
        )
        .bind(tenant_id)
        .bind(&req.trigger_event)
        .bind(&req.name)
        .bind(&req.description)
        .bind(&req.conditions)
        .bind(&req.actions)
        .bind(req.priority)
        .bind(req.is_active)
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        self.get(tenant_id, id).await
    }

    pub async fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        req: UpdateWorkflowRuleRequest,
    ) -> AppResult<WorkflowRuleResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let existing: Option<(Uuid,)> =
            sqlx::query_as("SELECT id FROM workflow_rules WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;
        if existing.is_none() {
            return Err(AppError::NotFound("Workflow rule".into()));
        }
        sqlx::query(
            "UPDATE workflow_rules SET \
                 name = COALESCE($3, name), \
                 description = COALESCE($4, description), \
                 conditions = COALESCE($5, conditions), \
                 actions = COALESCE($6, actions), \
                 priority = COALESCE($7, priority), \
                 is_active = COALESCE($8, is_active), \
                 updated_at = NOW() \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(req.name)
        .bind(req.description)
        .bind(req.conditions)
        .bind(req.actions)
        .bind(req.priority)
        .bind(req.is_active)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        self.get(tenant_id, id).await
    }

    pub async fn delete(&self, tenant_id: Uuid, id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows = sqlx::query("DELETE FROM workflow_rules WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        tx.commit().await?;
        if rows == 0 {
            return Err(AppError::NotFound("Workflow rule".into()));
        }
        Ok(())
    }

    /// List the runs for a given entity (typically a ticket id),
    /// most-recent first. Lets the SPA render "what auto-routed this
    /// ticket" on the ticket detail page.
    pub async fn list_runs_for_entity(
        &self,
        tenant_id: Uuid,
        entity_type: &str,
        entity_id: Uuid,
    ) -> AppResult<Vec<WorkflowRuleRunResponse>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows = sqlx::query_as::<_, RunRow>(
            "SELECT run.id, run.rule_id, r.name AS rule_name, \
                    run.entity_type, run.entity_id, run.applied_actions, run.error, run.ran_at \
             FROM workflow_rule_runs run \
             LEFT JOIN workflow_rules r ON r.id = run.rule_id \
             WHERE run.tenant_id = $1 AND run.entity_type = $2 AND run.entity_id = $3 \
             ORDER BY run.ran_at DESC",
        )
        .bind(tenant_id)
        .bind(entity_type)
        .bind(entity_id)
        .fetch_all(&mut *tx)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }
}
