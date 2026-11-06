//! KB article execution service.
//!
//! Writes the `kb_article_executions` + `kb_article_execution_steps`
//! rows and serves the reads behind the `/tickets/{id}/kb-executions`
//! and `/kb-executions/*` routes. The render path is reused from the
//! Phase 1a `KbService::render_article` (templated-KB server half),
//! so a template change there reaches here without a second call-site.

use chrono::{DateTime, Utc};
use std::collections::BTreeMap;
use std::sync::Arc;
use uuid::Uuid;

use crate::db::Database;
use crate::modules::auth::TenantId;
use crate::utils::error::{AppError, AppResult};

use super::execution_steps::parse_steps;
use super::models::{KbExecutionResponse, KbExecutionStepResponse, KbExecutionSummary};
use super::service::KbService;

use rows::{ExecutionRow, StepRow, SummaryRow};

#[derive(Clone)]
pub struct KbExecutionService {
    db: Database,
    kb: Arc<KbService>,
}

impl KbExecutionService {
    pub fn new(db: Database, kb: Arc<KbService>) -> Self {
        Self { db, kb }
    }

    /// Resolve the ticket for a tenant, failing with 404 when the
    /// ticket does not exist under this tenant. The RLS policy on
    /// `tickets` already fails-closed on a mismatched tenant, so this
    /// is a bare existence check inside the tenant transaction.
    async fn assert_ticket_exists(
        &self,
        tx: &mut sqlx::PgConnection,
        tenant_id: TenantId,
        ticket_id: Uuid,
    ) -> AppResult<()> {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM tickets WHERE tenant_id = $1 AND id = $2)",
        )
        .bind(tenant_id)
        .bind(ticket_id)
        .fetch_one(&mut *tx)
        .await?;
        if !exists {
            return Err(AppError::NotFound("Ticket".to_string()));
        }
        Ok(())
    }

    /// Create a new execution: renders the article through the Phase
    /// 1a path, parses the rendered Markdown for GFM task-list items,
    /// and writes the execution + its step rows in one transaction.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, ticket_id = %ticket_id, article_id = %article_id, user_id = %user_id))]
    pub async fn create_execution(
        &self,
        tenant_id: TenantId,
        ticket_id: Uuid,
        article_id: Uuid,
        user_id: Uuid,
        values: &BTreeMap<String, String>,
    ) -> AppResult<KbExecutionResponse> {
        // Render first; a 404 for the article, a 422 for a rejected
        // values map, and a 400 for a template parse error all surface
        // through the Phase 1a path.
        let rendered = self
            .kb
            .render_article(tenant_id, article_id, values)
            .await?;

        let steps = parse_steps(&rendered.content);
        let now = Utc::now();
        let values_json = serde_json::to_value(values)
            .map_err(|e| AppError::Internal(format!("serialize execution values: {e}")))?;

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        self.assert_ticket_exists(&mut tx, tenant_id, ticket_id)
            .await?;

        // Snapshot the article's current version id. NULL for the
        // historic case where no `kb_article_versions` row exists; the
        // normal path seeds version 1 on create so this should be
        // reachable only for a row written before migration 200 which
        // never ran the version seed. Phase 3 adds schema-level
        // versioning if needed.
        let article_version_id: Option<Uuid> = sqlx::query_scalar(
            r#"SELECT v.id FROM kb_article_versions v
               WHERE v.article_id = $1
               ORDER BY v.version_number DESC
               LIMIT 1"#,
        )
        .bind(article_id)
        .fetch_optional(&mut *tx)
        .await?;

        let execution_id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO kb_article_executions
               (id, tenant_id, ticket_id, article_id, article_version_id,
                variable_values, started_at, started_by_user_id)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"#,
        )
        .bind(execution_id)
        .bind(tenant_id)
        .bind(ticket_id)
        .bind(article_id)
        .bind(article_version_id)
        .bind(&values_json)
        .bind(now)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

        for step in &steps {
            let (checked_at, checked_by) = if step.initially_checked {
                (Some(now), Some(user_id))
            } else {
                (None, None)
            };
            sqlx::query(
                r#"INSERT INTO kb_article_execution_steps
                   (tenant_id, execution_id, step_index, step_text,
                    checked_at, checked_by_user_id)
                   VALUES ($1, $2, $3, $4, $5, $6)"#,
            )
            .bind(tenant_id)
            .bind(execution_id)
            .bind(step.index)
            .bind(&step.text)
            .bind(checked_at)
            .bind(checked_by)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;

        self.get_execution(tenant_id, execution_id).await
    }

    /// Full execution + step list by id, scoped to the caller's tenant.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, id = %id))]
    pub async fn get_execution(
        &self,
        tenant_id: TenantId,
        id: Uuid,
    ) -> AppResult<KbExecutionResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row = sqlx::query_as::<_, ExecutionRow>(
            r#"SELECT e.id, e.ticket_id, e.article_id, e.article_version_id,
                      e.variable_values, e.started_at, e.started_by_user_id,
                      a.title AS article_name,
                      NULLIF(TRIM(COALESCE(u.first_name, '') || ' ' || COALESCE(u.last_name, '')), '')
                          AS started_by_name
               FROM kb_article_executions e
               JOIN kb_articles a ON a.id = e.article_id
               LEFT JOIN users u ON u.id = e.started_by_user_id
               WHERE e.tenant_id = $1 AND e.id = $2"#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::NotFound("KB article execution".to_string()))?;

        let steps = sqlx::query_as::<_, StepRow>(
            r#"SELECT s.id, s.execution_id, s.step_index, s.step_text,
                      s.checked_at, s.checked_by_user_id,
                      NULLIF(TRIM(COALESCE(u.first_name, '') || ' ' || COALESCE(u.last_name, '')), '')
                          AS checked_by_name
               FROM kb_article_execution_steps s
               LEFT JOIN users u ON u.id = s.checked_by_user_id
               WHERE s.execution_id = $1
               ORDER BY s.step_index ASC"#,
        )
        .bind(id)
        .fetch_all(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(row.into_response(steps))
    }

    /// List executions on a ticket, newest first, with the rolled-up
    /// step counts for the ticket panel's progress bar.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, ticket_id = %ticket_id))]
    pub async fn list_for_ticket(
        &self,
        tenant_id: TenantId,
        ticket_id: Uuid,
    ) -> AppResult<Vec<KbExecutionSummary>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        self.assert_ticket_exists(&mut tx, tenant_id, ticket_id)
            .await?;

        let rows = sqlx::query_as::<_, SummaryRow>(
            r#"SELECT e.id, e.ticket_id, e.article_id, e.article_version_id,
                      e.started_at, e.started_by_user_id,
                      a.title AS article_name,
                      NULLIF(TRIM(COALESCE(u.first_name, '') || ' ' || COALESCE(u.last_name, '')), '')
                          AS started_by_name,
                      COALESCE(c.total_steps, 0) AS total_steps,
                      COALESCE(c.checked_steps, 0) AS checked_steps
               FROM kb_article_executions e
               JOIN kb_articles a ON a.id = e.article_id
               LEFT JOIN users u ON u.id = e.started_by_user_id
               LEFT JOIN LATERAL (
                   SELECT COUNT(*)::bigint AS total_steps,
                          COUNT(*) FILTER (WHERE s.checked_at IS NOT NULL)::bigint
                              AS checked_steps
                   FROM kb_article_execution_steps s
                   WHERE s.execution_id = e.id
               ) c ON TRUE
               WHERE e.tenant_id = $1 AND e.ticket_id = $2
               ORDER BY e.started_at DESC"#,
        )
        .bind(tenant_id)
        .bind(ticket_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;

        Ok(rows.into_iter().map(SummaryRow::into_summary).collect())
    }

    /// Flip the checked state on one step. Idempotent: a check on an
    /// already-checked step keeps its original `checked_at` and
    /// `checked_by_user_id` (no-op), an uncheck on an unchecked step
    /// is also a no-op. Returns the updated step row.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, execution_id = %execution_id, index = %index, user_id = %user_id))]
    pub async fn set_step_checked(
        &self,
        tenant_id: TenantId,
        execution_id: Uuid,
        index: i32,
        user_id: Uuid,
        checked: bool,
    ) -> AppResult<KbExecutionStepResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        // Make sure the execution belongs to the tenant and the step
        // exists; RLS already filters cross-tenant rows but the
        // existence check gives us a 404 instead of a 500 that a bare
        // UPDATE with zero rows would otherwise produce when we go to
        // return the response.
        let step_exists: bool = sqlx::query_scalar(
            r#"SELECT EXISTS(
                 SELECT 1
                 FROM kb_article_execution_steps s
                 JOIN kb_article_executions e
                   ON e.id = s.execution_id AND e.tenant_id = s.tenant_id
                 WHERE s.tenant_id = $1 AND s.execution_id = $2
                   AND s.step_index = $3
               )"#,
        )
        .bind(tenant_id)
        .bind(execution_id)
        .bind(index)
        .fetch_one(&mut *tx)
        .await?;
        if !step_exists {
            return Err(AppError::NotFound("KB execution step".to_string()));
        }

        if checked {
            // Set only when currently NULL so a double-check keeps the
            // first checker's identity.
            sqlx::query(
                r#"UPDATE kb_article_execution_steps
                   SET checked_at = NOW(), checked_by_user_id = $4
                   WHERE execution_id = $1 AND step_index = $2
                     AND tenant_id = $3 AND checked_at IS NULL"#,
            )
            .bind(execution_id)
            .bind(index)
            .bind(tenant_id)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        } else {
            sqlx::query(
                r#"UPDATE kb_article_execution_steps
                   SET checked_at = NULL, checked_by_user_id = NULL
                   WHERE execution_id = $1 AND step_index = $2
                     AND tenant_id = $3 AND checked_at IS NOT NULL"#,
            )
            .bind(execution_id)
            .bind(index)
            .bind(tenant_id)
            .execute(&mut *tx)
            .await?;
        }

        let row = sqlx::query_as::<_, StepRow>(
            r#"SELECT s.id, s.execution_id, s.step_index, s.step_text,
                      s.checked_at, s.checked_by_user_id,
                      NULLIF(TRIM(COALESCE(u.first_name, '') || ' ' || COALESCE(u.last_name, '')), '')
                          AS checked_by_name
               FROM kb_article_execution_steps s
               LEFT JOIN users u ON u.id = s.checked_by_user_id
               WHERE s.execution_id = $1 AND s.step_index = $2
                 AND s.tenant_id = $3"#,
        )
        .bind(execution_id)
        .bind(index)
        .bind(tenant_id)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row.into_response())
    }
}

mod rows {
    use super::*;

    #[derive(sqlx::FromRow)]
    pub(super) struct ExecutionRow {
        pub id: Uuid,
        pub ticket_id: Uuid,
        pub article_id: Uuid,
        pub article_version_id: Option<Uuid>,
        pub variable_values: serde_json::Value,
        pub started_at: DateTime<Utc>,
        pub started_by_user_id: Uuid,
        pub article_name: String,
        pub started_by_name: Option<String>,
    }

    impl ExecutionRow {
        pub(super) fn into_response(self, steps: Vec<StepRow>) -> KbExecutionResponse {
            let variable_values: BTreeMap<String, String> =
                serde_json::from_value(self.variable_values).unwrap_or_default();
            KbExecutionResponse {
                id: self.id,
                ticket_id: self.ticket_id,
                article_id: self.article_id,
                article_name: self.article_name,
                article_version_id: self.article_version_id,
                variable_values,
                started_at: self.started_at,
                started_by_user_id: self.started_by_user_id,
                started_by_name: self
                    .started_by_name
                    .unwrap_or_else(|| "Unknown".to_string()),
                steps: steps.into_iter().map(StepRow::into_response).collect(),
            }
        }
    }

    #[derive(sqlx::FromRow)]
    pub(super) struct StepRow {
        pub id: Uuid,
        pub execution_id: Uuid,
        pub step_index: i32,
        pub step_text: String,
        pub checked_at: Option<DateTime<Utc>>,
        pub checked_by_user_id: Option<Uuid>,
        pub checked_by_name: Option<String>,
    }

    impl StepRow {
        pub(super) fn into_response(self) -> KbExecutionStepResponse {
            KbExecutionStepResponse {
                id: self.id,
                execution_id: self.execution_id,
                index: self.step_index,
                text: self.step_text,
                checked_at: self.checked_at,
                checked_by_user_id: self.checked_by_user_id,
                checked_by_name: self.checked_by_name,
            }
        }
    }

    #[derive(sqlx::FromRow)]
    pub(super) struct SummaryRow {
        pub id: Uuid,
        pub ticket_id: Uuid,
        pub article_id: Uuid,
        pub article_version_id: Option<Uuid>,
        pub started_at: DateTime<Utc>,
        pub started_by_user_id: Uuid,
        pub article_name: String,
        pub started_by_name: Option<String>,
        pub total_steps: i64,
        pub checked_steps: i64,
    }

    impl SummaryRow {
        pub(super) fn into_summary(self) -> KbExecutionSummary {
            KbExecutionSummary {
                id: self.id,
                ticket_id: self.ticket_id,
                article_id: self.article_id,
                article_name: self.article_name,
                article_version_id: self.article_version_id,
                started_at: self.started_at,
                started_by_user_id: self.started_by_user_id,
                started_by_name: self
                    .started_by_name
                    .unwrap_or_else(|| "Unknown".to_string()),
                total_steps: self.total_steps,
                checked_steps: self.checked_steps,
            }
        }
    }
}
