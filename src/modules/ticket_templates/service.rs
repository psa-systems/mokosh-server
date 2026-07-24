//! PMS-448 AC4: ticket-template CRUD service.

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use super::models::{
    CreateTicketTemplateRequest, TicketTemplateResponse, UpdateTicketTemplateRequest,
};
use crate::db::Database;
use crate::utils::error::{AppError, AppResult};

#[derive(Debug, FromRow)]
struct TemplateRow {
    id: Uuid,
    name: String,
    description: Option<String>,
    subject: String,
    body: Option<String>,
    category_id: Option<Uuid>,
    priority_id: Option<Uuid>,
    type_id: Option<Uuid>,
    is_active: bool,
    created_by_id: Uuid,
    created_by_name: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<TemplateRow> for TicketTemplateResponse {
    fn from(r: TemplateRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            description: r.description,
            subject: r.subject,
            body: r.body,
            category_id: r.category_id,
            priority_id: r.priority_id,
            type_id: r.type_id,
            is_active: r.is_active,
            created_by_id: r.created_by_id,
            created_by_name: r.created_by_name,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

const TEMPLATE_SELECT: &str = "
    t.id, t.name, t.description, t.subject, t.body,
    t.category_id, t.priority_id, t.type_id, t.is_active, t.created_by_id,
    NULLIF(TRIM(CONCAT(u.first_name, ' ', u.last_name)), '') AS created_by_name,
    t.created_at, t.updated_at
";

/// PMS-683: every query runs inside `Database::begin_with_tenant`, which sets
/// the `app.current_tenant` GUC transaction-locally, so `ticket_templates` is
/// safe under the fail-closed `tenant_isolation` RLS policy (migration 095).
#[derive(Clone)]
pub struct TicketTemplatesService {
    db: Database,
}

impl TicketTemplatesService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// List templates for the tenant. When `active_only` is true the
    /// list is narrowed to the picker's view (active templates only);
    /// the admin management screen passes false to see retired ones.
    pub async fn list(
        &self,
        tenant_id: Uuid,
        active_only: bool,
    ) -> AppResult<Vec<TicketTemplateResponse>> {
        let sql = format!(
            "SELECT {TEMPLATE_SELECT} \
             FROM ticket_templates t \
             LEFT JOIN users u ON u.id = t.created_by_id \
             WHERE t.tenant_id = $1 AND ($2 = false OR t.is_active = true) \
             ORDER BY t.name ASC",
        );
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows = sqlx::query_as::<_, TemplateRow>(&sql)
            .bind(tenant_id)
            .bind(active_only)
            .fetch_all(&mut *tx)
            .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn get(&self, tenant_id: Uuid, id: Uuid) -> AppResult<TicketTemplateResponse> {
        let sql = format!(
            "SELECT {TEMPLATE_SELECT} \
             FROM ticket_templates t \
             LEFT JOIN users u ON u.id = t.created_by_id \
             WHERE t.tenant_id = $1 AND t.id = $2",
        );
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row = sqlx::query_as::<_, TemplateRow>(&sql)
            .bind(tenant_id)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(AppError::NotFound("TicketTemplate".into()))?;
        Ok(row.into())
    }

    pub async fn create(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        req: CreateTicketTemplateRequest,
    ) -> AppResult<TicketTemplateResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO ticket_templates \
                 (tenant_id, name, description, subject, body, category_id, \
                  priority_id, type_id, is_active, created_by_id) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
             RETURNING id",
        )
        .bind(tenant_id)
        .bind(&req.name)
        .bind(&req.description)
        .bind(&req.subject)
        .bind(&req.body)
        .bind(req.category_id)
        .bind(req.priority_id)
        .bind(req.type_id)
        .bind(req.is_active)
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        self.get(tenant_id, id).await
    }

    /// Read-modify-write so the `Option<Option<_>>` nullable-FK fields
    /// can express "clear this FK" (explicit JSON null) distinctly from
    /// "leave it" (key absent). Returns 404 if the row is absent or
    /// belongs to another tenant.
    pub async fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        req: UpdateTicketTemplateRequest,
    ) -> AppResult<TicketTemplateResponse> {
        let current = self.get(tenant_id, id).await?;

        let name = req.name.unwrap_or(current.name);
        let description = req.description.unwrap_or(current.description);
        let subject = req.subject.unwrap_or(current.subject);
        let body = req.body.unwrap_or(current.body);
        let category_id = req.category_id.unwrap_or(current.category_id);
        let priority_id = req.priority_id.unwrap_or(current.priority_id);
        let type_id = req.type_id.unwrap_or(current.type_id);
        let is_active = req.is_active.unwrap_or(current.is_active);

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            "UPDATE ticket_templates SET \
                 name = $3, description = $4, subject = $5, body = $6, \
                 category_id = $7, priority_id = $8, type_id = $9, \
                 is_active = $10, updated_at = NOW() \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(&name)
        .bind(&description)
        .bind(&subject)
        .bind(&body)
        .bind(category_id)
        .bind(priority_id)
        .bind(type_id)
        .bind(is_active)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        self.get(tenant_id, id).await
    }

    pub async fn delete(&self, tenant_id: Uuid, id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows = sqlx::query("DELETE FROM ticket_templates WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        tx.commit().await?;
        if rows == 0 {
            return Err(AppError::NotFound("TicketTemplate".into()));
        }
        Ok(())
    }
}
