//! Ticket service implementation

use crate::modules::auth::TenantId;
use chrono::Utc;
use std::sync::Arc;
use uuid::Uuid;

use crate::db::Database;
use crate::modules::audit::{audit_write, AuditAction, AuditCtx};
use crate::modules::notifications::NotificationsService;
use crate::utils::email::{LogMailer, Mailer};
use crate::utils::error::{AppError, AppResult};
use crate::utils::pagination::PaginationParams;

use super::automation::AutomationEngine;
use super::models::*;

/// Ticket management service
#[derive(Clone)]
pub struct TicketService {
    db: Database,
    automation: AutomationEngine,
    mailer: Arc<dyn Mailer>,
    /// When `Some`, ticket-note emails are enqueued via the
    /// notifications dispatcher (template + worker delivery) instead
    /// of being sent inline through `mailer`. The legacy mailer path
    /// is retained so test fixtures that build `TicketService::new`
    /// keep compiling.
    notifications: Option<NotificationsService>,
}

impl TicketService {
    /// Build a TicketService backed by `LogMailer`. Kept so call sites
    /// that don't need real SMTP (test factories, the legacy
    /// constructor) keep compiling.
    pub fn new(db: Database) -> Self {
        Self::with_mailer(db, Arc::new(LogMailer))
    }

    /// Build a TicketService wired to a specific mailer. Used from
    /// `create_api_router` so add-note notifications and the
    /// automation-rule send_notification action share the SMTP path as
    /// auth's password-reset / welcome emails.
    pub fn with_mailer(db: Database, mailer: Arc<dyn Mailer>) -> Self {
        let automation = AutomationEngine::with_deps(db.clone(), mailer.clone());
        Self {
            db,
            automation,
            mailer,
            notifications: None,
        }
    }

    /// Like [`Self::with_mailer`] but additionally wires the
    /// notifications dispatcher. The server uses this constructor in
    /// `create_api_router` so ticket-note emails and the automation
    /// engine's `send_notification` action flow through the queue
    /// (delivery handled by `DispatcherWorker`).
    pub fn with_dispatcher(
        db: Database,
        mailer: Arc<dyn Mailer>,
        notifications: NotificationsService,
    ) -> Self {
        let automation =
            AutomationEngine::with_dispatcher(db.clone(), mailer.clone(), notifications.clone());
        Self {
            db,
            automation,
            mailer,
            notifications: Some(notifications),
        }
    }

    /// Reject a foreign id that does not belong to this tenant, so a request
    /// body cannot link a row to another tenant's data. `table` is a
    /// compile-time constant, never user input.
    async fn validate_fk(
        &self,
        tenant_id: TenantId,
        table: &'static str,
        id: Uuid,
    ) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let exists: bool = sqlx::query_scalar(&format!(
            "SELECT EXISTS(SELECT 1 FROM {table} WHERE tenant_id = $1 AND id = $2)"
        ))
        .bind(tenant_id)
        .bind(id)
        .fetch_one(&mut *tx)
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
        tenant_id: TenantId,
        table: &'static str,
        id: Option<Uuid>,
    ) -> AppResult<()> {
        match id {
            Some(id) => self.validate_fk(tenant_id, table, id).await,
            None => Ok(()),
        }
    }

    /// Generate next ticket number for tenant
    async fn next_ticket_number(&self, tenant_id: TenantId) -> AppResult<String> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row = sqlx::query_as::<_, (i32,)>(
            r#"
            UPDATE ticket_sequences
            SET last_number = last_number + 1
            WHERE tenant_id = $1
            RETURNING last_number
            "#,
        )
        .bind(tenant_id)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;

        Ok(format!("T{:06}", row.0))
    }

    /// Create a new ticket
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_ticket(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        request: &CreateTicketRequest,
        ctx: &AuditCtx,
    ) -> AppResult<Ticket> {
        let ticket_id = Uuid::new_v4();
        let ticket_number = self.next_ticket_number(tenant_id).await?;

        // Get default status
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let default_status_id: Uuid = sqlx::query_scalar(
            "SELECT id FROM ticket_statuses WHERE tenant_id = $1 AND is_default = TRUE LIMIT 1",
        )
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| {
            AppError::Configuration("No default ticket status configured".to_string())
        })?;

        // Get default or specified priority
        let priority_id = match request.priority_id {
            Some(id) => id,
            None => sqlx::query_scalar(
                "SELECT id FROM ticket_priorities WHERE tenant_id = $1 AND is_default = TRUE LIMIT 1",
            )
            .bind(tenant_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| AppError::Configuration("No default priority configured".to_string()))?,
        };

        // Get default or specified queue
        let queue_id = match request.queue_id {
            Some(id) => id,
            None => sqlx::query_scalar(
                "SELECT id FROM ticket_queues WHERE tenant_id = $1 AND is_default = TRUE LIMIT 1",
            )
            .bind(tenant_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| AppError::Configuration("No default queue configured".to_string()))?,
        };
        drop(tx);

        // PSA audit: every foreign id from the request body must belong to
        // this tenant before it is linked, so a request cannot point a
        // ticket at another tenant's company/contact/site/etc.
        self.validate_fk(tenant_id, "companies", request.company_id)
            .await?;
        self.validate_fk_opt(tenant_id, "ticket_types", request.type_id)
            .await?;
        self.validate_fk_opt(tenant_id, "ticket_categories", request.category_id)
            .await?;
        self.validate_fk_opt(tenant_id, "contacts", request.contact_id)
            .await?;
        self.validate_fk_opt(tenant_id, "sites", request.site_id)
            .await?;
        self.validate_fk_opt(tenant_id, "users", request.assigned_to_id)
            .await?;
        self.validate_fk_opt(tenant_id, "teams", request.team_id)
            .await?;
        self.validate_fk_opt(tenant_id, "contracts", request.contract_id)
            .await?;
        self.validate_fk_opt(tenant_id, "sla_policies", request.sla_id)
            .await?;
        self.validate_fk_opt(tenant_id, "assets", request.asset_id)
            .await?;

        // Insert + audit row in one transaction: capture the new row
        // with Postgres to_jsonb and write the audit entry on the same
        // tx so a rollback drops both. PMS-117.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            r#"
            INSERT INTO tickets (
                id, tenant_id, ticket_number, title, description,
                status_id, priority_id, type_id, category_id, queue_id, source,
                company_id, contact_id, site_id, assigned_to_id, team_id,
                contract_id, sla_id, scheduled_start, scheduled_end,
                estimated_hours, is_billable, asset_id, custom_fields, tags,
                created_by_id
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
                $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26
            )
            "#,
        )
        .bind(ticket_id)
        .bind(tenant_id)
        .bind(&ticket_number)
        .bind(&request.title)
        .bind(&request.description)
        .bind(default_status_id)
        .bind(priority_id)
        .bind(request.type_id)
        .bind(request.category_id)
        .bind(queue_id)
        .bind(request.source.as_str())
        .bind(request.company_id)
        .bind(request.contact_id)
        .bind(request.site_id)
        .bind(request.assigned_to_id)
        .bind(request.team_id)
        .bind(request.contract_id)
        .bind(request.sla_id)
        .bind(request.scheduled_start)
        .bind(request.scheduled_end)
        .bind(request.estimated_hours)
        .bind(request.is_billable)
        .bind(request.asset_id)
        .bind(&request.custom_fields)
        .bind(&request.tags)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM tickets t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(ticket_id)
        .fetch_optional(&mut *tx)
        .await?;

        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Create,
            "tickets",
            Some(ticket_id),
            None,
            after,
        )
        .await?;
        tx.commit().await?;

        // Calculate and set SLA due dates
        self.calculate_sla_dates(tenant_id, ticket_id).await?;

        // Audit F11: run on_create automation rules. Failures are logged
        // but do not abort the ticket creation - a misconfigured rule
        // shouldn't block legitimate work.
        if let Err(e) = self
            .automation
            .process_rules(tenant_id, ticket_id, AutomationTrigger::OnCreate)
            .await
        {
            tracing::warn!(?e, %tenant_id, %ticket_id, "on_create automation failed");
        }

        self.get_ticket(tenant_id, ticket_id).await
    }

    /// Get ticket by ID
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_ticket(&self, tenant_id: TenantId, ticket_id: Uuid) -> AppResult<Ticket> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row = sqlx::query_as::<_, TicketRow>(
            r#"
            SELECT id, tenant_id, ticket_number, title, description,
                   status_id, priority_id, type_id, category_id, subcategory_id,
                   queue_id, source, company_id, contact_id, site_id,
                   assigned_to_id, team_id, parent_ticket_id, contract_id, sla_id,
                   sla_due_date, first_response_due, first_response_at,
                   resolution_due, resolved_at, closed_at,
                   scheduled_start, scheduled_end, estimated_hours, actual_hours,
                   is_billable, billing_status, asset_id, custom_fields, tags,
                   created_by_id, last_updated_by_id, created_at, updated_at
            FROM tickets
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(ticket_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::NotFound("Ticket".to_string()))?;

        Ok(row.into())
    }

    /// Get ticket by number
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_ticket_by_number(
        &self,
        tenant_id: TenantId,
        ticket_number: &str,
    ) -> AppResult<Ticket> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row = sqlx::query_as::<_, TicketRow>(
            r#"
            SELECT id, tenant_id, ticket_number, title, description,
                   status_id, priority_id, type_id, category_id, subcategory_id,
                   queue_id, source, company_id, contact_id, site_id,
                   assigned_to_id, team_id, parent_ticket_id, contract_id, sla_id,
                   sla_due_date, first_response_due, first_response_at,
                   resolution_due, resolved_at, closed_at,
                   scheduled_start, scheduled_end, estimated_hours, actual_hours,
                   is_billable, billing_status, asset_id, custom_fields, tags,
                   created_by_id, last_updated_by_id, created_at, updated_at
            FROM tickets
            WHERE tenant_id = $1 AND ticket_number = $2
            "#,
        )
        .bind(tenant_id)
        .bind(ticket_number)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::NotFound("Ticket".to_string()))?;

        Ok(row.into())
    }

    /// List tickets with filters
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_tickets(
        &self,
        tenant_id: TenantId,
        filter: &TicketFilter,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<Ticket>, u64)> {
        let offset = pagination.offset() as i32;
        let limit = pagination.limit() as i32;

        // Shared filter builder so the data/count placeholder numbering
        // cannot diverge between this and `list_ticket_responses`
        // (PMS-197). `list_tickets` has no `ticket_statuses` JOIN, so its
        // `is_open` test is a correlated `NOT EXISTS`.
        let TicketFilterSql {
            data_where,
            count_where,
            binds,
        } = build_ticket_filter_sql(
            filter,
            "NOT EXISTS (SELECT 1 FROM ticket_statuses s \
             WHERE s.id = t.status_id AND s.is_closed = TRUE)",
        );
        let order_by = pagination.order_by(
            "t.created_at",
            &["created_at", "updated_at", "sla_due_date", "priority_id"],
        );

        let query = format!(
            r#"
            SELECT t.id, t.tenant_id, t.ticket_number, t.title, t.description,
                   t.status_id, t.priority_id, t.type_id, t.category_id, t.subcategory_id,
                   t.queue_id, t.source, t.company_id, t.contact_id, t.site_id,
                   t.assigned_to_id, t.team_id, t.parent_ticket_id, t.contract_id, t.sla_id,
                   t.sla_due_date, t.first_response_due, t.first_response_at,
                   t.resolution_due, t.resolved_at, t.closed_at,
                   t.scheduled_start, t.scheduled_end, t.estimated_hours, t.actual_hours,
                   t.is_billable, t.billing_status, t.asset_id, t.custom_fields, t.tags,
                   t.created_by_id, t.last_updated_by_id, t.created_at, t.updated_at
            FROM tickets t
            WHERE {data_where}
            ORDER BY {order_by}
            LIMIT $2 OFFSET $3
            "#
        );

        let count_query = format!("SELECT COUNT(*) FROM tickets t WHERE {count_where}");

        // Build queries with dynamic parameters
        let mut query_builder = sqlx::query_as::<_, TicketRow>(&query)
            .bind(tenant_id)
            .bind(limit)
            .bind(offset);

        let mut count_builder = sqlx::query_scalar::<_, i64>(&count_query).bind(tenant_id);

        // Bind the filter values in the SAME order both queries number
        // them; `build_ticket_filter_sql` is the single source of truth
        // for that order.
        for b in &binds {
            match b {
                TicketFilterBind::Text(s) => {
                    query_builder = query_builder.bind(s.clone());
                    count_builder = count_builder.bind(s.clone());
                }
                TicketFilterBind::Id(id) => {
                    query_builder = query_builder.bind(*id);
                    count_builder = count_builder.bind(*id);
                }
            }
        }

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows = query_builder.fetch_all(&mut *tx).await?;
        let total = count_builder.fetch_one(&mut *tx).await?;

        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    /// Update ticket
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_ticket(
        &self,
        tenant_id: TenantId,
        ticket_id: Uuid,
        user_id: Uuid,
        request: &UpdateTicketRequest,
        ctx: &AuditCtx,
    ) -> AppResult<Ticket> {
        let ticket = self.get_ticket(tenant_id, ticket_id).await?;
        // Captured for a future "status changed" automation trigger;
        // the F11 wiring only fires the generic OnUpdate today.
        let _old_status_id = ticket.status_id;

        // PSA audit: validate any foreign id being set so an update cannot
        // re-link this ticket to another tenant's rows. Option fields are
        // only checked when present.
        self.validate_fk_opt(tenant_id, "ticket_priorities", request.priority_id)
            .await?;
        self.validate_fk_opt(tenant_id, "ticket_queues", request.queue_id)
            .await?;
        self.validate_fk_opt(tenant_id, "contacts", request.contact_id)
            .await?;
        self.validate_fk_opt(tenant_id, "sites", request.site_id)
            .await?;
        self.validate_fk_opt(tenant_id, "users", request.assigned_to_id)
            .await?;
        self.validate_fk_opt(tenant_id, "teams", request.team_id)
            .await?;
        self.validate_fk_opt(tenant_id, "contracts", request.contract_id)
            .await?;
        self.validate_fk_opt(tenant_id, "sla_policies", request.sla_id)
            .await?;
        self.validate_fk_opt(tenant_id, "assets", request.asset_id)
            .await?;

        // Mutation + audit row in one transaction: snapshot the row
        // before and after (Postgres to_jsonb captures exact stored
        // state) and write the audit entry on the same tx so a rollback
        // drops both. PMS-117.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let before: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM tickets t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(ticket_id)
        .fetch_optional(&mut *tx)
        .await?;

        // Build update
        if let Some(ref title) = request.title {
            sqlx::query("UPDATE tickets SET title = $1, last_updated_by_id = $2, updated_at = NOW() WHERE tenant_id = $3 AND id = $4")
                .bind(title)
                .bind(user_id)
                .bind(tenant_id)
                .bind(ticket_id)
                .execute(&mut *tx)
                .await?;
        }

        if let Some(ref description) = request.description {
            sqlx::query("UPDATE tickets SET description = $1, last_updated_by_id = $2, updated_at = NOW() WHERE tenant_id = $3 AND id = $4")
                .bind(description)
                .bind(user_id)
                .bind(tenant_id)
                .bind(ticket_id)
                .execute(&mut *tx)
                .await?;
        }

        if let Some(status_id) = request.status_id {
            // Check if status is closing the ticket
            let is_closed: bool =
                sqlx::query_scalar("SELECT is_closed FROM ticket_statuses WHERE id = $1")
                    .bind(status_id)
                    .fetch_one(&mut *tx)
                    .await?;

            if is_closed && ticket.closed_at.is_none() {
                sqlx::query(
                    "UPDATE tickets SET status_id = $1, closed_at = NOW(), resolved_at = COALESCE(resolved_at, NOW()), last_updated_by_id = $2, updated_at = NOW() WHERE tenant_id = $3 AND id = $4",
                )
                .bind(status_id)
                .bind(user_id)
                .bind(tenant_id)
                .bind(ticket_id)
                .execute(&mut *tx)
                .await?;
            } else {
                sqlx::query(
                    "UPDATE tickets SET status_id = $1, last_updated_by_id = $2, updated_at = NOW() WHERE tenant_id = $3 AND id = $4",
                )
                .bind(status_id)
                .bind(user_id)
                .bind(tenant_id)
                .bind(ticket_id)
                .execute(&mut *tx)
                .await?;
            }
        }

        // Whether the priority changed; the SLA recalc that depends on it
        // runs after the tx commits so it reads the committed priority
        // (calculate_sla_dates goes through the pool, not this tx).
        let priority_changed = request.priority_id.is_some();
        if let Some(priority_id) = request.priority_id {
            sqlx::query("UPDATE tickets SET priority_id = $1, last_updated_by_id = $2, updated_at = NOW() WHERE tenant_id = $3 AND id = $4")
                .bind(priority_id)
                .bind(user_id)
                .bind(tenant_id)
                .bind(ticket_id)
                .execute(&mut *tx)
                .await?;
        }

        if let Some(assigned_to_id) = request.assigned_to_id {
            sqlx::query("UPDATE tickets SET assigned_to_id = $1, last_updated_by_id = $2, updated_at = NOW() WHERE tenant_id = $3 AND id = $4")
                .bind(assigned_to_id)
                .bind(user_id)
                .bind(tenant_id)
                .bind(ticket_id)
                .execute(&mut *tx)
                .await?;
        }

        if let Some(queue_id) = request.queue_id {
            sqlx::query("UPDATE tickets SET queue_id = $1, last_updated_by_id = $2, updated_at = NOW() WHERE tenant_id = $3 AND id = $4")
                .bind(queue_id)
                .bind(user_id)
                .bind(tenant_id)
                .bind(ticket_id)
                .execute(&mut *tx)
                .await?;
        }

        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM tickets t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(ticket_id)
        .fetch_optional(&mut *tx)
        .await?;

        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Update,
            "tickets",
            Some(ticket_id),
            before,
            after,
        )
        .await?;
        tx.commit().await?;

        // Recalculate SLA when priority changes. Runs after commit so it
        // reads the persisted priority (mirrors the post-commit follow-up
        // pattern in contacts::update_company).
        if priority_changed {
            self.calculate_sla_dates(tenant_id, ticket_id).await?;
        }

        // Audit F11: run on_update automation rules. Same fail-soft
        // policy as on_create - log but do not surface a 500.
        if let Err(e) = self
            .automation
            .process_rules(tenant_id, ticket_id, AutomationTrigger::OnUpdate)
            .await
        {
            tracing::warn!(?e, %tenant_id, %ticket_id, "on_update automation failed");
        }

        self.get_ticket(tenant_id, ticket_id).await
    }

    /// Hard-delete a ticket. Children that declare `ON DELETE CASCADE`
    /// (`ticket_notes`, `ticket_status_history` in migrations/005_tickets.sql,
    /// the sla tables in 027_sla_notify.sql) are removed by the row delete, and
    /// `appointments.ticket_id` is `ON DELETE SET NULL`. Rows that reference the
    /// ticket with the default RESTRICT - time entries (006_time_tracking.sql),
    /// child tickets via `parent_ticket_id` (005_tickets.sql:119), billing rows
    /// (010_billing.sql:68) - block the delete; that FK violation
    /// (SQLSTATE 23503) is mapped to a clean `400` here instead of the generic
    /// `500` the blanket `sqlx::Error -> AppError` conversion would produce,
    /// mirroring `delete_company`'s explicit guard.
    ///
    /// Like `contacts::ContactService::delete_company`: 404 when the ticket is
    /// absent in the tenant, then mutation + audit row in one transaction so a
    /// rollback drops both. PMS-149 added this so the E2E teardown can remove
    /// test-created tickets and, in turn, their parent company (which
    /// `delete_company` refuses to drop while any ticket references it).
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_ticket(
        &self,
        tenant_id: TenantId,
        ticket_id: Uuid,
        ctx: &AuditCtx,
    ) -> AppResult<()> {
        // 404 if the ticket is not in this tenant before doing any work.
        self.get_ticket(tenant_id, ticket_id).await?;

        // Mutation + audit row in one transaction. DELETE: snapshot before,
        // old = before, after = None. PMS-117 audit convention.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let before: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM tickets t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(ticket_id)
        .fetch_optional(&mut *tx)
        .await?;

        if let Err(e) = sqlx::query("DELETE FROM tickets WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(ticket_id)
            .execute(&mut *tx)
            .await
        {
            // A referencing row with the default RESTRICT FK (time entries,
            // child tickets, billing) raises SQLSTATE 23503. Surface it as a
            // 400 with an actionable message instead of the generic 500 that
            // `sqlx::Error -> AppError` would yield (it only special-cases the
            // 23505 unique violation). The tx rolls back when dropped on return.
            if e.as_database_error().and_then(|d| d.code()).as_deref() == Some("23503") {
                return Err(AppError::BadRequest(
                    "Cannot delete ticket with related records (time entries, \
                     sub-tickets, or billing); remove them first"
                        .to_string(),
                ));
            }
            return Err(e.into());
        }

        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Delete,
            "tickets",
            Some(ticket_id),
            before,
            None,
        )
        .await?;
        tx.commit().await?;

        Ok(())
    }

    /// Assign ticket to user
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn assign_ticket(
        &self,
        tenant_id: TenantId,
        ticket_id: Uuid,
        assigned_to_id: Uuid,
        user_id: Uuid,
    ) -> AppResult<Ticket> {
        // PSA audit: the assignee must be a user in this tenant so a
        // request cannot assign a ticket to another tenant's user.
        self.validate_fk(tenant_id, "users", assigned_to_id).await?;

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            "UPDATE tickets SET assigned_to_id = $1, last_updated_by_id = $2, updated_at = NOW() WHERE tenant_id = $3 AND id = $4",
        )
        .bind(assigned_to_id)
        .bind(user_id)
        .bind(tenant_id)
        .bind(ticket_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        self.get_ticket(tenant_id, ticket_id).await
    }

    /// Add note to ticket
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn add_note(
        &self,
        tenant_id: TenantId,
        ticket_id: Uuid,
        user_id: Uuid,
        request: &CreateNoteRequest,
    ) -> AppResult<TicketNote> {
        let note_id = Uuid::new_v4();

        // PSA audit: the note's ticket must belong to this tenant before we
        // insert against it and bump the ticket's SLA/timestamp columns, so a
        // cross-tenant ticket_id cannot corrupt another tenant's ticket.
        self.validate_fk(tenant_id, "tickets", ticket_id).await?;

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            r#"
            INSERT INTO ticket_notes (id, tenant_id, ticket_id, note_type, content, created_by_id)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(note_id)
        .bind(tenant_id)
        .bind(ticket_id)
        .bind(request.note_type.as_str())
        .bind(&request.content)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

        // Update ticket's updated_at
        sqlx::query("UPDATE tickets SET updated_at = NOW(), last_updated_by_id = $1 WHERE tenant_id = $2 AND id = $3")
            .bind(user_id)
            .bind(tenant_id)
            .bind(ticket_id)
            .execute(&mut *tx)
            .await?;

        // Record first response if this is a public note and first response hasn't been recorded
        if request.note_type == NoteType::Public {
            sqlx::query(
                "UPDATE tickets SET first_response_at = COALESCE(first_response_at, NOW()) WHERE tenant_id = $1 AND id = $2",
            )
            .bind(tenant_id)
            .bind(ticket_id)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;

        // PMS-15: customer notification on public notes. Internal notes
        // never leave the building no matter what `send_email` says.
        // The notifications module (PMS-85 story) will own templating
        // and watcher fan-out; until then we send a single plain-text
        // message to the ticket's contact and record success on the
        // note row so the UI can show a "delivered" indicator.
        if request.send_email && request.note_type == NoteType::Public {
            self.send_note_email(tenant_id, ticket_id, note_id, &request.content)
                .await;
        }

        self.get_note(tenant_id, note_id).await
    }

    /// Fire-and-forget email for a public ticket note. Failures are
    /// logged; we never surface a 5xx for a note add when only the
    /// email side fails, because the note itself is already persisted
    /// and visible to the agent.
    async fn send_note_email(
        &self,
        tenant_id: TenantId,
        ticket_id: Uuid,
        note_id: Uuid,
        content: &str,
    ) {
        // One round-trip fetches ticket-number/title + contact email.
        let mut tx = match self.db.begin_with_tenant(tenant_id).await {
            Ok(tx) => tx,
            Err(e) => {
                tracing::warn!(?e, %ticket_id, "open tenant tx for note email failed");
                return;
            }
        };
        let row: Option<(String, String, Option<String>)> = match sqlx::query_as(
            r#"
            SELECT t.ticket_number, t.title, ct.email
            FROM tickets t
            LEFT JOIN contacts ct ON t.contact_id = ct.id
            WHERE t.tenant_id = $1 AND t.id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(ticket_id)
        .fetch_optional(&mut *tx)
        .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(?e, %ticket_id, "fetch contact for note email failed");
                return;
            }
        };
        // Close the read tx before the network send so it isn't held
        // across the dispatch/mailer await; the post-send mark-sent
        // write opens its own tenant tx.
        drop(tx);

        let Some((ticket_number, title, Some(email))) = row else {
            tracing::debug!(
                %ticket_id,
                "skipping note email: ticket has no contact with an email",
            );
            return;
        };

        let subject = format!("[{ticket_number}] {title}");
        let body =
            format!("A new update has been added to ticket {ticket_number}:\n\n{content}\n",);

        // Prefer the notifications dispatcher so the row is durable
        // and the worker retries on transient SMTP failures. Fall
        // through to the legacy direct-mailer path if the service was
        // built without a dispatcher (older test fixtures).
        let send_result: Result<(), String> = match &self.notifications {
            Some(notify) => {
                let context = serde_json::json!({
                    "recipient_email": email,
                    "ticket_number": ticket_number,
                    "ticket_title": title,
                    "content": content,
                });
                notify
                    .dispatch(tenant_id, "ticket.note_added", &context)
                    .await
                    .map(|_| ())
                    .map_err(|e| format!("notify dispatch: {e}"))
            }
            None => self
                .mailer
                .send_text(&email, &subject, &body)
                .await
                .map_err(|e| format!("mailer send_text: {e}")),
        };

        match send_result {
            Ok(()) => {
                let mark_sent = async {
                    let mut tx = self.db.begin_with_tenant(tenant_id).await?;
                    sqlx::query(
                        "UPDATE ticket_notes SET is_email_sent = TRUE, email_sent_at = NOW() WHERE id = $1",
                    )
                    .bind(note_id)
                    .execute(&mut *tx)
                    .await?;
                    tx.commit().await
                };
                if let Err(e) = mark_sent.await {
                    tracing::warn!(?e, %note_id, "mark is_email_sent failed");
                } else {
                    tracing::info!(%note_id, "ticket note email queued");
                }
            }
            Err(e) => tracing::warn!(error = %e, %note_id, "ticket note email enqueue failed"),
        }
    }

    /// Get note by ID
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_note(&self, tenant_id: TenantId, note_id: Uuid) -> AppResult<TicketNote> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row = sqlx::query_as::<_, TicketNoteRow>(
            r#"
            SELECT n.id, n.tenant_id, n.ticket_id, n.note_type, n.content, n.content_html,
                   n.is_email_sent, n.email_sent_at, n.created_by_id, n.created_at, n.updated_at,
                   u.first_name || ' ' || u.last_name as created_by_name
            FROM ticket_notes n
            LEFT JOIN users u ON n.created_by_id = u.id
            WHERE n.tenant_id = $1 AND n.id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(note_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::NotFound("Note".to_string()))?;

        Ok(row.into())
    }

    /// Get notes for a ticket
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_ticket_notes(
        &self,
        tenant_id: TenantId,
        ticket_id: Uuid,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<TicketNote>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM ticket_notes WHERE tenant_id = $1 AND ticket_id = $2",
        )
        .bind(tenant_id)
        .bind(ticket_id)
        .fetch_one(&mut *tx)
        .await?;

        let rows = sqlx::query_as::<_, TicketNoteRow>(
            r#"
            SELECT n.id, n.tenant_id, n.ticket_id, n.note_type, n.content, n.content_html,
                   n.is_email_sent, n.email_sent_at, n.created_by_id, n.created_at, n.updated_at,
                   u.first_name || ' ' || u.last_name as created_by_name
            FROM ticket_notes n
            LEFT JOIN users u ON n.created_by_id = u.id
            WHERE n.tenant_id = $1 AND n.ticket_id = $2
            ORDER BY n.created_at DESC
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(tenant_id)
        .bind(ticket_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&mut *tx)
        .await?;

        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    /// Calculate SLA due dates for a ticket
    async fn calculate_sla_dates(&self, tenant_id: TenantId, ticket_id: Uuid) -> AppResult<()> {
        // Get ticket details
        let ticket = self.get_ticket(tenant_id, ticket_id).await?;

        // Get SLA policy
        let sla_id = match ticket.sla_id {
            Some(id) => id,
            None => {
                // Try to get default SLA
                let mut tx = self.db.begin_with_tenant(tenant_id).await?;
                let default: Option<Uuid> = sqlx::query_scalar(
                    "SELECT id FROM sla_policies WHERE tenant_id = $1 AND is_default = TRUE LIMIT 1",
                )
                .bind(tenant_id)
                .fetch_optional(&mut *tx)
                .await?;

                match default {
                    Some(id) => id,
                    None => return Ok(()), // No SLA applicable
                }
            }
        };

        // Get SLA targets for this priority. The columns are declared
        // DECIMAL(10, 2); cast to float8 in SQL so sqlx can decode them
        // into `Option<f64>` without a column-type mismatch (the test
        // harness in `tests/tickets.rs` surfaced this as
        // `ColumnDecode { ... Rust type Option<f64> is not compatible
        // with SQL type NUMERIC }`).
        let targets = sqlx::query_as::<_, (Option<f64>, Option<f64>)>(
            r#"
            SELECT first_response_hours::float8, resolution_hours::float8
            FROM sla_targets
            WHERE sla_policy_id = $1 AND priority_id = $2
            "#,
        )
        .bind(sla_id)
        .bind(ticket.priority_id)
        .fetch_optional(self.db.pool())
        .await?;

        if let Some((first_response_hours, resolution_hours)) = targets {
            let now = Utc::now();

            let first_response_due =
                first_response_hours.map(|h| now + chrono::Duration::minutes((h * 60.0) as i64));
            let sla_due_date =
                resolution_hours.map(|h| now + chrono::Duration::minutes((h * 60.0) as i64));

            let mut tx = self.db.begin_with_tenant(tenant_id).await?;
            sqlx::query(
                "UPDATE tickets SET sla_id = $1, first_response_due = $2, sla_due_date = $3, resolution_due = $3 WHERE id = $4",
            )
            .bind(sla_id)
            .bind(first_response_due)
            .bind(sla_due_date)
            .bind(ticket_id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
        }

        Ok(())
    }

    /// Get ticket statuses for tenant
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_statuses(
        &self,
        tenant_id: TenantId,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<TicketStatus>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM ticket_statuses WHERE tenant_id = $1")
                .bind(tenant_id)
                .fetch_one(&mut *tx)
                .await?;

        let rows = sqlx::query_as::<_, TicketStatusRow>(
            r#"
            SELECT id, tenant_id, name, color, is_closed, is_default, sort_order
            FROM ticket_statuses
            WHERE tenant_id = $1
            ORDER BY sort_order
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(tenant_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&mut *tx)
        .await?;

        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    /// Get ticket priorities for tenant
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_priorities(
        &self,
        tenant_id: TenantId,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<TicketPriority>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM ticket_priorities WHERE tenant_id = $1")
                .bind(tenant_id)
                .fetch_one(&mut *tx)
                .await?;

        let rows = sqlx::query_as::<_, TicketPriorityRow>(
            r#"
            SELECT id, tenant_id, name, color, icon, sla_multiplier, sort_order, is_default
            FROM ticket_priorities
            WHERE tenant_id = $1
            ORDER BY sort_order
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(tenant_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&mut *tx)
        .await?;

        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    /// Get ticket queues for tenant
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_queues(
        &self,
        tenant_id: TenantId,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<TicketQueue>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM ticket_queues WHERE tenant_id = $1")
                .bind(tenant_id)
                .fetch_one(&mut *tx)
                .await?;

        let rows = sqlx::query_as::<_, TicketQueueRow>(
            r#"
            SELECT id, tenant_id, name, description, color, icon, is_default, sort_order
            FROM ticket_queues
            WHERE tenant_id = $1
            ORDER BY sort_order
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(tenant_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&mut *tx)
        .await?;

        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    /// Get ticket types for tenant
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_types(
        &self,
        tenant_id: TenantId,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<TicketType>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM ticket_types WHERE tenant_id = $1 AND is_active = TRUE",
        )
        .bind(tenant_id)
        .fetch_one(&mut *tx)
        .await?;

        let rows = sqlx::query_as::<_, TicketTypeRow>(
            r#"
            SELECT id, tenant_id, name, description, icon, is_active, sort_order
            FROM ticket_types
            WHERE tenant_id = $1 AND is_active = TRUE
            ORDER BY sort_order
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(tenant_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&mut *tx)
        .await?;

        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    /// Create a portal-originated ticket. Used by `POST
    /// /api/v1/portal/tickets`. Looks up an admin user in the tenant to
    /// satisfy the NOT NULL FK on `tickets.created_by_id` (portal
    /// contacts are not in the `users` table); the customer-visible
    /// identity is captured by `contact_id`. Returns the fully-joined
    /// response so the portal client renders names not UUIDs.
    #[allow(clippy::too_many_arguments)]
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_portal_ticket(
        &self,
        tenant_id: TenantId,
        company_id: Uuid,
        contact_id: Uuid,
        title: String,
        description: Option<String>,
        priority_id: Option<Uuid>,
        type_id: Option<Uuid>,
    ) -> AppResult<TicketResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let default_creator: Option<Uuid> = sqlx::query_scalar(
            r#"
            SELECT id FROM users
            WHERE tenant_id = $1 AND status = 'active'
              AND role IN ('super_admin', 'admin', 'manager')
            ORDER BY created_at
            LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await?;
        drop(tx);

        let Some(creator) = default_creator else {
            return Err(AppError::Configuration(
                "Cannot create portal ticket: tenant has no admin/manager user to attribute it to"
                    .to_string(),
            ));
        };

        let request = CreateTicketRequest {
            title,
            description,
            priority_id,
            type_id,
            category_id: None,
            queue_id: None,
            source: TicketSource::Portal,
            company_id,
            contact_id: Some(contact_id),
            site_id: None,
            assigned_to_id: None,
            team_id: None,
            contract_id: None,
            sla_id: None,
            scheduled_start: None,
            scheduled_end: None,
            estimated_hours: None,
            is_billable: false,
            asset_id: None,
            custom_fields: serde_json::Value::Null,
            tags: vec![],
        };
        // Portal flow has no AuditCtx extractor (portal auth identity is a
        // `contacts` row, not a `users` row); attribute to the system actor.
        let ticket = self
            .create_ticket(
                tenant_id,
                creator,
                &request,
                &AuditCtx::system(tenant_id.get()),
            )
            .await?;
        self.get_ticket_response(tenant_id, ticket.id).await
    }

    /// List tickets visible to a portal contact. Scoped to
    /// `company_id`; the contact sees every ticket their company has
    /// opened, not just ones where `contact_id = self`. This matches
    /// the typical helpdesk model where employees of company X can
    /// follow each other's tickets.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_portal_tickets(
        &self,
        tenant_id: TenantId,
        company_id: Uuid,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<TicketResponse>, u64)> {
        let filter = TicketFilter {
            company_id: Some(company_id),
            ..Default::default()
        };
        self.list_ticket_responses(tenant_id, &filter, pagination)
            .await
    }

    /// Get a single ticket scoped to a portal contact's company. 404
    /// instead of 403 if the ticket exists in another company, so we
    /// don't leak the existence of a ticket the contact can't see.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_portal_ticket(
        &self,
        tenant_id: TenantId,
        company_id: Uuid,
        ticket_id: Uuid,
    ) -> AppResult<TicketResponse> {
        let resp = self.get_ticket_response(tenant_id, ticket_id).await?;
        if resp.company_id != company_id {
            return Err(AppError::NotFound("Ticket".to_string()));
        }
        Ok(resp)
    }

    /// Fetch a fully-joined ticket response. Audit F3: the previous
    /// route-side construction populated `status.name`, `priority.name`,
    /// queue/company/contact/assigned/created-by names with empty
    /// strings; this method joins the lookup tables in one round-trip
    /// and produces a complete DTO ready for the wire.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_ticket_response(
        &self,
        tenant_id: TenantId,
        ticket_id: Uuid,
    ) -> AppResult<TicketResponse> {
        let sql = format!(
            "{} WHERE t.tenant_id = $1 AND t.id = $2",
            TICKET_RESPONSE_SELECT
        );
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row = sqlx::query_as::<_, TicketResponseRow>(&sql)
            .bind(tenant_id)
            .bind(ticket_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| AppError::NotFound("Ticket".to_string()))?;
        Ok(row.into())
    }

    /// List fully-joined ticket responses + total. Mirrors the filter
    /// semantics of [`TicketService::list_tickets`] but produces
    /// response DTOs directly. Audit F3.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_ticket_responses(
        &self,
        tenant_id: TenantId,
        filter: &TicketFilter,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<TicketResponse>, u64)> {
        let offset = pagination.offset() as i32;
        let limit = pagination.limit() as i32;

        // Shared filter builder so the data/count placeholder numbering
        // cannot diverge between this and `list_tickets` (PMS-197). This
        // method already INNER JOINs `ticket_statuses ts`, so its
        // `is_open` test reads `ts.is_closed` directly.
        let TicketFilterSql {
            data_where,
            count_where,
            binds,
        } = build_ticket_filter_sql(filter, "ts.is_closed = FALSE");
        let order_by = pagination.order_by(
            "t.created_at",
            &["created_at", "updated_at", "sla_due_date", "priority_id"],
        );

        let query = format!(
            "{select} WHERE {data_where} ORDER BY {order_by} LIMIT $2 OFFSET $3",
            select = TICKET_RESPONSE_SELECT,
        );
        let count_query =
            format!("SELECT COUNT(*) FROM tickets t INNER JOIN ticket_statuses ts ON t.status_id = ts.id WHERE {count_where}");

        let mut query_builder = sqlx::query_as::<_, TicketResponseRow>(&query)
            .bind(tenant_id)
            .bind(limit)
            .bind(offset);
        let mut count_builder = sqlx::query_scalar::<_, i64>(&count_query).bind(tenant_id);

        // Bind the filter values in the SAME order both queries number
        // them; `build_ticket_filter_sql` is the single source of truth
        // for that order.
        for b in &binds {
            match b {
                TicketFilterBind::Text(s) => {
                    query_builder = query_builder.bind(s.clone());
                    count_builder = count_builder.bind(s.clone());
                }
                TicketFilterBind::Id(id) => {
                    query_builder = query_builder.bind(*id);
                    count_builder = count_builder.bind(*id);
                }
            }
        }

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows = query_builder.fetch_all(&mut *tx).await?;
        let total = count_builder.fetch_one(&mut *tx).await?;

        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }
}

/// One filter value, bound to both the data and count query in the
/// order [`build_ticket_filter_sql`] emits them.
enum TicketFilterBind {
    Text(String),
    Id(Uuid),
}

/// WHERE fragments + ordered binds for the shared ticket filter set.
///
/// The data query carries `$1` tenant + `$2` limit + `$3` offset, so its
/// filter placeholders start at `$4`; the count query carries `$1`
/// tenant only, so its filter placeholders start at `$2`. `binds` lists
/// the values in the single order both queries bind them.
struct TicketFilterSql {
    data_where: String,
    count_where: String,
    binds: Vec<TicketFilterBind>,
}

/// Build the shared ticket filter clauses for `list_tickets` and
/// `list_ticket_responses` (PMS-197). Both methods share this exact
/// filter taxonomy; constructing the WHERE strings and the ordered bind
/// list in one place is what keeps the data/count placeholder numbering
/// from drifting apart between the two callers.
///
/// `is_open_fragment` is the only SQL that differs between callers:
/// `list_tickets` has no status JOIN and passes a correlated
/// `NOT EXISTS`, while `list_ticket_responses` already INNER JOINs
/// `ticket_statuses ts` and passes `ts.is_closed = FALSE`.
///
/// Invariant: every placeholder-bearing condition pushes to
/// `data_conds`, `count_conds`, AND `binds` together, and advances both
/// indices in lockstep. `#[allow(unused_assignments)]` because the final
/// increment after the last placeholder filter (`assigned_to_id`) is not
/// read today; it is kept so a future placeholder filter added below
/// stays correctly numbered (the previously-missing increment was the
/// latent bug PMS-197 called out).
#[allow(unused_assignments)]
fn build_ticket_filter_sql(filter: &TicketFilter, is_open_fragment: &str) -> TicketFilterSql {
    let mut data_conds = vec!["t.tenant_id = $1".to_string()];
    let mut count_conds = vec!["t.tenant_id = $1".to_string()];
    let mut data_idx = 4;
    let mut count_idx = 2;
    let mut binds = Vec::new();

    if let Some(q) = &filter.q {
        data_conds.push(format!(
            "(t.title ILIKE ${idx} OR t.ticket_number ILIKE ${idx})",
            idx = data_idx
        ));
        count_conds.push(format!(
            "(t.title ILIKE ${idx} OR t.ticket_number ILIKE ${idx})",
            idx = count_idx
        ));
        data_idx += 1;
        count_idx += 1;
        binds.push(TicketFilterBind::Text(format!("%{q}%")));
    }
    if let Some(status_id) = filter.status_id {
        data_conds.push(format!("t.status_id = ${data_idx}"));
        count_conds.push(format!("t.status_id = ${count_idx}"));
        data_idx += 1;
        count_idx += 1;
        binds.push(TicketFilterBind::Id(status_id));
    }
    if let Some(priority_id) = filter.priority_id {
        data_conds.push(format!("t.priority_id = ${data_idx}"));
        count_conds.push(format!("t.priority_id = ${count_idx}"));
        data_idx += 1;
        count_idx += 1;
        binds.push(TicketFilterBind::Id(priority_id));
    }
    if let Some(queue_id) = filter.queue_id {
        data_conds.push(format!("t.queue_id = ${data_idx}"));
        count_conds.push(format!("t.queue_id = ${count_idx}"));
        data_idx += 1;
        count_idx += 1;
        binds.push(TicketFilterBind::Id(queue_id));
    }
    if let Some(company_id) = filter.company_id {
        data_conds.push(format!("t.company_id = ${data_idx}"));
        count_conds.push(format!("t.company_id = ${count_idx}"));
        data_idx += 1;
        count_idx += 1;
        binds.push(TicketFilterBind::Id(company_id));
    }
    if let Some(assigned_to_id) = filter.assigned_to_id {
        data_conds.push(format!("t.assigned_to_id = ${data_idx}"));
        count_conds.push(format!("t.assigned_to_id = ${count_idx}"));
        data_idx += 1;
        count_idx += 1;
        binds.push(TicketFilterBind::Id(assigned_to_id));
    }
    // The remaining conditions are literal SQL (no placeholders, no
    // binds), so they do not touch the indices.
    if filter.is_unassigned == Some(true) {
        data_conds.push("t.assigned_to_id IS NULL".to_string());
        count_conds.push("t.assigned_to_id IS NULL".to_string());
    }
    if filter.is_overdue == Some(true) {
        data_conds.push("t.sla_due_date < NOW() AND t.closed_at IS NULL".to_string());
        count_conds.push("t.sla_due_date < NOW() AND t.closed_at IS NULL".to_string());
    }
    if filter.is_open == Some(true) {
        data_conds.push(is_open_fragment.to_string());
        count_conds.push(is_open_fragment.to_string());
    }

    TicketFilterSql {
        data_where: data_conds.join(" AND "),
        count_where: count_conds.join(" AND "),
        binds,
    }
}

/// SELECT clause shared by [`TicketService::get_ticket_response`] and
/// [`TicketService::list_ticket_responses`]. Centralised so the column
/// list, JOIN graph, and alias names stay in sync between the two.
const TICKET_RESPONSE_SELECT: &str = r#"
SELECT
    t.id, t.ticket_number, t.title, t.description,
    t.source, t.company_id, t.contact_id, t.assigned_to_id,
    t.sla_due_date, t.is_billable, t.billing_status,
    t.estimated_hours, t.actual_hours, t.tags,
    t.closed_at, t.created_at, t.updated_at,
    ts.id   AS status_id,
    ts.name AS status_name,
    ts.color AS status_color,
    ts.is_closed AS status_is_closed,
    tp.id   AS priority_id,
    tp.name AS priority_name,
    tp.color AS priority_color,
    tq.name AS queue_name,
    tt.name AS type_name,
    tc.name AS category_name,
    co.name AS company_name,
    NULLIF(TRIM(COALESCE(ct.first_name, '') || ' ' || COALESCE(ct.last_name, '')), '') AS contact_name,
    NULLIF(TRIM(COALESCE(au.first_name, '') || ' ' || COALESCE(au.last_name, '')), '') AS assigned_to_name,
    COALESCE(TRIM(cu.first_name || ' ' || cu.last_name), '') AS created_by_name
FROM tickets t
INNER JOIN ticket_statuses    ts ON t.status_id   = ts.id
INNER JOIN ticket_priorities  tp ON t.priority_id = tp.id
INNER JOIN ticket_queues      tq ON t.queue_id    = tq.id
LEFT  JOIN ticket_types       tt ON t.type_id     = tt.id
LEFT  JOIN ticket_categories  tc ON t.category_id = tc.id
INNER JOIN companies          co ON t.company_id  = co.id
LEFT  JOIN contacts           ct ON t.contact_id  = ct.id
LEFT  JOIN users              au ON t.assigned_to_id = au.id
LEFT  JOIN users              cu ON t.created_by_id  = cu.id
"#;

// ============================================================================
// DATABASE ROW TYPES
// ============================================================================

#[derive(sqlx::FromRow)]
struct TicketRow {
    id: Uuid,
    tenant_id: Uuid,
    ticket_number: String,
    title: String,
    description: Option<String>,
    status_id: Uuid,
    priority_id: Uuid,
    type_id: Option<Uuid>,
    category_id: Option<Uuid>,
    subcategory_id: Option<Uuid>,
    queue_id: Uuid,
    source: String,
    company_id: Uuid,
    contact_id: Option<Uuid>,
    site_id: Option<Uuid>,
    assigned_to_id: Option<Uuid>,
    team_id: Option<Uuid>,
    parent_ticket_id: Option<Uuid>,
    contract_id: Option<Uuid>,
    sla_id: Option<Uuid>,
    sla_due_date: Option<chrono::DateTime<Utc>>,
    first_response_due: Option<chrono::DateTime<Utc>>,
    first_response_at: Option<chrono::DateTime<Utc>>,
    resolution_due: Option<chrono::DateTime<Utc>>,
    resolved_at: Option<chrono::DateTime<Utc>>,
    closed_at: Option<chrono::DateTime<Utc>>,
    scheduled_start: Option<chrono::DateTime<Utc>>,
    scheduled_end: Option<chrono::DateTime<Utc>>,
    estimated_hours: Option<rust_decimal::Decimal>,
    actual_hours: rust_decimal::Decimal,
    is_billable: bool,
    billing_status: String,
    asset_id: Option<Uuid>,
    custom_fields: serde_json::Value,
    tags: Vec<String>,
    created_by_id: Uuid,
    last_updated_by_id: Option<Uuid>,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
}

impl From<TicketRow> for Ticket {
    fn from(row: TicketRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            ticket_number: row.ticket_number,
            title: row.title,
            description: row.description,
            status_id: row.status_id,
            priority_id: row.priority_id,
            type_id: row.type_id,
            category_id: row.category_id,
            subcategory_id: row.subcategory_id,
            queue_id: row.queue_id,
            source: TicketSource::from_str(&row.source).unwrap_or_default(),
            company_id: row.company_id,
            contact_id: row.contact_id,
            site_id: row.site_id,
            assigned_to_id: row.assigned_to_id,
            team_id: row.team_id,
            parent_ticket_id: row.parent_ticket_id,
            contract_id: row.contract_id,
            sla_id: row.sla_id,
            sla_due_date: row.sla_due_date,
            first_response_due: row.first_response_due,
            first_response_at: row.first_response_at,
            resolution_due: row.resolution_due,
            resolved_at: row.resolved_at,
            closed_at: row.closed_at,
            scheduled_start: row.scheduled_start,
            scheduled_end: row.scheduled_end,
            estimated_hours: row
                .estimated_hours
                .map(|d| d.to_string().parse().unwrap_or(0.0)),
            actual_hours: row.actual_hours.to_string().parse().unwrap_or(0.0),
            is_billable: row.is_billable,
            billing_status: BillingStatus::from_str(&row.billing_status).unwrap_or_default(),
            asset_id: row.asset_id,
            custom_fields: row.custom_fields,
            tags: row.tags,
            created_by_id: row.created_by_id,
            last_updated_by_id: row.last_updated_by_id,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

/// JOINed row built by [`TICKET_RESPONSE_SELECT`]. Lives next to the
/// `From` impl that turns it into a wire-shaped [`TicketResponse`].
#[derive(sqlx::FromRow)]
struct TicketResponseRow {
    id: Uuid,
    ticket_number: String,
    title: String,
    description: Option<String>,
    source: String,
    company_id: Uuid,
    contact_id: Option<Uuid>,
    assigned_to_id: Option<Uuid>,
    sla_due_date: Option<chrono::DateTime<Utc>>,
    is_billable: bool,
    billing_status: String,
    estimated_hours: Option<rust_decimal::Decimal>,
    actual_hours: rust_decimal::Decimal,
    tags: Vec<String>,
    closed_at: Option<chrono::DateTime<Utc>>,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
    status_id: Uuid,
    status_name: String,
    status_color: String,
    status_is_closed: Option<bool>,
    priority_id: Uuid,
    priority_name: String,
    priority_color: String,
    queue_name: String,
    type_name: Option<String>,
    category_name: Option<String>,
    company_name: String,
    contact_name: Option<String>,
    assigned_to_name: Option<String>,
    created_by_name: String,
}

impl From<TicketResponseRow> for TicketResponse {
    fn from(r: TicketResponseRow) -> Self {
        // The joined row already carries everything `compute_sla_status`
        // needs, so reuse the shared helper instead of rebuilding a full
        // Ticket just to call its method.
        let sla_status = compute_sla_status(r.closed_at, r.sla_due_date);

        TicketResponse {
            id: r.id,
            ticket_number: r.ticket_number,
            title: r.title,
            description: r.description,
            status: TicketStatusSummary {
                id: r.status_id,
                name: r.status_name,
                color: r.status_color,
                is_closed: r.status_is_closed.unwrap_or(false),
            },
            priority: TicketPrioritySummary {
                id: r.priority_id,
                name: r.priority_name,
                color: r.priority_color,
            },
            type_name: r.type_name,
            category_name: r.category_name,
            queue_name: r.queue_name,
            source: TicketSource::from_str(&r.source).unwrap_or_default(),
            company_id: r.company_id,
            company_name: r.company_name,
            contact_id: r.contact_id,
            contact_name: r.contact_name,
            assigned_to_id: r.assigned_to_id,
            assigned_to_name: r.assigned_to_name,
            sla_due_date: r.sla_due_date,
            sla_status,
            is_billable: r.is_billable,
            billing_status: BillingStatus::from_str(&r.billing_status).unwrap_or_default(),
            estimated_hours: r
                .estimated_hours
                .map(|d| d.to_string().parse().unwrap_or(0.0)),
            actual_hours: r.actual_hours.to_string().parse().unwrap_or(0.0),
            tags: r.tags,
            created_by_name: r.created_by_name,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct TicketNoteRow {
    id: Uuid,
    tenant_id: Uuid,
    ticket_id: Uuid,
    note_type: String,
    content: String,
    content_html: Option<String>,
    is_email_sent: bool,
    email_sent_at: Option<chrono::DateTime<Utc>>,
    created_by_id: Uuid,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
    created_by_name: Option<String>,
}

impl From<TicketNoteRow> for TicketNote {
    fn from(row: TicketNoteRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            ticket_id: row.ticket_id,
            note_type: NoteType::from_str(&row.note_type).unwrap_or_default(),
            content: row.content,
            content_html: row.content_html,
            is_email_sent: row.is_email_sent,
            email_sent_at: row.email_sent_at,
            created_by_id: row.created_by_id,
            created_by_name: row.created_by_name,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct TicketStatusRow {
    id: Uuid,
    tenant_id: Uuid,
    name: String,
    color: String,
    is_closed: bool,
    is_default: bool,
    sort_order: i32,
}

impl From<TicketStatusRow> for TicketStatus {
    fn from(row: TicketStatusRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            name: row.name,
            color: row.color,
            is_closed: row.is_closed,
            is_default: row.is_default,
            sort_order: row.sort_order,
        }
    }
}

#[derive(sqlx::FromRow)]
struct TicketPriorityRow {
    id: Uuid,
    tenant_id: Uuid,
    name: String,
    color: String,
    icon: Option<String>,
    sla_multiplier: rust_decimal::Decimal,
    sort_order: i32,
    is_default: bool,
}

impl From<TicketPriorityRow> for TicketPriority {
    fn from(row: TicketPriorityRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            name: row.name,
            color: row.color,
            icon: row.icon,
            sla_multiplier: row.sla_multiplier.to_string().parse().unwrap_or(1.0),
            sort_order: row.sort_order,
            is_default: row.is_default,
        }
    }
}

#[derive(sqlx::FromRow)]
struct TicketQueueRow {
    id: Uuid,
    tenant_id: Uuid,
    name: String,
    description: Option<String>,
    color: Option<String>,
    icon: Option<String>,
    is_default: bool,
    sort_order: i32,
}

impl From<TicketQueueRow> for TicketQueue {
    fn from(row: TicketQueueRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            name: row.name,
            description: row.description,
            color: row.color,
            icon: row.icon,
            is_default: row.is_default,
            sort_order: row.sort_order,
        }
    }
}

#[derive(sqlx::FromRow)]
struct TicketTypeRow {
    id: Uuid,
    tenant_id: Uuid,
    name: String,
    description: Option<String>,
    icon: Option<String>,
    is_active: bool,
    sort_order: i32,
}

impl From<TicketTypeRow> for TicketType {
    fn from(row: TicketTypeRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            name: row.name,
            description: row.description,
            icon: row.icon,
            is_active: row.is_active,
            sort_order: row.sort_order,
        }
    }
}
