//! Ticket service implementation

use chrono::Utc;
use std::sync::Arc;
use uuid::Uuid;

use crate::db::Database;
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
        }
    }

    /// Generate next ticket number for tenant
    async fn next_ticket_number(&self, tenant_id: Uuid) -> AppResult<String> {
        let row = sqlx::query_as::<_, (i32,)>(
            r#"
            UPDATE ticket_sequences
            SET last_number = last_number + 1
            WHERE tenant_id = $1
            RETURNING last_number
            "#,
        )
        .bind(tenant_id)
        .fetch_one(self.db.pool())
        .await?;

        Ok(format!("T{:06}", row.0))
    }

    /// Create a new ticket
    pub async fn create_ticket(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        request: &CreateTicketRequest,
    ) -> AppResult<Ticket> {
        let ticket_id = Uuid::new_v4();
        let ticket_number = self.next_ticket_number(tenant_id).await?;

        // Get default status
        let default_status_id: Uuid = sqlx::query_scalar(
            "SELECT id FROM ticket_statuses WHERE tenant_id = $1 AND is_default = TRUE LIMIT 1",
        )
        .bind(tenant_id)
        .fetch_optional(self.db.pool())
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
            .fetch_optional(self.db.pool())
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
            .fetch_optional(self.db.pool())
            .await?
            .ok_or_else(|| AppError::Configuration("No default queue configured".to_string()))?,
        };

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
        .execute(self.db.pool())
        .await?;

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
    pub async fn get_ticket(&self, tenant_id: Uuid, ticket_id: Uuid) -> AppResult<Ticket> {
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
        .fetch_optional(self.db.pool())
        .await?
        .ok_or_else(|| AppError::NotFound("Ticket".to_string()))?;

        Ok(row.into())
    }

    /// Get ticket by number
    pub async fn get_ticket_by_number(
        &self,
        tenant_id: Uuid,
        ticket_number: &str,
    ) -> AppResult<Ticket> {
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
        .fetch_optional(self.db.pool())
        .await?
        .ok_or_else(|| AppError::NotFound("Ticket".to_string()))?;

        Ok(row.into())
    }

    /// List tickets with filters
    // See update_company in contacts/service.rs for the dynamic-filter
    // pattern: the trailing `param_idx += 1` keeps the next added
    // condition one line of diff away.
    #[allow(unused_assignments)]
    pub async fn list_tickets(
        &self,
        tenant_id: Uuid,
        filter: &TicketFilter,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<Ticket>, u64)> {
        let offset = pagination.offset() as i32;
        let limit = pagination.limit() as i32;

        // Build query with filters
        let mut conditions = vec!["t.tenant_id = $1".to_string()];
        let mut param_idx = 4;

        if filter.q.is_some() {
            conditions.push(format!(
                "(t.title ILIKE ${} OR t.ticket_number ILIKE ${})",
                param_idx, param_idx
            ));
            param_idx += 1;
        }
        if filter.status_id.is_some() {
            conditions.push(format!("t.status_id = ${}", param_idx));
            param_idx += 1;
        }
        if filter.priority_id.is_some() {
            conditions.push(format!("t.priority_id = ${}", param_idx));
            param_idx += 1;
        }
        if filter.queue_id.is_some() {
            conditions.push(format!("t.queue_id = ${}", param_idx));
            param_idx += 1;
        }
        if filter.company_id.is_some() {
            conditions.push(format!("t.company_id = ${}", param_idx));
            param_idx += 1;
        }
        if filter.assigned_to_id.is_some() {
            conditions.push(format!("t.assigned_to_id = ${}", param_idx));
            param_idx += 1;
        }
        if filter.is_unassigned == Some(true) {
            conditions.push("t.assigned_to_id IS NULL".to_string());
        }
        if filter.is_overdue == Some(true) {
            conditions.push("t.sla_due_date < NOW() AND t.closed_at IS NULL".to_string());
        }
        if filter.is_open == Some(true) {
            conditions.push(
                "NOT EXISTS (SELECT 1 FROM ticket_statuses s WHERE s.id = t.status_id AND s.is_closed = TRUE)".to_string()
            );
        }

        let where_clause = conditions.join(" AND ");
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
            WHERE {}
            ORDER BY {}
            LIMIT $2 OFFSET $3
            "#,
            where_clause, order_by
        );

        let count_query = format!("SELECT COUNT(*) FROM tickets t WHERE {}", where_clause);

        // Build queries with dynamic parameters
        let mut query_builder = sqlx::query_as::<_, TicketRow>(&query)
            .bind(tenant_id)
            .bind(limit)
            .bind(offset);

        let mut count_builder = sqlx::query_scalar::<_, i64>(&count_query).bind(tenant_id);

        if let Some(ref q) = filter.q {
            let search = format!("%{}%", q);
            query_builder = query_builder.bind(search.clone());
            count_builder = count_builder.bind(search);
        }
        if let Some(ref status_id) = filter.status_id {
            query_builder = query_builder.bind(status_id);
            count_builder = count_builder.bind(status_id);
        }
        if let Some(ref priority_id) = filter.priority_id {
            query_builder = query_builder.bind(priority_id);
            count_builder = count_builder.bind(priority_id);
        }
        if let Some(ref queue_id) = filter.queue_id {
            query_builder = query_builder.bind(queue_id);
            count_builder = count_builder.bind(queue_id);
        }
        if let Some(ref company_id) = filter.company_id {
            query_builder = query_builder.bind(company_id);
            count_builder = count_builder.bind(company_id);
        }
        if let Some(ref assigned_to_id) = filter.assigned_to_id {
            query_builder = query_builder.bind(assigned_to_id);
            count_builder = count_builder.bind(assigned_to_id);
        }

        let rows = query_builder.fetch_all(self.db.pool()).await?;
        let total = count_builder.fetch_one(self.db.pool()).await?;

        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    /// Update ticket
    pub async fn update_ticket(
        &self,
        tenant_id: Uuid,
        ticket_id: Uuid,
        user_id: Uuid,
        request: &UpdateTicketRequest,
    ) -> AppResult<Ticket> {
        let ticket = self.get_ticket(tenant_id, ticket_id).await?;
        // Captured for a future "status changed" automation trigger;
        // the F11 wiring only fires the generic OnUpdate today.
        let _old_status_id = ticket.status_id;

        // Build update
        if let Some(ref title) = request.title {
            sqlx::query("UPDATE tickets SET title = $1, last_updated_by_id = $2, updated_at = NOW() WHERE tenant_id = $3 AND id = $4")
                .bind(title)
                .bind(user_id)
                .bind(tenant_id)
                .bind(ticket_id)
                .execute(self.db.pool())
                .await?;
        }

        if let Some(ref description) = request.description {
            sqlx::query("UPDATE tickets SET description = $1, last_updated_by_id = $2, updated_at = NOW() WHERE tenant_id = $3 AND id = $4")
                .bind(description)
                .bind(user_id)
                .bind(tenant_id)
                .bind(ticket_id)
                .execute(self.db.pool())
                .await?;
        }

        if let Some(status_id) = request.status_id {
            // Check if status is closing the ticket
            let is_closed: bool =
                sqlx::query_scalar("SELECT is_closed FROM ticket_statuses WHERE id = $1")
                    .bind(status_id)
                    .fetch_one(self.db.pool())
                    .await?;

            if is_closed && ticket.closed_at.is_none() {
                sqlx::query(
                    "UPDATE tickets SET status_id = $1, closed_at = NOW(), resolved_at = COALESCE(resolved_at, NOW()), last_updated_by_id = $2, updated_at = NOW() WHERE tenant_id = $3 AND id = $4",
                )
                .bind(status_id)
                .bind(user_id)
                .bind(tenant_id)
                .bind(ticket_id)
                .execute(self.db.pool())
                .await?;
            } else {
                sqlx::query(
                    "UPDATE tickets SET status_id = $1, last_updated_by_id = $2, updated_at = NOW() WHERE tenant_id = $3 AND id = $4",
                )
                .bind(status_id)
                .bind(user_id)
                .bind(tenant_id)
                .bind(ticket_id)
                .execute(self.db.pool())
                .await?;
            }
        }

        if let Some(priority_id) = request.priority_id {
            sqlx::query("UPDATE tickets SET priority_id = $1, last_updated_by_id = $2, updated_at = NOW() WHERE tenant_id = $3 AND id = $4")
                .bind(priority_id)
                .bind(user_id)
                .bind(tenant_id)
                .bind(ticket_id)
                .execute(self.db.pool())
                .await?;

            // Recalculate SLA when priority changes
            self.calculate_sla_dates(tenant_id, ticket_id).await?;
        }

        if let Some(assigned_to_id) = request.assigned_to_id {
            sqlx::query("UPDATE tickets SET assigned_to_id = $1, last_updated_by_id = $2, updated_at = NOW() WHERE tenant_id = $3 AND id = $4")
                .bind(assigned_to_id)
                .bind(user_id)
                .bind(tenant_id)
                .bind(ticket_id)
                .execute(self.db.pool())
                .await?;
        }

        if let Some(queue_id) = request.queue_id {
            sqlx::query("UPDATE tickets SET queue_id = $1, last_updated_by_id = $2, updated_at = NOW() WHERE tenant_id = $3 AND id = $4")
                .bind(queue_id)
                .bind(user_id)
                .bind(tenant_id)
                .bind(ticket_id)
                .execute(self.db.pool())
                .await?;
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

    /// Assign ticket to user
    pub async fn assign_ticket(
        &self,
        tenant_id: Uuid,
        ticket_id: Uuid,
        assigned_to_id: Uuid,
        user_id: Uuid,
    ) -> AppResult<Ticket> {
        sqlx::query(
            "UPDATE tickets SET assigned_to_id = $1, last_updated_by_id = $2, updated_at = NOW() WHERE tenant_id = $3 AND id = $4",
        )
        .bind(assigned_to_id)
        .bind(user_id)
        .bind(tenant_id)
        .bind(ticket_id)
        .execute(self.db.pool())
        .await?;

        self.get_ticket(tenant_id, ticket_id).await
    }

    /// Add note to ticket
    pub async fn add_note(
        &self,
        tenant_id: Uuid,
        ticket_id: Uuid,
        user_id: Uuid,
        request: &CreateNoteRequest,
    ) -> AppResult<TicketNote> {
        let note_id = Uuid::new_v4();

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
        .execute(self.db.pool())
        .await?;

        // Update ticket's updated_at
        sqlx::query("UPDATE tickets SET updated_at = NOW(), last_updated_by_id = $1 WHERE id = $2")
            .bind(user_id)
            .bind(ticket_id)
            .execute(self.db.pool())
            .await?;

        // Record first response if this is a public note and first response hasn't been recorded
        if request.note_type == NoteType::Public {
            sqlx::query(
                "UPDATE tickets SET first_response_at = COALESCE(first_response_at, NOW()) WHERE id = $1",
            )
            .bind(ticket_id)
            .execute(self.db.pool())
            .await?;
        }

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
        tenant_id: Uuid,
        ticket_id: Uuid,
        note_id: Uuid,
        content: &str,
    ) {
        // One round-trip fetches ticket-number/title + contact email.
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
        .fetch_optional(self.db.pool())
        .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(?e, %ticket_id, "fetch contact for note email failed");
                return;
            }
        };

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

        match self.mailer.send_text(&email, &subject, &body).await {
            Ok(()) => {
                if let Err(e) = sqlx::query(
                    "UPDATE ticket_notes SET is_email_sent = TRUE, email_sent_at = NOW() WHERE id = $1",
                )
                .bind(note_id)
                .execute(self.db.pool())
                .await
                {
                    tracing::warn!(?e, %note_id, "mark is_email_sent failed");
                } else {
                    tracing::info!(%note_id, "ticket note email sent");
                }
            }
            Err(e) => tracing::warn!(?e, %note_id, "ticket note email send failed"),
        }
    }

    /// Get note by ID
    pub async fn get_note(&self, tenant_id: Uuid, note_id: Uuid) -> AppResult<TicketNote> {
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
        .fetch_optional(self.db.pool())
        .await?
        .ok_or_else(|| AppError::NotFound("Note".to_string()))?;

        Ok(row.into())
    }

    /// Get notes for a ticket
    pub async fn get_ticket_notes(
        &self,
        tenant_id: Uuid,
        ticket_id: Uuid,
    ) -> AppResult<Vec<TicketNote>> {
        let rows = sqlx::query_as::<_, TicketNoteRow>(
            r#"
            SELECT n.id, n.tenant_id, n.ticket_id, n.note_type, n.content, n.content_html,
                   n.is_email_sent, n.email_sent_at, n.created_by_id, n.created_at, n.updated_at,
                   u.first_name || ' ' || u.last_name as created_by_name
            FROM ticket_notes n
            LEFT JOIN users u ON n.created_by_id = u.id
            WHERE n.tenant_id = $1 AND n.ticket_id = $2
            ORDER BY n.created_at DESC
            "#,
        )
        .bind(tenant_id)
        .bind(ticket_id)
        .fetch_all(self.db.pool())
        .await?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Calculate SLA due dates for a ticket
    async fn calculate_sla_dates(&self, tenant_id: Uuid, ticket_id: Uuid) -> AppResult<()> {
        // Get ticket details
        let ticket = self.get_ticket(tenant_id, ticket_id).await?;

        // Get SLA policy
        let sla_id = match ticket.sla_id {
            Some(id) => id,
            None => {
                // Try to get default SLA
                let default: Option<Uuid> = sqlx::query_scalar(
                    "SELECT id FROM sla_policies WHERE tenant_id = $1 AND is_default = TRUE LIMIT 1",
                )
                .bind(tenant_id)
                .fetch_optional(self.db.pool())
                .await?;

                match default {
                    Some(id) => id,
                    None => return Ok(()), // No SLA applicable
                }
            }
        };

        // Get SLA targets for this priority
        let targets = sqlx::query_as::<_, (Option<f64>, Option<f64>)>(
            r#"
            SELECT first_response_hours, resolution_hours
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

            sqlx::query(
                "UPDATE tickets SET sla_id = $1, first_response_due = $2, sla_due_date = $3, resolution_due = $3 WHERE id = $4",
            )
            .bind(sla_id)
            .bind(first_response_due)
            .bind(sla_due_date)
            .bind(ticket_id)
            .execute(self.db.pool())
            .await?;
        }

        Ok(())
    }

    /// Get ticket statuses for tenant
    pub async fn get_statuses(&self, tenant_id: Uuid) -> AppResult<Vec<TicketStatus>> {
        let rows = sqlx::query_as::<_, TicketStatusRow>(
            r#"
            SELECT id, tenant_id, name, color, is_closed, is_default, sort_order
            FROM ticket_statuses
            WHERE tenant_id = $1
            ORDER BY sort_order
            "#,
        )
        .bind(tenant_id)
        .fetch_all(self.db.pool())
        .await?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Get ticket priorities for tenant
    pub async fn get_priorities(&self, tenant_id: Uuid) -> AppResult<Vec<TicketPriority>> {
        let rows = sqlx::query_as::<_, TicketPriorityRow>(
            r#"
            SELECT id, tenant_id, name, color, icon, sla_multiplier, sort_order, is_default
            FROM ticket_priorities
            WHERE tenant_id = $1
            ORDER BY sort_order
            "#,
        )
        .bind(tenant_id)
        .fetch_all(self.db.pool())
        .await?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Get ticket queues for tenant
    pub async fn get_queues(&self, tenant_id: Uuid) -> AppResult<Vec<TicketQueue>> {
        let rows = sqlx::query_as::<_, TicketQueueRow>(
            r#"
            SELECT id, tenant_id, name, description, color, icon, is_default, sort_order
            FROM ticket_queues
            WHERE tenant_id = $1
            ORDER BY sort_order
            "#,
        )
        .bind(tenant_id)
        .fetch_all(self.db.pool())
        .await?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Get ticket types for tenant
    pub async fn get_types(&self, tenant_id: Uuid) -> AppResult<Vec<TicketType>> {
        let rows = sqlx::query_as::<_, TicketTypeRow>(
            r#"
            SELECT id, tenant_id, name, description, icon, is_active, sort_order
            FROM ticket_types
            WHERE tenant_id = $1 AND is_active = TRUE
            ORDER BY sort_order
            "#,
        )
        .bind(tenant_id)
        .fetch_all(self.db.pool())
        .await?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Create a portal-originated ticket. Used by `POST
    /// /api/v1/portal/tickets`. Looks up an admin user in the tenant to
    /// satisfy the NOT NULL FK on `tickets.created_by_id` (portal
    /// contacts are not in the `users` table); the customer-visible
    /// identity is captured by `contact_id`. Returns the fully-joined
    /// response so the portal client renders names not UUIDs.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_portal_ticket(
        &self,
        tenant_id: Uuid,
        company_id: Uuid,
        contact_id: Uuid,
        title: String,
        description: Option<String>,
        priority_id: Option<Uuid>,
        type_id: Option<Uuid>,
    ) -> AppResult<TicketResponse> {
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
        .fetch_optional(self.db.pool())
        .await?;

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
        let ticket = self.create_ticket(tenant_id, creator, &request).await?;
        self.get_ticket_response(tenant_id, ticket.id).await
    }

    /// List tickets visible to a portal contact. Scoped to
    /// `company_id`; the contact sees every ticket their company has
    /// opened, not just ones where `contact_id = self`. This matches
    /// the typical helpdesk model where employees of company X can
    /// follow each other's tickets.
    pub async fn list_portal_tickets(
        &self,
        tenant_id: Uuid,
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
    pub async fn get_portal_ticket(
        &self,
        tenant_id: Uuid,
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
    pub async fn get_ticket_response(
        &self,
        tenant_id: Uuid,
        ticket_id: Uuid,
    ) -> AppResult<TicketResponse> {
        let sql = format!(
            "{} WHERE t.tenant_id = $1 AND t.id = $2",
            TICKET_RESPONSE_SELECT
        );
        let row = sqlx::query_as::<_, TicketResponseRow>(&sql)
            .bind(tenant_id)
            .bind(ticket_id)
            .fetch_optional(self.db.pool())
            .await?
            .ok_or_else(|| AppError::NotFound("Ticket".to_string()))?;
        Ok(row.into())
    }

    /// List fully-joined ticket responses + total. Mirrors the filter
    /// semantics of [`TicketService::list_tickets`] but produces
    /// response DTOs directly. Audit F3.
    pub async fn list_ticket_responses(
        &self,
        tenant_id: Uuid,
        filter: &TicketFilter,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<TicketResponse>, u64)> {
        let offset = pagination.offset() as i32;
        let limit = pagination.limit() as i32;

        let mut conditions = vec!["t.tenant_id = $1".to_string()];
        let mut param_idx = 4;
        if filter.q.is_some() {
            conditions.push(format!(
                "(t.title ILIKE ${} OR t.ticket_number ILIKE ${})",
                param_idx, param_idx
            ));
            param_idx += 1;
        }
        if filter.status_id.is_some() {
            conditions.push(format!("t.status_id = ${}", param_idx));
            param_idx += 1;
        }
        if filter.priority_id.is_some() {
            conditions.push(format!("t.priority_id = ${}", param_idx));
            param_idx += 1;
        }
        if filter.queue_id.is_some() {
            conditions.push(format!("t.queue_id = ${}", param_idx));
            param_idx += 1;
        }
        if filter.company_id.is_some() {
            conditions.push(format!("t.company_id = ${}", param_idx));
            param_idx += 1;
        }
        if filter.assigned_to_id.is_some() {
            conditions.push(format!("t.assigned_to_id = ${}", param_idx));
        }
        if filter.is_unassigned == Some(true) {
            conditions.push("t.assigned_to_id IS NULL".to_string());
        }
        if filter.is_overdue == Some(true) {
            conditions.push("t.sla_due_date < NOW() AND t.closed_at IS NULL".to_string());
        }
        if filter.is_open == Some(true) {
            conditions.push("ts.is_closed = FALSE".to_string());
        }

        let where_clause = conditions.join(" AND ");
        let order_by = pagination.order_by(
            "t.created_at",
            &["created_at", "updated_at", "sla_due_date", "priority_id"],
        );

        let query = format!(
            "{select} WHERE {where_clause} ORDER BY {order_by} LIMIT $2 OFFSET $3",
            select = TICKET_RESPONSE_SELECT,
        );
        let count_query =
            format!("SELECT COUNT(*) FROM tickets t INNER JOIN ticket_statuses ts ON t.status_id = ts.id WHERE {}", where_clause);

        let mut query_builder = sqlx::query_as::<_, TicketResponseRow>(&query)
            .bind(tenant_id)
            .bind(limit)
            .bind(offset);
        let mut count_builder = sqlx::query_scalar::<_, i64>(&count_query).bind(tenant_id);

        if let Some(ref q) = filter.q {
            let search = format!("%{}%", q);
            query_builder = query_builder.bind(search.clone());
            count_builder = count_builder.bind(search);
        }
        if let Some(ref status_id) = filter.status_id {
            query_builder = query_builder.bind(status_id);
            count_builder = count_builder.bind(status_id);
        }
        if let Some(ref priority_id) = filter.priority_id {
            query_builder = query_builder.bind(priority_id);
            count_builder = count_builder.bind(priority_id);
        }
        if let Some(ref queue_id) = filter.queue_id {
            query_builder = query_builder.bind(queue_id);
            count_builder = count_builder.bind(queue_id);
        }
        if let Some(ref company_id) = filter.company_id {
            query_builder = query_builder.bind(company_id);
            count_builder = count_builder.bind(company_id);
        }
        if let Some(ref assigned_to_id) = filter.assigned_to_id {
            query_builder = query_builder.bind(assigned_to_id);
            count_builder = count_builder.bind(assigned_to_id);
        }

        let rows = query_builder.fetch_all(self.db.pool()).await?;
        let total = count_builder.fetch_one(self.db.pool()).await?;

        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
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
        // Local mirror of [`Ticket::sla_status`] — kept here because
        // the joined row already carries everything needed, and pulling
        // the rest of the Ticket struct just to call the method would
        // double the bookkeeping.
        let sla_status = if r.closed_at.is_some() {
            SlaStatus::NotApplicable
        } else if let Some(due) = r.sla_due_date {
            let now = Utc::now();
            if now > due {
                SlaStatus::Breached
            } else if (due - now).num_hours() < 2 {
                SlaStatus::Warning
            } else {
                SlaStatus::OnTrack
            }
        } else {
            SlaStatus::NotApplicable
        };

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
