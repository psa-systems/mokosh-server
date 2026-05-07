//! Ticket automation engine
//!
//! Handles ticket automation rules including:
//! - On create triggers
//! - On update triggers
//! - Scheduled triggers
//! - SLA breach/warning triggers

use uuid::Uuid;

use crate::db::Database;
use crate::utils::error::AppResult;

use super::models::*;

/// Automation engine for processing ticket automation rules
#[derive(Clone)]
pub struct AutomationEngine {
    db: Database,
}

impl AutomationEngine {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Process automation rules for a trigger type
    pub async fn process_rules(
        &self,
        tenant_id: Uuid,
        ticket_id: Uuid,
        trigger: AutomationTrigger,
    ) -> AppResult<()> {
        // Get active rules for this trigger type
        let rules = self.get_active_rules(tenant_id, trigger).await?;

        for rule in rules {
            if self
                .evaluate_conditions(tenant_id, ticket_id, &rule)
                .await?
            {
                self.execute_actions(tenant_id, ticket_id, &rule).await?;
            }
        }

        Ok(())
    }

    /// Get active automation rules for a trigger type
    async fn get_active_rules(
        &self,
        tenant_id: Uuid,
        trigger: AutomationTrigger,
    ) -> AppResult<Vec<AutomationRule>> {
        let rows = sqlx::query_as::<_, AutomationRuleRow>(
            r#"
            SELECT id, tenant_id, name, description, is_active, trigger_type,
                   conditions, actions, priority, last_run_at, run_count,
                   created_at, updated_at
            FROM ticket_automation_rules
            WHERE tenant_id = $1 AND trigger_type = $2 AND is_active = TRUE
            ORDER BY priority ASC
            "#,
        )
        .bind(tenant_id)
        .bind(trigger.as_str())
        .fetch_all(self.db.pool())
        .await?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Evaluate if rule conditions match the ticket
    async fn evaluate_conditions(
        &self,
        tenant_id: Uuid,
        ticket_id: Uuid,
        rule: &AutomationRule,
    ) -> AppResult<bool> {
        // Parse conditions from JSON
        let conditions: Vec<AutomationCondition> =
            serde_json::from_value(rule.conditions.clone()).unwrap_or_default();

        if conditions.is_empty() {
            return Ok(true); // No conditions means always match
        }

        // Get ticket data
        let ticket = sqlx::query_as::<_, TicketDataRow>(
            r#"
            SELECT t.*, s.name as status_name, p.name as priority_name
            FROM tickets t
            LEFT JOIN ticket_statuses s ON t.status_id = s.id
            LEFT JOIN ticket_priorities p ON t.priority_id = p.id
            WHERE t.tenant_id = $1 AND t.id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(ticket_id)
        .fetch_optional(self.db.pool())
        .await?;

        let Some(ticket) = ticket else {
            return Ok(false);
        };

        // Evaluate each condition
        for condition in conditions {
            if !self.evaluate_condition(&ticket, &condition) {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Evaluate a single condition against ticket data
    fn evaluate_condition(&self, ticket: &TicketDataRow, condition: &AutomationCondition) -> bool {
        let field_value = match condition.field.as_str() {
            "status" => Some(ticket.status_name.clone()),
            "priority" => Some(ticket.priority_name.clone()),
            "company_id" => Some(ticket.company_id.to_string()),
            "assigned_to_id" => ticket.assigned_to_id.map(|id| id.to_string()),
            "source" => Some(ticket.source.clone()),
            "is_billable" => Some(ticket.is_billable.to_string()),
            _ => None,
        };

        let Some(value) = field_value else {
            return false;
        };

        let expected = condition.value.as_str().unwrap_or("").to_string();

        match condition.operator.as_str() {
            "equals" => value == expected,
            "not_equals" => value != expected,
            "contains" => value.contains(&expected),
            "starts_with" => value.starts_with(&expected),
            "ends_with" => value.ends_with(&expected),
            "is_null" => value.is_empty(),
            "is_not_null" => !value.is_empty(),
            _ => false,
        }
    }

    /// Execute automation rule actions
    async fn execute_actions(
        &self,
        tenant_id: Uuid,
        ticket_id: Uuid,
        rule: &AutomationRule,
    ) -> AppResult<()> {
        let actions: Vec<AutomationAction> =
            serde_json::from_value(rule.actions.clone()).unwrap_or_default();

        for action in actions {
            match action.action_type.as_str() {
                "set_status" => {
                    if let Some(status_id) = action.params.get("status_id").and_then(|v| v.as_str())
                    {
                        if let Ok(id) = Uuid::parse_str(status_id) {
                            sqlx::query(
                                "UPDATE tickets SET status_id = $1, updated_at = NOW() WHERE id = $2",
                            )
                            .bind(id)
                            .bind(ticket_id)
                            .execute(self.db.pool())
                            .await?;
                        }
                    }
                }
                "set_priority" => {
                    if let Some(priority_id) =
                        action.params.get("priority_id").and_then(|v| v.as_str())
                    {
                        if let Ok(id) = Uuid::parse_str(priority_id) {
                            sqlx::query(
                                "UPDATE tickets SET priority_id = $1, updated_at = NOW() WHERE id = $2",
                            )
                            .bind(id)
                            .bind(ticket_id)
                            .execute(self.db.pool())
                            .await?;
                        }
                    }
                }
                "assign_to" => {
                    if let Some(user_id) = action.params.get("user_id").and_then(|v| v.as_str()) {
                        if let Ok(id) = Uuid::parse_str(user_id) {
                            sqlx::query(
                                "UPDATE tickets SET assigned_to_id = $1, updated_at = NOW() WHERE id = $2",
                            )
                            .bind(id)
                            .bind(ticket_id)
                            .execute(self.db.pool())
                            .await?;
                        }
                    }
                }
                "set_queue" => {
                    if let Some(queue_id) = action.params.get("queue_id").and_then(|v| v.as_str()) {
                        if let Ok(id) = Uuid::parse_str(queue_id) {
                            sqlx::query(
                                "UPDATE tickets SET queue_id = $1, updated_at = NOW() WHERE id = $2",
                            )
                            .bind(id)
                            .bind(ticket_id)
                            .execute(self.db.pool())
                            .await?;
                        }
                    }
                }
                "add_note" => {
                    if let Some(content) = action.params.get("content").and_then(|v| v.as_str()) {
                        let note_type = action
                            .params
                            .get("note_type")
                            .and_then(|v| v.as_str())
                            .unwrap_or("internal");
                        sqlx::query(
                            "INSERT INTO ticket_notes (id, tenant_id, ticket_id, note_type, content, created_by_id) VALUES ($1, $2, $3, $4, $5, $6)",
                        )
                        .bind(Uuid::new_v4())
                        .bind(tenant_id)
                        .bind(ticket_id)
                        .bind(note_type)
                        .bind(content)
                        .bind(Uuid::nil()) // System-generated
                        .execute(self.db.pool())
                        .await?;
                    }
                }
                "send_notification" => {
                    // TODO: Trigger notification through notification module
                    tracing::info!(
                        "Would send notification for ticket {} with params {:?}",
                        ticket_id,
                        action.params
                    );
                }
                "webhook" => {
                    // TODO: Execute webhook
                    tracing::info!(
                        "Would execute webhook for ticket {} with params {:?}",
                        ticket_id,
                        action.params
                    );
                }
                _ => {
                    tracing::warn!("Unknown automation action type: {}", action.action_type);
                }
            }
        }

        // Update rule stats
        sqlx::query(
            "UPDATE ticket_automation_rules SET last_run_at = NOW(), run_count = run_count + 1 WHERE id = $1",
        )
        .bind(rule.id)
        .execute(self.db.pool())
        .await?;

        Ok(())
    }
}

#[derive(sqlx::FromRow)]
struct AutomationRuleRow {
    id: Uuid,
    tenant_id: Uuid,
    name: String,
    description: Option<String>,
    is_active: bool,
    trigger_type: String,
    conditions: serde_json::Value,
    actions: serde_json::Value,
    priority: i32,
    last_run_at: Option<chrono::DateTime<chrono::Utc>>,
    run_count: i32,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<AutomationRuleRow> for AutomationRule {
    fn from(row: AutomationRuleRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            name: row.name,
            description: row.description,
            is_active: row.is_active,
            trigger_type: AutomationTrigger::from_str(&row.trigger_type)
                .unwrap_or(AutomationTrigger::OnCreate),
            conditions: row.conditions,
            actions: row.actions,
            priority: row.priority,
            last_run_at: row.last_run_at,
            run_count: row.run_count,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(sqlx::FromRow)]
#[allow(dead_code)] // `id` mirrors the ticket PK we already passed in; kept for FromRow symmetry with the SELECT.
struct TicketDataRow {
    id: Uuid,
    company_id: Uuid,
    assigned_to_id: Option<Uuid>,
    source: String,
    is_billable: bool,
    status_name: String,
    priority_name: String,
}
