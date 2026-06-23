//! PMS-448: ticket.created workflow executor.
//!
//! Runs operator-defined rules against a freshly-created ticket and
//! mutates the same row in the same transaction. Failure of any
//! single action is logged to `workflow_rule_runs` and surfaced as
//! the run row's `error`, but does NOT abort the create - a buggy
//! rule should not block legitimate ticket creation. The matching
//! and action-application logic is kept here so it can be unit-
//! tested without spinning up the full create_ticket path.

use uuid::Uuid;

use crate::utils::error::AppResult;

/// Snapshot of the ticket's matchable fields, captured right after
/// INSERT. The executor uses this to decide which rules apply.
/// Fields are intentionally the same as the structured-conditions
/// keys in the migration header so the match logic is a 1:1 mapping.
#[derive(Debug, Clone)]
pub struct TicketCreateContext {
    pub ticket_id: Uuid,
    pub priority_id: Uuid,
    pub queue_id: Uuid,
    pub company_id: Uuid,
    pub source: String,
    pub type_id: Option<Uuid>,
}

/// Pure-function entry point. Pulls every active `ticket.created`
/// rule for the tenant, evaluates conditions in priority order, and
/// applies matching actions. Errors are logged per-rule and do not
/// fail the call - the caller's outer transaction stays committable.
pub struct WorkflowExecutor;

impl WorkflowExecutor {
    pub async fn run_ticket_created(
        tx: &mut sqlx::PgConnection,
        tenant_id: Uuid,
        ctx: TicketCreateContext,
    ) -> AppResult<()> {
        let rules: Vec<RuleRow> = sqlx::query_as(
            "SELECT id, conditions, actions \
             FROM workflow_rules \
             WHERE tenant_id = $1 \
               AND trigger_event = 'ticket.created' \
               AND is_active = true \
             ORDER BY priority ASC, created_at ASC",
        )
        .bind(tenant_id)
        .fetch_all(&mut *tx)
        .await?;

        for rule in rules {
            if !matches_conditions(&rule.conditions, &ctx) {
                continue;
            }
            let outcome = apply_actions(tx, tenant_id, &ctx, &rule.actions).await;
            // Always record the run row, success or failure. The
            // SPA's ticket-detail timeline reads this surface;
            // dropping a failed run would hide buggy rules from the
            // operator.
            let error_msg = outcome.err().map(|e| e.to_string());
            sqlx::query(
                "INSERT INTO workflow_rule_runs \
                     (tenant_id, rule_id, entity_type, entity_id, applied_actions, error) \
                 VALUES ($1, $2, 'tickets', $3, $4, $5)",
            )
            .bind(tenant_id)
            .bind(rule.id)
            .bind(ctx.ticket_id)
            .bind(&rule.actions)
            .bind(error_msg)
            .execute(&mut *tx)
            .await?;
        }
        Ok(())
    }
}

#[derive(sqlx::FromRow)]
struct RuleRow {
    id: Uuid,
    conditions: serde_json::Value,
    actions: serde_json::Value,
}

/// Evaluate a structured conditions blob against the ticket. AND
/// across keys, IN across array values within a key. An empty
/// conditions object matches every ticket.
fn matches_conditions(conditions: &serde_json::Value, ctx: &TicketCreateContext) -> bool {
    let Some(map) = conditions.as_object() else {
        // Non-object conditions are treated as "match nothing" so a
        // typo in the SPA does not silently fire every rule.
        return false;
    };
    if map.is_empty() {
        return true;
    }
    for (key, value) in map {
        let Some(arr) = value.as_array() else {
            return false;
        };
        let ok = match key.as_str() {
            "priority_id" => uuid_in_array(arr, ctx.priority_id),
            "queue_id" => uuid_in_array(arr, ctx.queue_id),
            "company_id" => uuid_in_array(arr, ctx.company_id),
            "type_id" => ctx.type_id.is_some_and(|t| uuid_in_array(arr, t)),
            "source" => arr.iter().any(|v| v.as_str() == Some(ctx.source.as_str())),
            _ => false,
        };
        if !ok {
            return false;
        }
    }
    true
}

fn uuid_in_array(arr: &[serde_json::Value], needle: Uuid) -> bool {
    arr.iter()
        .filter_map(|v| v.as_str())
        .filter_map(|s| Uuid::parse_str(s).ok())
        .any(|u| u == needle)
}

/// Apply the structured actions blob to the ticket. Actions are
/// independent; partial failure of one does not prevent the others
/// from running, but the first error is returned so the run row
/// captures it.
async fn apply_actions(
    tx: &mut sqlx::PgConnection,
    tenant_id: Uuid,
    ctx: &TicketCreateContext,
    actions: &serde_json::Value,
) -> AppResult<()> {
    let Some(map) = actions.as_object() else {
        return Ok(());
    };
    let mut first_error: Option<String> = None;

    if let Some(uid) = map.get("assign_to_user_id").and_then(|v| v.as_str()) {
        match Uuid::parse_str(uid) {
            Ok(uid) => {
                let r = sqlx::query(
                    "UPDATE tickets SET assigned_to_id = $1 WHERE tenant_id = $2 AND id = $3",
                )
                .bind(uid)
                .bind(tenant_id)
                .bind(ctx.ticket_id)
                .execute(&mut *tx)
                .await;
                if let Err(e) = r {
                    first_error.get_or_insert_with(|| format!("assign_to_user_id failed: {e}"));
                }
            }
            Err(e) => {
                first_error.get_or_insert_with(|| format!("assign_to_user_id parse: {e}"));
            }
        }
    }

    if let Some(tid) = map.get("assign_to_team_id").and_then(|v| v.as_str()) {
        match Uuid::parse_str(tid) {
            Ok(tid) => {
                let r =
                    sqlx::query("UPDATE tickets SET team_id = $1 WHERE tenant_id = $2 AND id = $3")
                        .bind(tid)
                        .bind(tenant_id)
                        .bind(ctx.ticket_id)
                        .execute(&mut *tx)
                        .await;
                if let Err(e) = r {
                    first_error.get_or_insert_with(|| format!("assign_to_team_id failed: {e}"));
                }
            }
            Err(e) => {
                first_error.get_or_insert_with(|| format!("assign_to_team_id parse: {e}"));
            }
        }
    }

    if let Some(pid) = map.get("set_priority_id").and_then(|v| v.as_str()) {
        match Uuid::parse_str(pid) {
            Ok(pid) => {
                let r = sqlx::query(
                    "UPDATE tickets SET priority_id = $1 WHERE tenant_id = $2 AND id = $3",
                )
                .bind(pid)
                .bind(tenant_id)
                .bind(ctx.ticket_id)
                .execute(&mut *tx)
                .await;
                if let Err(e) = r {
                    first_error.get_or_insert_with(|| format!("set_priority_id failed: {e}"));
                }
            }
            Err(e) => {
                first_error.get_or_insert_with(|| format!("set_priority_id parse: {e}"));
            }
        }
    }

    if let Some(tag) = map.get("add_tag").and_then(|v| v.as_str()) {
        // Idempotent via array_append guard.
        let r = sqlx::query(
            "UPDATE tickets SET tags = array_append(tags, $1) \
             WHERE tenant_id = $2 AND id = $3 AND NOT ($1 = ANY(tags))",
        )
        .bind(tag)
        .bind(tenant_id)
        .bind(ctx.ticket_id)
        .execute(&mut *tx)
        .await;
        if let Err(e) = r {
            first_error.get_or_insert_with(|| format!("add_tag failed: {e}"));
        }
    }

    if let Some(note) = map.get("add_internal_note").and_then(|v| v.as_str()) {
        // Find a fallback admin to satisfy `ticket_notes.created_by_id`
        // (NOT NULL FK to users). The note is attributed to the
        // workflow's owner conceptually but the column is mandatory.
        let creator: Option<Uuid> = match sqlx::query_scalar(
            "SELECT id FROM users WHERE tenant_id = $1 AND status = 'active' \
                 AND role IN ('super_admin', 'admin', 'manager') \
             ORDER BY created_at LIMIT 1",
        )
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await
        {
            Ok(opt) => opt,
            Err(e) => {
                first_error.get_or_insert_with(|| format!("add_internal_note creator lookup: {e}"));
                None
            }
        };
        if let Some(creator) = creator {
            let r = sqlx::query(
                "INSERT INTO ticket_notes \
                     (tenant_id, ticket_id, note_type, content, created_by_id) \
                 VALUES ($1, $2, 'internal', $3, $4)",
            )
            .bind(tenant_id)
            .bind(ctx.ticket_id)
            .bind(note)
            .bind(creator)
            .execute(&mut *tx)
            .await;
            if let Err(e) = r {
                first_error.get_or_insert_with(|| format!("add_internal_note failed: {e}"));
            }
        }
    }

    match first_error {
        Some(msg) => Err(crate::utils::error::AppError::Internal(msg)),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ctx() -> TicketCreateContext {
        TicketCreateContext {
            ticket_id: Uuid::new_v4(),
            priority_id: Uuid::from_u128(0x1111),
            queue_id: Uuid::from_u128(0x2222),
            company_id: Uuid::from_u128(0x3333),
            source: "email".into(),
            type_id: None,
        }
    }

    #[test]
    fn empty_conditions_match_anything() {
        assert!(matches_conditions(&json!({}), &ctx()));
    }

    #[test]
    fn priority_id_in_array_matches() {
        let cond = json!({ "priority_id": [Uuid::from_u128(0x1111).to_string()] });
        assert!(matches_conditions(&cond, &ctx()));
    }

    #[test]
    fn priority_id_outside_array_misses() {
        let cond = json!({ "priority_id": [Uuid::from_u128(0x9999).to_string()] });
        assert!(!matches_conditions(&cond, &ctx()));
    }

    #[test]
    fn unknown_condition_key_misses() {
        // A typo'd key (`pri0rity_id`) must NOT silently fire every
        // rule - it should fail closed.
        let cond = json!({ "pri0rity_id": [Uuid::from_u128(0x1111).to_string()] });
        assert!(!matches_conditions(&cond, &ctx()));
    }

    #[test]
    fn source_string_in_list_matches() {
        let cond = json!({ "source": ["portal", "email"] });
        assert!(matches_conditions(&cond, &ctx()));
    }

    #[test]
    fn and_across_keys_requires_all() {
        let cond = json!({
            "source": ["email"],
            "priority_id": [Uuid::from_u128(0x9999).to_string()],
        });
        // priority misses; whole match misses despite source match.
        assert!(!matches_conditions(&cond, &ctx()));
    }
}
