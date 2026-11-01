//! PMS-448: ticket workflow executor.
//!
//! Runs operator-defined rules against ticket lifecycle events and
//! mutates the same row in the same transaction.
//!
//! * Phase 1 (`ticket.created`): rules whose conditions match the
//!   freshly-inserted ticket apply mutating actions (assign, retag,
//!   re-prioritise, internal note).
//! * Phase 2 (`ticket.status_changed`, `ticket.priority_changed`):
//!   matched rules write a `workflow_rule_runs` audit row at the time
//!   the transition lands but do not mutate.
//! * Phase 3 (PMS-467): the transition triggers gain mutating actions.
//!   An action that itself moves `status_id` or `priority_id` re-fires
//!   the matching transition trigger at depth + 1; the executor
//!   refuses to fire any rule whose call depth has reached the
//!   per-tenant `workflows/rule_max_depth` cap and writes a
//!   `workflow_rule_runs` row with the depth-cap error so the
//!   operator's audit trail captures why the cascade stopped.
//!
//! Failure of any single action is logged to `workflow_rule_runs` and
//! surfaced as the run row's `error`, but does NOT abort the outer
//! transaction - a buggy rule should not block legitimate ticket
//! work. The matching and action-application logic is kept here so it
//! can be unit-tested without spinning up the full ticket-service
//! path.

// SPEC-7.203: the only loop guard across the recursive status/priority cascade
// is the numeric depth counter; there is no de-duplication or cycle-detection against rule
// identity or ticket-state history, so a cascade that keeps alternating between two values
// runs until max_depth is hit.

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

/// PMS-448 phase 2: status-transition context. Carries the
/// transition's source + destination so a rule can match
/// "moved into 'closed'" without also firing on an admin nudge
/// that just bumped some other column. Conditions evaluation reuses
/// the same key matcher; `from_status_id` and `to_status_id` are
/// the two new keys on this trigger.
#[derive(Debug, Clone)]
pub struct TicketStatusChangedContext {
    pub ticket_id: Uuid,
    pub from_status_id: Uuid,
    pub to_status_id: Uuid,
    /// Resolved at the call site - the current values on the row
    /// post-update. Used so a rule can compose status + priority +
    /// queue filters (e.g. "moved into closed AND priority high").
    pub priority_id: Uuid,
    pub queue_id: Uuid,
    pub company_id: Uuid,
    pub type_id: Option<Uuid>,
}

/// PMS-448 phase 2: priority-transition context. Same shape as
/// status but with `from_priority_id` / `to_priority_id` as the
/// two new condition keys.
#[derive(Debug, Clone)]
pub struct TicketPriorityChangedContext {
    pub ticket_id: Uuid,
    pub from_priority_id: Uuid,
    pub to_priority_id: Uuid,
    pub status_id: Uuid,
    pub queue_id: Uuid,
    pub company_id: Uuid,
    pub type_id: Option<Uuid>,
}

/// Pure-function entry point. Pulls every active rule for the
/// trigger, evaluates conditions in priority order, and applies
/// matching actions. Errors are logged per-rule and do not fail the
/// call - the caller's outer transaction stays committable.
pub struct WorkflowExecutor;

impl WorkflowExecutor {
    // SPEC-7.164: selects only rules with trigger_event = 'ticket.created' AND
    // is_active = true for tenant_id, ordered priority ASC, created_at ASC, and evaluates
    // them in that order.
    // SPEC-7.175: returns Ok(()) unconditionally as long as the rule-querying
    // and run-row-inserting SQL succeeds; a failing action never propagates as an Err here.
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
            // SPEC-7.174: a rule that does not match its conditions produces no
            // workflow_rule_runs row at all; this continue skips both action application
            // and run-row insertion.
            if !matches_conditions(&rule.conditions, &ctx) {
                continue;
            }
            let outcome = apply_create_actions(tx, tenant_id, &ctx, &rule.actions).await;
            // Always record the run row, success or failure. The
            // SPA's ticket-detail timeline reads this surface;
            // dropping a failed run would hide buggy rules from the
            // operator.
            // SPEC-7.173: for each matched rule, unconditionally inserts a
            // workflow_rule_runs row with applied_actions set to the rule's full actions
            // blob (not just the ones that fired) and error set to the stringified
            // AppError when apply_create_actions returned Err, else NULL.
            let error_msg = outcome.err().map(|e| e.to_string());
            insert_run_row(
                tx,
                tenant_id,
                rule.id,
                ctx.ticket_id,
                &rule.actions,
                error_msg,
            )
            .await?;
        }
        Ok(())
    }

    /// PMS-448 phase 2: fires after a successful status transition.
    /// PMS-467 phase 3: when a matching rule's actions include
    /// `set_status_id` or `set_priority_id`, the post-update value is
    /// applied in-transaction and the matching transition trigger
    /// re-fires at the next depth level. The per-tenant cap from
    /// `workflows/rule_max_depth` (default 3) refuses to fire a rule
    /// whose depth has reached the cap and logs a depth-cap row.
    // SPEC-7.176: reads the tenant's cascade-cap setting via
    // read_workflow_rule_max_depth and delegates to run_status_changed_at_depth starting
    // at depth = 0.
    // SPEC-7.178: the cap comes from tenant_settings (category = 'workflows',
    // key = 'rule_max_depth'); absent defaults to 3, present is clamped to 1..=10.
    // SPEC-7.179, SPEC-7.201: read_workflow_rule_max_depth takes the
    // raw &mut PgConnection of this already-open tenant-scoped transaction (not a fresh
    // begin_with_tenant) to avoid deadlocking on the app.current_tenant GUC SET; the
    // 1..=10 clamp means a value of 1 disables nested/cascaded rule firing entirely.
    pub async fn run_ticket_status_changed(
        tx: &mut sqlx::PgConnection,
        tenant_id: Uuid,
        ctx: TicketStatusChangedContext,
    ) -> AppResult<()> {
        let max_depth =
            crate::modules::settings::read_workflow_rule_max_depth(tx, tenant_id).await?;
        run_status_changed_at_depth(tx, tenant_id, ctx, 0, max_depth).await
    }

    /// PMS-448 phase 2: fires after a successful priority transition.
    /// PMS-467 phase 3: see `run_ticket_status_changed`.
    // SPEC-7.177: reads the tenant's cascade-cap setting via
    // read_workflow_rule_max_depth and delegates to run_priority_changed_at_depth starting
    // at depth = 0.
    pub async fn run_ticket_priority_changed(
        tx: &mut sqlx::PgConnection,
        tenant_id: Uuid,
        ctx: TicketPriorityChangedContext,
    ) -> AppResult<()> {
        let max_depth =
            crate::modules::settings::read_workflow_rule_max_depth(tx, tenant_id).await?;
        run_priority_changed_at_depth(tx, tenant_id, ctx, 0, max_depth).await
    }
}

/// Recursive entry point for the status_changed trigger. The outer
/// call is depth 0 (the transition the operator/system originated);
/// every cascade that an action triggers re-enters here at the next
/// depth level so the per-tenant cap can fire-or-refuse cleanly.
// SPEC-7.180: selects only rules matching trigger_event = 'ticket.status_changed'
// AND is_active = true for the tenant, ordered priority ASC, created_at ASC.
async fn run_status_changed_at_depth(
    tx: &mut sqlx::PgConnection,
    tenant_id: Uuid,
    ctx: TicketStatusChangedContext,
    depth: u32,
    max_depth: u32,
) -> AppResult<()> {
    let rules: Vec<RuleRow> = sqlx::query_as(
        "SELECT id, conditions, actions \
         FROM workflow_rules \
         WHERE tenant_id = $1 \
           AND trigger_event = 'ticket.status_changed' \
           AND is_active = true \
         ORDER BY priority ASC, created_at ASC",
    )
    .bind(tenant_id)
    .fetch_all(&mut *tx)
    .await?;

    for rule in rules {
        // SPEC-7.185: a transition rule that does not match its conditions
        // produces no run row (same as the create-trigger path).
        if !matches_status_changed(&rule.conditions, &ctx) {
            continue;
        }
        // SPEC-7.183, SPEC-7.198: the recursion guard compares depth
        // (u32, starting at 0) with >= against max_depth; a rule matched exactly at
        // depth == max_depth is refused and never applied, so only depth 0..max_depth-1
        // can apply actions that cascade further.
        if depth >= max_depth {
            // Depth-cap refusal: the rule matched but the cascade
            // chain has hit the per-tenant ceiling. Record it so the
            // operator can see the cap fired without having to dig
            // through the surrounding context.
            let err = format!("cycle cap reached at depth {max_depth}");
            insert_run_row(
                tx,
                tenant_id,
                rule.id,
                ctx.ticket_id,
                &rule.actions,
                Some(err),
            )
            .await?;
            continue;
        }
        // SPEC-7.184: for depth < max_depth, applies the actions and
        // unconditionally inserts a run row recording success or the stringified error.
        let outcome = apply_transition_actions(
            tx,
            tenant_id,
            ctx.ticket_id,
            ctx.to_status_id,
            ctx.priority_id,
            ctx.queue_id,
            ctx.company_id,
            ctx.type_id,
            &rule.actions,
            depth,
            max_depth,
        )
        .await;
        let error_msg = outcome.err().map(|e| e.to_string());
        insert_run_row(
            tx,
            tenant_id,
            rule.id,
            ctx.ticket_id,
            &rule.actions,
            error_msg,
        )
        .await?;
    }
    Ok(())
}

// SPEC-7.180: selects only rules matching trigger_event = 'ticket.priority_changed'
// AND is_active = true for the tenant, ordered priority ASC, created_at ASC.
async fn run_priority_changed_at_depth(
    tx: &mut sqlx::PgConnection,
    tenant_id: Uuid,
    ctx: TicketPriorityChangedContext,
    depth: u32,
    max_depth: u32,
) -> AppResult<()> {
    let rules: Vec<RuleRow> = sqlx::query_as(
        "SELECT id, conditions, actions \
         FROM workflow_rules \
         WHERE tenant_id = $1 \
           AND trigger_event = 'ticket.priority_changed' \
           AND is_active = true \
         ORDER BY priority ASC, created_at ASC",
    )
    .bind(tenant_id)
    .fetch_all(&mut *tx)
    .await?;

    for rule in rules {
        // SPEC-7.185: a transition rule that does not match its conditions
        // produces no run row.
        if !matches_priority_changed(&rule.conditions, &ctx) {
            continue;
        }
        // SPEC-7.183, SPEC-7.198: depth-cap refusal mirrors the
        // status-changed path; a rule matched exactly at depth == max_depth is refused,
        // recorded with a "cycle cap reached at depth {max_depth}" run row, and the loop
        // continues to the next rule.
        if depth >= max_depth {
            let err = format!("cycle cap reached at depth {max_depth}");
            insert_run_row(
                tx,
                tenant_id,
                rule.id,
                ctx.ticket_id,
                &rule.actions,
                Some(err),
            )
            .await?;
            continue;
        }
        // SPEC-7.184: for depth < max_depth, applies the actions and
        // unconditionally inserts a run row recording success or the stringified error.
        let outcome = apply_transition_actions(
            tx,
            tenant_id,
            ctx.ticket_id,
            ctx.status_id,
            ctx.to_priority_id,
            ctx.queue_id,
            ctx.company_id,
            ctx.type_id,
            &rule.actions,
            depth,
            max_depth,
        )
        .await;
        let error_msg = outcome.err().map(|e| e.to_string());
        insert_run_row(
            tx,
            tenant_id,
            rule.id,
            ctx.ticket_id,
            &rule.actions,
            error_msg,
        )
        .await?;
    }
    Ok(())
}

/// Conditions matcher for `ticket.status_changed`. Adds two new
/// keys on top of the create-context matcher's surface:
///   - `from_status_id`: list of statuses the ticket transitioned
///     FROM. Lets a rule narrow to "leaving open".
///   - `to_status_id`: list of statuses the ticket transitioned
///     TO. Lets a rule narrow to "entering closed".
///
/// Other keys (priority_id / queue_id / company_id / type_id) match
/// against the ticket's current (post-update) values so a rule can
/// compose "moved into closed AND company X".
// SPEC-7.181: recognises keys from_status_id, to_status_id, priority_id,
// queue_id, company_id, type_id; any other key fails the match. Non-object or
// non-array-valued conditions fail closed the same way as the create matcher, and an
// empty object matches everything.
fn matches_status_changed(
    conditions: &serde_json::Value,
    ctx: &TicketStatusChangedContext,
) -> bool {
    let Some(map) = conditions.as_object() else {
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
            "from_status_id" => uuid_in_array(arr, ctx.from_status_id),
            "to_status_id" => uuid_in_array(arr, ctx.to_status_id),
            "priority_id" => uuid_in_array(arr, ctx.priority_id),
            "queue_id" => uuid_in_array(arr, ctx.queue_id),
            "company_id" => uuid_in_array(arr, ctx.company_id),
            "type_id" => ctx.type_id.is_some_and(|t| uuid_in_array(arr, t)),
            _ => false,
        };
        if !ok {
            return false;
        }
    }
    true
}

/// Conditions matcher for `ticket.priority_changed`. Same shape as
/// the status-changed matcher with `from_priority_id` /
/// `to_priority_id` as the two new keys.
// SPEC-7.182: recognises keys from_priority_id, to_priority_id, status_id,
// queue_id, company_id, type_id, with the same AND/IN/fail-closed/empty-matches-all
// semantics as matches_status_changed.
fn matches_priority_changed(
    conditions: &serde_json::Value,
    ctx: &TicketPriorityChangedContext,
) -> bool {
    let Some(map) = conditions.as_object() else {
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
            "from_priority_id" => uuid_in_array(arr, ctx.from_priority_id),
            "to_priority_id" => uuid_in_array(arr, ctx.to_priority_id),
            "status_id" => uuid_in_array(arr, ctx.status_id),
            "queue_id" => uuid_in_array(arr, ctx.queue_id),
            "company_id" => uuid_in_array(arr, ctx.company_id),
            "type_id" => ctx.type_id.is_some_and(|t| uuid_in_array(arr, t)),
            _ => false,
        };
        if !ok {
            return false;
        }
    }
    true
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
// SPEC-7.165: non-object conditions are treated as "match nothing" (returns
// false), explicitly to avoid a malformed/typo'd conditions blob silently firing every rule.
// SPEC-7.166: an empty conditions object ({}) matches every ticket for this trigger.
// SPEC-7.167: condition matching is AND across keys: every key present must
// independently match, else the whole rule fails to match (short-circuits on first non-match).
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
        // SPEC-7.168: within a key, matching is IN-array semantics: the key's
        // JSON value must be a JSON array; if it is not an array, the whole match fails.
        let Some(arr) = value.as_array() else {
            return false;
        };
        // SPEC-7.169: recognised condition keys for ticket.created are exactly
        // priority_id, queue_id, company_id, type_id, source; any other key name fails
        // closed (evaluates to false), even a typo'd key like "pri0rity_id".
        // SPEC-7.170: priority_id, queue_id, company_id compare the ticket's
        // UUID field against the condition array via string-parse-then-equality; non-UUID
        // or non-string elements are silently ignored (never match, never error).
        // SPEC-7.171: type_id only matches if the ticket's type_id is Some and
        // that UUID is in the array; if type_id is None, this key never matches.
        // SPEC-7.172: source matches by exact string equality against the
        // array's string elements (not UUID parsing).
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

/// Apply the structured actions blob to a freshly-created ticket.
/// Mirror-image of `apply_transition_actions` but without the
/// recursion plumbing because `ticket.created` cannot itself fire a
/// status_changed or priority_changed trigger (the create is the
/// originating event; the next mutation is the operator's).
// SPEC-7.186: applies actions in this fixed order regardless of key order in
// the JSON object: assign_to_user_id, assign_to_team_id, set_priority_id (no-cascade),
// set_status_id (no-cascade), add_tag, add_internal_note; returns Ok(()) if actions is
// not a JSON object (silently does nothing).
// SPEC-7.199: ticket.created never calls run_ticket_status_changed /
// run_ticket_priority_changed; this is a hard structural guarantee (not depth-limited)
// because the create is the originating event, the next mutation is the operator's.
async fn apply_create_actions(
    tx: &mut sqlx::PgConnection,
    tenant_id: Uuid,
    ctx: &TicketCreateContext,
    actions: &serde_json::Value,
) -> AppResult<()> {
    let Some(map) = actions.as_object() else {
        return Ok(());
    };
    let mut first_error: Option<String> = None;

    // SPEC-7.187: each action sub-step below runs even if an earlier sub-step
    // already failed (no early return on an individual action failure); only the FIRST
    // failure is retained via first_error.get_or_insert_with, and that one message becomes
    // the workflow_rule_runs.error for this rule-run.
    apply_assign_user(tx, tenant_id, ctx.ticket_id, map, &mut first_error).await;
    apply_assign_team(tx, tenant_id, ctx.ticket_id, map, &mut first_error).await;
    apply_set_priority_no_cascade(tx, tenant_id, ctx.ticket_id, map, &mut first_error).await;
    apply_set_status_no_cascade(tx, tenant_id, ctx.ticket_id, map, &mut first_error).await;
    apply_add_tag(tx, tenant_id, ctx.ticket_id, map, &mut first_error).await;
    apply_add_internal_note(tx, tenant_id, ctx.ticket_id, map, &mut first_error).await;

    match first_error {
        Some(msg) => Err(crate::utils::error::AppError::Internal(msg)),
        None => Ok(()),
    }
}

/// PMS-467: apply actions for a transition trigger and cascade as
/// needed. `set_status_id` / `set_priority_id` apply the UPDATE and
/// then re-fire the matching transition trigger at depth + 1. The
/// caller's depth-cap check has already short-circuited the rule if
/// depth reached `max_depth`, so this function is only invoked when a
/// nested fire is permitted to land at least one more level.
#[allow(clippy::too_many_arguments)]
async fn apply_transition_actions(
    tx: &mut sqlx::PgConnection,
    tenant_id: Uuid,
    ticket_id: Uuid,
    current_status_id: Uuid,
    current_priority_id: Uuid,
    current_queue_id: Uuid,
    current_company_id: Uuid,
    current_type_id: Option<Uuid>,
    actions: &serde_json::Value,
    depth: u32,
    max_depth: u32,
) -> AppResult<()> {
    let Some(map) = actions.as_object() else {
        return Ok(());
    };
    let mut first_error: Option<String> = None;

    // SPEC-7.194: applies non-cascading actions first, in this order:
    // assign_to_user_id, assign_to_team_id, add_tag, add_internal_note. set_priority_id /
    // set_status_id are not in this list and the "no_cascade" setters used by the create
    // path are never called at all on the transition path.
    apply_assign_user(tx, tenant_id, ticket_id, map, &mut first_error).await;
    apply_assign_team(tx, tenant_id, ticket_id, map, &mut first_error).await;
    apply_add_tag(tx, tenant_id, ticket_id, map, &mut first_error).await;
    apply_add_internal_note(tx, tenant_id, ticket_id, map, &mut first_error).await;

    // Cascade-capable actions run last so the non-cascade mutations
    // (assign / tag / note) are visible inside the nested rule's run
    // row before recursion descends. Priority cascades before status
    // so a rule that changes both ends up firing priority_changed
    // first (matching the ticket-update ordering in the service).
    // SPEC-7.195: set_priority_id is evaluated before set_status_id so a rule
    // that changes both ends up firing priority_changed first.
    // SPEC-7.196: set_priority_id / set_status_id are no-ops when the new value
    // equals the current value (no UPDATE, no cascade, no error); otherwise each UPDATEs
    // the column then recurses into the matching transition runner at depth + 1 inside the
    // same transaction, with errors "set_priority_id/set_status_id failed/parse" and a
    // wrapped cascade error ("priority cascade: {e}" / "status cascade: {e}") retained only
    // if first_error is still None.
    // SPEC-7.202: the != guard before each UPDATE prevents a rule that targets
    // the ticket's current value from cascading or recursing, closing a trivial
    // infinite-loop vector.
    if let Some(new_priority_id) = map
        .get("set_priority_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        if new_priority_id != current_priority_id {
            let r =
                sqlx::query("UPDATE tickets SET priority_id = $1 WHERE tenant_id = $2 AND id = $3")
                    .bind(new_priority_id)
                    .bind(tenant_id)
                    .bind(ticket_id)
                    .execute(&mut *tx)
                    .await;
            if let Err(e) = r {
                first_error.get_or_insert_with(|| format!("set_priority_id failed: {e}"));
            } else {
                let nested = TicketPriorityChangedContext {
                    ticket_id,
                    from_priority_id: current_priority_id,
                    to_priority_id: new_priority_id,
                    status_id: current_status_id,
                    queue_id: current_queue_id,
                    company_id: current_company_id,
                    type_id: current_type_id,
                };
                // SPEC-7.200: boxed with Box::pin to satisfy Rust's requirement
                // that recursive async fns have a statically-sized future.
                if let Err(e) = Box::pin(run_priority_changed_at_depth(
                    tx,
                    tenant_id,
                    nested,
                    depth + 1,
                    max_depth,
                ))
                .await
                {
                    first_error.get_or_insert_with(|| format!("priority cascade: {e}"));
                }
            }
        }
    }

    if let Some(new_status_id) = map
        .get("set_status_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        if new_status_id != current_status_id {
            let r =
                sqlx::query("UPDATE tickets SET status_id = $1 WHERE tenant_id = $2 AND id = $3")
                    .bind(new_status_id)
                    .bind(tenant_id)
                    .bind(ticket_id)
                    .execute(&mut *tx)
                    .await;
            if let Err(e) = r {
                first_error.get_or_insert_with(|| format!("set_status_id failed: {e}"));
            } else {
                let nested = TicketStatusChangedContext {
                    ticket_id,
                    from_status_id: current_status_id,
                    to_status_id: new_status_id,
                    priority_id: current_priority_id,
                    queue_id: current_queue_id,
                    company_id: current_company_id,
                    type_id: current_type_id,
                };
                if let Err(e) = Box::pin(run_status_changed_at_depth(
                    tx,
                    tenant_id,
                    nested,
                    depth + 1,
                    max_depth,
                ))
                .await
                {
                    first_error.get_or_insert_with(|| format!("status cascade: {e}"));
                }
            }
        }
    }

    // SPEC-7.197: returns Err(AppError::Internal(msg)) with msg equal to the
    // single retained first_error string if any action (including a cascade) failed,
    // else Ok(()).
    match first_error {
        Some(msg) => Err(crate::utils::error::AppError::Internal(msg)),
        None => Ok(()),
    }
}

// SPEC-7.188: assign_to_user_id / assign_to_team_id actions parse a UUID from
// the string value and UPDATE assigned_to_id / team_id; an absent key or non-string value
// is a no-op; a SQL failure and a UUID-parse failure produce distinct error messages
// ("... failed: {e}" vs "... parse: {e}").
async fn apply_assign_user(
    tx: &mut sqlx::PgConnection,
    tenant_id: Uuid,
    ticket_id: Uuid,
    map: &serde_json::Map<String, serde_json::Value>,
    first_error: &mut Option<String>,
) {
    let Some(raw) = map.get("assign_to_user_id").and_then(|v| v.as_str()) else {
        return;
    };
    match Uuid::parse_str(raw) {
        Ok(uid) => {
            let r = sqlx::query(
                "UPDATE tickets SET assigned_to_id = $1 WHERE tenant_id = $2 AND id = $3",
            )
            .bind(uid)
            .bind(tenant_id)
            .bind(ticket_id)
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

async fn apply_assign_team(
    tx: &mut sqlx::PgConnection,
    tenant_id: Uuid,
    ticket_id: Uuid,
    map: &serde_json::Map<String, serde_json::Value>,
    first_error: &mut Option<String>,
) {
    let Some(raw) = map.get("assign_to_team_id").and_then(|v| v.as_str()) else {
        return;
    };
    match Uuid::parse_str(raw) {
        Ok(tid) => {
            let r = sqlx::query("UPDATE tickets SET team_id = $1 WHERE tenant_id = $2 AND id = $3")
                .bind(tid)
                .bind(tenant_id)
                .bind(ticket_id)
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

/// PMS-448 phase 1: priority mutation without recursion. Used by the
/// create path. The transition path uses the cascade-capable variant
/// inside `apply_transition_actions`.
// SPEC-7.189: on the ticket.created path, set_priority_id / set_status_id
// update the column directly via these no-cascade variants and never fire the
// corresponding ticket.priority_changed / ticket.status_changed trigger, because ticket
// creation is the originating event, not a transition.
async fn apply_set_priority_no_cascade(
    tx: &mut sqlx::PgConnection,
    tenant_id: Uuid,
    ticket_id: Uuid,
    map: &serde_json::Map<String, serde_json::Value>,
    first_error: &mut Option<String>,
) {
    let Some(raw) = map.get("set_priority_id").and_then(|v| v.as_str()) else {
        return;
    };
    match Uuid::parse_str(raw) {
        Ok(pid) => {
            let r =
                sqlx::query("UPDATE tickets SET priority_id = $1 WHERE tenant_id = $2 AND id = $3")
                    .bind(pid)
                    .bind(tenant_id)
                    .bind(ticket_id)
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

/// PMS-467: status mutation without recursion. Used by the create
/// path so a `ticket.created` rule can pin a starting status without
/// firing `ticket.status_changed` (the create is the originating
/// event; nothing transitioned).
async fn apply_set_status_no_cascade(
    tx: &mut sqlx::PgConnection,
    tenant_id: Uuid,
    ticket_id: Uuid,
    map: &serde_json::Map<String, serde_json::Value>,
    first_error: &mut Option<String>,
) {
    let Some(raw) = map.get("set_status_id").and_then(|v| v.as_str()) else {
        return;
    };
    match Uuid::parse_str(raw) {
        Ok(sid) => {
            let r =
                sqlx::query("UPDATE tickets SET status_id = $1 WHERE tenant_id = $2 AND id = $3")
                    .bind(sid)
                    .bind(tenant_id)
                    .bind(ticket_id)
                    .execute(&mut *tx)
                    .await;
            if let Err(e) = r {
                first_error.get_or_insert_with(|| format!("set_status_id failed: {e}"));
            }
        }
        Err(e) => {
            first_error.get_or_insert_with(|| format!("set_status_id parse: {e}"));
        }
    }
}

// SPEC-7.190: add_tag requires a string value and appends it via
// array_append, guarded by NOT ($1 = ANY(tags)) so a duplicate tag is not appended twice;
// an absent or non-string key is a no-op.
async fn apply_add_tag(
    tx: &mut sqlx::PgConnection,
    tenant_id: Uuid,
    ticket_id: Uuid,
    map: &serde_json::Map<String, serde_json::Value>,
    first_error: &mut Option<String>,
) {
    let Some(tag) = map.get("add_tag").and_then(|v| v.as_str()) else {
        return;
    };
    let r = sqlx::query(
        "UPDATE tickets SET tags = array_append(tags, $1) \
         WHERE tenant_id = $2 AND id = $3 AND NOT ($1 = ANY(tags))",
    )
    .bind(tag)
    .bind(tenant_id)
    .bind(ticket_id)
    .execute(&mut *tx)
    .await;
    if let Err(e) = r {
        first_error.get_or_insert_with(|| format!("add_tag failed: {e}"));
    }
}

async fn apply_add_internal_note(
    tx: &mut sqlx::PgConnection,
    tenant_id: Uuid,
    ticket_id: Uuid,
    map: &serde_json::Map<String, serde_json::Value>,
    first_error: &mut Option<String>,
) {
    let Some(note) = map.get("add_internal_note").and_then(|v| v.as_str()) else {
        return;
    };
    // SPEC-7.191: looks up the OLDEST active user with role super_admin,
    // admin, or manager as the note's created_by_id, not the user who triggered the
    // workflow and not the rule's created_by_id; a SQL failure on this lookup itself
    // sets error "add_internal_note creator lookup: {e}".
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
    // SPEC-7.192: if no eligible admin-tier user exists, this if-let guard
    // skips the INSERT entirely: no note inserted and no error recorded, even though the
    // rule matched and configured this action.
    if let Some(creator) = creator {
        // SPEC-7.193: inserts into ticket_notes with note_type = 'internal';
        // a SQL failure here sets error "add_internal_note failed: {e}".
        let r = sqlx::query(
            "INSERT INTO ticket_notes \
                 (tenant_id, ticket_id, note_type, content, created_by_id) \
             VALUES ($1, $2, 'internal', $3, $4)",
        )
        .bind(tenant_id)
        .bind(ticket_id)
        .bind(note)
        .bind(creator)
        .execute(&mut *tx)
        .await;
        if let Err(e) = r {
            first_error.get_or_insert_with(|| format!("add_internal_note failed: {e}"));
        }
    }
}

// SPEC-7.204: this INSERT (and the rule-listing SELECTs in
// run_ticket_created / run_status_changed_at_depth / run_priority_changed_at_depth) use
// `.await?`, so a SQL-level failure here propagates up through the whole recursive call
// chain and can abort the caller's outer transaction, unlike action-level failures which
// are always absorbed into a run row's error column instead.
async fn insert_run_row(
    tx: &mut sqlx::PgConnection,
    tenant_id: Uuid,
    rule_id: Uuid,
    entity_id: Uuid,
    actions: &serde_json::Value,
    error: Option<String>,
) -> AppResult<()> {
    sqlx::query(
        "INSERT INTO workflow_rule_runs \
             (tenant_id, rule_id, entity_type, entity_id, applied_actions, error) \
         VALUES ($1, $2, 'tickets', $3, $4, $5)",
    )
    .bind(tenant_id)
    .bind(rule_id)
    .bind(entity_id)
    .bind(actions)
    .bind(error)
    .execute(&mut *tx)
    .await?;
    Ok(())
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
