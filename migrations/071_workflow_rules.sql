-- PMS-448 phase 1: ticket.created workflow rules.
--
-- A focused first cut of the workflow engine: a single trigger
-- (`ticket.created`), structured conditions on the new ticket's
-- well-known dimensions (priority / queue / company / source / type),
-- and structured actions that mutate the same ticket (assign,
-- reprioritise, tag, add an internal note). The TicketService's
-- create path runs the matching rules in-transaction after the
-- INSERT lands.
--
-- The shape is deliberately constrained to a single trigger so the
-- executor compiles to predictable SQL: every condition column is
-- a real column on the `tickets` table, and every action mutates
-- the same row. Phase 2 will generalise to additional triggers
-- (`ticket.status_changed`, `ticket.priority_changed`,
-- `time_entry.created`) by promoting `trigger_event` to a
-- discriminator and letting `conditions` / `actions` carry per-
-- trigger schemas.
--
-- Conditions JSONB shape (every key optional; AND across keys, IN
-- across array values within a key):
--   {
--     "priority_id":   ["<uuid>", ...],     // matches if ticket.priority_id IN list
--     "queue_id":      ["<uuid>", ...],     // matches if ticket.queue_id IN list
--     "company_id":    ["<uuid>", ...],
--     "source":        ["email", "portal"], // string IN list (see TicketSource)
--     "type_id":       ["<uuid>", ...]
--   }
-- An empty conditions blob matches every new ticket of that tenant.
--
-- Actions JSONB shape (every key optional; applied in declaration
-- order so a later action sees the earlier action's mutations):
--   {
--     "assign_to_user_id": "<uuid>",       // sets tickets.assigned_to_id
--     "assign_to_team_id": "<uuid>",       // sets tickets.team_id
--     "set_priority_id":   "<uuid>",       // overrides the priority the requester chose
--     "add_tag":           "auto-routed",  // appends to tickets.tags array (idempotent)
--     "add_internal_note": "Auto: high-priority customer; on-call paged."
--   }
--
-- Both blobs are validated by the executor at run time, NOT by the
-- DB. Phase 2 may promote certain conditions to columns once the
-- shape stabilises.

CREATE TABLE workflow_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Phase 1 only emits one value here. Stored as VARCHAR so a
    -- Phase 2 migration can widen the surface without rewriting
    -- existing rows.
    trigger_event VARCHAR(50) NOT NULL,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    conditions JSONB NOT NULL DEFAULT '{}'::jsonb,
    actions JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- Lower priorities run first within a trigger; ties break on
    -- `created_at` for determinism. Defaults to 100 so an operator
    -- can slot a new "always run last" rule by setting 200 without
    -- thinking about gaps.
    priority INTEGER NOT NULL DEFAULT 100,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_by_id UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- The executor's hot path: pull every active rule for this tenant
-- + trigger, ordered by priority. Indexed (tenant_id, trigger_event)
-- so it is one index scan per ticket create.
CREATE INDEX idx_workflow_rules_trigger
    ON workflow_rules(tenant_id, trigger_event)
    WHERE is_active = true;

-- Audit / observability: for every ticket the executor processes,
-- record which rule fired and what happened. Lets an operator
-- answer "why did this customer's ticket get auto-assigned to Jane?"
-- without having to replay the engine state.
CREATE TABLE workflow_rule_runs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    rule_id UUID NOT NULL REFERENCES workflow_rules(id) ON DELETE CASCADE,
    -- The entity the run touched. Phase 1 only fires on tickets so
    -- this is always a `tickets.id`; Phase 2 may diversify so it is
    -- not a strong FK.
    entity_type VARCHAR(50) NOT NULL,
    entity_id UUID NOT NULL,
    -- Snapshot of the actions JSONB that were applied (post-
    -- validation). Lets the SPA render the rule-run timeline
    -- without re-deriving from the rule itself.
    applied_actions JSONB NOT NULL,
    -- NULL on success; populated with the validation / SQL error
    -- when an action could not be applied. The executor records the
    -- run row even on partial failure so the SPA can surface the
    -- problem to the operator.
    error TEXT,
    ran_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_workflow_rule_runs_entity
    ON workflow_rule_runs(tenant_id, entity_type, entity_id);
CREATE INDEX idx_workflow_rule_runs_rule
    ON workflow_rule_runs(rule_id, ran_at DESC);
