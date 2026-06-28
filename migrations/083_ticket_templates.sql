-- PMS-448 AC4: ticket templates.
--
-- A ticket template is a named, tenant-scoped pre-fill for the
-- new-ticket form: "Server is down" pre-fills the subject
-- (tickets.title), the description (tickets.description), and the
-- category (tickets.category_id), plus optional priority / type
-- defaults. The SPA lists active templates on the new-ticket screen
-- and, when one is chosen, seeds the form fields from this row; the
-- agent stays free to edit any field before submitting. The server
-- owns the definitions (admin-authored CRUD) but does NOT itself
-- create tickets from a template - that is a plain ticket create
-- with the operator-edited values, so the existing create path
-- (audit + SLA assignment + ticket.created workflow rules) runs
-- unchanged.
--
-- Columns mirror the ticket fields a template can seed so the SPA
-- maps a template 1:1 onto the create form:
--   subject     -> tickets.title       (required; the template's headline)
--   body        -> tickets.description (optional)
--   category_id -> tickets.category_id (optional)
--   priority_id -> tickets.priority_id (optional default)
--   type_id     -> tickets.type_id     (optional default)
--
-- The lookup FKs are nullable: a template can pre-fill only the
-- subject + body and leave the operator to pick a category. They are
-- ON DELETE SET NULL so retiring a category does not cascade-delete
-- the templates that referenced it; the template simply loses that
-- pre-fill. Same-tenant integrity for the lookups is enforced at the
-- service layer (every read/write threads tenant_id), matching the
-- rest of the schema's "no middleware tenant scoping" posture.

CREATE TABLE ticket_templates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Operator-facing template name, shown in the picker (e.g.
    -- "Server is down"). Distinct from `subject`: the name labels the
    -- template, the subject seeds the ticket title.
    name VARCHAR(200) NOT NULL,
    -- Admin-facing note about WHEN to use this template. Not copied
    -- onto the ticket.
    description TEXT,
    subject VARCHAR(500) NOT NULL,
    body TEXT,
    category_id UUID REFERENCES ticket_categories(id) ON DELETE SET NULL,
    priority_id UUID REFERENCES ticket_priorities(id) ON DELETE SET NULL,
    type_id UUID REFERENCES ticket_types(id) ON DELETE SET NULL,
    -- Inactive templates stay in the table (so their FKs and history
    -- survive) but drop out of the picker. The SPA's new-ticket
    -- screen lists active templates only.
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_by_id UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- The picker's hot path: list active templates for this tenant.
-- Partial so retired templates do not bloat the index.
CREATE INDEX idx_ticket_templates_tenant_active
    ON ticket_templates(tenant_id)
    WHERE is_active = true;
