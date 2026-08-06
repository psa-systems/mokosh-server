-- PMS-731: form definitions with per-field validation.
--
-- The substrate the PMS-730 MACD request flow is built on: define a
-- form, describe its ordered field set, validate a submission field by
-- field, and store the submission tenant-scoped.
--
-- Deliberately NOT an extraction from eForm. eForm's entire form-definition
-- surface is a three-field struct (`name`, `label`, `field_type`) with no
-- required flag and no validation rules, stored as an opaque JSON blob in a
-- column bolted on by an error-swallowing ALTER. The reusable part is four
-- lines; the part the request flow needs does not exist there at all.
--
-- Scope is bounded by the MACD field list reviewed on PMS-731. The field
-- TYPES and the validation RULES below are exactly those that list needs and
-- nothing more:
--   types: text, textarea, email, date, select, boolean
--   rules: required, length min/max, email pattern, date-not-in-past,
--          option-set membership
-- Numeric range and file upload are deliberately absent: no field in the MACD
-- set uses either, and a rule with no caller is a liability rather than an
-- affordance. Both can be added by a later migration when a form needs them.

-- ============================================================================
-- FORM DEFINITIONS
-- ============================================================================

CREATE TABLE form_definitions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Operator-facing name, shown in the picker ("New starter").
    name VARCHAR(200) NOT NULL,
    -- Stable machine key used in URLs and by the PMS-730 magic link, so a
    -- renamed form does not invalidate links already issued to clients.
    slug VARCHAR(100) NOT NULL,
    description TEXT,
    -- PMS-730's "KB article selected by the requested change type". The
    -- mapping lives HERE rather than in a separate change-type table because
    -- this row IS the request-type vocabulary: one definition per request
    -- type, so the mapping is a column, not a join. ON DELETE SET NULL
    -- mirrors migrations 068 / 099: retiring an article drops the linkage
    -- and leaves the form intact. A ticket created from a submission copies
    -- this into `tickets.procedure_kb_article_id` (migration 099).
    kb_article_id UUID REFERENCES kb_articles(id) ON DELETE SET NULL,
    -- Cross-field rules evaluated after every field has passed its own
    -- checks. Exactly one rule kind is supported in v1:
    --   {"kind":"required_if","field":"forward_to",
    --    "when_field":"mailbox_handling","equals":"forward"}
    -- This exists because the MACD departure form needs `forward_to` only
    -- when `mailbox_handling = forward`, which is conditional REQUIREDNESS.
    -- A per-field condition engine (and conditional display generally) is
    -- deliberately out of scope; one form-level rule list buys the single
    -- behaviour the field list actually demands, and nothing else.
    rules JSONB NOT NULL DEFAULT '[]'::jsonb,
    -- Retired definitions stay for their submissions' FKs and history but
    -- drop out of the picker and refuse new submissions.
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_by_id UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- The slug is the link-stable identifier, so it must be unique per tenant.
CREATE UNIQUE INDEX idx_form_definitions_tenant_slug
    ON form_definitions(tenant_id, slug);

-- Picker hot path. Partial so retired definitions do not bloat the index.
CREATE INDEX idx_form_definitions_tenant_active
    ON form_definitions(tenant_id)
    WHERE is_active = true;

-- ============================================================================
-- FORM FIELDS
-- ============================================================================

CREATE TABLE form_fields (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    form_definition_id UUID NOT NULL REFERENCES form_definitions(id) ON DELETE CASCADE,
    -- Machine name; the key this field's answer occupies in a submission
    -- payload. Unique within its form.
    name VARCHAR(100) NOT NULL,
    -- Human label rendered next to the input.
    label VARCHAR(200) NOT NULL,
    -- Optional hint rendered under the input.
    help_text TEXT,
    field_type VARCHAR(20) NOT NULL
        CHECK (field_type IN ('text', 'textarea', 'email', 'date', 'select', 'boolean')),
    is_required BOOLEAN NOT NULL DEFAULT false,
    -- Length bounds. Meaningful for text / textarea / email only; the
    -- validator ignores them for the other types rather than erroring, so a
    -- stray bound on a boolean is inert rather than a 500.
    min_length INTEGER CHECK (min_length IS NULL OR min_length >= 0),
    max_length INTEGER CHECK (max_length IS NULL OR max_length > 0),
    CONSTRAINT form_fields_length_bounds_ordered
        CHECK (min_length IS NULL OR max_length IS NULL OR min_length <= max_length),
    -- Permitted values for `select`. A submission's answer must appear here.
    options TEXT[],
    -- `date` only: reject a date earlier than the submission date. Every date
    -- in the MACD set (start_date, effective_date, last_working_day,
    -- disable_access_on) is forward-looking.
    date_not_in_past BOOLEAN NOT NULL DEFAULT false,
    -- Render order within the form. Ties break on `name` for determinism.
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- A `select` without options can never be satisfied, so reject the
    -- definition at write time rather than every submission at read time.
    CONSTRAINT form_fields_select_has_options
        CHECK (field_type <> 'select' OR (options IS NOT NULL AND array_length(options, 1) >= 1))
);

-- A payload key maps to exactly one field.
CREATE UNIQUE INDEX idx_form_fields_definition_name
    ON form_fields(form_definition_id, name);

-- Rendering a form reads its fields in order.
CREATE INDEX idx_form_fields_definition_order
    ON form_fields(form_definition_id, sort_order, name);

-- ============================================================================
-- FORM SUBMISSIONS
-- ============================================================================

CREATE TABLE form_submissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- RESTRICT, not CASCADE: a submission is a record of something a client
    -- asked for, and deleting the form definition must not erase it. Retiring
    -- a definition is `is_active = false`, which is why that column exists.
    form_definition_id UUID NOT NULL REFERENCES form_definitions(id) ON DELETE RESTRICT,
    -- The validated answers, keyed by `form_fields.name`. JSONB rather than a
    -- row per value: RLS attaches to the TABLE via tenant_id and is indifferent
    -- to the payload's shape, so normalising buys nothing here, and nothing in
    -- the PMS-730 acceptance criteria queries across submissions by individual
    -- field value. Normalise later if PMS-732 reporting actually needs it.
    payload JSONB NOT NULL,
    -- Set once the PMS-730 magic-link flow lands; NULL for a submission made
    -- through the authenticated agent surface.
    submitted_by_contact_id UUID REFERENCES contacts(id) ON DELETE SET NULL,
    -- Set once a submission has been turned into a ticket (PMS-730), so the
    -- conversion is idempotent and the request is traceable to its ticket.
    ticket_id UUID REFERENCES tickets(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_form_submissions_tenant_definition
    ON form_submissions(tenant_id, form_definition_id, created_at DESC);

CREATE INDEX idx_form_submissions_ticket
    ON form_submissions(tenant_id, ticket_id)
    WHERE ticket_id IS NOT NULL;

-- ============================================================================
-- ROW-LEVEL SECURITY
-- ============================================================================
--
-- The fail-closed `tenant_isolation` policy is attached to existing tables by
-- DO-block loops over `information_schema` in migrations 024 and 038. Those
-- loops have ALREADY RUN, so a table created here inherits NOTHING and must
-- attach the policy explicitly. Shape mirrors 038 / 090 / 091 / 094 / 095 and
-- 042_portal_setup_tokens.sql exactly: an unset or empty `app.current_tenant`
-- collapses to NULL, so USING matches no rows (fail-closed read) and WITH
-- CHECK rejects the write; FORCE binds the table owner too, so even the schema
-- owner cannot bypass it. The GUC is set transaction-locally by
-- `Database::begin_with_tenant` (src/db/pool.rs), which every serving query in
-- the forms service goes through.

ALTER TABLE form_definitions ENABLE ROW LEVEL SECURITY;
ALTER TABLE form_definitions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON form_definitions
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

ALTER TABLE form_fields ENABLE ROW LEVEL SECURITY;
ALTER TABLE form_fields FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON form_fields
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

ALTER TABLE form_submissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE form_submissions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON form_submissions
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);
