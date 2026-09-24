-- Opportunities and leads: the pipeline half of CRM basics.
--
-- Companies, contacts, sites and quotes already ship. What is missing
-- is the interest that precedes a quote: a lead recorded against a
-- company or a prospective company, moved through a small set of
-- stages, and closed won or lost. This table is the shape that closes
-- the CRM-basics story.
--
-- Design notes:
--
--   - Stage is an open TEXT with a CHECK. Six stages ship on day one
--     (`lead | qualified | proposal | negotiation | won | lost`), and
--     a future addition lands as a data change plus a widened CHECK
--     in a migration of its own. Configurable per-tenant stages are
--     an explicit non-goal for the first pass.
--
--   - Outcome is filled in on close; the CHECK constraint refuses an
--     outcome unless the stage is one of `won | lost`, and refuses a
--     `won`/`lost` stage without an outcome. The two columns cannot
--     drift apart.
--
--   - `quote_id` links the opportunity to the quote raised from it,
--     nullable because a lead may not have reached a quote yet.
--     `ON DELETE SET NULL` so a deleted draft quote leaves the row.
--
--   - `contact_id`, `expected_close_date`, `value_amount` and `notes`
--     are all optional: an early lead may carry only a name and a
--     company. `currency` is 3-char ISO 4217; the tenant default
--     rules that already apply to invoices apply here too and are
--     resolved at write time by the service.

BEGIN;

CREATE TABLE opportunities (
    id                     UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id              UUID          NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    company_id             UUID          NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    contact_id             UUID          REFERENCES contacts(id) ON DELETE SET NULL,
    title                  VARCHAR(255)  NOT NULL,
    value_amount           NUMERIC(14,2),
    currency               VARCHAR(3)    NOT NULL DEFAULT 'USD',
    stage                  TEXT          NOT NULL DEFAULT 'lead',
    expected_close_date    DATE,
    outcome                TEXT,
    quote_id               UUID          REFERENCES quotes(id) ON DELETE SET NULL,
    notes                  TEXT,
    created_by_id          UUID          REFERENCES users(id) ON DELETE SET NULL,
    created_at             TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at             TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    closed_at              TIMESTAMPTZ,
    deleted_at             TIMESTAMPTZ,
    CHECK (stage IN ('lead', 'qualified', 'proposal', 'negotiation', 'won', 'lost')),
    CHECK (outcome IS NULL OR outcome IN ('won', 'lost')),
    CHECK (
        (stage IN ('won', 'lost')     AND outcome IS NOT NULL)
        OR
        (stage NOT IN ('won', 'lost') AND outcome IS NULL)
    ),
    CHECK (
        value_amount IS NULL OR value_amount >= 0
    )
);

CREATE INDEX opportunities_open_by_tenant_idx
    ON opportunities (tenant_id, company_id, stage)
    WHERE deleted_at IS NULL AND closed_at IS NULL;

CREATE INDEX opportunities_by_company_idx
    ON opportunities (tenant_id, company_id)
    WHERE deleted_at IS NULL;

COMMENT ON TABLE opportunities IS
    'Sales pipeline: leads through won/lost, keyed to companies and (optionally) quotes.';
COMMENT ON COLUMN opportunities.stage IS
    'Pipeline stage. Open TEXT with a CHECK: adding a stage means widening the CHECK in a new migration.';
COMMENT ON COLUMN opportunities.outcome IS
    'Filled in on close. NULL while the opportunity is open; won/lost once closed. The paired CHECK on stage+outcome keeps them in step.';

ALTER TABLE opportunities ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON opportunities
    USING (tenant_id = current_setting('app.current_tenant', TRUE)::UUID);

GRANT SELECT, INSERT, UPDATE, DELETE ON opportunities TO mokosh_app;

COMMIT;
