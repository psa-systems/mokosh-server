-- KB article executions: the "I followed this article against this
-- ticket" record. A row per execution carries the article id, a
-- snapshot of the article version it rendered against (NULL when the
-- article has no versions yet, which should never happen because every
-- create seeds version 1, but defended for a historic row), and the
-- caller's `values` map that fed the Phase 1a render path. The
-- rendered Markdown is scanned once for GFM task-list items, and the
-- steps are written to the sibling table so a per-step toggle is a
-- single-row UPDATE rather than a re-render.
--
-- `kb_article_execution_steps` has a `(execution_id, step_index)`
-- composite primary key (step_index is 0-based ordinal in the rendered
-- content), plus its own `id uuid` for a row identity separate from the
-- composite key, so a future route that addresses a step by id does not
-- need the parent id. `checked_at` + `checked_by_user_id` move together:
-- a check sets both, an uncheck clears both.
--
-- Tenant-first (PMS-1318). Granted to `mokosh_app` (PMS-1265). RLS on
-- both tables; the step table carries its own `tenant_id` so the policy
-- scopes without a join, which keeps the per-step UPDATE on the fast
-- path.

CREATE TABLE IF NOT EXISTS kb_article_executions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    ticket_id uuid NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    article_id uuid NOT NULL REFERENCES kb_articles(id) ON DELETE RESTRICT,
    -- Snapshot of the article version this execution rendered against.
    -- NULL for the historic case where no version row exists; the write
    -- path always resolves MAX(version_number) first and stores its id.
    article_version_id uuid REFERENCES kb_article_versions(id) ON DELETE SET NULL,
    variable_values jsonb NOT NULL DEFAULT '{}'::jsonb,
    started_at timestamptz NOT NULL DEFAULT NOW(),
    started_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS kb_article_executions_tenant_id_idx
    ON kb_article_executions (tenant_id);
CREATE INDEX IF NOT EXISTS kb_article_executions_ticket_idx
    ON kb_article_executions (tenant_id, ticket_id, started_at DESC);
CREATE INDEX IF NOT EXISTS kb_article_executions_article_idx
    ON kb_article_executions (tenant_id, article_id);

ALTER TABLE kb_article_executions ENABLE ROW LEVEL SECURITY;
ALTER TABLE kb_article_executions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON kb_article_executions
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );

GRANT SELECT, INSERT, UPDATE, DELETE ON kb_article_executions TO mokosh_app;


CREATE TABLE IF NOT EXISTS kb_article_execution_steps (
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    execution_id uuid NOT NULL
        REFERENCES kb_article_executions(id) ON DELETE CASCADE,
    step_index integer NOT NULL,
    step_text text NOT NULL,
    checked_at timestamptz,
    checked_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    PRIMARY KEY (execution_id, step_index),
    -- The two fields move together: either both set or both NULL.
    CONSTRAINT kb_execution_step_check_pair CHECK (
        (checked_at IS NULL AND checked_by_user_id IS NULL)
        OR (checked_at IS NOT NULL AND checked_by_user_id IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS kb_article_execution_steps_tenant_id_idx
    ON kb_article_execution_steps (tenant_id);
CREATE INDEX IF NOT EXISTS kb_article_execution_steps_execution_idx
    ON kb_article_execution_steps (execution_id, step_index);
-- Row-identity uniqueness so a lookup by `id` is unambiguous even though
-- the primary key is the composite.
CREATE UNIQUE INDEX IF NOT EXISTS kb_article_execution_steps_id_uq
    ON kb_article_execution_steps (id);

ALTER TABLE kb_article_execution_steps ENABLE ROW LEVEL SECURITY;
ALTER TABLE kb_article_execution_steps FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON kb_article_execution_steps
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );

GRANT SELECT, INSERT, UPDATE, DELETE ON kb_article_execution_steps TO mokosh_app;
