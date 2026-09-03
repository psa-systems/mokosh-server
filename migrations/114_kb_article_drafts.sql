-- PMS-922: per-user in-progress text for a KB article, which is NOT a revision.
--
-- The editor wants autosave. It cannot have it against `PUT /kb/articles/{id}`,
-- because `update_article` calls `snapshot_version` on every save and appends a
-- row to `kb_article_versions`. An editor that PUT on a timer would write a new
-- revision every interval, and the history that `VersionHistoryCard` and
-- `.../versions/{n}/restore` depend on would become a list of near-identical
-- autosaves with the real edits buried among them.
--
-- So drafts get their own table, and the contract is that nothing here ever
-- becomes a version implicitly. A draft is superseded by a real save, which
-- deletes it; it is never promoted.
--
-- PER USER, not per article. Two people editing the same article must not
-- overwrite each other's in-progress text. That is a conflict to surface, not
-- one to silently resolve, and a shared draft row resolves it by losing
-- somebody's work.

CREATE TABLE kb_article_drafts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    -- Carried rather than joined through `kb_articles`. `kb_article_versions`
    -- has no `tenant_id` and needs the parent-join policy in migration 041;
    -- a column here keeps this table on the ordinary `tenant_isolation` shape
    -- that `tests/rls_coverage.rs` enforces for every tenant-scoped table.
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    article_id UUID NOT NULL REFERENCES kb_articles(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- The client compares this against the article's own `updated_at` to decide
    -- whether the draft is newer than what is saved, so it is the field the
    -- restore-or-discard prompt turns on.
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One draft per person per article: the upsert target.
CREATE UNIQUE INDEX idx_kb_drafts_unique
    ON kb_article_drafts (tenant_id, article_id, user_id);

-- `ON DELETE CASCADE` on both parents means a deleted article or a deleted user
-- takes its drafts with it, so a draft cannot outlive the thing it drafts.

-- Fail-closed RLS, the same shape every tenant-scoped table carries since
-- 038_rls_fail_closed.sql. `tests/rls_coverage.rs` fails the build if a table
-- with a `tenant_id` column lacks this.
ALTER TABLE kb_article_drafts ENABLE ROW LEVEL SECURITY;
ALTER TABLE kb_article_drafts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON kb_article_drafts;
CREATE POLICY tenant_isolation ON kb_article_drafts
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);
