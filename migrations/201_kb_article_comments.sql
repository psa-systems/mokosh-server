-- PMS-1128: staff discussion on a knowledge base article.
--
-- A NEW table, not a generalisation of `ticket_notes`. A ticket note carries a
-- ticket FK, email tracking, portal (contact) authorship and a `note_type`
-- that decides whether a customer sees it; a KB comment needs threading,
-- resolve, an anchor into the text (PMS-1130) and NO customer plane at all.
-- Contacts holding `kb:read` read articles through the same page staff do,
-- so the one way internal discussion cannot leak onto a customer-visible
-- article is for there to be no customer-visible comment: this table has no
-- visibility column, its routes refuse a contact bearer, and a customer Q&A
-- later is its own column and capability rather than a default flip here.
--
-- One level of threading: a reply answers a root, never another reply, which
-- is enforced in the service so the tree is always two deep and one query.
-- A deleted comment keeps its row (`deleted_at`) so the thread keeps its
-- shape and a reply is not orphaned by the removal of what it answered.
-- `anchor` and `anchor_version` are reserved for the inline comments of
-- PMS-1130 and stored opaque here.

CREATE TABLE kb_article_comments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    -- Carried rather than joined through `kb_articles`, for the reason
    -- migration 114 gives: the ordinary `tenant_isolation` policy that
    -- `tests/rls_coverage.rs` enforces for every tenant-scoped table.
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    article_id UUID NOT NULL REFERENCES kb_articles(id) ON DELETE CASCADE,
    parent_id UUID REFERENCES kb_article_comments(id) ON DELETE CASCADE,
    author_id UUID NOT NULL REFERENCES users(id),
    body TEXT NOT NULL,
    anchor JSONB,
    anchor_version INTEGER,
    resolved_at TIMESTAMPTZ,
    resolved_by_id UUID REFERENCES users(id) ON DELETE SET NULL,
    edited_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_kb_article_comments_article
    ON kb_article_comments (article_id, created_at);

-- Fail-closed RLS, the shape every tenant-scoped table carries since
-- 038_rls_fail_closed.sql.
ALTER TABLE kb_article_comments ENABLE ROW LEVEL SECURITY;
ALTER TABLE kb_article_comments FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON kb_article_comments;
CREATE POLICY tenant_isolation ON kb_article_comments
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);
