-- PMS-923: images an article can embed.
--
-- Numbered 115, not 114: PMS-922's `kb_article_drafts` is 114 on its own
-- branch. `scripts/check-migration-prefixes.nu` requires the prefixes to be
-- unique, so two follow-ups split from the same parent cannot both claim one.
--
-- The editor's image action could only take a URL, because the only upload
-- endpoints are note-scoped ticket attachments and the tenant logo. Neither can
-- hold an article's screenshot.
--
-- The `id` is the capability. An image embedded in markdown is fetched by the
-- browser as `<img src="...">`, an `<img>` cannot carry an `Authorization`
-- header, and the SPA authenticates with a bearer rather than a cookie, so the
-- URL that serves the bytes cannot sit behind the auth middleware. A v4 UUID
-- carries 122 bits of randomness and is the only thing guarding the file.
--
-- That is the same bargain the tenant logo already makes (a mail client fetches
-- it out of an email and can never authenticate) and the same one the
-- request-form magic link makes. It is a real cost, and it is recorded in the
-- "Routing model" section of CLAUDE.md alongside the other public handlers,
-- because anyone holding the URL can fetch the image even for an `internal`
-- article. The alternative, minting a short-lived signed URL at render time,
-- touches the renderer and is noted in PMS-923 rather than assumed here.

CREATE TABLE kb_article_attachments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    article_id UUID NOT NULL REFERENCES kb_articles(id) ON DELETE CASCADE,
    file_name VARCHAR(255) NOT NULL,
    mime_type VARCHAR(100) NOT NULL,
    file_size BIGINT NOT NULL,
    -- The uploader survives their own deactivation: an article's images must
    -- not disappear because somebody left, so this is SET NULL rather than
    -- CASCADE and the column is nullable.
    uploaded_by_id UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_kb_attachments_article ON kb_article_attachments (tenant_id, article_id);

-- Fail-closed RLS, the shape every tenant-scoped table carries since
-- 038_rls_fail_closed.sql and that `tests/rls_coverage.rs` enforces.
--
-- The PUBLIC read path deliberately does not go through this policy: it has no
-- tenant context to set, because the id is the only identity presented. That
-- read runs on the migrator pool with an explicit SAFETY note at the call site,
-- the same exemption `tenant_intake_tokens` documents in migration 095.
ALTER TABLE kb_article_attachments ENABLE ROW LEVEL SECURITY;
ALTER TABLE kb_article_attachments FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON kb_article_attachments;
CREATE POLICY tenant_isolation ON kb_article_attachments
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);
