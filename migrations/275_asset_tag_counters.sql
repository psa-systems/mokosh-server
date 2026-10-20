-- Asset tags are system-generated per tenant: a technician who wrote
-- down "AST-042" needs the same asset to come back when they look it
-- up tomorrow. A free-text column lets anyone (SPA, import, future
-- CLI) overwrite the tag and break that promise, so the server now
-- owns every tag it issues.
--
-- Two pieces:
--
-- 1. `asset_tag_counters`: one row per tenant carrying the next
--    sequence number to issue. Lazy init: the first `create_asset`
--    seeds it from the highest `AST-<n>` tag already in `assets`
--    (data_transfer imports may land them). The row is tenant-
--    scoped so an import that wipes and reloads clears it along
--    with the rest; the next create re-seeds from the loaded tags.
--
-- 2. `uq_assets_tenant_asset_tag_ci`: case-insensitive uniqueness
--    scoped by tenant, with `asset_tag` nullable allowed (legacy
--    rows without a tag are not disturbed by this change). The
--    service generator and the import path both rely on it as the
--    backstop against duplicate tags.

CREATE TABLE asset_tag_counters (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    next_number BIGINT NOT NULL DEFAULT 1,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE asset_tag_counters ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset_tag_counters FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON asset_tag_counters
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );

GRANT SELECT, INSERT, UPDATE, DELETE ON asset_tag_counters TO mokosh_app;

CREATE UNIQUE INDEX uq_assets_tenant_asset_tag_ci
    ON assets (tenant_id, lower(asset_tag))
    WHERE asset_tag IS NOT NULL;
