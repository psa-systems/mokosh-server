-- PMS-322: replace the hardcoded `projects.project_type` enum with a
-- tenant-scoped `project_types` lookup table so the MAPPS Settings hub
-- (MAPPS-169) can manage the option set per tenant without a migration.
--
-- migration 007 declared `project_type VARCHAR(20) NOT NULL DEFAULT 'client'
-- CHECK (project_type IN ('client','internal'))`. An audit of the server found
-- NO code that branches on the literal 'client'/'internal' values: the string
-- is only defaulted (CreateProjectRequest), stored, and echoed back. So the
-- two values move to data cleanly. The legacy `projects.project_type` string
-- column is KEPT for one release (the create/read paths still write/return it);
-- a follow-up release can drop it once clients read `project_type_id`.
--
-- Following the 043_pms196 precedent, this is a new forward migration (007's
-- checksum is validated on `migrate run` and cannot be edited).

-- ============================================================================
-- 1. project_types lookup table.
-- ============================================================================
CREATE TABLE project_types (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(50) NOT NULL,
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    sort_order INTEGER NOT NULL DEFAULT 0,
    -- `is_system` marks rows the code still depends on (the seeded
    -- client/internal values). The API refuses to delete them; the Settings
    -- editor uses the flag to forbid delete/rename in the UI.
    is_system BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_project_types_tenant ON project_types(tenant_id);
-- One row per (tenant, name) so the backfill join and the create-project
-- name -> id resolution are unambiguous.
CREATE UNIQUE INDEX idx_project_types_tenant_name ON project_types(tenant_id, name);

-- ============================================================================
-- 2. RLS: the table carries tenant_id, but the 038 fail-closed sweep already
-- ran, so a table created now needs its policy added explicitly (mirrors how
-- 041 covered user_oauth_identities).
-- ============================================================================
ALTER TABLE project_types ENABLE ROW LEVEL SECURITY;
ALTER TABLE project_types FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON project_types
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );

-- ============================================================================
-- 3. updated_at trigger (the 024/043 sweeps already ran; attach explicitly).
-- ============================================================================
DROP TRIGGER IF EXISTS update_project_types_updated_at ON project_types;
CREATE TRIGGER update_project_types_updated_at
    BEFORE UPDATE ON project_types
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- 4. Seed client/internal for EVERY existing tenant as system defaults. The
-- per-tenant seed lets copy_default_config replicate them to future tenants
-- by copying the default tenant's rows (it now has these two).
-- ============================================================================
INSERT INTO project_types (tenant_id, name, is_default, is_active, sort_order, is_system)
SELECT t.id, v.name, v.is_default, TRUE, v.sort_order, TRUE
FROM tenants t
CROSS JOIN (VALUES
    ('client', TRUE, 1),
    ('internal', FALSE, 2)
) AS v(name, is_default, sort_order);

-- ============================================================================
-- 5. Add projects.project_type_id, backfill from the legacy string, index it.
-- ============================================================================
ALTER TABLE projects
    ADD COLUMN project_type_id UUID REFERENCES project_types(id);

UPDATE projects p
SET project_type_id = pt.id
FROM project_types pt
WHERE pt.tenant_id = p.tenant_id
  AND pt.name = p.project_type;

CREATE INDEX idx_projects_project_type_id ON projects(project_type_id);

-- ============================================================================
-- 6. Drop the CHECK so new tenant-defined types are no longer rejected. The
-- legacy `project_type` string column itself stays for one release.
-- ============================================================================
ALTER TABLE projects
    DROP CONSTRAINT IF EXISTS projects_project_type_check;
