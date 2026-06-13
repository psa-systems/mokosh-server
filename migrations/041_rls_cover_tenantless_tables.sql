-- PMS-258: bring the tables that the dynamic RLS loops never touched under
-- fail-closed row level security.
--
-- The 024 and 038 policy loops select tables `WHERE column_name = 'tenant_id'`,
-- so six tables were skipped: `tenants` (root, by design) and five others that
-- carry no `tenant_id` column of their own. This migration covers the five.
--
-- `user_oauth_identities` is the critical one. Its unique key was the GLOBAL
-- `(provider, subject)`, so the same upstream identity (e.g. one Google `sub`)
-- could exist only once across the whole database. Under personal-tenant
-- isolation that means one user's identity row blocks every other tenant's,
-- and the link leaks across the per-user boundary. It gets a denormalized
-- `tenant_id`, a tenant-scoped unique key, and the standard direct policy.
--
-- `kb_article_versions`, `invoice_lines`, `rate_card_items`, `sla_targets` have
-- no `tenant_id` and are isolated only transitively through a parent FK. They
-- get a fail-closed PARENT-JOIN policy (EXISTS over the parent's `tenant_id`)
-- rather than a denormalized column. Reasons: no backfill, no NOT NULL column
-- to keep populated on every INSERT (no drift risk), and these rows are always
-- reached through their parent anyway. The policy form mirrors 038's
-- fail-closed `NULLIF(current_setting('app.current_tenant', true), '')::uuid`
-- expression so behaviour is identical to the ~60 directly-scoped tables.

-- 1. user_oauth_identities: denormalized tenant_id + tenant-scoped uniqueness.
ALTER TABLE user_oauth_identities
    ADD COLUMN tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE;

-- Backfill from the owning user's tenant. Idempotent; a no-op on an empty table.
UPDATE user_oauth_identities o
    SET tenant_id = u.tenant_id
    FROM users u
    WHERE u.id = o.user_id;

ALTER TABLE user_oauth_identities ALTER COLUMN tenant_id SET NOT NULL;

-- Replace the cross-tenant-colliding global unique key with a tenant-scoped one.
ALTER TABLE user_oauth_identities
    DROP CONSTRAINT IF EXISTS user_oauth_identities_provider_subject_key;
ALTER TABLE user_oauth_identities
    ADD CONSTRAINT user_oauth_identities_tenant_provider_subject_key
    UNIQUE (tenant_id, provider, subject);

CREATE INDEX idx_user_oauth_identities_tenant ON user_oauth_identities (tenant_id);

ALTER TABLE user_oauth_identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_oauth_identities FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON user_oauth_identities;
CREATE POLICY tenant_isolation ON user_oauth_identities
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );

-- 2. Parent-join policies for the four tenant-less child tables.
-- The %I-style block keeps each policy identical in shape; the parent table and
-- the child's FK column are the only things that vary.
DO $$
DECLARE
    -- child table, child FK column, parent table
    rec record;
BEGIN
    FOR rec IN
        SELECT * FROM (VALUES
            ('kb_article_versions', 'article_id',    'kb_articles'),
            ('invoice_lines',       'invoice_id',    'invoices'),
            ('rate_card_items',     'rate_card_id',  'rate_cards'),
            ('sla_targets',         'sla_policy_id', 'sla_policies')
        ) AS v(child, fk, parent)
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', rec.child);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', rec.child);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', rec.child);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %1$I
                 USING (
                     EXISTS (
                         SELECT 1 FROM %3$I p
                         WHERE p.id = %1$I.%2$I
                         AND p.tenant_id = NULLIF(current_setting(''app.current_tenant'', true), '''')::uuid
                     )
                 )
                 WITH CHECK (
                     EXISTS (
                         SELECT 1 FROM %3$I p
                         WHERE p.id = %1$I.%2$I
                         AND p.tenant_id = NULLIF(current_setting(''app.current_tenant'', true), '''')::uuid
                     )
                 )',
            rec.child, rec.fk, rec.parent
        );
    END LOOP;
END $$;
