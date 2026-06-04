-- PMS-128 split: updated_at trigger function + dynamic trigger attachment, plus row-level
-- security policy enable. Both blocks iterate `information_schema` to attach themselves
-- to every matching table, so they must run AFTER all CREATE TABLEs (the split itself
-- plus the renumbered follow-up migrations).

-- ============================================================================
-- UPDATED_AT TRIGGER FUNCTION
-- ============================================================================

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply updated_at trigger to all relevant tables
DO $$
DECLARE
    t text;
BEGIN
    FOR t IN
        SELECT table_name
        FROM information_schema.columns
        WHERE column_name = 'updated_at'
        AND table_schema = 'public'
    LOOP
        EXECUTE format('
            CREATE TRIGGER update_%I_updated_at
            BEFORE UPDATE ON %I
            FOR EACH ROW
            EXECUTE FUNCTION update_updated_at_column();
        ', t, t);
    END LOOP;
END $$;

-- ============================================================================
-- ROW LEVEL SECURITY (for multi-tenant)
-- ============================================================================

-- Enable RLS on all tables with tenant_id
DO $$
DECLARE
    t text;
BEGIN
    FOR t IN
        SELECT table_name
        FROM information_schema.columns
        WHERE column_name = 'tenant_id'
        AND table_schema = 'public'
        AND table_name != 'tenants'
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('
            CREATE POLICY tenant_isolation ON %I
            USING (tenant_id = COALESCE(
                NULLIF(current_setting(''app.current_tenant'', true), '''')::UUID,
                tenant_id
            ))
        ', t);
    END LOOP;
END $$;
