-- PMS-196: schema-level data-integrity hardening that could not be made by
-- editing already-shipped migrations (024/028/004), because sqlx validates the
-- checksum of every previously-applied migration on `migrate run` and a
-- modified file aborts startup (now fatally, see src/main.rs). The team's
-- precedent for fixing a shipped migration is a new forward migration (cf.
-- 038_rls_fail_closed.sql replacing 024's RLS policy). This migration follows
-- that precedent for the trigger-attachment and missing-FK findings.

-- ============================================================================
-- 1. updated_at trigger sweep, idempotent and re-runnable.
-- ============================================================================
-- 024's trigger loop ran `CREATE TRIGGER` with no guard, so it (a) errors if
-- re-executed and (b) only attached triggers to tables that existed at 024.
-- Tables added after 024 (e.g. kb_article_votes in 032) carry an `updated_at`
-- column but never got the trigger, so their `updated_at` is frozen at INSERT.
-- This block re-runs the same information_schema sweep with
-- `DROP TRIGGER IF EXISTS ... ; CREATE TRIGGER ...`, which is fully idempotent
-- on re-run and attaches the trigger to every `updated_at` table that is still
-- missing it (kb_article_votes included).
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
        EXECUTE format('DROP TRIGGER IF EXISTS update_%I_updated_at ON %I', t, t);
        EXECUTE format('
            CREATE TRIGGER update_%I_updated_at
            BEFORE UPDATE ON %I
            FOR EACH ROW
            EXECUTE FUNCTION update_updated_at_column();
        ', t, t);
    END LOOP;
END $$;

-- ============================================================================
-- 2. appointment_reminders foreign keys (028 created bare UUID columns).
-- ============================================================================
-- Without these FKs, deleting a tenant or appointment leaves orphan dedupe
-- rows that can wrongly suppress reminders for a later row that reuses the id.
-- ON DELETE CASCADE drops the ledger rows with their parent.
ALTER TABLE appointment_reminders
    ADD CONSTRAINT appointment_reminders_tenant_id_fkey
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    ADD CONSTRAINT appointment_reminders_appointment_id_fkey
        FOREIGN KEY (appointment_id) REFERENCES appointments(id) ON DELETE CASCADE;

-- ============================================================================
-- 3. companies pointer foreign keys (004 created bare UUID columns).
-- ============================================================================
-- These are optional pointers to other rows; ON DELETE SET NULL clears the
-- pointer when the referenced row is removed rather than blocking the delete.
ALTER TABLE companies
    ADD CONSTRAINT companies_default_billing_contact_id_fkey
        FOREIGN KEY (default_billing_contact_id) REFERENCES contacts(id) ON DELETE SET NULL,
    ADD CONSTRAINT companies_default_technical_contact_id_fkey
        FOREIGN KEY (default_technical_contact_id) REFERENCES contacts(id) ON DELETE SET NULL,
    ADD CONSTRAINT companies_sla_id_fkey
        FOREIGN KEY (sla_id) REFERENCES sla_policies(id) ON DELETE SET NULL,
    ADD CONSTRAINT companies_default_contract_id_fkey
        FOREIGN KEY (default_contract_id) REFERENCES contracts(id) ON DELETE SET NULL;
