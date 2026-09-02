-- PMS-791 / MAPPS-461: add updated_at to team_members so role changes are
-- audit-trackable without delete + re-insert.
--
-- The existing shared trigger function is `update_updated_at_column` (see
-- migration 024_triggers_and_rls.sql:10), NOT `set_updated_at`. Reuse it.

ALTER TABLE team_members
    ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE TRIGGER team_members_updated_at
    BEFORE UPDATE ON team_members
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
