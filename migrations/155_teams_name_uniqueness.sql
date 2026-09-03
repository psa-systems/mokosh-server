-- PMS-791 / MAPPS-461: two active teams cannot share a name (case-insensitive)
-- inside a tenant. Archived teams (is_active = false) are exempt so a team can
-- be archived and its name reused for a new team without a data migration.
--
-- Mirrors MAPPS-457's tenant-name uniqueness pattern (migration 124). The
-- service-level probe in TeamsService::create_team + update_team surfaces a
-- nicer "A team with this name already exists" 409 than the raw sqlx unique
-- violation; this index is the ultimate guard for any path that skips the
-- probe.

CREATE UNIQUE INDEX teams_name_ci_unique_idx
    ON teams (tenant_id, LOWER(name))
    WHERE is_active;
