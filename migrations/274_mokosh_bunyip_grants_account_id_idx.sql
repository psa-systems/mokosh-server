-- PMS-1495: the members-list UNION ALL query filters
-- `mokosh_bunyip_grants` by `WHERE revoked_at IS NULL AND
-- mokosh_account_id = $1` with no reference to
-- `grantee_bunyip_user_id`. The only existing index on this table,
-- `mokosh_bunyip_grants_active_by_grantee_idx`
-- (`grantee_bunyip_user_id, mokosh_account_id`), leads on
-- `grantee_bunyip_user_id`, so a query that only has
-- `mokosh_account_id` cannot use it and falls back to a sequential
-- scan that grows with the mirror's total row count across every
-- tenant, not this tenant's page.
--
-- A second partial index leading on `mokosh_account_id` gives the
-- members query (and the pre-existing per-tenant grants read it
-- replaces) an index scan bounded by the tenant's own active grants.
CREATE INDEX idx_mokosh_bunyip_grants_by_account_id_active
    ON mokosh_bunyip_grants (mokosh_account_id)
    WHERE revoked_at IS NULL;
