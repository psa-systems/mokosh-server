-- BUNYIP-674 [BUNYIP-626 child 3]: local mirror of the Bunyip grant table
-- so a revoked cross-account grant takes effect on the next request
-- rather than at the next `at+jwt` refresh.
--
-- Bunyip is authoritative: the `mokosh_grant_changed` webhook receiver at
-- `POST /api/v1/bunyip/webhooks/mokosh-grant-changed` upserts one row per
-- (grantee_bunyip_user_id, mokosh_account_id) triple on every emit. A
-- revoked event drops the role to NULL and stamps `revoked_at`; a granted
-- event carries the current role and NULLs `revoked_at`, so a duplicate
-- delivery (BUNYIP-211-style retry) is idempotent and a `granted` event
-- arriving AFTER a `revoked` one for the same grant reinstates it (the
-- authoritative state is whatever Bunyip last sent).
--
-- No foreign key to `users(id)`: Mokosh's `users` row for a Bunyip user
-- lands JIT on the first sign-in, so a grant may arrive from Bunyip
-- BEFORE the grantee has ever signed into Mokosh. The mokosh RS layer's
-- lookup (a separate follow-up alongside the grant claim on `at+jwt`)
-- resolves the grantee's Mokosh row after the FK-less write.
--
-- `mokosh_account_id` is the Mokosh tenant slug the owner controls. Kept
-- as TEXT for the same reason it is on Bunyip's own table: the tenants
-- live here and the receiver validates the value on read, but a stale
-- mirror row that names a tenant that no longer exists becomes inert
-- rather than a foreign-key error.
--
-- `bunyip_grant_id` (Uuid) is Bunyip's own primary key on
-- `mokosh_account_grants`. Kept for observability (correlating a mokosh
-- row to the bunyip event that wrote it) and NOT used as a uniqueness
-- key: a revoke-then-regrant on Bunyip mints a NEW `bunyip_grant_id`,
-- and treating that as a distinct row here would leave the previous
-- revoked row live as "the grant is still revoked", which is the
-- opposite of what the receiver settled on.
--
-- RLS: this table is cross-tenant BY DESIGN (a grantee's row names an
-- owner's tenant they do not otherwise belong to), so it stays outside
-- the standard tenant_isolation policy. It has no `tenant_id` column, so
-- `tests/rls_coverage.rs` lists it in `TENANTLESS_WITHOUT_RLS`.
CREATE TABLE mokosh_bunyip_grants (
    id                     UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    grantee_bunyip_user_id UUID        NOT NULL,
    owner_bunyip_user_id   UUID        NOT NULL,
    mokosh_account_id      TEXT        NOT NULL,
    bunyip_grant_id        UUID,
    role                   TEXT,
    granted_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at             TIMESTAMPTZ,
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (grantee_bunyip_user_id, mokosh_account_id),
    CHECK (
        (revoked_at IS NULL     AND role IS NOT NULL)
        OR
        (revoked_at IS NOT NULL AND role IS NULL)
    ),
    CHECK (
        role IS NULL
        OR role IN ('admin', 'manager', 'technician', 'finance', 'read_only')
    )
);

CREATE INDEX mokosh_bunyip_grants_active_by_grantee_idx
    ON mokosh_bunyip_grants (grantee_bunyip_user_id, mokosh_account_id)
    WHERE revoked_at IS NULL;

COMMENT ON TABLE mokosh_bunyip_grants IS
    'BUNYIP-674: local mirror of Bunyip mokosh_account_grants. Refreshed by the mokosh_grant_changed webhook so revocation takes effect within the next request rather than the at+jwt refresh.';
COMMENT ON COLUMN mokosh_bunyip_grants.mokosh_account_id IS
    'The mokosh tenant slug (Bunyip does not have local tenant knowledge; a stale row that names a tenant that no longer exists is inert).';
COMMENT ON COLUMN mokosh_bunyip_grants.bunyip_grant_id IS
    'The id on Bunyip mokosh_account_grants that wrote this row. Kept for observability (correlating an audit trail); not a uniqueness key because revoke-then-regrant on Bunyip mints a new id.';
COMMENT ON COLUMN mokosh_bunyip_grants.role IS
    'App-level RBAC role from PMS-1162 while the grant is active; NULL after revocation. The CHECK constraint pins the role-vs-revoked_at coupling so a webhook that violates it surfaces at write time.';
