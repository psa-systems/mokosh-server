-- PMS-1414: admin-flippable feature toggles, keyed by the `Feature` variants in
-- `src/modules/features/registry.rs`.
--
-- Ported from BUNYIP-840, whose standup framing is the point: every major
-- feature ships behind an on/off switch, off in production and on in staging,
-- flipped from an admin page with no deploy. mokosh had no way to do the last
-- part. `src/config/flags.rs` (PMS-983) gives a process-wide switch a typed
-- shape, but its values come from the configuration provider, and the one flag a
-- client reads (`ORGANIZATIONS_ENABLED`) reaches the SPA through
-- `window.__MOKOSH_CONFIG__`, injected by the container entrypoint. So flipping
-- it means a `NiceGuyIT/docker` pull request and a deploy, which is exactly the
-- cost this table removes.
--
-- ## The two rules a reader needs
--
-- A MISSING ROW READS AS OFF. The registry, not this table, is the list of
-- features; a row only records that somebody changed one. So a fresh database, a
-- restored backup and a newly added `Feature` variant all behave the same way,
-- and nothing has to seed a row per feature on upgrade.
--
-- AN UNKNOWN KEY IS IGNORED. A row naming a key no variant matches is a feature
-- this build has removed or not yet gained, and it is read as absent with one
-- warning per process rather than being deleted. Deleting it would lose an
-- operator's intent across a rollback, which is the one direction where the
-- rows matter more than the code.
--
-- The CHECK keeps keys to the `snake_case` the wire and the enum both use, so a
-- key cannot arrive with a space or a capital and then fail to match the variant
-- it was meant for.
--
-- `updated_by` is nullable and `ON DELETE SET NULL`: a toggle outlives the admin
-- who flipped it, and a departed colleague's row must not block deleting their
-- user. The audit log carries the full actor; this column is for the admin page's
-- "who last touched this".
--
-- Not tenant-scoped, deliberately. These are deployment-wide switches in the
-- same family as the email relay and the product name (PMS-638, PMS-789), so
-- there is no `tenant_id`, no RLS policy and no per-tenant override. A per-tenant
-- entitlement is `ModuleGate`, which already exists and answers a different
-- question.

CREATE TABLE feature_toggles (
    key        TEXT        PRIMARY KEY CHECK (key ~ '^[a-z][a-z0-9_]*$'),
    enabled    BOOLEAN     NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by UUID        REFERENCES users (id) ON DELETE SET NULL
);

COMMENT ON TABLE feature_toggles IS
    'PMS-1414: deployment-wide feature switches. A missing row reads as off; the registry in src/modules/features/registry.rs is the list of features.';

-- PMS-1265: a new table is granted to mokosh_app in the same migration, because
-- a deployment whose migrations run as another owner leaves the serving role
-- without access and every read fails at runtime rather than here.
GRANT SELECT, INSERT, UPDATE, DELETE ON feature_toggles TO mokosh_app;
