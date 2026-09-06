-- MAPPS-457: enforce case-insensitive uniqueness on non-personal tenant names.
--
-- Motivation: the super-admin create-tenant flow had no name-collision guard.
-- Two rows with `name = 'Acme Corp'` and different slugs both succeeded, so the
-- tenant roster rendered visually-identical rows the operator could not tell
-- apart without the URL preview. The slug column has a unique DB constraint;
-- this closes the parallel gap on `name`.
--
-- Personal tenants (name auto-generated as `X's workspace` from the owner's
-- given_name or email) can legitimately collide when two different users share
-- a first name. The `WHERE personal_owner_id IS NULL` partial-index scope
-- keeps that path untouched; only tenants provisioned via `create_tenant`
-- (which sets `personal_owner_id = NULL`) fall under the constraint.
--
-- The service-level probes in `TenantService::create_tenant` and
-- `TenantService::update_tenant` mirror this filter and surface a nicer error
-- message than the raw sqlx unique-violation would; the index below is the
-- ultimate guard for any path that skips the probes.

CREATE UNIQUE INDEX tenants_name_ci_unique_idx
    ON tenants (LOWER(name))
    WHERE personal_owner_id IS NULL;
