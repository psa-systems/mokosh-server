-- PMS-1533: `integrations` was unique only on `(tenant_id, provider)`, so
-- nothing stopped two tenants from both holding the same provider's
-- `external_organisation_id` (added nullable, unenforced, by 282). A
-- webhook keyed on `(provider, external_organisation_id)` then has no way
-- to tell the two rows apart and `tenant_for_external_organisation`
-- (`src/modules/billing/service.rs`) returns whichever row Postgres
-- streams first, silently misrouting every event for the losing tenant.
--
-- A partial unique index, not a CHECK: most rows have no delegated
-- invoice issuer and `external_organisation_id IS NULL`, and NULL never
-- collides with NULL in a unique index, so only the rows that actually
-- claim an external organisation are constrained.
CREATE UNIQUE INDEX idx_integrations_provider_external_org
    ON integrations (provider, external_organisation_id)
    WHERE external_organisation_id IS NOT NULL;
