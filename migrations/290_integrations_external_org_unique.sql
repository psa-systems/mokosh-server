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
--
-- The index is CROSS-TENANT, which is the point and is unusual here: every
-- other constraint on this table stops at `tenant_id`, and RLS means the
-- row this one collides with is invisible to the transaction that trips
-- it. That is why `record_connection` turns the 23505 into a message about
-- another tenant rather than letting it surface as a 500: the insert can
-- see nothing to explain its own failure.
--
-- Written as 290 rather than 287: this change was first authored against a
-- tree where 287 was free, and `bill_payments` took it in the meantime
-- (PMS-1536). Two migrations cannot share a version (PMS-965).
CREATE UNIQUE INDEX idx_integrations_provider_external_org
    ON integrations (provider, external_organisation_id)
    WHERE external_organisation_id IS NOT NULL;
