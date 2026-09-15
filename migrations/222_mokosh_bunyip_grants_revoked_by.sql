-- PMS-1210: audit-distinguish an owner revoke from a grantee "leave account".
--
-- BUNYIP-673 shipped the owner-side revoke path (`POST /v1/grants/{id}
-- /revoke` on bunyip-api). BUNYIP-674 shipped the mirror + webhook
-- receiver on mokosh-server. Neither knows WHO initiated a revoke: the
-- receiver stamps `revoked_at` on the mirror row and moves on, so the
-- audit trail cannot distinguish "the owner took my access away" from
-- "the grantee left this account" - the two states read identically.
-- Cloudflare's account-membership model exposes the same distinction on
-- the account audit log, and the grantee-side leave path added in this
-- ticket is what generates the second class of event.
--
-- One nullable VARCHAR(20) column with a CHECK on the closed set:
--
--   'owner'   - the account owner revoked the grant.
--   'grantee' - the grantee left the account. This is the new class the
--               `DELETE /api/v1/my-grants/{id}` endpoint stamps.
--   'system'  - a cascade (account deletion webhook, tenant suspension,
--               scheduled cleanup). Reserved for follow-up work; a
--               `NULL` value from the current owner-revoke path stays
--               `NULL` on this migration so historical rows read as
--               "unknown initiator" rather than getting a guessed value.
--
-- Nullable rather than NOT NULL because migrations are immutable, so
-- backfilling the historical rows to a wrong value cannot be undone -
-- the audit UI treats `NULL` as "unknown initiator" and this is fine.
-- Every write from now on fills the column in: the receiver's
-- owner-revoke path (updated in the same commit that adds the DELETE
-- handler) and the grantee-leave path both write the appropriate value.

ALTER TABLE mokosh_bunyip_grants ADD COLUMN revoked_by VARCHAR(20)
    CHECK (revoked_by IS NULL OR revoked_by IN ('owner', 'grantee', 'system'));

COMMENT ON COLUMN mokosh_bunyip_grants.revoked_by IS
    'PMS-1210: who initiated the revoke. owner | grantee | system | NULL (historical or unknown).';
