-- PMS-1210: record who initiated a grant revoke, so the audit line can tell
-- an owner-side revoke apart from a grantee's "Leave account" gesture.
--
-- Nullable on purpose:
--   - historical rows from before this migration survive as `NULL`, read as
--     "unknown initiator" in the audit UI. No backfill on the immutable
--     shape rule the codebase already relies on.
--   - a webhook receiver that has not been updated to name the initiator
--     stamps `NULL` today; the four stated values below are what NEW writers
--     use.
--
-- The initiator vocabulary:
--   'owner'   the owner revoked through Bunyip; the receiver in
--             `src/modules/auth/bunyip_webhook.rs` stamps this on a
--             `revoked` event coming through the mokosh_grant_changed
--             webhook.
--   'grantee' the caller left the account themselves through
--             `DELETE /api/v1/my-grants/{id}` (this ticket).
--   'system'  future account-deletion cascade (not written yet).
--
-- The CHECK constraint refuses any other value at write time, so the audit
-- UI can key on the raw value without a second parser.

ALTER TABLE mokosh_bunyip_grants
    ADD COLUMN revoked_by VARCHAR(20)
    CHECK (revoked_by IS NULL OR revoked_by IN ('owner', 'grantee', 'system'));

COMMENT ON COLUMN mokosh_bunyip_grants.revoked_by IS
    'PMS-1210: who initiated the revoke (owner | grantee | system). NULL for legacy rows and for webhook events written before the receiver was updated to name the initiator.';
