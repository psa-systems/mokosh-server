-- PMS-1208 finding 3: give the mirror a standalone-mode identity axis.
--
-- BUNYIP-674 shipped `mokosh_bunyip_grants` keyed on
-- `grantee_bunyip_user_id`. In SaaS mode that value is the Bunyip
-- sub, and `MembershipRepo::list_views_for_identity` UNIONs grant
-- rows onto the identity's memberships by joining the sub to
-- `users.bunyip_user_id`.
--
-- Standalone mode has no bunyip identity plane and no user's
-- `bunyip_user_id` is ever set, so the UNION never fires and a
-- grant a standalone owner successfully creates is invisible to the
-- grantee's switcher. The `DELETE /my-grants/{id}` path already
-- works standalone because it filters the mirror by
-- `grantee_bunyip_user_id = caller.id` (mokosh users.id doubling as
-- the sub in standalone), but the switcher UNION cannot use the
-- same axis - it joins identity to users via email, not by id.
--
-- Adding `grantee_email` gives the mirror a second identity axis
-- the standalone UNION can match against, without paying anything
-- in SaaS mode (both axes are populated on every write from now on
-- and either matches; the read prefers the sub when available).
-- The column is nullable so pre-migration rows keep working, and
-- every write from PMS-1208's accept path onward fills it in.

ALTER TABLE mokosh_bunyip_grants
    ADD COLUMN grantee_email TEXT;

COMMENT ON COLUMN mokosh_bunyip_grants.grantee_email IS
    'PMS-1208: the grantee''s email at accept time. Populated by the accept path AND by the receiver''s granted branch (from the invitation row / webhook payload). Used by `MembershipRepo::list_views_for_identity` in standalone mode where no bunyip_user_id is set on the identity''s linked users row.';

-- Read pattern the UNION uses. Case-insensitive to match the
-- identity/users email join shape.
CREATE INDEX idx_mokosh_bunyip_grants_by_grantee_email_active
    ON mokosh_bunyip_grants (lower(grantee_email))
    WHERE revoked_at IS NULL AND grantee_email IS NOT NULL;
