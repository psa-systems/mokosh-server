-- PMS-196: align mokosh_auth.org_invitations with admin_invites.
--
-- 20260514000001 created `email` as TEXT (case-sensitive) while admin_invites
-- uses CITEXT, so "User@x.com" and "user@x.com" were treated as different
-- invitees and the partial-unique "one open invite per (tenant, email)" guard
-- could be bypassed by case. It also lacked the octet_length CHECK on
-- token_hash that admin_invites carries. This migration brings both into line.
-- The citext extension is already installed (20260506000001_create_schema.sql).

ALTER TABLE mokosh_auth.org_invitations
    ALTER COLUMN email TYPE CITEXT;

ALTER TABLE mokosh_auth.org_invitations
    ADD CONSTRAINT org_invitations_token_hash_len_chk
        CHECK (octet_length(token_hash) = 32);
