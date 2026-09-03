-- PMS-729 phase 2 §5 H4: TOTP + recovery codes for portal contacts.
--
-- Mirrors the agent-side MFA schema:
--   - `users.mfa_enabled`, `users.mfa_secret` (migration 003)
--   - `users.mfa_recovery_codes_hashes` (migration 029)
--
-- Portal contacts get the same three primitives on their own row so an
-- opt-in second factor lives independently per contact. A contact
-- without MFA behaves exactly as before (login is password-only). A
-- contact with `portal_mfa_enabled = TRUE` needs a TOTP code (or a
-- single-use recovery code) on top of the password to complete login.
--
-- Column semantics:
--   portal_mfa_enabled                - flipped to TRUE only after the
--                                       contact confirms a valid TOTP
--                                       code against the stored secret
--                                       via /auth/me/mfa/enable.
--   portal_mfa_secret                 - base32-encoded TOTP secret,
--                                       stored plaintext (same posture
--                                       as agent). NULL until the
--                                       first /auth/me/mfa/setup call.
--                                       Cleared on /disable.
--   portal_mfa_enrolled_at            - stamped by /enable so admin
--                                       reporting can see MFA adoption
--                                       over time.
--   portal_mfa_recovery_codes_hashes  - array of Argon2id hashes of
--                                       single-use recovery codes.
--                                       Server never stores plaintext;
--                                       the /enable response is the
--                                       ONLY time the customer sees
--                                       them.
--
-- Tenant scoping is inherited from the row itself (`contacts.tenant_id`
-- + the existing RLS policy).

ALTER TABLE contacts
    ADD COLUMN portal_mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN portal_mfa_secret VARCHAR(100),
    ADD COLUMN portal_mfa_enrolled_at TIMESTAMPTZ,
    ADD COLUMN portal_mfa_recovery_codes_hashes TEXT[] NOT NULL DEFAULT '{}';

COMMENT ON COLUMN contacts.portal_mfa_enabled IS
    'PMS-729 phase 2 H4: portal-side TOTP MFA flag. Flipped to TRUE by /auth/me/mfa/enable after the contact proves a valid code.';
COMMENT ON COLUMN contacts.portal_mfa_secret IS
    'PMS-729 phase 2 H4: base32 TOTP secret. NULL until first setup; cleared on disable.';
COMMENT ON COLUMN contacts.portal_mfa_recovery_codes_hashes IS
    'PMS-729 phase 2 H4: Argon2id hashes of single-use recovery codes. Plaintext returned by /enable exactly once.';
