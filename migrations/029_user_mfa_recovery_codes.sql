-- PMS-4 AC3: per-user MFA recovery codes.
--
-- Single-use codes the user can submit instead of a TOTP code if they
-- lose access to their authenticator. Each element is the lowercase
-- hex SHA-256 of the canonical code (see
-- `mokosh-auth-crypto::recovery`); the host side reuses that crate so
-- the SSO and legacy paths share canonicalisation.
--
-- `NOT NULL DEFAULT '{}'` lets existing rows keep working and removes
-- the need to handle NULL on every read. Postgres 11+ adds a column
-- with a constant default without rewriting the table; the
-- `ACCESS EXCLUSIVE` lock is brief (catalog-only).
--
-- This migration shipped originally as `027_user_mfa_recovery_codes.sql`
-- (PMS-4, PR #83) but collided with PMS-106's `027_sla_notify.sql`
-- which merged first; sqlx rejected the duplicate version on fresh
-- DBs. Renamed to 029 and `IF NOT EXISTS`-ified so any environment
-- that already applied the old 027 form re-runs cleanly.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS mfa_recovery_codes_hashes TEXT[] NOT NULL DEFAULT '{}';
