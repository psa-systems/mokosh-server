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
ALTER TABLE users
    ADD COLUMN mfa_recovery_codes_hashes TEXT[] NOT NULL DEFAULT '{}';
