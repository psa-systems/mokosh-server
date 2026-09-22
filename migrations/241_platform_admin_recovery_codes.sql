-- Recovery codes for platform-admin MFA.
--
-- Migration 160 gave `platform_admins` the same TOTP trio as `users`:
-- `mfa_enabled`, `mfa_secret`, `mfa_last_totp_step`. It stopped short of
-- migration 029's fourth column, so the login gate accepted a TOTP code
-- and nothing else - a lost authenticator was recovery-code-shaped
-- everywhere except here.
--
-- One TEXT[] of sha256 hex hashes, empty by default, so a row from before
-- reads the way it always did (no codes, none to spend). The enable path
-- mints ten codes and stores their hashes; the login path spends one by
-- `array_remove` on hash match, same shape `users` and `contacts` already
-- share through `utils::recovery::hash_code_hex`.
--
-- No backfill: no platform admin holds a code minted before this migration,
-- so `'{}'` is the truthful starting value everywhere.

ALTER TABLE platform_admins
    ADD COLUMN mfa_recovery_codes_hashes TEXT[] NOT NULL DEFAULT '{}';

COMMENT ON COLUMN platform_admins.mfa_recovery_codes_hashes IS
    'sha256 hex hashes of the recovery codes the enable path minted. Spent by array_remove on match; plaintext is returned to the operator exactly once.';
