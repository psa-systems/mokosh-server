-- MAPPS-497 item 4 (PMS-502 identity-level extension): add the TOTP
-- anti-replay watermark to `identities` so the phase-3 identity-first
-- login path (MAPPS-492) can burn the accepted step, matching the
-- per-tenant `users.mfa_last_used_step` shape.
--
-- Without this, the same TOTP code stays replayable against
-- `authenticate_identity_first` for its whole +/-1 step window (~60s)
-- because no tenant is yet scoped, so the tenant-keyed `users`
-- watermark cannot fire. The phase-3 primitives verify the code but
-- have no place to burn the step. This migration adds the identity-
-- level column so `authenticate_identity_first` can `UPDATE identities
-- SET mfa_last_totp_step = $step WHERE id = $id AND ($step > mfa_last_totp_step)`
-- and treat 0 rows-affected as a replay.
--
-- Nullable-style columns are avoided (`DEFAULT 0` for the watermark,
-- `DEFAULT 0` for the counter) so every existing row is immediately
-- eligible for a step > 0 write; no backfill needed.

ALTER TABLE identities
    ADD COLUMN mfa_last_totp_step BIGINT NOT NULL DEFAULT 0;
