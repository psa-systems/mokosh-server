-- PMS-502: persistent second-factor brute-force defence + TOTP anti-replay.
--
-- The legacy agent login MFA path (`POST /api/v1/auth/login` with
-- `mfa_code`) verified the TOTP code but discarded the matched step and
-- kept no per-account attempt accounting. The only throttle was the
-- shared in-memory per-email login limiter (5/min), which resets on a
-- process restart, does not coordinate across replicas, and is shared
-- with password attempts. That is too weak for a second factor whose
-- live guess space is only 3 of 1,000,000 codes at any instant.
--
-- This mirrors the portal-login remediation (PMS-501, migration 082) but
-- on the `users` row and scoped to the second factor:
--
--   mfa_last_used_step   - the TOTP step (unix_seconds / 30) of the last
--                          accepted code. A later code must match a
--                          STRICTLY GREATER step, so a captured code
--                          cannot be replayed inside its +/-1 window.
--   mfa_failed_attempts  - consecutive failed/replayed second-factor
--                          codes; reset to 0 on the next accepted code.
--   mfa_locked_until      - when set and in the future, the login handler
--                          rejects the MFA code before verifying it
--                          (exponential backoff window).

ALTER TABLE users
    ADD COLUMN mfa_last_used_step BIGINT,
    ADD COLUMN mfa_failed_attempts INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN mfa_locked_until TIMESTAMPTZ;
