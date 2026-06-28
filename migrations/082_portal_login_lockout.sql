-- PMS-501: persistent portal-login brute-force defence.
--
-- The portal login path (`POST /api/v1/portal/auth/login`) had no
-- failed-attempt accounting, so an attacker could grind unlimited
-- password guesses against a known (tenant_slug, email). The in-memory
-- per-IP/per-account rate limiter added alongside this migration does not
-- survive a process restart and does not coordinate across replicas, so
-- the account-level lockout state is persisted on the contact row here.
--
--   portal_failed_login_count - consecutive failed portal logins; reset to
--                               0 on the next successful login.
--   portal_locked_until       - when set and in the future, the portal
--                               login handler rejects before verifying the
--                               password (exponential backoff window).

ALTER TABLE contacts
    ADD COLUMN portal_failed_login_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN portal_locked_until TIMESTAMPTZ;
