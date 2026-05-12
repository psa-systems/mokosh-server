-- Per-user account lockout. After N consecutive failed password
-- attempts within a window, the account is locked for M minutes; the
-- counter resets on a successful sign-in. We track these on the user
-- row rather than a separate table because the data is tiny and the
-- only consumers are the login handler + the unlock-on-success path.

ALTER TABLE mokosh_auth.users
    ADD COLUMN failed_login_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN last_failed_login_at TIMESTAMPTZ,
    ADD COLUMN locked_until TIMESTAMPTZ;
