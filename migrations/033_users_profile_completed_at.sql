-- Force-onboarding gate for Bunyip-OIDC users.
--
-- The SPA hides the rest of the app behind a name-entry screen until a
-- new user has filled in first/last name. NULL = needs onboarding;
-- non-NULL = name was confirmed (timestamp of confirmation, also useful
-- for analytics on activation latency).
--
-- Backfill existing rows to NOW() so every user who is already in the
-- system is treated as completed and is not pushed into onboarding the
-- next time they log in.
ALTER TABLE users
    ADD COLUMN profile_completed_at TIMESTAMPTZ;

UPDATE users
SET profile_completed_at = NOW()
WHERE profile_completed_at IS NULL;
