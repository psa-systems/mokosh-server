-- Cosmetic metadata for oauth_clients consumed by the Bunyip app launcher.
-- Both columns are nullable; the launcher falls back to the client's name
-- (and a generic icon) when they are unset.
--
-- This lives with the auth-subsystem migrations (not mokosh-server's host
-- `migrations/` directory) because it alters an auth-owned table. The host
-- migrator runs before the auth migrator, so a host migration touching
-- `mokosh_auth.oauth_clients` would execute before the schema/table exists
-- and fail. Keeping it here guarantees `oauth_clients` already exists
-- (created in 20260506000003) when these columns are added.

ALTER TABLE mokosh_auth.oauth_clients
    ADD COLUMN IF NOT EXISTS description TEXT,
    ADD COLUMN IF NOT EXISTS icon_url    TEXT;
