-- Cosmetic metadata for oauth_clients consumed by the Bunyip app launcher.
-- Both columns are nullable; the launcher falls back to the client's name
-- (and a generic icon) when they are unset.
ALTER TABLE mokosh_auth.oauth_clients
    ADD COLUMN IF NOT EXISTS description TEXT,
    ADD COLUMN IF NOT EXISTS icon_url    TEXT;
