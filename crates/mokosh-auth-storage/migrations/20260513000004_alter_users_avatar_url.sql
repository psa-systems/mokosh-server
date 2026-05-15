-- Settings -> Profile lets a signed-in user set their avatar URL. TEXT
-- (no length cap at the DB layer; the handler enforces a reasonable
-- limit). NULL = no avatar; the SPA falls back to initials.

ALTER TABLE mokosh_auth.users
    ADD COLUMN avatar_url TEXT;
