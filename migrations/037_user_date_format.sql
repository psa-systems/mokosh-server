-- PMS-253: per-user date/time format preference.
--
-- NULL means "use the browser locale" (matches the legacy rendering
-- behaviour, so existing users see no change). Non-NULL is a token
-- string from the canonical grammar (YYYY, MMM, DD, HH, mm, etc.); the
-- client tokenizes against the user's stored format and renders every
-- datetime through one helper. Server stores the string verbatim and
-- has no opinion on which tokens are valid - validation lives in the
-- client so the same grammar can evolve without a migration each time.
--
-- Cap length at 64 chars: more than enough room for the longest preset
-- ("dddd, MMMM D, YYYY h:mm:ss A" = 28 chars), small enough to keep a
-- pathological format from blowing up every render path.

ALTER TABLE users
    ADD COLUMN date_format_string TEXT NULL
        CHECK (date_format_string IS NULL OR char_length(date_format_string) <= 64);

COMMENT ON COLUMN users.date_format_string IS
    'Per-user date/time format string (mokosh-apps token grammar). NULL = use browser locale. Capped at 64 chars by check constraint.';
