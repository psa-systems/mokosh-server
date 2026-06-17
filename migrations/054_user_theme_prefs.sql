-- PMS-410: per-user theme preferences.
--
-- NULL means "unset" for both columns, matching the legacy behaviour so
-- existing users see no change. The accent catalog lives in the SPA;
-- the server stores the accent id opaquely and only bounds its shape.
--
-- `theme_base_mode` picks the light/dark palette. NULL = unset, which
-- the client treats as following the system preference. The enum is
-- pinned by a CHECK so a bad value is rejected at write time (surfaces
-- as a 422) rather than silently persisting.
--
-- `theme_accent_id` is an opaque accent id string. NULL = unset, which
-- the client falls back to its default accent. Cap length at 32 chars:
-- enough room for any catalog id, small enough to keep a pathological
-- value from blowing up the row.

ALTER TABLE users
    ADD COLUMN theme_base_mode TEXT NULL
        CHECK (theme_base_mode IS NULL OR theme_base_mode IN ('light', 'dark', 'system'));

ALTER TABLE users
    ADD COLUMN theme_accent_id TEXT NULL
        CHECK (theme_accent_id IS NULL OR char_length(theme_accent_id) <= 32);

COMMENT ON COLUMN users.theme_base_mode IS
    'Per-user theme base mode. One of light, dark, system. NULL = unset; client treats as system. Pinned by check constraint.';

COMMENT ON COLUMN users.theme_accent_id IS
    'Per-user accent id (opaque; accent catalog lives in mokosh-apps). NULL = unset; client falls back to its default accent. Capped at 32 chars by check constraint.';
