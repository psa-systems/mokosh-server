-- PMS-657: detect a country-level login-location change on the legacy cookie
-- login and notify the user.
--
-- last_login_country holds the ISO 3166-1 alpha-2 code of the country the user
-- last logged in from (NULL until the first geolocatable login). It is compared
-- against the current login's country to detect a significant change.
-- login_location_alerts is the per-user opt-out (default on). Country is resolved
-- from the client IP via IP2Location when IP2LOCATION_DB_PATH is configured; the
-- feature is a no-op otherwise.
ALTER TABLE users
    ADD COLUMN last_login_country    TEXT
        CHECK (last_login_country IS NULL OR length(last_login_country) <= 64),
    ADD COLUMN login_location_alerts BOOLEAN NOT NULL DEFAULT TRUE;
