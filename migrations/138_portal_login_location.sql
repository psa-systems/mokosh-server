-- PMS-729 phase 2 §5 H7: portal login-location alerts.
--
-- Mirrors the agent-side scheme (`users.last_login_country` +
-- `users.login_location_alerts`, migration 087) so a portal contact who
-- signs in from a new country gets an email exactly like a staff user
-- would.
--
-- On a successful portal login, the service resolves the client IP to
-- an ISO 3166-1 alpha-2 country via `GeoIpService` (PMS-657). If the
-- country differs from the value stored here, the server emails the
-- contact + updates the column. First geolocatable login records the
-- country silently (no alert; nothing to compare against).
--
-- Per-contact opt-out: `portal_login_location_alerts` (default TRUE).
-- A contact who does not want the alert flips it to FALSE via a
-- future `/portal/auth/me/preferences` endpoint (H7 follow-up).
--
-- Feature no-ops without `IP2LOCATION_DB_PATH` set: the country column
-- stays NULL for every contact and no email is dispatched. Turning the
-- feature on later picks up as soon as `geoip` is configured; the
-- first login from a public IP records the country silently.

ALTER TABLE contacts
    ADD COLUMN portal_last_login_country CHAR(2),
    ADD COLUMN portal_login_location_alerts BOOLEAN NOT NULL DEFAULT TRUE;

COMMENT ON COLUMN contacts.portal_last_login_country IS
    'PMS-729 phase 2 H7: ISO 3166-1 alpha-2 country of the contact''s most recent geolocatable portal login. NULL until the first login from a public IP. Compared against the incoming country to decide whether to send the new-sign-in email.';
COMMENT ON COLUMN contacts.portal_login_location_alerts IS
    'PMS-729 phase 2 H7: per-contact opt-out for the new-sign-in email. TRUE by default; a contact who flips it FALSE stops receiving alerts (the country column still updates).';
