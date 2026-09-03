-- MAPPS-532: give the portal a revocation point.
--
-- The portal identity plane is stateless: `PortalAuthService::login` mints
-- a JWT and writes nothing but `portal_last_login_at`, and `PortalJwtClaims`
-- carries no session id, so there is no row to delete when a contact signs
-- out. `POST /api/v1/portal/auth/logout` had nothing it could revoke, and a
-- portal token stayed good for its full 8-hour TTL after the customer
-- clicked Logout.
--
--   portal_tokens_valid_from - reject a portal token whose `iat` predates
--                              this. NULL (the default, and every existing
--                              row) means no cutoff, so tokens already in
--                              flight when this migration lands keep working
--                              until they expire.
--
-- Same shape as `users.password_changed_at` (PMS-681) on the platform side,
-- and read on every portal request by `portal_auth_middleware`, which
-- already loads this row for the contact's names.

ALTER TABLE contacts
    ADD COLUMN portal_tokens_valid_from TIMESTAMPTZ;
