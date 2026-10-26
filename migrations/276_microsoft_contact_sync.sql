-- MAPPS-1101: Microsoft 365 joins the contact-sync providers.
--
-- Microsoft Graph is the receiving API (/v1.0/me/contacts and
-- /v1.0/me/contacts/delta). The credential is an OAuth 2.0 refresh token
-- against an Entra ID app registration the Mokosh deployment holds, so
-- customers consent to one app rather than registering their own in Azure;
-- the posture matches the Google client (PMS-1430). The refresh token
-- itself lands in the secret provider under SecretKind::ContactSync, like
-- Google's does, so this migration only widens what `provider` may say.
--
-- The CHECK is the shape test for `provider`; a row naming a value the code
-- cannot build is a connection nothing can sync, and the constraint is what
-- makes that unrepresentable (migration 220, 238, 254).

ALTER TABLE contact_sync_connections
    DROP CONSTRAINT contact_sync_connections_provider_check;

ALTER TABLE contact_sync_connections
    ADD CONSTRAINT contact_sync_connections_provider_check
    CHECK (provider IN ('google', 'vcard', 'icloud', 'microsoft'));

COMMENT ON COLUMN contact_sync_connections.provider IS
    'MAPPS-1101: google (OAuth, People API), vcard (uploaded file, PMS-1290), icloud (CardDAV + app-specific password, PMS-1341), or microsoft (OAuth, Graph /me/contacts).';
