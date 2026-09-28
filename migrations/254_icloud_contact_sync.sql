-- PMS-1341: iCloud joins the contact-sync providers.
--
-- Apple offers no public OAuth scope for contacts, so this connection is
-- CardDAV against `contacts.icloud.com` with an Apple ID and an app-specific
-- password. That is a different credential shape from Google's refresh token,
-- and it is why the provider list is a CHECK rather than a free string: a
-- connection naming a provider the code cannot build is a row nothing can sync,
-- and the constraint is what makes that unrepresentable (migration 220, 238).
--
-- The credential itself does NOT land here. It goes to the secret provider like
-- every other tenant credential (PMS-912: a tenant credential belongs in the
-- `SecretProvider`, not in a column beside the row that names it), so this
-- migration only widens what `provider` may say.
ALTER TABLE contact_sync_connections
    DROP CONSTRAINT contact_sync_connections_provider_check;

ALTER TABLE contact_sync_connections
    ADD CONSTRAINT contact_sync_connections_provider_check
    CHECK (provider IN ('google', 'vcard', 'icloud'));

COMMENT ON COLUMN contact_sync_connections.provider IS
    'PMS-1341: google (OAuth, People API), vcard (an uploaded file, PMS-1290), or icloud (CardDAV with an app-specific password).';
