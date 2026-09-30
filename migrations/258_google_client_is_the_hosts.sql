-- PMS-1430: the Google OAuth client is the host's, so no tenant stores one.
--
-- PMS-1264 stored one client id on the SYSTEM tenant and PMS-1340 let every
-- tenant store its own, both in `tenant_settings` under
-- (`integrations`, `google_contacts_client_id`), with the matching secret in the
-- tenant secret provider under `SecretKind::OauthClient`. That put a Google
-- Cloud console walkthrough in front of every customer: create a project, enable
-- the People API, build a consent screen, add yourself as a test user, pick three
-- scopes, create a Web application client, and paste an id and a secret back.
-- Which Google application a Mokosh installation authenticates as is a property
-- of the deployment, so it moves to one pair of governed application-tier
-- secrets (`src/app_secrets/`), and nothing here holds it any more.
--
-- This deletes the id rows. The SECRETS beside them cannot be deleted from SQL:
-- they live in whichever `SecretProvider` the deployment declared, which may be
-- Infisical over the network, so a one-shot pass
-- (`contact_sync::client_cleanup`, PMS-1320) removes them at the next boot. The
-- two halves are deliberately separated rather than one being skipped: an id row
-- left behind would be read by nothing, but a secret left behind is a live
-- credential nobody can see in the product any more.
--
-- Rows are DELETED rather than kept for reference. A stored client id is not
-- history worth keeping: it names a Google application the deployment no longer
-- connects as, and leaving it invites a later reader to wire it back up.
--
-- What this does NOT touch, and must not: `contact_sync_connections` and the
-- refresh tokens under `SecretKind::ContactSync`. Those are a tenant's own grant
-- and stay exactly where they are. They will, however, stop working: a refresh
-- token is bound to the client that issued it, so a connection made under a
-- tenant's own registration is refused by Google with `invalid_grant` against the
-- host client, and `contact_sync::runs` marks it `reconnect_required` so the
-- admin is asked to connect again. There is no migration for that: Google does
-- not re-issue a token to a different client, and pretending otherwise would be
-- worse than asking.

DELETE FROM tenant_settings
WHERE category = 'integrations'
  AND key = 'google_contacts_client_id';
