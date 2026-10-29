-- PMS-1568: migration 276 widened `contact_sync_connections.provider` to
-- include `microsoft`, but left `contact_sync_oauth_states.provider`
-- (migration 221) checking only `'google'`. The Microsoft connect path
-- (`ContactSyncService::begin_microsoft_connect`) inserts a state row with
-- provider `microsoft` before the connection even exists, so the in-flight
-- state is what this constraint blocked, not the finished connection.

ALTER TABLE contact_sync_oauth_states
    DROP CONSTRAINT contact_sync_oauth_states_provider_check;

ALTER TABLE contact_sync_oauth_states
    ADD CONSTRAINT contact_sync_oauth_states_provider_check
    CHECK (provider IN ('google', 'microsoft'));
