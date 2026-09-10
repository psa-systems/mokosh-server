-- PMS-987: application-tier CONFIGURATION held in the database.
--
-- app_config is the sibling of app_secrets (PMS-988), and the split between
-- the two is deliberate. app_secrets holds AES-256-GCM ciphertext keyed by
-- the deployment's ENCRYPTION_KEY, so a leaked row dump is unusable without
-- the key. app_config holds PLAINTEXT, because configuration is not the
-- thing encryption is buying us anything against: an SMTP host, a public
-- base URL, a feature flag - none of it is a credential and none of it
-- benefits from ciphertext-at-rest. If a value is a SECRET, it belongs in
-- app_secrets. If it is CONFIGURATION, it belongs here.
--
-- Application-scope: one row per env-style key, no tenant column, and no
-- RLS. Tenant configuration lives elsewhere (the tenants table and its
-- children), and mixing planes here would let a caller ask "what SMTP host
-- does this tenant use", which is not a question this table exists to
-- answer.
--
-- Bootstrap-tier keys are refused at the provider layer, not by the schema:
-- DATABASE_URL, MOKOSH_APP_DATABASE_URL, ENCRYPTION_KEY, CONFIG_FILE_DIR,
-- CONFIG_PROVIDERS and the BUNYIP_CONFIG_* trio in src/config/registry.rs
-- cannot come from this table (the credential used to reach the database
-- cannot come from the database). See src/config/database.rs for the guard.

CREATE TABLE app_config (
    name TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

GRANT SELECT, INSERT, UPDATE, DELETE ON app_config TO mokosh_app;
