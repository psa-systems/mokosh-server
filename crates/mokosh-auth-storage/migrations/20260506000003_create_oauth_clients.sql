-- Registered OAuth/OIDC clients. Populated by the `mokosh-bootstrap
-- clients register` CLI; not by user-facing endpoints (no RFC 7591).

CREATE TABLE mokosh_auth.oauth_clients (
    id                          UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    -- The public `client_id` value advertised to relying parties. It is a
    -- UUID by convention but stored separately from `id` so we can rotate
    -- the public identifier without rewriting foreign keys.
    client_id                   UUID         NOT NULL UNIQUE,
    -- NULL = platform-wide client (e.g. mokosh-clients-web, internal admin
    -- tools). Set = client is scoped to one tenant only.
    tenant_id                   UUID         REFERENCES public.tenants(id) ON DELETE CASCADE,
    -- Argon2id PHC string. NULL for public clients.
    client_secret_hash          TEXT,
    client_type                 TEXT         NOT NULL,
    name                        TEXT         NOT NULL,
    redirect_uris               TEXT[]       NOT NULL,
    post_logout_redirect_uris   TEXT[]       NOT NULL DEFAULT '{}',
    backchannel_logout_uri      TEXT,
    lifecycle_event_uri         TEXT,
    allowed_scopes              TEXT[]       NOT NULL,
    allowed_grant_types         TEXT[]       NOT NULL,
    token_endpoint_auth_method  TEXT         NOT NULL,
    -- Reserved for future protocol revisions. Today, the CHECK below
    -- forces this to TRUE; PKCE is non-negotiable.
    require_pkce                BOOLEAN      NOT NULL DEFAULT TRUE,
    access_token_ttl_seconds    INTEGER      NOT NULL DEFAULT 600,
    refresh_token_ttl_seconds   INTEGER      NOT NULL DEFAULT 2592000,
    refresh_idle_ttl_seconds    INTEGER      NOT NULL DEFAULT 1209600,
    audience                    TEXT         NOT NULL,
    -- Phase-2 hook: DPoP-bound tokens (RFC 9449).
    dpop_bound                  BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at                  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    created_by                  UUID         REFERENCES mokosh_auth.users(id) ON DELETE SET NULL,
    disabled_at                 TIMESTAMPTZ,

    CONSTRAINT oauth_clients_pkce_required_chk
        CHECK (require_pkce = TRUE),
    CONSTRAINT oauth_clients_type_chk
        CHECK (client_type IN ('public', 'confidential')),
    CONSTRAINT oauth_clients_auth_method_chk
        CHECK (token_endpoint_auth_method IN
               ('none','client_secret_basic','client_secret_post','private_key_jwt')),
    -- Public clients MUST NOT have a stored secret; confidential clients
    -- MUST have one. Anything else is a misconfiguration we refuse to
    -- write.
    CONSTRAINT oauth_clients_secret_consistency_chk
        CHECK ((client_type = 'public'       AND client_secret_hash IS NULL)
            OR (client_type = 'confidential' AND client_secret_hash IS NOT NULL)),
    CONSTRAINT oauth_clients_token_ttl_chk
        CHECK (access_token_ttl_seconds  BETWEEN 60   AND 3600
           AND refresh_token_ttl_seconds BETWEEN 3600 AND 7776000  -- 90d max
           AND refresh_idle_ttl_seconds  BETWEEN 60   AND refresh_token_ttl_seconds)
);

CREATE INDEX oauth_clients_tenant_idx
    ON mokosh_auth.oauth_clients (tenant_id)
    WHERE disabled_at IS NULL;
