-- PMS-450 phase 1: email-to-ticket intake.
--
-- Two surfaces:
--
-- 1. `tenant_intake_tokens` holds one or more bearer tokens per tenant
--    that the external mail gateway (postfix MDA, Cloudron mail
--    hook, Microsoft Graph subscription forwarder, ...) presents on
--    `POST /api/v1/email-intake`. The plaintext token is shown to
--    the operator ONCE at create time; only the SHA-256 hash is
--    stored, so a database leak does not hand an attacker a working
--    token. `kind` is a discriminator so the same table can later
--    host other webhook surfaces (rmm-intake, billing-webhook, ...)
--    without a schema change.
--
-- 2. A partial unique index on `tickets(tenant_id, email_message_id)`
--    so the dedup the service does at the application layer is also
--    enforced at the DB layer: a duplicate intake against the same
--    tenant + Message-Id loses cleanly with a constraint violation
--    instead of double-creating. Partial because the column was
--    nullable at table creation (every non-email ticket leaves it
--    NULL); the index only covers rows where it is set.
--
-- Phase 2 (out of this PR, tracked under PMS-450) will:
--   - add a `tenant_settings.email_intake_default_company_id` so the
--     intake can auto-create a contact when the From: address is not
--     yet on the contacts list;
--   - turn an inbound reply that matches a known ticket's
--     `email_message_id` (via the `references` array on the request)
--     into a ticket comment instead of a new ticket;
--   - add an `email_intake_log` audit table that captures every raw
--     intake payload (headers, body) so a malformed sender can be
--     debugged after the fact.

CREATE TABLE tenant_intake_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Discriminator. Phase 1 only uses 'email_intake'. Free-text
    -- VARCHAR rather than an enum so a tenant or follow-up PR can
    -- coin a new surface without a CHECK-widening migration.
    kind VARCHAR(50) NOT NULL,
    -- SHA-256 hex of the bearer the operator pastes into the mail
    -- gateway. 64 chars. Never the plaintext.
    token_hash CHAR(64) NOT NULL,
    -- Human-readable label so an operator listing their tokens sees
    -- "Cloudron mail hook" or "Helpdesk inbox forwarder" instead of
    -- a UUID.
    label VARCHAR(200) NOT NULL,
    -- Last time this token authenticated a request. NULL until the
    -- first use. Surfaced on the operator's token list so an unused
    -- token can be revoked confidently.
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
);

-- Lookup index for the request path: hash the presented bearer,
-- SELECT WHERE token_hash = $1 AND revoked_at IS NULL. UNIQUE so a
-- collision is impossible (SHA-256 collision space is the smaller
-- worry; this catches a botched seed that double-inserts).
CREATE UNIQUE INDEX idx_tenant_intake_tokens_hash
    ON tenant_intake_tokens(token_hash);

-- Tenant-scoped list path for the operator's settings UI: "show me
-- every intake token I have, grouped by kind".
CREATE INDEX idx_tenant_intake_tokens_tenant_kind
    ON tenant_intake_tokens(tenant_id, kind);

-- Partial unique index for email Message-Id dedup. Without this,
-- two concurrent intakes of the same Message-Id (rare but happens
-- when a gateway retries) would race past the application-layer
-- check and double-create.
CREATE UNIQUE INDEX idx_tickets_email_message_id
    ON tickets(tenant_id, email_message_id)
    WHERE email_message_id IS NOT NULL;
