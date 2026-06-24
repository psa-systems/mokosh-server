-- PMS-469 / PMS-450 phase 2: email-intake audit log + fallback company key.
--
-- Two surfaces:
--
-- 1. `email_intake_log` captures every inbound intake payload as it
--    arrives (raw headers as JSONB, plaintext body, html body) and is
--    UPDATEd at the end of the flow with the resulting ticket_id (on
--    success) or an error string (on failure). Lets an operator
--    debug "we sent the email, why didn't a ticket appear" without
--    having to recover the raw payload from the gateway side.
--
--    Retained for 90 days by a future scheduled cleanup (separate
--    ticket); the partial index on (tenant_id, received_at DESC) is
--    sized for the "recent failures" admin filter.
--
-- 2. `tenant_settings` gains a new well-known key
--    `(category='email_intake', key='default_company_id')` whose
--    value is a UUID referencing `companies.id`. When set, an intake
--    whose From: address does not match an existing contact will
--    auto-create a contact under that company instead of returning
--    422. When unset (or NULL after the FK cascade), the Phase 1
--    posture is preserved: unknown sender => 422.
--
-- Reader: src/modules/email_intake/service.rs::record_intake_log /
--         resolve_or_create_contact.
-- Writer: validated by src/modules/settings/models.rs.

CREATE TABLE email_intake_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Message-Id of the inbound email exactly as the gateway sent it
    -- (RFC 5322 angle brackets preserved). Indexed in (tenant_id,
    -- message_id) so the admin "find the log row for this Message-Id"
    -- lookup is one index scan; NOT unique because a constraint
    -- violation on the partial unique tickets index leaves us free
    -- to log a second attempt for the same Message-Id with an error.
    message_id VARCHAR(255) NOT NULL,
    -- Populated when the flow settles successfully. NULL while the
    -- row is in-flight or when an error short-circuited the flow.
    ticket_id UUID REFERENCES tickets(id) ON DELETE SET NULL,
    raw_headers JSONB NOT NULL DEFAULT '{}'::jsonb,
    raw_body_text TEXT,
    raw_body_html TEXT,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- NULL on success; populated with the AppError message when the
    -- intake failed. Lets the admin filter "recent intakes that did
    -- not produce a ticket".
    error TEXT
);

CREATE INDEX idx_email_intake_log_tenant_received
    ON email_intake_log(tenant_id, received_at DESC);
CREATE INDEX idx_email_intake_log_tenant_message
    ON email_intake_log(tenant_id, message_id);
