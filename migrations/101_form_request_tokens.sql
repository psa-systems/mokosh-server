-- PMS-730: client request forms (MACD) delivered by magic link.
--
-- An MSP user sends a client a link to a form definition (migration 100). The
-- client fills it in without logging in, and the submission becomes a ticket
-- attributed to their company and carrying the KB article that describes how
-- to perform the change.
--
-- TOKEN SHAPE: the emailed token is `{token_id}.{secret}` and only the Argon2
-- hash of the secret is stored. This deliberately does NOT copy
-- `portal_setup_tokens`, whose token is `{contact_id}.{secret}`: a salted
-- Argon2 hash cannot be looked up by value, so that design fetches EVERY token
-- for the contact and verifies each candidate in turn, which is affordable
-- only because `contact_id` narrows the set first. (Note that
-- 042_portal_setup_tokens.sql indexes `token_hash` and the code cannot use the
-- index, for exactly this reason.) A request link has no equivalent narrowing
-- key, so the same shape would Argon2-verify against the whole table on every
-- submission. Keying the prefix on the row's own id makes resolution a primary
-- key lookup plus exactly one verify, with the same single-use and expiry
-- semantics and the same "a guessed token is indistinguishable from an expired
-- one" response contract.

CREATE TABLE form_request_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Which form the client is being asked to fill in. CASCADE because a link
    -- to a deleted definition can never resolve; the definition itself cannot
    -- be deleted once submitted (migration 100 puts RESTRICT on submissions),
    -- so this only fires for a definition that was never used.
    form_definition_id UUID NOT NULL REFERENCES form_definitions(id) ON DELETE CASCADE,
    -- The client this link is scoped to. The created ticket is attributed
    -- here, NOT to anything the submitter types, so a leaked link cannot file
    -- a request against a different company.
    company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    -- The contact the link was sent to, when it was addressed to a known one.
    -- Nullable: a link can be sent to an address that is not yet a contact.
    contact_id UUID REFERENCES contacts(id) ON DELETE SET NULL,
    -- Where the link was actually emailed. Kept even when `contact_id` is set,
    -- so the audit trail survives the contact's address being edited later.
    recipient_email VARCHAR(255) NOT NULL,
    -- Argon2 hash of the secret half of `{token_id}.{secret}`.
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    -- Stamped on redemption. Single-use: a second submission through the same
    -- link is rejected as Gone rather than silently creating a second ticket.
    used_at TIMESTAMPTZ,
    -- The submission this link produced, once redeemed. Makes the chain
    -- link -> submission -> ticket traceable in both directions.
    submission_id UUID REFERENCES form_submissions(id) ON DELETE SET NULL,
    created_by_id UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- "Which links did we send this client, and are they still live" is the only
-- listing this table needs.
CREATE INDEX idx_form_request_tokens_tenant_company
    ON form_request_tokens(tenant_id, company_id, created_at DESC);

-- Resolution is a primary-key lookup by design (see the TOKEN SHAPE note), so
-- no index on token_hash: it would never be used, exactly as the one on
-- portal_setup_tokens is not.

-- Row-level security. The DO-block loops in migrations 024 / 038 have already
-- run, so this table inherits no policy and attaches its own, fail-closed on
-- an unset GUC, matching 042 / 100.
--
-- NOTE for the serving code: resolving a presented token is a PRE-AUTH read.
-- There is no session and therefore no `app.current_tenant` to set, because
-- the tenant is what the lookup RESOLVES. That single query runs on the
-- BYPASSRLS migrator pool with an explicit SAFETY comment at the call site,
-- exactly as `portal_setup_tokens` redemption and the `tenant_intake_tokens`
-- bearer lookup do. Every other access is tenant-scoped through
-- `begin_with_tenant`.
ALTER TABLE form_request_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE form_request_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON form_request_tokens
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- ============================================================================
-- NOTIFICATION TEMPLATE + RULE: forms.request_link
-- ============================================================================
--
-- Seeded for EVERY tenant, not just the default one. Migration 097 established
-- why: a tenant missing the row gets no mail at all, because the dispatcher is
-- the only delivery path. `TenantService::copy_default_config` gains
-- 'forms.request_link' in its event-type list so tenants created from here on
-- get it too.
--
-- Placeholders are flat, single-brace-pair keys because `render_template`
-- (src/modules/notifications/service.rs) does a flat `context.get(key)` with no
-- path traversal; a dotted key can never resolve. That was the PMS-702 defect
-- migration 096 had to repair, and it is not repeated here.
--
-- The body is an E'...' literal so `\n` is stored as a newline rather than a
-- literal backslash-n, which was the other half of the PMS-702 defect.
--
-- Both INSERTs are guarded with NOT EXISTS, so a re-run is a no-op and a
-- tenant that has already customised the row through the CRUD API is left
-- alone.

INSERT INTO notification_templates
    (tenant_id, name, event_type, channel_type, subject, body_text, body_html, is_active)
SELECT t.id,
       'Request form link',
       'forms.request_link',
       'email',
       '{{form_name}} request form from {{tenant_name}}',
       E'{{display_name}},\n\nPlease complete the {{form_name}} form so we can action your request:\n\n{{form_link}}\n\nThis link is for your use only, can be submitted once, and expires on {{expires_on}}.\n\nIf you were not expecting this, you can ignore this message.',
       '<p>{{display_name}},</p><p>Please complete the <strong>{{form_name}}</strong> form so we can action your request.</p><p><a href="{{form_link}}">Open the {{form_name}} form</a></p><p>This link is for your use only, can be submitted once, and expires on {{expires_on}}.</p><p>If you were not expecting this, you can ignore this message.</p>',
       TRUE
FROM tenants t
WHERE NOT EXISTS (
    SELECT 1 FROM notification_templates existing
    WHERE existing.tenant_id = t.id
      AND existing.event_type = 'forms.request_link'
      AND existing.channel_type = 'email'
);

INSERT INTO notification_rules
    (tenant_id, name, event_type, channels, recipients, template_id, is_active)
SELECT nt.tenant_id,
       'Request form link',
       'forms.request_link',
       ARRAY['email']::VARCHAR(20)[],
       -- The recipient rides the dispatch context as `recipient_email`, the
       -- same way the auth templates carry theirs: the addressee is a client
       -- contact, not a role inside the tenant.
       '{"user_ids": [], "emails": []}'::jsonb,
       nt.id,
       TRUE
FROM notification_templates nt
WHERE nt.event_type = 'forms.request_link'
  AND nt.channel_type = 'email'
  AND NOT EXISTS (
      SELECT 1 FROM notification_rules existing
      WHERE existing.tenant_id = nt.tenant_id
        AND existing.event_type = 'forms.request_link'
  );
