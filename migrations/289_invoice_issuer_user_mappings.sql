-- PMS-1541: which contact a person is in the provider's own list.
--
-- A reimbursement names the person who was paid back. Xero requires a
-- `Contact` on every bank transaction and refuses the call without one;
-- QuickBooks takes an optional `EntityRef`, and filling it is what makes the
-- MSP's books say who was reimbursed rather than leaving a spend with no
-- counterparty.
--
-- `users`, not `vendors` or `companies`: a claim's `user_id` is a member of
-- the tenant (migration 279), and the existing mapping tables key on the row
-- type they map. One table per subject is the shape migrations 282, 285 and
-- 286 set, and the reason is the same: a table with a nullable column per
-- subject type would be several tables wearing a discriminator.
--
-- ON DELETE CASCADE on `user_id`: a mapping for somebody who has left the
-- tenant maps nothing, and a claim they filed keeps its own
-- `external_expense_id`, which is the record that matters afterwards.
--
-- Shape is migration 285's, deliberately: same provider CHECK, same
-- uniqueness per (tenant, provider, subject), same fail-closed RLS.
--
-- PMS-1265: granted to `mokosh_app`, the role that serves.

CREATE TABLE IF NOT EXISTS invoice_issuer_user_mappings (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider text NOT NULL
        CHECK (provider IN ('xero', 'quickbooks')),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Xero's ContactID (a uuid) or QuickBooks' EntityRef value (numeric, as a
    -- string). Text for the same reason the vendor column is: the two
    -- providers do not agree on the shape and neither is ours to parse.
    external_contact_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT NOW(),
    updated_at timestamptz NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, provider, user_id)
);

CREATE INDEX IF NOT EXISTS invoice_issuer_user_mappings_tenant_id_idx
    ON invoice_issuer_user_mappings (tenant_id);

ALTER TABLE invoice_issuer_user_mappings ENABLE ROW LEVEL SECURITY;
ALTER TABLE invoice_issuer_user_mappings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON invoice_issuer_user_mappings
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );

GRANT SELECT, INSERT, UPDATE, DELETE ON invoice_issuer_user_mappings TO mokosh_app;
