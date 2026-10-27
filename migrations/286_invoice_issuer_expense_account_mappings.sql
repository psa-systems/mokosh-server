-- MAPPS-1155: which ledger account an expense category is in the provider's
-- own chart of accounts.
--
-- QuickBooks puts a bill line against an expense ACCOUNT: every element of
-- `Line[].AccountBasedExpenseLineDetail` carries an `AccountRef.value`, and
-- the call is refused without one. Mokosh's own name for "what kind of cost
-- is this" is `bill_lines.category_id` (migration 279), so the mapping is
-- category -> account, at the same granularity as the line that needs it.
--
-- Per-vendor would have been one row instead of many, and wrong: an MSP buys
-- hardware and a software subscription from the same distributor, and those
-- are two accounts in their books. A mapping that cannot say so files the
-- MSP's costs in the wrong place in their own ledger, which is the kind of
-- error they find at year end and we cannot fix retroactively.
--
-- Xero needs no row here: a Xero ACCPAY line takes an `AccountCode` and
-- Xero defaults it from the contact, so the provider column is kept (same
-- CHECK as 282 and 285) rather than hardcoding quickbooks - a tenant may map
-- both, and only one provider reads it today.
--
-- Shape is migration 282's, deliberately: same provider CHECK, same
-- uniqueness per (tenant, provider, subject), same fail-closed RLS.
--
-- PMS-1265: granted to `mokosh_app`, the role that serves.

CREATE TABLE IF NOT EXISTS invoice_issuer_expense_account_mappings (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider text NOT NULL
        CHECK (provider IN ('xero', 'quickbooks')),
    category_id uuid NOT NULL REFERENCES expense_categories(id) ON DELETE CASCADE,
    -- QuickBooks' `Account.Id` (numeric, as a string) or a Xero `AccountCode`
    -- (a short alphanumeric code). Text for the same reason the vendor column
    -- is: the two providers do not agree on the shape and neither is ours to
    -- parse.
    external_account_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT NOW(),
    updated_at timestamptz NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, provider, category_id)
);

CREATE INDEX IF NOT EXISTS invoice_issuer_expense_account_mappings_tenant_id_idx
    ON invoice_issuer_expense_account_mappings (tenant_id);

ALTER TABLE invoice_issuer_expense_account_mappings ENABLE ROW LEVEL SECURITY;
ALTER TABLE invoice_issuer_expense_account_mappings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON invoice_issuer_expense_account_mappings
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );

GRANT SELECT, INSERT, UPDATE, DELETE ON invoice_issuer_expense_account_mappings TO mokosh_app;
