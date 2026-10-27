-- PMS-1541: which account a reimbursement leaves, in the provider's own books.
--
-- Pushing a reimbursed claim is a SPEND bank transaction in Xero and a
-- purchase in QuickBooks, and both refuse one without naming the account the
-- money came out of: the MSP's bank account or credit card, not an expense
-- account. Migration 286 already maps WHAT the cost was (category -> expense
-- account); this is WHERE it was paid from.
--
-- One value per tenant per provider, so it sits on the `integrations` row
-- beside `external_organisation_id` rather than in a mapping table that would
-- hold exactly one row per tenant. A mapping table earns its keep when the
-- left-hand side is a set of Mokosh rows (vendors, categories, people); there
-- is no Mokosh row on the left here, only the tenant itself.
--
-- Strictly additive: a nullable column, no backfill. Every existing
-- integration carries NULL, and the dispatcher refuses the push by name until
-- an admin sets it, which is the same posture an unmapped vendor gets.

ALTER TABLE integrations
    ADD COLUMN IF NOT EXISTS external_payment_account_id text;

COMMENT ON COLUMN integrations.external_payment_account_id IS
    'PMS-1541: the provider account a reimbursement is paid from - a Xero BankAccount AccountID or a QuickBooks Account.Id for the bank or credit-card account. NULL for a provider that is not a delegated invoice issuer, and for a Xero/QuickBooks row whose admin has not set it; reimbursing a delegated claim is refused by name until they do.';
