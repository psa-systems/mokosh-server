-- MAPPS-1099 scaffold: columns for when an invoice was issued by an external
-- provider (Xero, QuickBooks) rather than by Mokosh.
--
-- A tenant that delegates the Invoicing capability to Xero or QuickBooks has
-- the external provider issue the document the customer receives. Mokosh
-- mirrors the row locally for history and reconciliation, with the external
-- provider as the system of record for the number and the delivery.
--
-- All three columns are nullable with no default: a row with NULLs is a
-- Mokosh-issued invoice (the current path), and a row with values is one
-- the external provider issued. The code that WRITES values here lands in
-- a later phase of MAPPS-1099 (the Xero / QuickBooks clients and the
-- InvoiceIssuer dispatch). Adding the columns now is schema groundwork;
-- the migration ships separately from the clients so a later rollback of
-- the client code does not need to roll back the schema.
--
-- No index: today nothing reads these columns. The clients will add their
-- own indexes (likely on external_invoice_id for webhook lookups) in the
-- phase that writes them.
--
-- `external_provider` carries the provider discriminator, matching the
-- shape stored in `integrations.provider` so the join to the integration
-- row is a plain equality. `external_invoice_id` is the provider's own
-- row id (Xero's invoice guid, QuickBooks's numeric id). `external_number`
-- is the human-readable invoice number as the provider rendered it, kept
-- because that is what the customer sees and what admins reconcile against.

ALTER TABLE invoices
    ADD COLUMN IF NOT EXISTS external_provider text,
    ADD COLUMN IF NOT EXISTS external_invoice_id text,
    ADD COLUMN IF NOT EXISTS external_number text;

COMMENT ON COLUMN invoices.external_provider IS
    'MAPPS-1099: xero or quickbooks when the invoice was issued by that provider; NULL for a Mokosh-issued row.';
COMMENT ON COLUMN invoices.external_invoice_id IS
    'MAPPS-1099: the external provider''s own id for the invoice row; NULL for a Mokosh-issued row.';
COMMENT ON COLUMN invoices.external_number IS
    'MAPPS-1099: the human-readable invoice number as the external provider rendered it, so reconciliation matches what the customer sees. NULL for a Mokosh-issued row.';
