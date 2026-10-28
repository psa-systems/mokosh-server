-- PMS-1546: columns for the provider's copy of a credit note.
--
-- A credit note corrects an invoice the customer holds, and for a
-- delegated invoice the copy the customer holds is the PROVIDER's
-- (migration 278 put the provider's invoice id on `invoices`). Until now
-- `create_credit_note` had no provider path at all, so after a credit the
-- two ledgers disagreed by exactly the credited amount and Xero or
-- QuickBooks kept showing the customer the original balance.
--
-- Same shape and same reasoning as 278, one table along: all three
-- columns nullable with no default, so a row with NULLs is a
-- Mokosh-issued credit note (every row today) and a row with values is
-- one the provider also holds. `external_provider` carries the
-- discriminator in the form `integrations.provider` stores, so the join
-- to the integration row stays a plain equality.
--
-- `external_number` is the provider's own credit note number (Xero's
-- `CreditNoteNumber`, QuickBooks's `DocNumber`), kept for the reason the
-- invoice's is: it is what the customer reads off the document and what
-- an accountant reconciles against.
--
-- No index: nothing looks a credit note up by its external id. The
-- invoice webhook (MAPPS-1136) resolves invoices, and PMS-1543's
-- reconciliation reads the provider's running total rather than matching
-- documents, so an index here would be one nothing queries.
--
-- No allocation column. Whether the provider applied the credit to its
-- copy of the invoice is the provider's own state, readable there, and a
-- local boolean would be a second home for it that nothing keys on
-- (PMS-1543 made the same call about a payment id).

ALTER TABLE credit_notes
    ADD COLUMN IF NOT EXISTS external_provider text,
    ADD COLUMN IF NOT EXISTS external_credit_note_id text,
    ADD COLUMN IF NOT EXISTS external_number text;

COMMENT ON COLUMN credit_notes.external_provider IS
    'PMS-1546: xero or quickbooks when the provider holds a copy of this credit note; NULL for a Mokosh-only row.';
COMMENT ON COLUMN credit_notes.external_credit_note_id IS
    'PMS-1546: the provider''s own id for its credit document (Xero CreditNoteID, QuickBooks CreditMemo Id); NULL for a Mokosh-only row.';
COMMENT ON COLUMN credit_notes.external_number IS
    'PMS-1546: the credit note number as the provider rendered it, so reconciliation matches what the customer sees. NULL for a Mokosh-only row.';

-- A QuickBooks sales line carries an `ItemRef` and the call is refused
-- without one, so a credit note line delegated to QuickBooks has to name
-- the product its mapping resolves (migration 282), exactly as an invoice
-- line does since 123. Nullable: a Mokosh-only credit note and every row
-- written before now names no product, and the Xero path needs none
-- (a Xero line is a description at a price).
ALTER TABLE credit_note_lines
    ADD COLUMN IF NOT EXISTS product_id UUID REFERENCES products(id);

CREATE INDEX IF NOT EXISTS idx_credit_note_lines_product
    ON credit_note_lines (product_id) WHERE product_id IS NOT NULL;

COMMENT ON COLUMN credit_note_lines.product_id IS
    'PMS-1546: the catalogue product this line credits, needed to resolve the QuickBooks ItemRef; NULL when the line names none.';
