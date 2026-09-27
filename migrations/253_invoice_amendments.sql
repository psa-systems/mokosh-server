-- PMS-1334: an amendment is a second invoice that replaces a sent one.
--
-- A sent invoice is not edited: the customer holds the document, which is why
-- `InvoiceStatus::is_frozen` refuses writes and why PMS-953 made a credit note
-- the correction. That leaves no answer for "the invoice is wrong and nothing
-- has been paid", where a credit note plus a fresh invoice means the customer
-- receives three documents for one mistake.
--
-- Stripe's revision model is the one adopted here (docs.stripe.com/invoicing/
-- invoice-edits): create a draft linked to the original, leave the original
-- alone and payable, and void it at the moment the replacement is sent. The
-- original stays addressable by its number as a zero-value document, which is
-- what a paper trail means, and `void_reason` says which invoice replaced it.
--
-- One column, on the amendment, naming what it replaces. The reverse direction
-- (Stripe's `latest_revision`) is deliberately NOT stored: it is derivable from
-- this column, and PMS-953's rule is that a derived fact gets one home, since
-- the second one is the only one that can be silently wrong.
ALTER TABLE invoices
    ADD COLUMN amends_invoice_id UUID REFERENCES invoices(id) ON DELETE SET NULL;

COMMENT ON COLUMN invoices.amends_invoice_id IS
    'PMS-1334: the sent invoice this one replaces. NULL on an ordinary invoice.';

-- The lookups are "does this invoice already have a draft amendment" (refusing
-- a second one, Stripe's constraint) and "what replaced this invoice", both of
-- which read by the invoice being replaced. Partial: the column is NULL on
-- every ordinary invoice, and they are the overwhelming majority.
CREATE INDEX idx_invoices_amends ON invoices(amends_invoice_id)
    WHERE amends_invoice_id IS NOT NULL;
