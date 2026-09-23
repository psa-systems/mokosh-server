-- PMS-1333: voiding an invoice is its own act, with its own columns.
--
-- Before this, `void` was reached only as a side effect of crediting an
-- invoice for its full total (PMS-953, narrowed by PMS-1226). That is the wrong
-- reading twice over: a credited invoice is a valid invoice carrying a credit,
-- and Stripe, whose representation this deployment has to stay close to, moves
-- such an invoice to `paid` rather than voiding it
-- (https://docs.stripe.com/invoicing/dashboard/credit-notes: "if a credit note
-- reduces the balance of an open invoice to 0, the invoice status changes to
-- paid"). Removing that arm leaves `void` reachable by nothing, which is the
-- state PMS-953 found it in, so it gets a writer of its own instead:
-- `BillingService::void_invoice`, for an invoice that was never issued.
--
-- The three columns are the write-off's shape (PMS-1036, migration 190): who,
-- when, and why, recorded on the row rather than derived, because a voided
-- document is kept and a reader a year later needs the reason on it. No amount
-- column beside them: a write-off freezes the balance it forgave, while a void
-- says the document never stood, so there is no amount to freeze.
ALTER TABLE invoices
    ADD COLUMN IF NOT EXISTS voided_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS voided_by_id UUID REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS void_reason TEXT;

COMMENT ON COLUMN invoices.voided_at IS
    'PMS-1333: when this invoice was voided. NULL on every other status.';
COMMENT ON COLUMN invoices.voided_by_id IS
    'PMS-1333: the user who voided it. NULL once that user is deleted.';
COMMENT ON COLUMN invoices.void_reason IS
    'PMS-1333: why it was voided, as the operator typed it. Optional: a draft withdrawn before it was ever sent often has nothing to say.';

-- Correct the rows the old rule already wrote. Nothing but that arm ever set
-- `void`, so every `void` invoice in an existing database is one a credit note
-- settled, and under the corrected reading it is `paid`: the balance is zero
-- and the document stood. Doing it here rather than leaving them is what keeps
-- the change from being a surprise later, because those rows carry no
-- `voided_at` and the next payment or credit event on one would re-derive its
-- status through the ladder and flip it to `paid` with nothing in a log.
--
-- `paid_at` is deliberately left NULL: nobody paid. That is the same pair a
-- newly credited invoice gets, so history and new rows read alike.
UPDATE invoices
SET status = 'paid',
    updated_at = NOW()
WHERE status = 'void'
  AND amount_credited >= total;
