-- PMS-911: the MSP's identity as it stood when the invoice was sent.
--
-- An invoice sent to a client carries the MSP's identity, not the platform's.
-- Those values live in `tenants.branding`, which is a live document an operator
-- edits, so resolving them at render time means an invoice sent last quarter
-- reprints under this quarter's name, address and tax number. That contradicts
-- the invoice-immutability rule PMS-953 established: once an invoice is frozen
-- the customer holds a copy of it, and the only correction is a credit note.
--
-- So the values are copied onto the invoice at the moment it freezes. One JSONB
-- column rather than a set of typed ones, because this is a copy of a document
-- rather than a set of fields anything queries or joins on: nothing filters
-- invoices by the tax number that was printed on them, and a column per
-- branding key would need a migration every time the branding record grows.
ALTER TABLE invoices ADD COLUMN IF NOT EXISTS issuer_snapshot JSONB;

COMMENT ON COLUMN invoices.issuer_snapshot IS
    'The issuing MSP''s identity frozen at the first transition to `sent`, so a later rebrand cannot change a document a client already holds. NULL for an invoice that has never been sent, and for every invoice sent before PMS-911. Written once and never updated.';

-- NOT backfilled, deliberately, and this is the interesting decision.
--
-- Filling it in from today's `tenants.branding` for invoices already sent would
-- be a lie with a timestamp on it: it would assert that those documents carried
-- the current name and address, which is exactly the claim this column exists
-- to make truthfully. An invoice sent before this migration was rendered from
-- live values and there is no record of what they were, so the honest state is
-- an absent snapshot, and the renderer falls back to current branding for those
-- rows the way it always did. The set only shrinks: every invoice sent from
-- here carries its own.
--
-- The logo is the same story one layer down. The snapshot holds a digest of the
-- logo's BYTES rather than its URL, because the live logo is stored under one
-- key per tenant and overwritten on replace (see `crate::storage`), so a stored
-- URL would re-render with whatever mark is current. A migration cannot read a
-- file, so it could not have computed that digest even if backfilling were the
-- right call.
