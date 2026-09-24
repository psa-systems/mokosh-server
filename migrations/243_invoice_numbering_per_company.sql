-- PMS-979: per-customer invoice numbering.
--
-- Until now every invoice in a tenant drew from one counter
-- (`invoice_sequences`, migration 010), so a number was `INV-000042` and said
-- nothing about whose invoice it was. It also leaked the tenant's total
-- invoice volume to every customer who received one, which a customer-visible
-- number should not do now that the portal shows them.
--
-- The new shape is a short per-customer prefix, a dash, then a zero-padded
-- per-customer sequence: `A7QF-000001`. A customer's invoices are visibly
-- theirs and their history reads consistently.
--
-- Three decisions are recorded here because the columns alone do not show
-- them.
--
-- The prefix is RANDOM, not derived from the company name, for the reason
-- migration 174 gave `portal_id`: names collide, names change, and a derived
-- identifier stops being stable the first time a customer rebrands. It is
-- assigned lazily on the company's first invoice rather than backfilled, so
-- no existing row needs one and a company that is never invoiced never gets
-- one.
--
-- The alphabet excludes I, L, O, 0 and 1, so a customer reading a number back
-- over the phone cannot turn it into a different customer's. That leaves 31
-- characters, so 923,521 prefixes per tenant; a collision retries against the
-- unique index rather than being assumed away.
--
-- The counter is a TABLE ROW rather than a Postgres sequence, matching
-- `invoice_sequences`, and the difference is the point: a sequence keeps its
-- increment when the transaction that took it rolls back, which would leave
-- gaps in a customer's numbering, and gap-free is an audit expectation on
-- invoices. A row rolls back with everything else, and concurrent creates
-- queue on it rather than racing.

ALTER TABLE companies ADD COLUMN invoice_prefix VARCHAR(4);

-- Unique per TENANT, not globally: a number is only ever read inside the
-- tenant that issued it, and a global unique would make one MSP's growth
-- exhaust another's namespace.
CREATE UNIQUE INDEX idx_companies_invoice_prefix
    ON companies (tenant_id, invoice_prefix)
    WHERE invoice_prefix IS NOT NULL;

-- The alphabet, enforced at the column so a hand-written UPDATE cannot
-- introduce the ambiguity the generator avoids.
ALTER TABLE companies ADD CONSTRAINT companies_invoice_prefix_alphabet
    CHECK (invoice_prefix IS NULL OR invoice_prefix ~ '^[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{4}$');

COMMENT ON COLUMN companies.invoice_prefix IS
    'PMS-979: the company''s stable invoice prefix, random rather than name-derived, assigned on its first invoice under the company_prefix scheme.';

-- One counter per customer. Seeded on first use by the service, the same
-- seed-or-bump `invoice_sequences` takes.
CREATE TABLE invoice_company_sequences (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    last_number INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, company_id)
);

-- PMS-1265: the app pool serves requests, and invoice creation writes here.
GRANT SELECT, INSERT, UPDATE, DELETE ON invoice_company_sequences TO mokosh_app;

-- Which scheme produced this invoice's number. NULL means an invoice issued
-- before this migration, whose number came from the tenant-wide counter; the
-- column exists so the scheme can be replaced again without renumbering
-- anything, which is the property the issue asks for. History is never
-- rewritten: a number is a stored string on the row it belongs to, and the
-- scheme that produced it is now recorded beside it.
ALTER TABLE invoices ADD COLUMN number_scheme TEXT;

ALTER TABLE invoices ADD CONSTRAINT invoices_number_scheme_known
    CHECK (number_scheme IS NULL OR number_scheme IN ('tenant_sequence', 'company_prefix'));

COMMENT ON COLUMN invoices.number_scheme IS
    'PMS-979: which numbering scheme produced invoice_number. NULL = issued before the column existed, from the tenant-wide counter.';
