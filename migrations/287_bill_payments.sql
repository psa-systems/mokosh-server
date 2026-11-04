-- PMS-1536: what the MSP has actually paid a vendor.
--
-- `bills.status` has allowed 'paid' since migration 279 and nothing could set
-- it; `bills.paid_minor` was read by five queries and written by none. A bill
-- the MSP had paid stayed 'approved' forever, so the payables ledger could not
-- answer "what do we still owe".
--
-- Rows rather than a running total alone, for the reason PMS-953 keeps
-- `payments` on the receivables side: an MSP reconciling a vendor statement
-- needs what was paid and when, and a single column cannot say that. The
-- running total stays on `bills.paid_minor`, written only by
-- `recompute_bill_payment_state`, which is this table's one consumer.
--
-- Minor units, like every other amount in this subsystem (migration 279), not
-- the DECIMAL(12,2) the older `payments` table uses.
--
-- `payment_method` repeats `payments`' CHECK set verbatim. A second vocabulary
-- for the same question would make "how did we pay this" un-answerable across
-- the two directions.
--
-- PMS-1318: tenant first. PMS-1265: granted to `mokosh_app`, the role that
-- serves.

CREATE TABLE IF NOT EXISTS bill_payments (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    bill_id uuid NOT NULL REFERENCES bills(id) ON DELETE CASCADE,
    paid_on date NOT NULL,
    amount_minor bigint NOT NULL,
    payment_method text NOT NULL
        CHECK (payment_method IN ('check', 'credit_card', 'ach', 'wire', 'cash', 'other')),
    reference text,
    notes text,
    created_at timestamptz NOT NULL DEFAULT NOW(),
    -- A payment is money leaving: a zero row is noise and a negative one is a
    -- vendor credit, which is a different document. The service refuses both
    -- with a message; this is the floor under it.
    CONSTRAINT bill_payments_amount_positive CHECK (amount_minor > 0)
);

CREATE INDEX IF NOT EXISTS bill_payments_tenant_id_idx ON bill_payments (tenant_id);
CREATE INDEX IF NOT EXISTS bill_payments_bill_id_idx ON bill_payments (tenant_id, bill_id);

ALTER TABLE bill_payments ENABLE ROW LEVEL SECURITY;
ALTER TABLE bill_payments FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON bill_payments
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );

GRANT SELECT, INSERT, UPDATE, DELETE ON bill_payments TO mokosh_app;
