-- PMS-64 AC5: recurring-invoicing idempotency ledger.
--
-- A recurring billing run turns each active contract's recurring line
-- items into an invoice, once per billing period. To stay idempotent
-- across double-runs and process restarts, every generated invoice is
-- recorded here keyed UNIQUE on (tenant_id, contract_id, period_start).
--
-- The generator inserts the ledger row in the SAME transaction as the
-- invoice it created, using INSERT ... ON CONFLICT DO NOTHING. If a row
-- for (tenant_id, contract_id, period_start) already exists (a prior run
-- billed that period), the conflict short-circuits and the transaction
-- rolls back the would-be-duplicate invoice, so a period is invoiced at
-- most once.
--
-- A dedicated ledger (rather than deriving "already invoiced" from the
-- invoices table) keeps the billing-run bookkeeping separate from the
-- invoice lifecycle: manually-created, edited, or voided invoices linked
-- to the same contract never confuse the dedupe, and the period bounds
-- are stored explicitly rather than re-derived.

CREATE TABLE contract_invoice_runs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    contract_id UUID NOT NULL REFERENCES contracts(id) ON DELETE CASCADE,
    invoice_id UUID NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_contract_invoice_runs_period
        UNIQUE (tenant_id, contract_id, period_start)
);

CREATE INDEX idx_contract_invoice_runs_contract ON contract_invoice_runs(contract_id);
CREATE INDEX idx_contract_invoice_runs_tenant ON contract_invoice_runs(tenant_id);
