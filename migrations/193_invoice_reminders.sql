-- PMS-1037: a reminder worker mails the customer on a schedule once an
-- invoice is past due.
--
-- Overdue itself is derived on every read (`status IN ('sent',
-- 'partially_paid') AND balance_due > 0 AND due_date < today`, in the
-- tenant's day), not stored: a stored flag is a second home for a fact that
-- `due_date` and `balance_due` already hold, and the only one that can be
-- stale. What IS stored is each reminder sent, because that is the
-- idempotency guard: the worker runs hourly, and a run that fires twice in
-- the hour must send once. `offset_days` is the schedule entry the mail was
-- sent for (3, 7, 14 ...), so the same invoice can be reminded at each step
-- and never twice at one.
CREATE TABLE invoice_reminders (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    invoice_id UUID NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
    offset_days INTEGER NOT NULL CHECK (offset_days > 0),
    sent_to VARCHAR(255) NOT NULL,
    sent_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, invoice_id, offset_days)
);
CREATE INDEX idx_invoice_reminders_invoice ON invoice_reminders (invoice_id);

ALTER TABLE invoice_reminders ENABLE ROW LEVEL SECURITY;
ALTER TABLE invoice_reminders FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON invoice_reminders
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );
