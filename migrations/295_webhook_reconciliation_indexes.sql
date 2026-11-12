-- Index the webhook reconciliation lookup (PMS-1560).
--
-- Migration 278 added `external_provider` / `external_invoice_id` to
-- `invoices` and deferred the index to whichever later phase reads the
-- columns. That phase shipped: `delegated_invoice`
-- (src/modules/billing/service.rs) and its bill sibling `delegated_bill`
-- (src/modules/expenses/service.rs) both query by the exact triple below,
-- and `webhook_invoice_issuer.rs`'s `apply_one` calls one or the other on
-- every inbound webhook event. Without an index, that lookup is a seq
-- scan of the tenant's invoices or bills on every webhook delivery.
--
-- Partial on the non-null predicate: on a deployment with delegation
-- mostly off, the large majority of rows carry NULL in both columns and
-- gain nothing from being indexed. Plain, not unique: nothing in the
-- schema guarantees `(provider, external_invoice_id)` is unique across
-- tenants, since the provider's id space is the provider's own.

CREATE INDEX IF NOT EXISTS invoices_tenant_provider_external_id_idx
    ON invoices (tenant_id, external_provider, external_invoice_id)
    WHERE external_invoice_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS bills_tenant_provider_external_id_idx
    ON bills (tenant_id, external_provider, external_bill_id)
    WHERE external_bill_id IS NOT NULL;
