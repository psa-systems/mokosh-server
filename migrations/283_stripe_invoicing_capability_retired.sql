-- PMS-1525: strip the `invoicing` capability from Stripe rows, because no
-- issuer in this build can receive it.
--
-- `ExternalInvoicingProvider` has two variants, Xero and QuickBooks, and
-- `invoice_issuer_dispatch` reads `enabled_capabilities` for `invoicing` for
-- those two and for nothing else. `issuer_delegation`'s own comment says why
-- Stripe is not among them: its invoicing is "pay-now links on Mokosh-issued
-- invoices", which is what `Capability::Payments` already means. The registry
-- declared it anyway, and this is the data that declaration produced.
--
-- Two reasons the rows go rather than being left inert.
--
-- The capability's description tells an operator the provider issues the
-- document and that Mokosh stops being the system of record for numbering and
-- delivery. Nothing of the sort happens, and since MAPPS-1131 the integrations
-- panel lists what is DELEGATED, so the claim is on the card.
--
-- And a row carrying it is a delegation waiting to switch itself on. The day
-- somebody ships a Stripe issuer, every tenant holding this value would start
-- delegating without having asked, and they could not have changed their mind
-- in the meantime: MAPPS-1098 closed the per-provider integrations routes for
-- payment providers, so there has been no surface that can write or clear this
-- value since.
--
-- `payments` is left exactly as it is. A gateway row exists because somebody
-- wanted to take card payments, and that half is real and read.
--
-- Counting rather than asserting a count, for migration 260's reason
-- (PMS-1117): the expected number is however many tenants a given deployment
-- happens to have ticked it for, which is zero on a fresh database and zero
-- again on one that never did. Asserting a number would fail the boot on the
-- deployments that need it least. A NOTICE is the honest signal.
--
-- Idempotent: a second run finds no array still containing the value.

DO $$
DECLARE
    stripped bigint;
BEGIN
    UPDATE integrations
    SET enabled_capabilities = array_remove(enabled_capabilities, 'invoicing'),
        updated_at = NOW()
    WHERE provider = 'stripe'
      AND 'invoicing' = ANY(enabled_capabilities);
    GET DIAGNOSTICS stripped = ROW_COUNT;

    IF stripped > 0 THEN
        RAISE NOTICE
            'PMS-1525: cleared the invoicing capability from % Stripe integration row(s). No issuer in this build could receive it, and nothing read it; card payments are unaffected.',
            stripped;
    END IF;
END $$;
