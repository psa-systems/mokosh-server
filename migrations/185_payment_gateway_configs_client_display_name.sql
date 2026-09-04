-- MAPPS-671 (mokosh-invoices P2a): let the MSP admin override the label a
-- portal contact sees on the Pay Now button. NULL keeps the provider-
-- default from `get_invoice_payment_readiness` ("Pay with card" for
-- Stripe, "Pay with PayPal" for PayPal); a non-NULL value replaces it.
--
-- Nullable + no backfill: every existing row keeps its current button
-- behaviour, which is the same as if this column had never existed.
-- 64 chars matches the SPA input cap and is enough for "Pay with your
-- company credit card" without turning the button into a paragraph.
ALTER TABLE payment_gateway_configs
    ADD COLUMN client_display_name VARCHAR(64);
