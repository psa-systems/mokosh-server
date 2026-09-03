-- PMS-990: net terms. `payment_terms` was a name-only lookup (PMS-333), so a
-- due date was either typed by the client or hardcoded to thirty days in the
-- two server paths that mint invoices on their own. A term now carries the
-- number of days it means, and the server derives `due_date` from
-- `invoice_date + net_days` when the caller gives no due date, using the
-- invoice's term or the tenant's default term.
--
-- Nullable, because a term is free text and "On approval" or "Milestone"
-- means no fixed count; a NULL term falls back to thirty days, the value the
-- hardcoded paths used, so nothing changes for a tenant that never sets one.
-- The cap is ten years: a larger value is a typo, not a policy.
ALTER TABLE payment_terms
    ADD COLUMN net_days INTEGER
        CHECK (net_days IS NULL OR (net_days >= 0 AND net_days <= 3650));

-- Backfill the seeded names (050) and their readable forms (117), plus any
-- tenant-made term that spells its count in its name: "Net 45" means 45.
-- A name that does not say is left NULL for the operator to fill in.
UPDATE payment_terms
SET net_days = 0
WHERE net_days IS NULL
  AND lower(name) IN ('due on receipt', 'due_on_receipt');

UPDATE payment_terms
SET net_days = substring(name FROM '^[Nn][Ee][Tt] ?([0-9]{1,4})$')::INTEGER
WHERE net_days IS NULL
  AND name ~ '^[Nn][Ee][Tt] ?[0-9]{1,4}$'
  AND substring(name FROM '^[Nn][Ee][Tt] ?([0-9]{1,4})$')::INTEGER <= 3650;
