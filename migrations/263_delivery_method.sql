-- PMS-1462: a sent invoice or quote records HOW it was delivered, by whom, and
-- when. Replaces the invoice-only `skip_email` path (PMS-992) that marked a
-- document sent with nobody stated as the deliverer; the quote half had no
-- field for it at all. Three methods: `email`, `postal`, `other`. Adding a
-- method later is a migration that widens the CHECK.
--
-- `delivery_note` is required only on `other`; the CHECK enforces that so a
-- caller cannot send `other` with a blank note and have the row disagree with
-- the service refusal. `email` and `postal` store NULL for it.
--
-- `delivered_by_id` matches the shape `voided_by_id` has on `invoices`
-- (migration 242): `ON DELETE SET NULL` so a departed user's row is kept but
-- the FK does not block deleting them. The audit log carries the full actor
-- separately.
--
-- `emailed_to` / `emailed_at` are added to `quotes` to match invoices
-- (migration 134); the quote send now records who it mailed just like the
-- invoice one.
--
-- Backfill reads the audit log written since PMS-978:
--
--  * An invoice with an `invoice.sent` audit row -> `email`, delivered by that
--    row's user.
--  * An invoice with an `invoice.marked_sent` audit row (the `skip_email`
--    path) -> `other`, with the note "User sent invoice via other means" and
--    that row's user.
--  * An invoice with `emailed_to IS NOT NULL` and no matching audit row
--    (pre-PMS-978 send) -> `email`, delivered_by_id NULL.
--  * Every other sent invoice and every sent quote has no recorded delivery.
--    `delivery_method` stays NULL; the API serves them as `null` and the
--    client renders "Delivery not recorded". Inventing a method would be the
--    same false claim this migration exists to remove.

ALTER TABLE invoices
    ADD COLUMN delivery_method   TEXT NULL
        CHECK (delivery_method IN ('email', 'postal', 'other')),
    ADD COLUMN delivery_note     TEXT NULL,
    ADD COLUMN delivered_by_id   UUID NULL REFERENCES users (id) ON DELETE SET NULL,
    ADD CONSTRAINT invoices_delivery_other_note_present
        CHECK (delivery_method <> 'other' OR length(btrim(delivery_note)) > 0);

ALTER TABLE quotes
    ADD COLUMN delivery_method   TEXT NULL
        CHECK (delivery_method IN ('email', 'postal', 'other')),
    ADD COLUMN delivery_note     TEXT NULL,
    ADD COLUMN delivered_by_id   UUID NULL REFERENCES users (id) ON DELETE SET NULL,
    ADD COLUMN emailed_to        VARCHAR(255) NULL,
    ADD COLUMN emailed_at        TIMESTAMPTZ  NULL,
    ADD CONSTRAINT quotes_delivery_other_note_present
        CHECK (delivery_method <> 'other' OR length(btrim(delivery_note)) > 0);

COMMENT ON COLUMN invoices.delivery_method IS
    'PMS-1462: email | postal | other. NULL on draft and on sent invoices with no recorded delivery.';
COMMENT ON COLUMN invoices.delivery_note IS
    'PMS-1462: required on `other`, NULL otherwise.';
COMMENT ON COLUMN invoices.delivered_by_id IS
    'PMS-1462: the user who performed the delivery. NULL if unknown.';
COMMENT ON COLUMN quotes.delivery_method IS
    'PMS-1462: email | postal | other. NULL on sent quotes with no recorded delivery.';
COMMENT ON COLUMN quotes.delivery_note IS
    'PMS-1462: required on `other`, NULL otherwise.';
COMMENT ON COLUMN quotes.delivered_by_id IS
    'PMS-1462: the user who performed the delivery.';
COMMENT ON COLUMN quotes.emailed_to IS
    'PMS-1462: who the quote was emailed to on the send, matching invoices.emailed_to (PMS-992).';
COMMENT ON COLUMN quotes.emailed_at IS
    'PMS-1462: when the quote email was accepted by the relay.';

-- Backfill from the audit log. One statement per source so PMS-1117's row-
-- count style can grow out of this if a reviewer wants it; today we assert
-- no row counts because the volume depends entirely on what the audit log
-- happens to carry.
UPDATE invoices i SET
    delivery_method = 'email',
    delivered_by_id = al.user_id
FROM audit_log al
WHERE al.tenant_id = i.tenant_id
  AND al.entity_type = 'invoices'
  AND al.entity_id   = i.id
  AND al.new_values->>'event' = 'invoice.sent'
  AND i.delivery_method IS NULL;

UPDATE invoices i SET
    delivery_method = 'other',
    delivery_note   = 'User sent invoice via other means',
    delivered_by_id = al.user_id
FROM audit_log al
WHERE al.tenant_id = i.tenant_id
  AND al.entity_type = 'invoices'
  AND al.entity_id   = i.id
  AND al.new_values->>'event' = 'invoice.marked_sent'
  AND i.delivery_method IS NULL;

-- Pre-PMS-978 sends: `emailed_to` was written but no audit event names the
-- send. The method is still `email` by the one surviving fact (the address);
-- `delivered_by_id` stays NULL because we cannot invent an actor.
UPDATE invoices SET
    delivery_method = 'email'
WHERE emailed_to IS NOT NULL
  AND delivery_method IS NULL;
