-- PMS-815: give `contact_companies` a deterministic per-contact link order.
--
-- PMS-806 ordered a contact's links by `(created_at, id)` and built the
-- "removing the primary promotes the OLDEST remaining link" rule on top of it.
-- `created_at` defaults to NOW(), which is the transaction timestamp, so every
-- link written by one create or update shares a single value and the ordering
-- fell through to `id`, a random `uuid_generate_v4()`. Promotion was a coin
-- flip whenever the surviving links were created together, which is what made
-- `removing_links_repromotes_and_recomputes` fail intermittently in CI.
--
-- `sort_order` mirrors `contact_phones` and carries the position the link was
-- written in, so `(created_at, sort_order)` is a total order. The service sets
-- it on INSERT only: a surviving link keeps the value it was created with, so
-- rewriting the list never reshuffles which link counts as oldest.

ALTER TABLE contact_companies ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 0;

-- Backfill by the key the old query used, so existing rows keep whatever order
-- they already resolved to instead of being renumbered arbitrarily.
UPDATE contact_companies l
SET sort_order = ranked.position
FROM (
    SELECT id,
           (ROW_NUMBER() OVER (PARTITION BY contact_id ORDER BY created_at, id))::int - 1
               AS position
    FROM contact_companies
) ranked
WHERE l.id = ranked.id;
