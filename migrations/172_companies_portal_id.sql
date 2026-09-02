-- PMS-928 (mokosh-contact-login prompt 011): 9-digit numeric Portal ID
-- on companies, alongside the existing 16-char Crockford portal_slug.
--
-- The slug stays for one release cycle so live invitation emails from
-- prompts 003-010 keep working via a client-side compat redirect
-- (MAPPS-589). A follow-up ticket drops portal_slug once the 72h
-- magic-link TTL of the last slug-shape invitation has expired.
--
-- Column notes:
--   `portal_id` is a random opaque BIGINT in the range 100000000..=999999999.
--   Random (not composite {tenant}-{company}) so a URL observer cannot
--   infer tenant grouping from the id. UNIQUE across the whole table
--   because the URL shape is `/portal/{portal_id}/*` (no per-tenant
--   subdomain), so a collision would render one Company's URL onto the
--   other. Nullable so existing rows do not need an immediate backfill;
--   `ContactService::grant_portal_access` assigns one lazily on the
--   first grant, and a follow-up backfill script populates the rest.
--
-- Range check gate:
--   >= 100_000_000 keeps out the sub-100M "looks like a test row" range
--   so a stray small integer never accidentally reads as a Portal ID.
--   <= 999_999_999 keeps out the overflow into 10-digit territory that
--   would break the 9-digit dictability the ticket set out to buy.
--
-- Partial index on `portal_id IS NOT NULL`:
--   The login endpoint's tenant+company resolution query filters by
--   `c.portal_id = $1`. A partial index keeps that lookup O(1) without
--   penalising the (many, during transition) rows that still hold only
--   a portal_slug.

ALTER TABLE companies ADD COLUMN portal_id BIGINT UNIQUE;

ALTER TABLE companies ADD CONSTRAINT companies_portal_id_range
    CHECK (portal_id IS NULL OR (portal_id >= 100000000 AND portal_id <= 999999999));

CREATE INDEX idx_companies_portal_id ON companies (portal_id) WHERE portal_id IS NOT NULL;
