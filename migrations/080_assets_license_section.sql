-- PMS-454: asset licence section.
--
-- Manual QA expanded the CMDB scope (issue comment) to include a
-- per-asset licence section so a software asset can record who it is
-- licensed from, how many seats it covers, and when the licence lapses.
-- The earlier CMDB-expansion migration (063) added the other QA fields
-- (assigned user, IP, hostname, MAC, installed date, department,
-- in-transit ticket); this migration adds the remaining one.
--
-- Modelled as flat columns on `assets` (not a side table) to match how
-- 063 added the rest of the CMDB fields: one asset carries one licence
-- section, every column nullable so non-software assets simply leave it
-- blank.
--
--   - license_vendor      : who the licence is purchased from (vendor /
--                           publisher). Free-text VARCHAR(150).
--   - license_seat_count   : number of seats / devices the licence
--                           covers. A non-negative count.
--   - license_expiry       : date the licence lapses. Separate from
--                           warranty_expiry (a perpetual licence on
--                           out-of-warranty hardware is common).

ALTER TABLE assets
    ADD COLUMN license_vendor VARCHAR(150),
    ADD COLUMN license_seat_count INTEGER CHECK (license_seat_count IS NULL OR license_seat_count >= 0),
    ADD COLUMN license_expiry DATE;

-- Partial index on the expiry: the "licences lapsing soon" filter the
-- SPA surfaces only ever scans rows that carry a licence, so tenants
-- with no software assets pay nothing.
CREATE INDEX idx_assets_license_expiry
    ON assets(tenant_id, license_expiry)
    WHERE license_expiry IS NOT NULL;
