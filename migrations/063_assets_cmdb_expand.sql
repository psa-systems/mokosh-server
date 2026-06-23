-- PMS-454: expand the asset schema with the CMDB fields the existing
-- model was missing. The original `assets` table (migration 011) already
-- carried site_id, status, purchase_date, purchase_price,
-- warranty_expiry, end_of_life, manufacturer, model, serial_number, and
-- the asset_relationships join. This migration adds the remaining
-- columns the QA report and the PMS-454 spec called out:
--
--   - assigned_user_id : tech / user the asset is issued to.
--   - ip_address      : primary IPv4 / IPv6 (Postgres INET handles both).
--   - hostname        : DNS name (255 char cap matches the FQDN limit).
--   - mac_address     : NIC MAC, free-text so we don't reject unusual
--                       formats (colon-separated, hyphen-separated,
--                       Cisco-dotted).
--   - installed_date  : separate from purchase_date. An asset may have
--                       been purchased months before it was deployed.
--   - department      : free-text department tag. We do not link to a
--                       departments table because none exists; a future
--                       migration can FK-ify if one lands.
--   - in_transit_ticket_id : the ticket tracking the move when an asset
--                       is `in_transit`. SET NULL on ticket delete so
--                       the asset row survives but loses the back-link.
--
-- The status CHECK constraint widens to include 'in_transit' so an
-- asset on the move can be flagged as such. Existing CHECK is dropped
-- and recreated because Postgres has no in-place ALTER CHECK.

ALTER TABLE assets
    ADD COLUMN assigned_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN ip_address INET,
    ADD COLUMN hostname VARCHAR(255),
    ADD COLUMN mac_address VARCHAR(50),
    ADD COLUMN installed_date DATE,
    ADD COLUMN department VARCHAR(100),
    ADD COLUMN in_transit_ticket_id UUID REFERENCES tickets(id) ON DELETE SET NULL;

-- Drop the existing status CHECK (`assets_status_check` is Postgres's
-- default name for an unnamed CHECK on the `status` column).
ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_status_check;
ALTER TABLE assets ADD CONSTRAINT assets_status_check
    CHECK (status IN ('active', 'inactive', 'retired', 'in_repair', 'in_stock', 'in_transit'));

-- Indexes on the new fields the asset list / search surfaces filter on.
-- IP / hostname / department are filterable in the list view, so
-- per-tenant indexes keep ILIKE scans bounded.
CREATE INDEX idx_assets_assigned_user ON assets(assigned_user_id) WHERE assigned_user_id IS NOT NULL;
CREATE INDEX idx_assets_hostname ON assets(tenant_id, hostname) WHERE hostname IS NOT NULL;
CREATE INDEX idx_assets_department ON assets(tenant_id, department) WHERE department IS NOT NULL;
CREATE INDEX idx_assets_in_transit_ticket ON assets(in_transit_ticket_id) WHERE in_transit_ticket_id IS NOT NULL;
