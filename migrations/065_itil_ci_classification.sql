-- PMS-456: ITIL CI classification.
--
-- The CMDB already has per-tenant `asset_types` (free-text taxonomy
-- with hierarchy + per-type custom-fields schema). This migration
-- layers an ITIL classification on top:
--
--   * `asset_types.itil_category` tags the type with the industry-standard
--     ITIL CI class (hardware / software / service / network / document /
--     location). Free-text VARCHAR rather than an enum so a tenant can
--     coin a new category without a schema migration; the SPA offers the
--     standard set as suggestions.
--
--   * `assets.itil_lifecycle_stage` tracks the per-CI lifecycle position
--     (planned / in_service / retired). Pulls onto the asset (not the
--     type) because two assets sharing a type are in different lifecycle
--     positions all the time (a retired Dell R740 and an in-service
--     Dell R740 both have the same asset_type).
--
-- Phase 2 of PMS-456 (CI relationships graph + impact analysis) is
-- intentionally not in this PR. The existing `asset_relationships` table
-- already gives the parent-child shape; the impact-analysis traversal +
-- the SPA's CI map visualisation are tracked as a follow-up.

ALTER TABLE asset_types
    ADD COLUMN itil_category VARCHAR(50);

-- Partial index because the column is opt-in: tenants that have not
-- classified any type pay nothing. Tenants that do let the SPA's
-- "show me all hardware CIs" filter run as one index scan per
-- category.
CREATE INDEX idx_asset_types_itil_category
    ON asset_types(tenant_id, itil_category)
    WHERE itil_category IS NOT NULL;

ALTER TABLE assets
    ADD COLUMN itil_lifecycle_stage VARCHAR(50);

CREATE INDEX idx_assets_itil_lifecycle_stage
    ON assets(tenant_id, itil_lifecycle_stage)
    WHERE itil_lifecycle_stage IS NOT NULL;
