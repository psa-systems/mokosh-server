-- PMS-1488 (asset catalog, phase 3): the materialised view the
-- signature-detector endpoint reads.
--
-- Background. The design calls for an Assets-list banner that reads
-- "You have 7 Dell Latitude 5450s. Save as a template?" when the
-- tenant has produced >= 5 identical creates in the last 7 days. The
-- naive shape would scan the `assets` table on every request to the
-- signature endpoint; the MV + a 60s refresh job (registered in
-- `src/main.rs`) answers that from a tiny indexed snapshot instead.
--
-- The view aggregates by (tenant_id, lower(manufacturer),
-- lower(model), asset_type_id) over the last 7 days of creates. The
-- threshold (>= 5) and the window (7 days) are hard-coded here; a
-- future phase 3.5 moves them to a tenant setting.
--
-- No `tenant_id` RLS policy on the view: it is already keyed on
-- `tenant_id` and the endpoint filters by `caller.tenant_id`. The
-- underlying `assets` table's RLS does not transit through the
-- materialised view (the view is a snapshot of the role that
-- refreshed it, which is the migrator). Keeping it RLS-exempt and
-- filtering in the handler mirrors how `mokosh_bunyip_grants` sits.

CREATE MATERIALIZED VIEW asset_signature_candidates_mv AS
SELECT
    a.tenant_id,
    lower(a.manufacturer) AS manufacturer,
    lower(a.model)        AS model,
    a.asset_type_id,
    COUNT(*)              AS recent_count,
    MIN(a.created_at)     AS earliest_at,
    MAX(a.created_at)     AS latest_at
FROM assets a
WHERE a.created_at > NOW() - INTERVAL '7 days'
  AND a.manufacturer IS NOT NULL
  AND a.manufacturer <> ''
  AND a.model IS NOT NULL
  AND a.model <> ''
GROUP BY a.tenant_id, lower(a.manufacturer), lower(a.model), a.asset_type_id
HAVING COUNT(*) >= 5;

-- The handler reads `WHERE tenant_id = $1 ORDER BY recent_count DESC
-- LIMIT 1`, so the index is tenant + count.
CREATE INDEX idx_asset_signature_candidates_mv
    ON asset_signature_candidates_mv (tenant_id, recent_count DESC);

-- PMS-1265: the serving app pool reads the view through the
-- signature-detector endpoint, so grant it select; writes stay on
-- the migrator role (which runs REFRESH).
GRANT SELECT ON asset_signature_candidates_mv TO mokosh_app;

COMMENT ON MATERIALIZED VIEW asset_signature_candidates_mv IS
    'PMS-1488: the signature-detector banner reads this. Refreshed every 60s by `AssetCatalogSignatureRefresh` in src/main.rs; empty when no tenant has produced >= 5 identical (manufacturer, model, asset_type) creates in the last 7 days.';
