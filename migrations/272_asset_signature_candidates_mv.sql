-- PMS-1492 (asset catalog + bulk order, phase 3, MR3): the signature
-- detector's materialised view, read by the SPA's "You have N identical
-- X" banner.
--
-- Design doc: docs/mokosh-assets/04-templates-and-bulk-order.md
--
-- Why a MATERIALIZED VIEW rather than running the query on every read.
-- The signature banner shows up on every Assets list render; a per-request
-- COUNT grouped by three columns against the full assets table on a 100k-
-- asset tenant is a sequential scan plus a hash aggregate, which the
-- planner will not short-circuit for a predicate that returns zero rows.
-- A matview refreshed on a 60s cadence serves every tenant's banner from
-- a bitmap-index scan, and the staleness is bounded by the refresh
-- interval. The design doc commits to the trade.
--
-- Why no RLS on the matview itself. Materialised views in Postgres do
-- not support RLS the same way base tables do (the matview is a plain
-- relation populated from a SELECT; RLS applies to the SELECT at
-- population time, not at read time). The handler filters by tenant_id
-- in the SELECT instead; the service layer never reaches this view
-- without a `WHERE tenant_id = $1` predicate. The GRANT SELECT below
-- is to the app role only so a direct psql reader cannot leak data by
-- forgetting the filter.
--
-- Why GRANT MAINTAIN. The scheduler runs as `mokosh_app`; REFRESH
-- MATERIALIZED VIEW requires either ownership or the MAINTAIN
-- privilege (PG 17+). Granting MAINTAIN keeps the view owned by the
-- migrator role while letting the app refresh it.

CREATE MATERIALIZED VIEW asset_signature_candidates_mv AS
SELECT
    tenant_id,
    lower(manufacturer)                 AS manufacturer_lower,
    lower(model)                        AS model_lower,
    -- Keep one canonical mixed-case representative per group so the
    -- SPA banner can render "Dell Latitude 5450" rather than
    -- "dell latitude 5450". MIN() is deterministic within a group.
    MIN(manufacturer)                   AS manufacturer,
    MIN(model)                          AS model,
    asset_type_id,
    COUNT(*)::bigint                    AS group_count
FROM assets
WHERE created_at > NOW() - INTERVAL '7 days'
  AND manufacturer IS NOT NULL
  AND model        IS NOT NULL
GROUP BY tenant_id, lower(manufacturer), lower(model), asset_type_id
HAVING COUNT(*) >= 5
WITH NO DATA;

-- CONCURRENT REFRESH needs a UNIQUE index. The grouping keys are the
-- natural key; the matview is one row per (tenant, manufacturer_lower,
-- model_lower, asset_type_id).
CREATE UNIQUE INDEX idx_asset_signature_candidates_mv_unique
    ON asset_signature_candidates_mv
       (tenant_id, manufacturer_lower, model_lower, asset_type_id);

-- The handler's ORDER BY: within one tenant, biggest group first.
CREATE INDEX idx_asset_signature_candidates_mv_tenant_count
    ON asset_signature_candidates_mv (tenant_id, group_count DESC);

-- Grant SELECT so the handler reads from the app role; grant MAINTAIN
-- so the scheduler can REFRESH without needing to run as the owner.
-- MAINTAIN is a PG 17+ privilege; mokosh-server pins PG 18.
GRANT SELECT, MAINTAIN ON asset_signature_candidates_mv TO mokosh_app;

-- Populate once at migration time so the first SELECT returns a sane
-- shape rather than an empty "not yet materialised" result. The 60s
-- scheduler takes over from here.
REFRESH MATERIALIZED VIEW asset_signature_candidates_mv;

COMMENT ON MATERIALIZED VIEW asset_signature_candidates_mv IS
    'PMS-1492 phase 3 MR3: hot-pattern detector for the signature banner. Refreshed every 60s by the asset_signature_detector job.';
