-- PMS-475 / PMS-456 phase 2: per-tenant cap for the CI impact-graph
-- traversal.
--
-- The new `GET /api/v1/assets/{id}/impact?direction=...&depth=N`
-- endpoint walks `asset_relationships` recursively to render the
-- "what depends on what" map the SPA's CI Map tab needs. The query
-- is unbounded by default (every related asset transitively), so a
-- per-tenant ceiling prevents a pathological web of relationships
-- from producing a query plan large enough to matter. The well-known
-- key is:
--
--   category = 'ci'
--   key      = 'impact_max_depth'
--   value    = JSONB integer in 1..=10, default 5 when unset
--
-- The server enforces a hard ceiling of 10 on top of the per-tenant
-- value (even a tenant that sets 99 sees the depth cap clamp at 10);
-- 10 was chosen because real CMDB chains rarely exceed 5-6 levels
-- and a depth-10 traversal on the partial indexes already in place
-- comfortably stays under 50 ms on the synthetic fixture.
--
-- Reader: src/modules/settings/service.rs::read_ci_impact_max_depth
-- Writer: validated by src/modules/settings/models.rs.
-- Executor: src/modules/assets/service.rs::compute_impact_graph.

INSERT INTO tenant_settings (tenant_id, category, key, value)
SELECT id, 'ci', 'impact_max_depth', to_jsonb(5)
FROM tenants
ON CONFLICT (tenant_id, category, key) DO NOTHING;
