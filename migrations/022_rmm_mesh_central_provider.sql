-- Add mesh_central to the rmm_connections.provider CHECK constraint.
--
-- PMS-105 ("MeshCentral provider variant") was marked resolved, but the
-- initial schema CHECK at migrations/001_initial_schema.sql:1486 only
-- listed tactical_rmm | datto | connectwise | ninja_rmm. The variant
-- could not exist on disk; this migration closes the docs-vs-code drift
-- so PMS-103 (RMM device-sync worker) can land with mesh_central as a
-- registered provider behind the new RmmProvider trait.

ALTER TABLE rmm_connections
    DROP CONSTRAINT IF EXISTS rmm_connections_provider_check;

ALTER TABLE rmm_connections
    ADD CONSTRAINT rmm_connections_provider_check
    CHECK (provider IN ('tactical_rmm', 'mesh_central', 'datto', 'connectwise', 'ninja_rmm'));
