-- PMS-188: make asset_audit_log survive deletion of its asset.
--
-- asset_audit_log.asset_id was declared `REFERENCES assets(id) ON DELETE
-- CASCADE` (migration 011). That cascade means a `deleted` audit row written
-- inside delete_asset's transaction is removed by the very DELETE it records,
-- so vault/asset deletions would stay untraceable even after we start writing
-- the row. An audit log must outlive the record it audits, so drop the cascade
-- FK and keep asset_id as a plain (still NOT NULL) column. The id is retained
-- verbatim for forensic lookup; integrity is intentionally relaxed because an
-- append-only audit trail legitimately references rows that no longer exist.
--
-- Idempotent: DROP CONSTRAINT IF EXISTS is a no-op when re-run.

ALTER TABLE asset_audit_log
    DROP CONSTRAINT IF EXISTS asset_audit_log_asset_id_fkey;
