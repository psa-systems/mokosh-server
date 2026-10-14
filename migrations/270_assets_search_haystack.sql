-- PMS-1486 (asset search v2, phase 1): one haystack column covering every
-- field an operator pastes into the search box, plus the two facet
-- indexes the structured-filter endpoint reads.
--
-- Background. The existing search on `/assets?q=` ILIKEs `name` and
-- `serial_number`. The CMDB columns (`hostname`, `ip_address`,
-- `mac_address`, `asset_tag`, `manufacturer`, `model`, `department`,
-- `notes`) are rendered in the SPA but not reachable through the search
-- box. The field an operator pastes most often (a serial off the
-- hardware, a MAC off a network tool, an asset tag off a sticker) is
-- the one most likely to return zero rows.
--
-- Why one GENERATED column rather than ten per-column indexes. pg_trgm
-- is already the shape every text search in this repo uses (tickets,
-- companies, contacts, kb_articles); switching to tsvector just for
-- assets would diverge for no gain here, since what the operator pastes
-- is a substring, not a word stem. One STORED generated column
-- concatenates every searchable field with a space separator so a
-- trigram at a column boundary cannot bridge two fields and read as a
-- hit that is not really there, and one GIN gin_trgm_ops over the
-- concatenation serves every paste pattern with one scan.
--
-- Why STORED, not VIRTUAL. The haystack is written once per
-- INSERT/UPDATE; serving reads it without recomputing. On a 10k-asset
-- tenant at ~200 bytes per row this is 2 MB extra on disk, which is
-- the trade for not re-running the concat on every list query.
--
-- Why host(ip_address) rather than ip_address::text. INET's cast to
-- text yields `10.0.0.1/32` on a /32 host, which would miss a search
-- for the dotted-quad an operator pastes. `host()` renders without the
-- CIDR suffix, matching what the operator sees in a terminal.
ALTER TABLE assets
    ADD COLUMN search_haystack TEXT GENERATED ALWAYS AS (
        lower(
            COALESCE(name, '')             || ' ' ||
            COALESCE(asset_tag, '')        || ' ' ||
            COALESCE(serial_number, '')    || ' ' ||
            COALESCE(hostname, '')         || ' ' ||
            COALESCE(host(ip_address), '') || ' ' ||
            COALESCE(mac_address, '')      || ' ' ||
            COALESCE(manufacturer, '')     || ' ' ||
            COALESCE(model, '')            || ' ' ||
            COALESCE(department, '')       || ' ' ||
            COALESCE(notes, '')
        )
    ) STORED;

CREATE INDEX idx_assets_search_haystack_trgm
    ON assets USING gin (search_haystack gin_trgm_ops);

-- Facet indexes the structured endpoint lowers filter pills to. The
-- status facet already has `idx_assets_status`; `itil_lifecycle_stage`
-- is already covered by migration 065's `idx_assets_itil_lifecycle_stage`.
-- Phase 1 adds a GIN over `tags` + btree partials over the date facets.
--
-- Tags are a TEXT[]; a GIN on the array answers `tag_contains ?` with
-- an index scan rather than an unnest-and-scan.
CREATE INDEX idx_assets_tags_gin
    ON assets USING gin (tags);

-- Range facets on warranty_expiry + end_of_life + purchase_date +
-- installed_date (phase 1 lowers `within {days:N}` to a BETWEEN).
-- A plain tenant-scoped btree pair is cheap and the planner takes
-- the one the filter uses.
CREATE INDEX idx_assets_warranty_expiry
    ON assets(tenant_id, warranty_expiry)
    WHERE warranty_expiry IS NOT NULL;
CREATE INDEX idx_assets_end_of_life
    ON assets(tenant_id, end_of_life)
    WHERE end_of_life IS NOT NULL;

-- Rely on the existing GRANT the migration 235 cleanup covered;
-- adding a column does not require a new GRANT on the table.

COMMENT ON COLUMN assets.search_haystack IS
    'PMS-1486: STORED generated column concatenating every field the free-text search matches on. One pg_trgm GIN above indexes it; serving reads via `search_haystack ILIKE $N`.';
