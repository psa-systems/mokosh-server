-- PMS-778: index every column the global search filters on.
--
-- `SearchService::search` (src/modules/search/service.rs) runs one ILIKE
-- '%q%' predicate per searchable column. A leading wildcard is unusable by a
-- btree, so trigram is the only index type that can serve it, and Postgres can
-- only turn a multi-branch OR into a BitmapOr when EVERY branch has its own
-- index. Before this migration only `tickets.title`, `companies.name` and
-- `assets.name` were covered, so eight of the ten statements sequentially
-- scanned the whole tenant slice - including the unbounded COUNT(*) beside
-- each LIMIT 5 result query, which is the expensive half.
--
-- `idx_contacts_name_trgm` (004) stays: it indexes the expression
-- (first_name || ' ' || last_name), which serves the contacts list endpoint's
-- single-field search but matches none of the three per-column predicates
-- here. Dropping it is a separate decision.
--
-- Write cost is accepted: these tables are written at human pace, and GIN
-- defers most index maintenance through the pending list. Revisit if the RMM
-- ingest path (src/modules/rmm/service.rs) ever becomes the dominant ticket
-- writer.

CREATE INDEX IF NOT EXISTS idx_tickets_number_trgm ON tickets USING gin (ticket_number gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_tickets_description_trgm ON tickets USING gin (description gin_trgm_ops);

CREATE INDEX IF NOT EXISTS idx_contacts_first_name_trgm ON contacts USING gin (first_name gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_contacts_last_name_trgm ON contacts USING gin (last_name gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_contacts_email_trgm ON contacts USING gin (email gin_trgm_ops);

CREATE INDEX IF NOT EXISTS idx_assets_serial_number_trgm ON assets USING gin (serial_number gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_assets_asset_tag_trgm ON assets USING gin (asset_tag gin_trgm_ops);

CREATE INDEX IF NOT EXISTS idx_projects_name_trgm ON projects USING gin (name gin_trgm_ops);
