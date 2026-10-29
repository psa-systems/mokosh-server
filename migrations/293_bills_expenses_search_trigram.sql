-- PMS-1561 F3: `list_bills` and `list_expenses` ILIKE their `q` filter
-- against `bills.bill_number`, `vendors.name`, `expenses.notes` and
-- `expense_lines.description` (src/modules/expenses/service.rs). `search_pattern`
-- wraps a non-empty `q` in `%...%`, a leading wildcard no btree index can
-- serve, and none of these four columns had a trigram index: a repo-wide grep
-- of every migration for `pg_trgm`/`gin_trgm` before this one covers only
-- `tickets`, `contacts`, `knowledge_base`, `users.full_name`, the portal
-- search and the assets search haystack. Both the count and the page query
-- pay the scan cost on every search request.
CREATE INDEX IF NOT EXISTS idx_bills_bill_number_trgm ON bills USING gin (bill_number gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_vendors_name_trgm ON vendors USING gin (name gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_expenses_notes_trgm ON expenses USING gin (notes gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_expense_lines_description_trgm ON expense_lines USING gin (description gin_trgm_ops);
