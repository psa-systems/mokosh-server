-- PMS-321: enforce that a ticket category's parent lives in the SAME tenant at
-- the database layer, closing a cross-tenant gap the app already guards in
-- `TicketService::create_category` / `update_category` (via `validate_fk` +
-- the recursive-CTE cycle check) but the schema did not.
--
-- migration 005 declared `parent_id UUID REFERENCES ticket_categories(id)`, a
-- single-column self-FK that only checks the target row EXISTS - it says
-- nothing about whose tenant it belongs to, so a direct SQL write (anything
-- bypassing the service layer) could parent a category under another tenant's
-- row. Following the 043_pms196 precedent, the fix is a new forward migration
-- (the shipped 005 file cannot be edited - sqlx validates its checksum on
-- `migrate run` and a modified file aborts startup).
--
-- The composite FK target needs a matching unique key, so add UNIQUE
-- (tenant_id, id) first (trivially satisfiable - `id` is already the primary
-- key). The composite FK uses the default MATCH SIMPLE semantics: a row with a
-- NULL `parent_id` (a root category) is not checked, so top-level categories
-- are unaffected; `tenant_id` is NOT NULL, so any non-root row is fully
-- enforced. ON DELETE is left at the default RESTRICT, matching 005, so
-- deleting a category that still has children raises SQLSTATE 23503, which
-- `TicketService::delete_lookup` already maps to a 409.

ALTER TABLE ticket_categories
    ADD CONSTRAINT ticket_categories_tenant_id_id_key UNIQUE (tenant_id, id);

ALTER TABLE ticket_categories
    DROP CONSTRAINT IF EXISTS ticket_categories_parent_id_fkey;

ALTER TABLE ticket_categories
    ADD CONSTRAINT ticket_categories_parent_id_fkey
        FOREIGN KEY (tenant_id, parent_id)
        REFERENCES ticket_categories (tenant_id, id);
