-- PMS-1380 (F7): the contact-sync snapshot query's company-names subquery
-- (`src/modules/contact_sync/sync.rs`, `snapshot`) filters
-- `contact_companies` on an unfiltered `contact_id = c.id`, once per contact
-- in the tenant. Neither existing index on this table serves that predicate:
-- `idx_contact_companies_company` leads with `(tenant_id, company_id)`, and
-- `idx_contact_companies_one_primary` is a partial index restricted to
-- `is_primary` rows. This mirrors `idx_contact_phones_contact`, the index the
-- sibling phones subquery two lines above already uses.
CREATE INDEX idx_contact_companies_contact ON contact_companies(tenant_id, contact_id);
