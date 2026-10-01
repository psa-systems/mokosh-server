-- PMS-1448: contact_sync's snapshot() runs a correlated subquery per contact
-- row (`SELECT co.name FROM contact_companies cc ... WHERE cc.contact_id = c.id`),
-- the same shape already served by `idx_contact_phones_contact` for the sibling
-- phone-number subquery. `idx_contact_companies_company` leads with
-- `(tenant_id, company_id)` and `idx_contact_companies_one_primary` is a
-- partial index restricted to `is_primary` rows, so neither serves a bare
-- `contact_id = c.id` lookup: this leaves the subquery a sequential scan.
CREATE INDEX idx_contact_companies_contact ON contact_companies(tenant_id, contact_id);
