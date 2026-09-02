-- MAPPS-637: per-Company email uniqueness for portal contacts.
--
-- The `contacts.portal_password_hash` column is per-row and the
-- portal login flow is per-Company (each Portal ID resolves to
-- exactly one contact), so per-portal password isolation is
-- already the data intent. But nothing at the schema layer
-- refused the anti-pattern that used to feed the multi-Company
-- picker: two contact rows with the SAME email under the SAME
-- Company. Two identical portal accounts at one Company can only
-- be a data-entry mistake (there's no product reason for it), and
-- letting them exist creates ambiguity for every "sign in as this
-- email at this portal" login attempt.
--
-- Partial + case-insensitive so only ROWS THE POLICY APPLIES TO
-- get the constraint:
--   * `email IS NOT NULL` — freeform / stub contacts with no
--     email stay unaffected.
--   * `is_portal_user = TRUE` — non-portal CRM contacts stay
--     unaffected (a Company can legitimately have several rows
--     tracking the same email if none of them is a portal user).
--   * `LOWER(email)` — a duplicate that only differs in case
--     ("Foo@bar.com" vs "foo@bar.com") is refused; matches how
--     the login lookup compares.
--
-- A person who legitimately has portal access at TWO different
-- Companies of the SAME MSP tenant is still supported: two rows
-- with the same email under DIFFERENT `company_id`s pass this
-- index; the (tenant, Company) tuple is what changes. Same person
-- at two different MSP tenants (`tenant_id`) is also supported
-- for the same reason.
--
-- Idempotent via `IF NOT EXISTS`. A new INSERT that collides
-- fails with the usual UNIQUE_VIOLATION (23505); the service
-- layer surfaces that as a field-level validation error on
-- `email` for the affected caller (see the paired
-- `create_contact` / `update_contact` change).

CREATE UNIQUE INDEX IF NOT EXISTS contacts_unique_portal_email_per_company
    ON contacts (tenant_id, company_id, LOWER(email))
    WHERE email IS NOT NULL
      AND company_id IS NOT NULL
      AND is_portal_user = TRUE;
