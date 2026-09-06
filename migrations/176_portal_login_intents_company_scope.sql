-- PMS-928 (mokosh-contact-login prompt 011): optional per-Company
-- scope for magic-link login intents.
--
-- When the finder call carries a `portal_id`, the redeem step must
-- match only contacts inside that specific Company, so a user who
-- signs into MSP Foo via Company A's Portal ID does NOT land on
-- Company B's picker even if the email is duplicated across both
-- Companies inside the same MSP tenant. Persisting the scope on the
-- intent row itself keeps the redeem query simple and race-free (the
-- alternative would be to trust the caller to re-supply the scope
-- at redeem time; not acceptable for an unauthenticated flow).
--
-- The column stays NULLABLE for backward compatibility with intents
-- minted from the tenant-only finder path (email + slug via the
-- localStorage bookmark, prompt 010). NULL means "any Company under
-- this tenant matches"; NOT NULL means "only this Company's contacts
-- match at redeem time".
--
-- ON DELETE CASCADE mirrors the tenant / contact family relationships:
-- a Company deletion should drop its outstanding intents rather than
-- leave them dangling to redeem into a missing tile.

ALTER TABLE portal_login_intents
    ADD COLUMN company_id UUID
    REFERENCES companies(id) ON DELETE CASCADE;

CREATE INDEX idx_portal_login_intents_company
    ON portal_login_intents (company_id)
    WHERE company_id IS NOT NULL;
