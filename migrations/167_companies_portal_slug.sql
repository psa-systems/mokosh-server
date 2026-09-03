-- MAPPS-XXX (mokosh-contact-login prompt 002): random unguessable slug
-- per Company for the contact portal URL.
--
-- Contact portal URL shape: msp.<apex>/portal/{slug}/login. Slug is 16
-- chars of Crockford base32 (~80 bits entropy) so a targeted attacker
-- cannot enumerate portals. NULL when no contact has portal access at
-- this Company yet; populated on first `ContactService::grant_portal_access`
-- call and reused for every subsequent contact under the same Company.
--
-- Distinct from the pre-pivot `tenants.slug` (a friendly per-MSP
-- subdomain): this is per-Company + random + unguessable + rotates
-- only when the MSP admin explicitly requests a new slug.
ALTER TABLE companies
    ADD COLUMN portal_slug VARCHAR(32) UNIQUE;

CREATE INDEX idx_companies_portal_slug
    ON companies (portal_slug)
    WHERE portal_slug IS NOT NULL;
