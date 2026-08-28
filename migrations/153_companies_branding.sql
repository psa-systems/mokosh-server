-- MAPPS-617 (mokosh-branding prompt 001): per-Company branding
-- overrides. Layered brand model: the effective branding for a given
-- (tenant, company) tuple is the tenant's `branding` merged with the
-- Company's `branding`, with every non-null Company key winning over
-- the tenant key. Missing keys on both sides fall back to a hardcoded
-- SPA default so the portal never paints an empty logo slot.
--
-- NOT NULL DEFAULT '{}' so a live rollout does not need a
-- backfill pass; every existing Company row starts with an empty
-- override block and inherits the tenant defaults through the
-- resolver.
--
-- The existing `companies.logo_url VARCHAR(500)` column stays for
-- backward-compat with any consumer still reading it directly. A
-- follow-up migration will remove it once callers have been
-- migrated to `branding.logo_url`.

ALTER TABLE companies
    ADD COLUMN branding JSONB NOT NULL DEFAULT '{}'::jsonb;
