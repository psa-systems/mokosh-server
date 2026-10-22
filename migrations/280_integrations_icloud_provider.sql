-- MAPPS-1122: `icloud` joins the providers `integrations.provider` accepts.
--
-- The registry's header states the rule this follows: the provider strings are
-- the same set this CHECK accepts, and adding one means widening the CHECK in a
-- new migration and adding the enum variant in the same change.
--
-- No row will carry it today. iCloud's connection and credential both belong to
-- contact sync (PMS-1341), so `IntegrationsService` refuses every write for it
-- and the entry exists so the panel can say the organization has one and where
-- it is set up. The CHECK is widened anyway, because the alternative is an enum
-- and a constraint that disagree, and the next person to give iCloud a row here
-- would find out from a 23514 in production rather than from this file.
ALTER TABLE integrations DROP CONSTRAINT IF EXISTS integrations_provider_check;
ALTER TABLE integrations
    ADD CONSTRAINT integrations_provider_check
    CHECK (
        provider IN ('stripe', 'paypal', 'quickbooks', 'xero', 'google', 'microsoft', 'icloud')
    );
