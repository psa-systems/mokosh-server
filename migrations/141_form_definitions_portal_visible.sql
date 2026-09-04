-- PMS-729 phase 2 §7 slice B / I8: form_definitions.portal_visible.
--
-- Phase 1's forms (PMS-730) were client-facing but delivered as one-off
-- magic links from an MSP: the customer never opened the form list on
-- their own. Slice B adds an authenticated portal-side form list + submit
-- flow, and the tenant needs a way to say "yes, this form is publishable
-- into the portal picker" without exposing every draft or internal-only
-- form.
--
-- Column defaults to `FALSE` so the phase 1 forms stay opt-in: an MSP has
-- to flip the flag deliberately (through the branding editor or the CRUD
-- API) before a form appears to a portal customer. That mirrors D18's
-- "never cross-company, never surprise" scoping and keeps existing forms
-- unchanged.
--
-- Read hot path is the picker `GET /portal/forms`, which filters both on
-- `is_active` and on this new flag. A partial index keyed on both keeps
-- the picker read cheap without bloating on retired forms.

ALTER TABLE form_definitions
    ADD COLUMN portal_visible BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX idx_form_definitions_tenant_portal_visible
    ON form_definitions(tenant_id)
    WHERE is_active = TRUE AND portal_visible = TRUE;

COMMENT ON COLUMN form_definitions.portal_visible IS
    'PMS-729 phase 2 §7 slice B: when TRUE, the definition appears in the authenticated portal form picker (/portal/forms). Deliberately opt-in.';
