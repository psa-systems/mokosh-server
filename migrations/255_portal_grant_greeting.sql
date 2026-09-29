-- PMS-1415: give the portal-grant mail the greeting its two siblings
-- already have.
--
-- The composer for this template (`src/modules/contacts/service.rs:2501-2508`)
-- already builds a `salutation` value into the render context for exactly
-- the same reason PMS-774 introduced the placeholder everywhere else:
-- `contacts.first_name` is NOT NULL but may hold an empty string, so the
-- greeting word has to come from `salutation` rather than from the bare
-- name. Migration 184 (itself re-issuing migration 146's body after a
-- rename) never picked up the fix and still opens on the literal
-- `Hello {{display_name}},` in both `body_text` and `body_html`, so a
-- contact with a blank first name reads "Hello ," on the very first
-- portal email they receive. `auth.portal_password_reset` got the same
-- repair in migration 224 and `forms.request_link` in migration 230;
-- this migration follows the same shape.
--
-- `TenantService::seed_default_config` copies this row to every tenant
-- (migration 186's own backfill did the same for every tenant that
-- pre-dated it), so the row count here is the tenant count and is not
-- knowable when this file is written; the migration-224 shape applies.
-- A fragment replace rather than a whole-body guard, per the migration-096
-- contract, so a tenant's own hand-customised copy that no longer contains
-- this exact opening is left alone, and `{{display_name}}` used elsewhere
-- in the body (the Company ID line, if a tenant's copy still names it) is
-- untouched.

DO $$
DECLARE
    text_fragment CONSTANT text := E'Hello {{display_name}},\n\n';
    text_replacement CONSTANT text := E'{{salutation}},\n\n';
    html_fragment CONSTANT text := '<p>Hello {{display_name}},</p>';
    html_replacement CONSTANT text := '<p>{{salutation}},</p>';
    expected bigint;
    matched  bigint;
BEGIN
    SELECT count(*) INTO expected
      FROM notification_templates
     WHERE event_type = 'auth.portal_grant'
       AND channel_type = 'email'
       AND (strpos(COALESCE(body_text, ''), text_fragment) > 0
            OR strpos(COALESCE(body_html, ''), html_fragment) > 0);

    UPDATE notification_templates
       SET body_text = replace(body_text, text_fragment, text_replacement),
           body_html = replace(body_html, html_fragment, html_replacement),
           updated_at = NOW()
     WHERE event_type = 'auth.portal_grant'
       AND channel_type = 'email'
       AND (strpos(COALESCE(body_text, ''), text_fragment) > 0
            OR strpos(COALESCE(body_html, ''), html_fragment) > 0);

    GET DIAGNOSTICS matched = ROW_COUNT;
    PERFORM mokosh_assert_content_rows_matched(
        matched, expected, 'auth.portal_grant greeting (PMS-1415)');

    IF expected = 0 THEN
        RAISE EXCEPTION
            'no notification_templates row carries the auth.portal_grant '
            'Hello {{display_name}}, opening, so this migration would be a '
            'silent no-op: the seeded text this guards on has moved (PMS-1415/PMS-1117)'
            USING ERRCODE = 'check_violation';
    END IF;
END $$;
