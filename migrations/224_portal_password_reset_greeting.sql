-- PMS-1198 (CF-2): give the portal password-reset mail the greeting its
-- sibling already has.
--
-- Migration 206 (PMS-1140) split `auth.password_reset` into a staff-only
-- template and a new customer-only `auth.portal_password_reset`, and gave the
-- other new template in that same migration, `auth.portal_welcome`, a
-- `{{salutation}},` opening line fed from `TenantService::send_admin_welcome`.
-- `auth.portal_password_reset` never got the same treatment: it opens
-- directly on "We received a request to reset your password..." with no name
-- and no placeholder for one, even though its dispatch site,
-- `ContactPortalService::request_password_reset`, already reads the
-- contact's first name off the row it just queried. Migration 206 is
-- immutable, so this steps forward rather than editing it.
--
-- `TenantService::seed_default_config` copies this row to every tenant (206's
-- own backfill did the same for every tenant that pre-dated it), so the row
-- count here is the tenant count and is not knowable when this file is
-- written; the migration-212 shape applies. A fragment replace rather than a
-- whole-body guard for the same reason 212 states: migration 212 itself
-- already rewrote this row's footer to `{{msp_footer_line}}` after 206 seeded
-- it, so a guard on 206's original whole body would match nothing on any
-- database that has run 212. Replacing the opening-sentence fragment touches
-- every row that still carries it (206's seed, however its footer since
-- evolved) and leaves a tenant's own hand-customised copy - one that no
-- longer contains that fragment - alone, per the migration-096 contract.

DO $$
DECLARE
    text_fragment CONSTANT text :=
        E'We received a request to reset your password for the {{msp_name}} client portal.\n\n';
    text_replacement CONSTANT text :=
        E'{{salutation}},\n\nWe received a request to reset your password for the {{msp_name}} client portal.\n\n';
    html_fragment CONSTANT text :=
        '<h1 style="font-size:18px;margin:0 0 12px 0;">Reset your password</h1>'
        || '<p>We received a request to reset your password for the {{msp_name}} client portal.</p>';
    html_replacement CONSTANT text :=
        '<h1 style="font-size:18px;margin:0 0 12px 0;">Reset your password</h1>'
        || '<p>{{salutation}},</p>'
        || '<p>We received a request to reset your password for the {{msp_name}} client portal.</p>';
    expected bigint;
    matched  bigint;
BEGIN
    SELECT count(*) INTO expected
      FROM notification_templates
     WHERE event_type = 'auth.portal_password_reset'
       AND channel_type = 'email'
       AND strpos(COALESCE(body_text, ''), text_fragment) > 0
       AND strpos(COALESCE(body_html, ''), html_fragment) > 0;

    UPDATE notification_templates
       SET body_text = replace(body_text, text_fragment, text_replacement),
           body_html = replace(body_html, html_fragment, html_replacement),
           updated_at = NOW()
     WHERE event_type = 'auth.portal_password_reset'
       AND channel_type = 'email'
       AND strpos(COALESCE(body_text, ''), text_fragment) > 0
       AND strpos(COALESCE(body_html, ''), html_fragment) > 0;

    GET DIAGNOSTICS matched = ROW_COUNT;
    PERFORM mokosh_assert_content_rows_matched(
        matched, expected, 'auth.portal_password_reset greeting (PMS-1198)');

    IF expected = 0 THEN
        RAISE EXCEPTION
            'no notification_templates row carries the auth.portal_password_reset '
            'opening sentence, so this migration would be a silent no-op: the '
            'seeded text this guards on has moved (PMS-1198/PMS-1117)'
            USING ERRCODE = 'check_violation';
    END IF;
END $$;
