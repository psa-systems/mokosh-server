-- PMS-1507: route the `auth.mokosh_grant_invite` greeting through
-- `{{salutation}}` instead of its own `Hello {{invitee_display_name}},`
-- literal.
--
-- Migration 268 (PMS-1208) seeded this template with a fourth independent
-- greeting mechanism: a literal "Hello {{invitee_display_name}}," filled
-- from `local_part(&invitation.invitee_email)`, with no trimming and no
-- blank-name fallback. Nine prior corrective migrations (106, 116, 203,
-- 204, 206, 224, 229, 230, 266) exist to retrofit `{{salutation}}` onto a
-- template that shipped without it; this is the same defect.
--
-- A fragment replace rather than a whole-body guard, per the migration-096
-- contract, so a tenant's own hand-customised copy that no longer contains
-- the exact opening is left alone. Applied to both `body_text` and
-- `body_html` so the two stay in sync, same as migration 266's approach.

DO $$
DECLARE
    text_fragment     CONSTANT text := E'Hello {{invitee_display_name}},';
    text_replacement  CONSTANT text := E'{{salutation}},';
    html_fragment     CONSTANT text := '<p>Hello {{invitee_display_name}},</p>';
    html_replacement  CONSTANT text := '<p>{{salutation}},</p>';
    expected bigint;
    matched  bigint;
BEGIN
    SELECT count(*) INTO expected
      FROM notification_templates
     WHERE event_type = 'auth.mokosh_grant_invite'
       AND channel_type = 'email'
       AND strpos(COALESCE(body_text, ''), text_fragment) > 0;

    UPDATE notification_templates
       SET body_text = replace(body_text, text_fragment, text_replacement),
           updated_at = NOW()
     WHERE event_type = 'auth.mokosh_grant_invite'
       AND channel_type = 'email'
       AND strpos(COALESCE(body_text, ''), text_fragment) > 0;

    GET DIAGNOSTICS matched = ROW_COUNT;
    PERFORM mokosh_assert_content_rows_matched(
        matched, expected, 'auth.mokosh_grant_invite body_text greeting (PMS-1507)');

    IF expected = 0 THEN
        RAISE EXCEPTION
            'no notification_templates row carries the auth.mokosh_grant_invite '
            'Hello {{invitee_display_name}}, body_text opening, so this migration '
            'would be a silent no-op: the seeded text this guards on has moved '
            '(PMS-1507/PMS-1117)'
            USING ERRCODE = 'check_violation';
    END IF;

    SELECT count(*) INTO expected
      FROM notification_templates
     WHERE event_type = 'auth.mokosh_grant_invite'
       AND channel_type = 'email'
       AND strpos(COALESCE(body_html, ''), html_fragment) > 0;

    UPDATE notification_templates
       SET body_html = replace(body_html, html_fragment, html_replacement),
           updated_at = NOW()
     WHERE event_type = 'auth.mokosh_grant_invite'
       AND channel_type = 'email'
       AND strpos(COALESCE(body_html, ''), html_fragment) > 0;

    GET DIAGNOSTICS matched = ROW_COUNT;
    PERFORM mokosh_assert_content_rows_matched(
        matched, expected, 'auth.mokosh_grant_invite body_html greeting (PMS-1507)');

    IF expected = 0 THEN
        RAISE EXCEPTION
            'no notification_templates row carries the auth.mokosh_grant_invite '
            '<p>Hello {{invitee_display_name}},</p> body_html opening, so this '
            'migration would be a silent no-op: the seeded text this guards on '
            'has moved (PMS-1507/PMS-1117)'
            USING ERRCODE = 'check_violation';
    END IF;
END $$;
