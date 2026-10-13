-- PMS-1485: give `invitations.created` and `quote.sent` the greeting every
-- other personal, named-recipient template opens with.
--
-- Migration 265 (PMS-1378) seeded both templates without a `{{salutation}},`
-- opening. Three prior migrations (203, 230, 255) exist solely to retrofit
-- that greeting onto personal templates that shipped without one, so these
-- two are the same defect. Both dispatch call sites
-- (`src/modules/invitations/service.rs`, `src/modules/quotes/service.rs`) now
-- pass `salutation("")` in their context maps, so the placeholder resolves
-- to the bare "Hello," fallback.
--
-- A fragment replace rather than a whole-body guard, per the migration-096
-- contract, so a tenant's own hand-customised copy that no longer contains
-- the exact opening is left alone.

DO $$
DECLARE
    invite_fragment     CONSTANT text := E'You have been invited to join {{tenant_name}}';
    invite_replacement  CONSTANT text := E'{{salutation}},\n\nYou have been invited to join {{tenant_name}}';
    quote_fragment       CONSTANT text := E'{{sender_org_name}} has sent you a quote';
    quote_replacement    CONSTANT text := E'{{salutation}},\n\n{{sender_org_name}} has sent you a quote';
    expected bigint;
    matched  bigint;
BEGIN
    SELECT count(*) INTO expected
      FROM notification_templates
     WHERE event_type = 'invitations.created'
       AND channel_type = 'email'
       AND strpos(COALESCE(body_text, ''), invite_fragment) > 0;

    UPDATE notification_templates
       SET body_text = replace(body_text, invite_fragment, invite_replacement),
           updated_at = NOW()
     WHERE event_type = 'invitations.created'
       AND channel_type = 'email'
       AND strpos(COALESCE(body_text, ''), invite_fragment) > 0;

    GET DIAGNOSTICS matched = ROW_COUNT;
    PERFORM mokosh_assert_content_rows_matched(
        matched, expected, 'invitations.created greeting (PMS-1485)');

    IF expected = 0 THEN
        RAISE EXCEPTION
            'no notification_templates row carries the invitations.created '
            'You have been invited... opening, so this migration would be a '
            'silent no-op: the seeded text this guards on has moved (PMS-1485/PMS-1117)'
            USING ERRCODE = 'check_violation';
    END IF;

    SELECT count(*) INTO expected
      FROM notification_templates
     WHERE event_type = 'quote.sent'
       AND channel_type = 'email'
       AND strpos(COALESCE(body_text, ''), quote_fragment) > 0;

    UPDATE notification_templates
       SET body_text = replace(body_text, quote_fragment, quote_replacement),
           updated_at = NOW()
     WHERE event_type = 'quote.sent'
       AND channel_type = 'email'
       AND strpos(COALESCE(body_text, ''), quote_fragment) > 0;

    GET DIAGNOSTICS matched = ROW_COUNT;
    PERFORM mokosh_assert_content_rows_matched(
        matched, expected, 'quote.sent greeting (PMS-1485)');

    IF expected = 0 THEN
        RAISE EXCEPTION
            'no notification_templates row carries the quote.sent has sent '
            'you a quote opening, so this migration would be a silent no-op: '
            'the seeded text this guards on has moved (PMS-1485/PMS-1117)'
            USING ERRCODE = 'check_violation';
    END IF;
END $$;
