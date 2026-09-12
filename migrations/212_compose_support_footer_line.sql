-- PMS-1171: the footer sentence stops interpolating an address that can be absent.
--
-- Every branded template wrote its footer out with the support address inline:
--
--   Sent on behalf of {{msp_name}}. Questions? Reply to {{msp_support_email}}.
--
-- `notifications::render_template` is a flat `{{key}}` replacer with no
-- conditionals (PMS-1140), and `enrich_with_branding` supplies an absent
-- branding field as an empty string, so a tenant that never set a support
-- address shipped `Questions? Reply to .` in every transactional mail. The
-- HTML half was worse: `<a href="mailto:"></a>` renders as nothing at all, so
-- the sentence ended in a bare full stop. Observed in a delivered portal
-- sign-in message on 2026-09-12.
--
-- A value that can legitimately be absent cannot be interpolated into prose,
-- because the punctuation around it has nowhere to go. The sentence is now
-- composed in Rust (`notifications::service::footer_line` /
-- `footer_line_html`), where a condition can be expressed, exactly as
-- `OrgIdentity::contact_line` and `logo_html` already are. This migration
-- points the seeded bodies at the composed keys.
--
-- ## Why a substring replace rather than a whole-body guard
--
-- `TenantService::seed_default_config` copies these rows to every tenant, so
-- the text lives in as many rows as there are tenants, and several of those
-- bodies have been rewritten by migrations 116, 139, 152, 203 and 204 in
-- different combinations. A guard on a whole body would match the default
-- tenant's row and miss every copy whose surrounding text moved - the exact
-- PMS-1117 failure this file has to avoid. Replacing the footer FRAGMENT
-- touches every row that still carries it and leaves the rest of each body
-- untouched.
--
-- A tenant who rewrote their own footer through the CRUD API no longer carries
-- the fragment, so this does not touch their copy. That is deliberate (the
-- migration 096 contract): their footer keeps saying whatever they made it
-- say, including `Reply to .` if they wrote it that way. `msp_support_email`
-- is still supplied, so such a template keeps rendering.
--
-- The assertion is against a count taken before the UPDATE rather than a
-- literal, because the row count is the tenant count and is not knowable when
-- this is written. It still fails loudly on the case that matters: an UPDATE
-- that matches fewer rows than carry the fragment.

DO $$
DECLARE
    text_fragment  text := 'Sent on behalf of {{msp_name}}. Questions? Reply to {{msp_support_email}}.';
    html_fragment  text := 'Sent on behalf of {{msp_name}}. Questions? Reply to <a href="mailto:{{msp_support_email}}">{{msp_support_email}}</a>.';
    expected       bigint;
    matched        bigint;
BEGIN
    -- `strpos` rather than LIKE: the fragment contains underscores, which LIKE
    -- reads as single-character wildcards.
    SELECT count(*) INTO expected
      FROM notification_templates
     WHERE strpos(COALESCE(body_text, ''), text_fragment) > 0
        OR strpos(COALESCE(body_html, ''), html_fragment) > 0;

    UPDATE notification_templates
       SET body_text = replace(COALESCE(body_text, ''), text_fragment, '{{msp_footer_line}}'),
           body_html = replace(COALESCE(body_html, ''), html_fragment, '{{msp_footer_line_html}}')
     WHERE strpos(COALESCE(body_text, ''), text_fragment) > 0
        OR strpos(COALESCE(body_html, ''), html_fragment) > 0;

    GET DIAGNOSTICS matched = ROW_COUNT;
    PERFORM mokosh_assert_content_rows_matched(
        matched, expected, 'support footer composed into one key (PMS-1171)');

    -- `matched = expected` is satisfied by 0 = 0, which is the PMS-1117 trap
    -- wearing an assertion. The seeded templates DO carry this footer (023
    -- seeds them; 139, 178 and 206 rewrite them around it), so zero means the
    -- fragment moved under this migration and the composed keys are now
    -- rendering nowhere. Fail rather than commit a no-op that looks applied.
    IF expected = 0 THEN
        RAISE EXCEPTION
            'no notification_templates row carries the support footer fragment, '
            'so this migration would be a silent no-op: the seeded text this '
            'guards on has moved (PMS-1171/PMS-1117)'
            USING ERRCODE = 'check_violation';
    END IF;
END $$;
