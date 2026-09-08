-- PMS-1117: apply the guarded-content-UPDATE assertion (migration 205) to
-- notification_templates first, since `auth.password_reset` and
-- `auth.welcome` are the two rows migrations 139 and 152 silently missed.
--
-- This is a read-only sanity check, not a rewrite: it asserts that every
-- tenant's copy of these two seeded email templates still has a real subject
-- and body, using `mokosh_assert_content_rows_matched` the same way a guarded
-- UPDATE would. It runs once, when a database reaches this migration, the
-- same as every other migration - it does not re-run on every subsequent
-- boot, so it is NOT a substitute for the same-migration assertion a future
-- guarded UPDATE on this table must carry (that is what
-- `scripts/check-guarded-content-migrations.nu` enforces going forward). What
-- it catches here and now is the shape of the incident this issue is about:
-- if some already-applied migration left either template with no content at
-- all (rather than merely with the wrong branding, which is a product
-- decision tracked elsewhere and deliberately not asserted on here), this
-- fails loud instead of shipping an email with an empty body.
DO $$
DECLARE
    reset_rows bigint;
    welcome_rows bigint;
BEGIN
    SELECT count(*) INTO reset_rows
    FROM notification_templates
    WHERE event_type = 'auth.password_reset'
      AND channel_type = 'email'
      AND subject IS NOT NULL AND subject <> ''
      AND body_text IS NOT NULL AND body_text <> '';
    PERFORM mokosh_assert_content_rows_matched(
        reset_rows, (SELECT count(*) FROM notification_templates
                      WHERE event_type = 'auth.password_reset' AND channel_type = 'email'),
        'auth.password_reset (email) seeded rows must carry a non-empty subject and body (PMS-1117)');

    SELECT count(*) INTO welcome_rows
    FROM notification_templates
    WHERE event_type = 'auth.welcome'
      AND channel_type = 'email'
      AND subject IS NOT NULL AND subject <> ''
      AND body_text IS NOT NULL AND body_text <> '';
    PERFORM mokosh_assert_content_rows_matched(
        welcome_rows, (SELECT count(*) FROM notification_templates
                        WHERE event_type = 'auth.welcome' AND channel_type = 'email'),
        'auth.welcome (email) seeded rows must carry a non-empty subject and body (PMS-1117)');
END $$;
