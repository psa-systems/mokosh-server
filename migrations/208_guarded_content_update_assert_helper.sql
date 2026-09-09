-- PMS-1117: a guarded content UPDATE that matches zero rows is indistinguishable
-- from one that did its work.
--
-- Migration 096's contract (a guarded content UPDATE matches on the exact text
-- it expects, so a row an operator customised through the CRUD API is left
-- alone) has one failure mode with no signal at all: when the guard matches
-- nothing, the UPDATE is a no-op, the migration still commits, and
-- `_sqlx_migrations` records it as applied. This has hit the same two rows
-- twice. Migration 139 guarded `auth.password_reset` and `auth.welcome` on
-- text migration 116 had already rewritten, so both of its rebranding UPDATEs
-- matched zero rows and the two highest-volume customer-facing emails shipped
-- unbranded for months; migration 152 then guarded `auth.welcome` on 139's
-- (never-applied) output and matched zero rows for the same reason, one
-- migration downstream. Neither was caught by review, by CI, or at deploy
-- time - what caught 139 was an unrelated integration test failing, and what
-- caught 152 was a human reading the file next to it.
--
-- This function is the fix: a guarded content UPDATE states how many rows it
-- expects to match and asserts it inside the same migration, so a zero-row
-- miss RAISEs and fails the migration (and therefore the boot, since
-- RUN_MIGRATIONS defaults to true) instead of silently committing. Unlike a
-- code-review or CI-time check, this runs on every apply of every migration
-- that uses it, in every environment, which is what "without anyone
-- remembering to invoke it" means concretely.
--
-- Usage, immediately after the guarded UPDATE, inside a DO block:
--
--   DO $$
--   DECLARE
--       matched bigint;
--   BEGIN
--       UPDATE notification_templates SET
--           subject = '...'
--       WHERE event_type = 'auth.welcome'
--         AND channel_type = 'email'
--         AND subject = '<the exact text the previous migration left>';
--       GET DIAGNOSTICS matched = ROW_COUNT;
--       PERFORM mokosh_assert_content_rows_matched(
--           matched, 1, 'auth.welcome subject rebrand (PMS-1117)');
--   END $$;
--
-- `expected` is usually 1 (one seeded row per event_type/channel_type) but can
-- be 0 when the UPDATE is itself conditional on a prior migration's outcome,
-- or >1 when a guard intentionally spans several tenants' copies of a row; the
-- caller states it rather than the helper assuming 1, because assuming would
-- silence exactly the class of bug this exists to catch.
--
-- `scripts/check-guarded-content-migrations.nu` (wired into `just check` and
-- `.forgejo/workflows/check.yml`) enforces that a guarded content UPDATE added
-- after this migration carries a `GET DIAGNOSTICS` + assertion pair; this
-- migration is the "after" line, documented in CLAUDE.md alongside it. The
-- cost, stated up front: it only catches a migration written to use it, so 139
-- and 152 are not retroactively guarded - they are immutable, and the content
-- they were meant to write already landed via migrations 203/204.

CREATE OR REPLACE FUNCTION mokosh_assert_content_rows_matched(
    matched bigint,
    expected bigint,
    context text
) RETURNS void AS $$
DECLARE
    msg text;
BEGIN
    IF matched <> expected THEN
        msg := format(
            'guarded content UPDATE matched %s row(s), expected %s (%s): a '
            || 'later migration may already have rewritten the text this '
            || 'UPDATE guards on - check the WHERE clause against the most '
            || 'recent SET for this row (PMS-1117)',
            matched, expected, context
        );
        RAISE EXCEPTION '%', msg USING ERRCODE = 'check_violation';
    END IF;
END;
$$ LANGUAGE plpgsql;
