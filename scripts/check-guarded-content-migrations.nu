#!/usr/bin/env nu

# A guarded content UPDATE that matches zero rows must not be indistinguishable
# from one that worked (PMS-1117).
#
# `notification_templates` rows are rewritten by UPDATEs guarded on the exact
# text a previous migration left, so a tenant who customised a row through the
# CRUD API keeps their copy. That contract (migration 096) has one failure mode
# with no signal at all: when the guard matches nothing (because a migration in
# between already rewrote the text), the UPDATE is a no-op, the migration still
# commits, and `_sqlx_migrations` records it as applied. This has hit the same
# two rows twice - migration 139's rebrand and migration 152's follow-up both
# matched zero rows on every database that ever ran them, and neither was
# caught by review, CI, or deploy.
#
# Migration 208 (`mokosh_assert_content_rows_matched`) gives every future
# guarded content UPDATE a way to assert its own match count and RAISE instead
# of silently no-opping; CLAUDE.md's Migrations section documents the
# convention. This script is the CI half: any migration numbered above the
# cutoff that guards an UPDATE's WHERE clause on a free-text column's literal
# value must also call `GET DIAGNOSTICS` in the same file, which is what using
# the convention looks like from the outside. It does not (and cannot,
# statically) verify the assertion's expected count is correct - only that the
# author declared and checked one at all.
#
# Migrations already committed are exempt: the convention "applies only to
# migrations written after it" (PMS-1117's own stated cost), and migrations are
# immutable, so 139/152/203/204 cannot be retrofitted. `CUTOFF_PREFIX` is
# migration 209, the last migration that predates this check.

const CUTOFF_PREFIX = 209

# Free-text columns known to hold guardable seeded content. Extend this list
# (not the regex shape) when a guarded content UPDATE against a new column
# shows up; `notification_templates.subject` / `body_text` / `body_html` are
# the incident that motivated this check, `name` / `description` cover the
# same pattern on other seeded rows.
const CONTENT_COLUMNS = [subject body_text body_html name description]

def main [] {
    let files = (
        glob migrations/*.sql
        | where {|f|
            let prefix = ($f | path basename | parse --regex '^(?<n>\d+)_' | get -o 0.n)
            ($prefix != null) and (($prefix | into int) > $CUTOFF_PREFIX)
        }
    )

    let violations = (
        $files
        | each {|f|
            let text = (open --raw $f | decode utf-8)
            let has_update = ($text | str contains "UPDATE")
            if not $has_update {
                null
            } else {
                let guarded = (
                    $CONTENT_COLUMNS
                    | any {|col| $text =~ $"AND\\s+($col)\\s*\(=|LIKE\)\\s*'" }
                )
                if $guarded and (not ($text | str contains "GET DIAGNOSTICS")) {
                    {file: $f, reason: "WHERE clause guards on a content-column literal with no GET DIAGNOSTICS assertion"}
                } else {
                    null
                }
            }
        }
        | compact
    )

    if ($violations | is-empty) {
        print $"guarded-content-migration OK: ($files | length) migration\(s\) checked above prefix ($CUTOFF_PREFIX)"
    } else {
        print --stderr "ERROR: guarded content UPDATE(s) with no zero-row assertion (PMS-1117)."
        print --stderr "A WHERE clause that matches an UPDATE's SET against previous content is"
        print --stderr "how a guarded content migration avoids clobbering a customised row - and"
        print --stderr "how it silently no-ops when a prior migration already rewrote that text."
        print --stderr "Wrap the UPDATE in a DO block, capture GET DIAGNOSTICS matched = ROW_COUNT,"
        print --stderr "and call mokosh_assert_content_rows_matched(matched, expected, context) (see"
        print --stderr "migration 208) so a zero-row match fails the migration instead of shipping."
        print --stderr ($violations | table)
        exit 1
    }
}
