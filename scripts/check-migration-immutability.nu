#!/usr/bin/env nu

# Enforce migration immutability (DEV-395).
#
# sqlx records a SHA-384 checksum of each migration file in `_sqlx_migrations`
# when it applies it, then re-verifies on every startup that the file on disk
# still matches. Editing a migration that has already been applied to ANY
# database (dev, staging, prod) makes that database refuse to start:
# `migration N was previously applied but has been modified`. The only safe way
# to change schema or seed data is to add a NEW migration.
#
# This gate fails a PR that modifies, renames, or deletes a migration file that
# already exists on `main`, before it can merge and break a deployed database.
# (This is exactly how mokosh-server v0.4.0 broke nc-01: 023_seed_data.sql was
# edited after a build had already applied the earlier version.)
#
# Adding a brand-new migration file is always allowed.
#
# Requires origin/main to be present with history: the workflow checks out with
# `fetch-depth: 0`. Run from the repo root.

def main [] {
    let base = "origin/main"

    # `A...HEAD` diffs the merge-base of A and HEAD against HEAD, so only this
    # branch's own changes count (being behind main does not trip it).
    # --diff-filter=MRD = Modified / Renamed / Deleted relative to that
    # merge-base, i.e. files that already existed on main. Added (A) files are
    # excluded: new migrations are fine.
    let diff = (
        do { ^git diff --diff-filter=MRD --name-only $"($base)...HEAD" -- migrations/ }
        | complete
    )

    if $diff.exit_code != 0 {
        # Fail loud rather than silently passing: an empty result from a broken
        # diff must NOT read as "no migrations changed".
        print --stderr $"ERROR: could not diff migrations against ($base) \(git exit ($diff.exit_code))."
        print --stderr "Is origin/main fetched with history? CI checks out with fetch-depth: 0."
        print --stderr ($diff.stderr | str trim)
        exit 2
    }

    let changed = ($diff.stdout | lines | where ($it | str trim | is-not-empty))

    if ($changed | is-empty) {
        print "migration immutability OK: no committed migration was modified, renamed, or deleted"
        return
    }

    print --stderr "ERROR: a migration already committed on main was modified, renamed, or deleted:"
    for f in $changed { print --stderr $"  ($f)" }
    print --stderr ""
    print --stderr "Migrations are immutable once applied: sqlx verifies each file's checksum on"
    print --stderr "startup, so editing an applied migration makes every deployed database refuse"
    print --stderr "to boot. Revert the file(s) above and add a NEW migrations/NNN_*.sql instead."
    exit 1
}
