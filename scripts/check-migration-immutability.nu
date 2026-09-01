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

# PMS-965: the one shape of change this gate has to permit.
#
# A duplicate version number cannot be resolved without touching a file that is
# already on main: `_sqlx_migrations` is keyed on the version, so two files
# numbered the same make every database fail to finish migrating, and one of
# them has to move. The rename is safe for exactly one reason, and the entry
# below has to state it: the file being moved has never been applied to any
# database, so there is no recorded checksum for the rename to invalidate.
#
# That is checkable rather than asserted. A file that always loses a version
# collision never applies anywhere (sqlx aborts on the duplicate key before
# reaching it), and `BRANCH_ALLOW_LIST` in oci-build/get-tags.nu decides whether
# its branch ever reached a deployed database at all.
#
# An entry is removable once the rename is on main, because from then on the
# file no longer differs from the base. Leaving one costs nothing; adding one
# without the reason defeats the gate.
const RENAME_ALLOWED = [
    # PMS-965: PMS-911 (#628) and PMS-875 both landed a migration numbered 127.
    # `127_invoice_issuer_snapshot.sql` sorts first, so it is the one that
    # applies and the one whose checksum every half-migrated database now
    # records; this file is the one that always failed, on every database, and
    # its branch never published an image (BRANCH_ALLOW_LIST holds only
    # `mokosh-client-login`), so no checksum for it exists anywhere. Renumbered
    # to 130.
    #
    # Named by its DESTINATION, because `git diff --name-only` reports a rename
    # by where the file ended up rather than where it came from.
    "migrations/130_system_shared_policy_on_optin.sql",
]

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

    let all_changed = ($diff.stdout | lines | where ($it | str trim | is-not-empty))
    let changed = ($all_changed | where ($it not-in $RENAME_ALLOWED))
    let exempt = ($all_changed | where ($it in $RENAME_ALLOWED))

    for f in $exempt {
        print $"migration immutability: ($f) is on the PMS-965 rename allow-list \(never applied anywhere)"
    }

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
