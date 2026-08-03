#!/usr/bin/env nu

# PMS-692: every request-serving `.pool()` call reaches the unprivileged
# `mokosh_app` (NOBYPASSRLS) pool, which fail-closes RLS-covered reads/writes to
# zero rows when no `app.current_tenant` GUC is set. A serving query against an
# RLS-covered table must instead go through `Database::begin_with_tenant`.
#
# A bare `.pool()` call is legitimate ONLY on an RLS-exempt table (`tenants`, the
# isolation root, migration 038) or a pre-auth / cross-tenant path, and must
# carry an adjacent `// SAFETY (PMS-285` note saying why. This gate fails a PR
# that adds a bare `.pool()` serving call without that note - mirroring how
# check-migration-immutability.nu is wired into check.yml.
#
# `migrator_pool()` is the sanctioned BYPASSRLS accessor and is exempt. The
# `Database` accessors themselves are defined in src/db/pool.rs and are skipped.

const LOOKBACK = 8

def main [] {
    let files = (glob src/**/*.rs | where {|f| not ($f | str contains 'src/db/pool.rs') })
    let violations = (
        $files
        | each {|f|
            let lines = (open --raw $f | decode utf-8 | lines)
            $lines
            | enumerate
            | each {|row|
                let text = $row.item
                let trimmed = ($text | str trim)
                let is_call = (($text | str contains '.pool()') and (not ($text | str contains 'migrator_pool')))
                let is_comment = ($trimmed | str starts-with '//')
                if ($is_call and (not $is_comment)) {
                    let start = ([0, ($row.index - $LOOKBACK)] | math max)
                    let window = ($lines | slice $start..<$row.index)
                    let safe = ($window | any {|l| $l | str contains 'SAFETY (PMS-285' })
                    if $safe { null } else { {file: $f, line: ($row.index + 1), code: $trimmed} }
                } else {
                    null
                }
            }
            | compact
        }
        | flatten
    )

    if ($violations | is-empty) {
        print "pool-safety OK: every serving .pool() call carries an adjacent // SAFETY (PMS-285 note"
    } else {
        print --stderr "ERROR: bare .pool() serving call(s) without a // SAFETY (PMS-285 note (PMS-692)."
        print --stderr "Serving queries against RLS-covered tables must run through begin_with_tenant;"
        print --stderr "a .pool() call is legitimate only on an RLS-exempt table (tenants) or a pre-auth"
        print --stderr "path. Add a `// SAFETY (PMS-285): <why>` note right above it, or use migrator_pool()."
        print --stderr ($violations | table)
        exit 1
    }
}
