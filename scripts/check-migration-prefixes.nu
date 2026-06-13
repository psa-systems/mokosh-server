#!/usr/bin/env nu

# Enforce unique migration prefixes (PMS-198).
#
# sqlx applies migrations in numeric-prefix order and keys the
# `_sqlx_migrations` ledger on that prefix. Two files that share a prefix
# (e.g. PMS-106 and PMS-4 both picking `027` on separate branches) collide:
# one shadows the other and the recorded version becomes ambiguous. There is
# no branch-level guard, so the clash only surfaces after both branches land.
# This check fails loud at review time instead.
#
# Exit 0 when every prefix is unique, 1 (with the offending prefixes) when not.

def main [] {
    let prefixes = (
        glob migrations/*.sql
        | each {|f| $f | path basename }
        | parse --regex '^(?<prefix>\d+)_'
        | get prefix
    )

    let dups = ($prefixes | uniq --count | where count > 1)

    if ($dups | is-empty) {
        print $"migration prefixes OK: ($prefixes | length) files, all prefixes unique"
    } else {
        print --stderr "ERROR: duplicate migration prefixes detected (each prefix must be unique):"
        print --stderr ($dups | table)
        exit 1
    }
}
