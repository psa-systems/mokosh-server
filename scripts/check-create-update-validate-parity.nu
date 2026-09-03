#!/usr/bin/env nu

# PMS-867: a value must be accepted or refused identically whether it arrives on
# a create or on an update.
#
# `CreateXRequest` and `UpdateXRequest` describe the same row from two
# directions, so a `#[validate(...)]` on one side and nothing on the other is
# not a style difference, it is two different contracts for one column. Two
# distinct things go wrong, and neither is visible from the update struct alone:
#
#   - Over a `max`, the column rejects the value itself, so the update path
#     answers 500 with a raw Postgres `22001 value too long for type character
#     varying(n)` where create answers a 422 naming the field. That is the shape
#     PMS-841 reproduced for `forms.contact_info`.
#   - Under a `min`, nothing rejects anything: `""` satisfies a `NOT NULL`
#     column, so the update path stores a nameless contract or a titleless
#     article where create refuses the same string.
#
# `Upsert` counts as a create: `UpsertRmmAlertRuleRequest` is the create side of
# `UpdateRmmAlertRuleRequest`.
#
# This reads Rust source rather than prose, so `check-doc-links` does not cover
# it. It compares attribute TEXT, not semantics: it cannot tell you whether a
# cap is the right number, only that the two sides disagree about it.

# Where request DTOs are declared. `crates/` is in scope because PMS-897 and
# PMS-898 started moving wire types there, and a pair that moves must not fall
# out of the sweep on the way.
const DTO_GLOBS = ['src/**/*.rs' 'crates/*/src/**/*.rs']

# A same-named field whose two sides differ on purpose. One row per asymmetry,
# each carrying the reason, so a deliberate difference is stated rather than
# indistinguishable from an oversight.
#
# `pair` is the `X` of `CreateXRequest` / `UpdateXRequest`.
const ALLOWED = [
    # (empty: every pair currently agrees)
]

# Split a Rust source file into the struct bodies we care about.
#
# Brace depth rather than a regex for the closing line: a field can carry a
# `#[validate(custom(function = ...))]` whose parentheses nest, and a doc
# comment can contain a brace.
def struct-bodies [source: string] {
    mut bodies = []
    mut current_name = null
    mut current_lines = []
    mut depth = 0

    for line in ($source | lines) {
        if $current_name == null {
            let m = ($line | parse --regex '^pub struct (?<name>(?:Create|Update|Upsert)\w*Request)\s*\{')
            if not ($m | is-empty) {
                $current_name = ($m | first | get name)
                $depth = 1
            }
            continue
        }

        # Track depth BEFORE deciding the struct ended, so a field whose
        # attribute opens a brace does not close the struct early.
        let opens = ($line | split chars | where {|c| $c == '{' } | length)
        let closes = ($line | split chars | where {|c| $c == '}' } | length)
        $depth = $depth + $opens - $closes

        if $depth <= 0 {
            $bodies = ($bodies | append {name: $current_name, lines: $current_lines})
            $current_name = null
            $current_lines = []
        } else {
            $current_lines = ($current_lines | append $line)
        }
    }

    $bodies
}

# The `#[validate(...)]` attributes attached to each field of a struct body,
# keyed by field name. Attributes accumulate until a field line consumes them,
# which is what makes a multi-attribute field (a `length` and a `custom` on the
# same field) compare as the set it is.
def field-validators [lines: list<string>] {
    mut pending = []
    mut fields = {}

    for line in $lines {
        let trimmed = ($line | str trim)

        let attr = ($trimmed | parse --regex '^#\[validate\((?<body>.*)\)\]$')
        if not ($attr | is-empty) {
            $pending = ($pending | append ($attr | first | get body))
            continue
        }

        let field = ($trimmed | parse --regex '^pub (?<name>\w+):')
        if not ($field | is-empty) {
            let name = ($field | first | get name)
            $fields = ($fields | upsert $name ($pending | sort))
            $pending = []
        }
    }

    $fields
}

# `Option<String>` on the update side and `String` on the create side is the
# expected shape, not a difference, so the comparison is on attributes only.
def compare-pair [pair: string, create: record, update: record] {
    let create_fields = (field-validators $create.lines)
    let update_fields = (field-validators $update.lines)

    $create_fields
    | columns
    | where {|name| $name in ($update_fields | columns) }
    | each {|name|
        let on_create = ($create_fields | get $name)
        let on_update = ($update_fields | get $name)
        if $on_create == $on_update {
            null
        } else {
            {
                pair: $pair,
                field: $name,
                create: (if ($on_create | is-empty) { 'none' } else { $on_create | str join ' + ' }),
                update: (if ($on_update | is-empty) { 'none' } else { $on_update | str join ' + ' }),
            }
        }
    }
    | compact
}

def main [] {
    let files = ($DTO_GLOBS | each {|g| glob $g } | flatten | uniq)

    let structs = (
        $files
        | each {|f| struct-bodies (open --raw $f | decode utf-8) }
        | flatten
    )

    # `Upsert` is a create. Keyed by the `X` in the middle so the two sides meet.
    let creates = (
        $structs
        | where {|s| ($s.name | str starts-with 'Create') or ($s.name | str starts-with 'Upsert') }
        | reduce --fold {} {|s, acc|
            let key = ($s.name | str replace --regex '^(Create|Upsert)' '' | str replace --regex 'Request$' '')
            $acc | upsert $key $s
        }
    )

    let updates = (
        $structs
        | where {|s| $s.name | str starts-with 'Update' }
        | reduce --fold {} {|s, acc|
            let key = ($s.name | str replace --regex '^Update' '' | str replace --regex 'Request$' '')
            $acc | upsert $key $s
        }
    )

    let paired = ($updates | columns | where {|k| $k in ($creates | columns) })

    let differences = (
        $paired
        | each {|pair| compare-pair $pair ($creates | get $pair) ($updates | get $pair) }
        | flatten
    )

    let allowed_keys = ($ALLOWED | each {|a| $'($a.pair).($a.field)' })
    let violations = (
        $differences
        | where {|d| $'($d.pair).($d.field)' not-in $allowed_keys }
    )

    # An allowlist row for a pair that now agrees is stale: it states a reason
    # for a difference that is no longer there, which is worse than no row.
    let difference_keys = ($differences | each {|d| $'($d.pair).($d.field)' })
    let stale = ($ALLOWED | where {|a| $'($a.pair).($a.field)' not-in $difference_keys })

    if ($violations | is-empty) and ($stale | is-empty) {
        print $"create/update validate parity OK: ($paired | length) pairs, every same-named field validates identically"
        return
    }

    print --stderr $"ERROR: a Create*Request and its Update*Request disagree about a field \(PMS-867\). ($paired | length) pairs checked."
    print --stderr "Copy the create-side #[validate(...)] onto the update field, or add an ALLOWED row"
    print --stderr "in this script stating why the two sides differ on purpose."

    # One line per violation rather than a `table`: the attribute column is wide
    # and a CI terminal elides it into `...` exactly where the detail matters.
    for v in $violations {
        print --stderr $"  ($v.pair).($v.field): create has [($v.create)], update has [($v.update)]"
    }
    for s in $stale {
        print --stderr $"  ($s.pair).($s.field): ALLOWED row is stale, the two sides now agree - delete it"
    }
    exit 1
}
