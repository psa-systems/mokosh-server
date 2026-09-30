#!/usr/bin/env nu

# Keep CLAUDE.md an index, not an essay collection (PMS-1437).
#
# CLAUDE.md is loaded into every agent session. It had grown to 138 KB because
# each convention landed as a multi-paragraph bullet; PMS-1437 moved the full
# text under docs/ and left one line per rule. This guard stops the regrowth:
# a size budget, a line-length cap (fenced code exempt), and every docs/ link
# and anchor CLAUDE.md points at must resolve, so the index cannot rot.
#
#   nu scripts/check-claude-md.nu               # check the repo's CLAUDE.md
#   nu scripts/check-claude-md.nu --self-test   # prove each rule fires, on fixtures

const MAX_BYTES = 20000
const MAX_LINE = 400

# Lines outside fenced code blocks, as {line, text}.
def prose-lines [text: string] {
    mut out = []
    mut fenced = false
    for row in ($text | lines | enumerate) {
        if ($row.item | str trim | str starts-with "```") {
            $fenced = (not $fenced)
            continue
        }
        if not $fenced { $out = ($out | append {line: ($row.index + 1), text: $row.item}) }
    }
    $out
}

# GitHub/Forgejo heading anchor: lowercase, drop punctuation, spaces to hyphens.
def slug [heading: string] {
    $heading
    | str trim
    | str downcase
    | str replace --all --regex '[^\w\- ]' ''
    | str replace --all ' ' '-'
}

# Every heading anchor a Markdown file defines.
def anchors-in [text: string] {
    prose-lines $text
    | where {|r| $r.text =~ '^#{1,6} ' }
    | each {|r| slug ($r.text | str replace --regex '^#{1,6} ' '' | str replace --regex '\s+#+\s*$' '') }
}

def size-errors [text: string] {
    let bytes = ($text | encode utf-8 | bytes length)
    if $bytes > $MAX_BYTES {
        [$"CLAUDE.md is ($bytes) bytes, over the ($MAX_BYTES)-byte budget: move the detail under docs/ and keep one index line here"]
    } else { [] }
}

def line-errors [text: string] {
    prose-lines $text
    | where {|r| ($r.text | str length) > $MAX_LINE }
    | each {|r| $"CLAUDE.md:($r.line): ($r.text | str length) characters, over ($MAX_LINE): move the essay under docs/" }
}

# Every `](docs/...)` link in CLAUDE.md must name a file under root, and its
# anchor, when present, a heading in that file.
def link-errors [text: string, root: string] {
    prose-lines $text
    | each {|r|
        $r.text
        | parse --regex '\]\((?<target>docs/[^)\s]+)\)'
        | get target
        | each {|t| {line: $r.line, target: $t} }
    }
    | flatten
    | each {|l|
        let parts = ($l.target | split row "#")
        let file = ($root | path join ($parts | first))
        if not ($file | path exists) {
            $"CLAUDE.md:($l.line): ($l.target) names a file that does not exist"
        } else if ($parts | length) > 1 and not (($parts | get 1) in (anchors-in (open --raw $file | decode utf-8))) {
            $"CLAUDE.md:($l.line): ($l.target) names an anchor with no matching heading"
        } else { null }
    }
    | compact
}

def errors-for [text: string, root: string] {
    (size-errors $text) | append (line-errors $text) | append (link-errors $text $root)
}

def self-test [] {
    let root = (mktemp --directory)
    mkdir ($root | path join "docs/invariants")
    "# Billing\n\n## Invoice tax (PMS-1029)\n\nText.\n" | save ($root | path join "docs/invariants/billing.md")

    let good = "# CLAUDE.md\n\n- Tax ([PMS-1029](docs/invariants/billing.md#invoice-tax-pms-1029))\n"
    let cases = [
        [name, text, expect];
        ["a clean index passes", $good, 0]
        ["an oversized file fails", ($good + ("x" | fill --character "y" --width 20001)), 2]
        ["a long prose line fails", ("# C\n\n" + ("a" | fill --character "a" --width 401) + "\n"), 1]
        ["a long line inside a fence is exempt", ("```\n" + ("a" | fill --character "a" --width 401) + "\n```\n"), 0]
        ["a missing docs file fails", "- x ([A](docs/invariants/nope.md))\n", 1]
        ["a missing anchor fails", "- x ([A](docs/invariants/billing.md#no-such-heading))\n", 1]
    ]

    mut failed = 0
    for c in $cases {
        let n = (errors-for $c.text $root | length)
        if $n == $c.expect {
            print $"self-test: ($c.name)"
        } else {
            print --stderr $"self-test: FAIL \(($c.name): expected ($c.expect) errors, got ($n))"
            $failed += 1
        }
    }
    rm --recursive $root

    if $failed > 0 { exit 1 }
    print 'check-claude-md self-test: clean'
}

def main [
    --self-test   # run against fixtures instead of the repo's CLAUDE.md
] {
    if $self_test {
        self-test
        return
    }

    let text = (open --raw CLAUDE.md | decode utf-8)
    let errors = (errors-for $text ".")
    if ($errors | is-empty) {
        let bytes = ($text | encode utf-8 | bytes length)
        print $"CLAUDE.md OK: ($bytes) of ($MAX_BYTES) bytes, no prose line over ($MAX_LINE) characters, every docs/ link and anchor resolves"
    } else {
        print --stderr "ERROR: CLAUDE.md is an index; its detail lives under docs/ (PMS-1437)."
        for e in $errors { print --stderr $"  ($e)" }
        exit 1
    }
}
