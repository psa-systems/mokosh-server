#!/usr/bin/env nu

# Documented-recipe guard for the entry-point docs (PMS-843).
#
# These are the first commands a newcomer types, and they drifted from the
# justfile: several sites invoked a `dev-down` recipe for a stop step that has
# always been named `down`, so every documented restart failed at its first
# instruction with a `just` error naming no alternative.
#
# Fails when a doc names a recipe the justfile does not define (or defines as
# `[private]`, which keeps it out of `just --list`). This checks a name against
# the justfile, not prose wording: a rename that leaves a doc behind is a broken
# command, and only the cross-reference can catch it.

# The entry points plus every page that tells a reader to run a recipe. A page
# that gains a `just <recipe>` span belongs here, or its commands leave the
# guard silently: this fails on a doc naming a missing recipe, never on a doc
# leaving its scope (PMS-995 moved the README's commands onto four new pages).
# Not every doc: some legitimately name recipes from another repo
# (`just e2e-bootstrap` in the docker repo, docs/e2e.md).
const DOCS = [
    "README.md"
    "docs/README.md"
    "docs/quickstart.md"
    "docs/architecture.md"
    "docs/binaries.md"
    "docs/configuration.md"
    "docs/recipes.md"
]

const JUSTFILE = "justfile"

# Recipe names `just --list` prints: every non-private recipe header. A header
# is `name[ params][: deps]` at column 0; `:=` is a variable assignment.
def justfile-recipes [] {
    let lines = (open --raw $JUSTFILE | decode utf-8 | lines)

    $lines
    | enumerate
    | each {|row|
        if ($row.item | str contains ":=") { return null }
        let parsed = ($row.item | parse --regex '^(?<name>[a-z][a-z0-9_-]*)(?<params>[^:]*):')
        if ($parsed | is-empty) { return null }

        # An attribute sits directly above its recipe, after any doc comment.
        let private = (
            $lines
            | first $row.index
            | reverse
            | take while {|l| ($l | str starts-with "[") or ($l | str starts-with "#") }
            | any {|l| $l == "[private]" }
        )
        if $private { null } else { $parsed | get name.0 }
    }
    | compact
    | uniq
}

# The recipe a `just ...` invocation names. Null when the line invokes no
# recipe (a bare `just --list`, or a placeholder that is not a recipe name).
def invoked-recipe [command: string] {
    let rest = ($command | str replace --regex '^just\b' '' | str trim)
    let first = ($rest | split row --regex '\s+' | where {|t| $t != "" } | get --optional 0)

    # `just` on its own, or with only a trailing comment, runs `default`.
    if ($first == null) or ($first | str starts-with "#") { return "default" }
    if ($first | str starts-with "-") { return null }
    if ($first =~ '^[a-z][a-z0-9-]*$') { $first } else { null }
}

# Every `just <recipe>` a doc tells the reader to run: a command line inside a
# fenced block, or an inline code span that is itself a `just` command.
def documented-recipes [file: string] {
    mut hits = []
    mut fenced = false

    for row in (open --raw $file | decode utf-8 | lines | enumerate) {
        let line = ($row.item | str trim)

        if ($line | str starts-with "```") {
            $fenced = (not $fenced)
            continue
        }

        let commands = if $fenced {
            [$line]
        } else {
            # Odd-indexed pieces of a backtick split are the inline code spans.
            $line | split row "`" | enumerate | where {|p| $p.index mod 2 == 1 } | get item
        }

        for command in $commands {
            if not (($command == "just") or ($command | str starts-with "just ")) { continue }
            let recipe = (invoked-recipe $command)
            if $recipe != null {
                $hits = ($hits | append {file: $file, line: ($row.index + 1), recipe: $recipe})
            }
        }
    }

    $hits
}

def main [] {
    let recipes = (justfile-recipes)
    if ($recipes | is-empty) {
        print --stderr $"ERROR: no recipes parsed out of ($JUSTFILE)"
        exit 1
    }

    let hits = ($DOCS | each {|d| documented-recipes $d } | flatten)
    let missing = ($hits | where {|h| $h.recipe not-in $recipes })

    if ($missing | is-empty) {
        print $"doc recipes OK: ($hits | length) `just` invocations across ($DOCS | length) docs, all defined in ($JUSTFILE)"
    } else {
        print --stderr "ERROR: a doc names a `just` recipe that does not exist."
        print --stderr $"Run `just --list` and use a real recipe name, or add the recipe to ($JUSTFILE)."
        for m in $missing { print --stderr $"  ($m.file):($m.line): `just ($m.recipe)` is not a recipe" }
        exit 1
    }
}
