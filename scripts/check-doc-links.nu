#!/usr/bin/env nu

# Relative-link resolver for every tracked Markdown file (PMS-850).
#
# The 2026-07-01 docs move relocated docs/dev-docs/ without repointing its
# relative links, leaving 72 `](../...)` targets one directory short of the
# file they name. Three doc audits reported the same set before it was fixed,
# because a broken link fails silently: the reader clicks, lands on nothing,
# and concludes the docs are abandoned.
#
# This resolves a path against the tree, not prose wording: a doc link is a
# cross-reference to a file, and only the filesystem can say whether it still
# exists. Anchors, URLs and mail links resolve outside the tree and are skipped.

# The link target a Markdown link points at, or null when it does not name a
# path in this repository.
def relative-target [target: string] {
    # Same-document anchor, protocol-relative URL, or any scheme (http:, https:,
    # mailto:). None of these name a file in the tree.
    if ($target | str starts-with "#") { return null }
    if ($target | str starts-with "//") { return null }
    if ($target =~ '^[a-zA-Z][a-zA-Z0-9+.-]*:') { return null }

    let path = (
        $target
        | split row "#" | get 0
        | split row "?" | get 0
        | str replace --all "%20" " "
    )
    if ($path | is-empty) { null } else { $path }
}

# Every link target in a file, as {file, line, target}. Fenced blocks and HTML
# comments are skipped: a `](...)` inside either is not a rendered link
# (README.md parks a walkthrough GIF in a comment until the asset lands).
def links-in [file: string] {
    mut hits = []
    mut fenced = false
    mut commented = false

    for row in (open --raw $file | decode utf-8 | lines | enumerate) {
        if (($row.item | str trim) | str starts-with "```") {
            $fenced = (not $fenced)
            continue
        }
        if $fenced { continue }

        if $commented {
            if ($row.item | str contains "-->") { $commented = false }
            continue
        }
        if ($row.item | str contains "<!--") and (not ($row.item | str contains "-->")) {
            $commented = true
            continue
        }

        # All three shapes a target can arrive in: an inline link or image
        # `](target)`, a reference definition `[label]: target`, and a raw HTML
        # `href=`/`src=`. The repo uses only the first today; covering the other
        # two keeps a later one from slipping past the guard unnoticed.
        let targets = (
            [
                ($row.item | parse --regex '\]\((?<target>[^)\s]+)')
                ($row.item | parse --regex '^\[[^\]]+\]:\s+(?<target>\S+)')
                ($row.item | parse --regex '(?:href|src)="(?<target>[^"]*)"')
            ]
            | flatten
            | get target
        )

        for t in $targets {
            $hits = ($hits | append {file: $file, line: ($row.index + 1), target: $t})
        }
    }

    $hits
}

# Where a target resolves from the file that carries it. A leading `/` is
# repository-root-relative; everything else is relative to the file's directory.
def resolve [file: string, path: string] {
    if ($path | str starts-with "/") {
        $path | str substring 1..
    } else {
        [($file | path dirname) $path] | path join
    }
}

def main [] {
    let docs = (^git ls-files "*.md" | lines | where {|f| $f != "" })
    if ($docs | is-empty) {
        print --stderr "ERROR: no tracked Markdown files found"
        exit 1
    }

    let checked = (
        $docs
        | each {|f| links-in $f }
        | flatten
        | each {|h|
            let path = (relative-target $h.target)
            if $path == null { null } else { $h | insert resolved (resolve $h.file $path) }
        }
        | compact
    )

    let broken = ($checked | where {|h| not ($h.resolved | path exists) })

    if ($broken | is-empty) {
        print $"doc links OK: ($checked | length) relative links across ($docs | length) Markdown files all resolve"
    } else {
        print --stderr "ERROR: a Markdown link points at a path that does not exist."
        print --stderr "Repoint it at the file's current location, or drop the link."
        for b in $broken { print --stderr $"  ($b.file):($b.line): ($b.target) -> ($b.resolved)" }
        exit 1
    }
}
