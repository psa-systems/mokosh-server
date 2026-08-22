#!/usr/bin/env nu

# Resolvable-path guard for the config files an operator reads (PMS-855).
#
# .env.example, compose.dev.yml and the justfile carried four comments pointing
# at a `docs/mokosh-smtp/` directory that has never existed in this repo at any
# commit. Two of them are in .env.example, which `just ensure-env` mints into
# .env in every clone, so the dead pointer reached every developer who set the
# project up and told an operator configuring mail to go looking for nothing.
#
# Fails when one of these files names a `docs/...` path that is not on disk.
# Markdown link checkers do not cover this: these are bare paths inside comments,
# not links, and nothing else reads them.

# Scoped to the config files an operator follows while setting the stack up.
const FILES = [".env.example" "compose.dev.yml" "justfile"]

# Trailing prose punctuation is not part of the path: `docs/e2e.md).` ends a
# sentence, and no file here ends in one of these.
def strip-trailing [token: string] {
    $token | str replace --regex '[.,;:)\]}"`]+$' ''
}

# Every `docs/...` path a file names, with the line it sits on.
def referenced-paths [file: string] {
    open --raw $file
    | decode utf-8
    | lines
    | enumerate
    | each {|row|
        $row.item
        | parse --regex '(?:^|[^A-Za-z0-9._/-])(?<path>docs/[A-Za-z0-9._/-]+)'
        | each {|m| {file: $file, line: ($row.index + 1), path: (strip-trailing $m.path)} }
    }
    | flatten
    | where {|h| $h.path != "docs/" }
}

def main [] {
    let hits = ($FILES | each {|f| referenced-paths $f } | flatten)
    let missing = ($hits | where {|h| not ($h.path | path exists) })

    if ($missing | is-empty) {
        print $"config doc paths OK: ($hits | length) `docs/` references across ($FILES | length) files, all resolve"
    } else {
        print --stderr "ERROR: a config comment names a `docs/` path that does not exist."
        print --stderr "Repoint it at the real file, or drop the pointer and put the detail inline."
        for m in $missing { print --stderr $"  ($m.file):($m.line): ($m.path) is not on disk" }
        exit 1
    }
}
