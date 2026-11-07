#!/usr/bin/env nu
# CLAUDE-560: classify a git diff between two refs as one of:
#   `code`          - at least one `+`/`-` line in a code file is not a comment
#                     or whitespace. The full compile + test gate must run.
#   `comments-only` - at least one code file changed, but every `+`/`-` line
#                     in every code file is a comment or whitespace. The
#                     expensive jobs (fmt, clippy, build, tests) can be
#                     skipped; the CLAUDE.md guard and secrets scan still run.
#   `non-code`      - no code file changed at all (docs-only, config-only,
#                     etc.). Today's docs-only short-circuit still applies.
#
# A code file is one whose path ends with one of the extensions listed in
# $c_family_exts or $hash_family_exts below. Any other file is ignored by
# this classifier and the existing path-based filters handle it.
#
# Usage:
#   nu scripts/classify-diff.nu <base-ref> <head-ref>
#   nu scripts/classify-diff.nu --self-test
#
# Prints exactly one of `code`, `comments-only`, `non-code` on stdout and
# exits 0. On a git error or an invalid ref, prints `code` (the conservative
# answer) and exits 0, so the workflow never skips a gate because of a
# classifier failure.

# C-family comment syntax: `//` or `/* ... */`, plus `--` for SQL. The
# `*` and `*/` prefixes cover block-comment continuation lines that
# follow the conventional `/* ... \n * ... \n */` layout.
const C_FAMILY_EXTS = [
    ".rs" ".ts" ".tsx" ".js" ".jsx" ".mjs" ".cjs"
    ".css" ".scss" ".sql"
    ".c" ".cpp" ".cc" ".h" ".hpp"
    ".java" ".go" ".kt"
]

# Hash-comment syntax only: `#`. No block comments.
const HASH_FAMILY_EXTS = [
    ".nu" ".py" ".sh" ".bash" ".zsh"
    ".yml" ".yaml" ".toml"
    ".just" ".justfile" "Dockerfile"
]

# SPEC-10.312: code-file extension lists

# Return "c", "hash", or "non-code" for a given path.
def file_family [path: string] {
    for ext in $C_FAMILY_EXTS {
        if ($path | str ends-with $ext) { return "c" }
    }
    for ext in $HASH_FAMILY_EXTS {
        if ($path | str ends-with $ext) { return "hash" }
    }
    # Dockerfile may appear without extension.
    let basename = ($path | path basename)
    if $basename == "Dockerfile" or ($basename | str starts-with "Dockerfile.") {
        return "hash"
    }
    return "non-code"
}

# SPEC-10.313: comment and whitespace rule

# True when `content` (one changed line, minus its leading +/- marker) is
# a comment or whitespace in a file of the given `family` ("c" or "hash").
def is_comment_line [content: string, family: string] {
    let trimmed = ($content | str trim)
    if ($trimmed | is-empty) { return true }
    if $family == "hash" {
        return ($trimmed | str starts-with "#")
    }
    # C-family: `//`, `/*`, `*/`, `*` continuation, `--` SQL.
    if ($trimmed | str starts-with "//") { return true }
    if ($trimmed | str starts-with "/*") { return true }
    if ($trimmed | str starts-with "*/") { return true }
    if ($trimmed | str starts-with "*") { return true }
    if ($trimmed | str starts-with "--") { return true }
    return false
}

# Classify the diff of a single path. Returns "code", "comments-only", or
# "no-change" (the file was touched via rename/mode only, with no content
# changes). Called from `classify_diff` below.
def classify_file [base: string, head: string, path: string, family: string] {
    let diff = (^git diff --unified=0 $base $head -- $path | lines)
    mut saw_change = false
    for line in $diff {
        # Metadata and hunk headers are not `+`/`-` content lines.
        if ($line | str starts-with "+++") { continue }
        if ($line | str starts-with "---") { continue }
        if ($line | str starts-with "@@") { continue }
        if not (($line | str starts-with "+") or ($line | str starts-with "-")) { continue }
        $saw_change = true
        let content = ($line | str substring 1..)
        if not (is_comment_line $content $family) {
            return "code"
        }
    }
    if $saw_change { "comments-only" } else { "no-change" }
}

# SPEC-10.311 SPEC-10.314: git error falls back to code

# Classify the whole diff between $base and $head.
def classify_diff [base: string, head: string] {
    let changed_paths = (
        do { ^git diff --name-only $base $head } | complete
    )
    if $changed_paths.exit_code != 0 {
        # Any git error (invalid ref, no merge-base, ...) falls back to
        # "code" so the gate still runs. Stderr is printed as a side
        # effect of `complete` so a CI log reader can see the cause.
        print --stderr $changed_paths.stderr
        return "code"
    }
    let paths = (
        $changed_paths.stdout | lines
        | each {|l| $l | str trim}
        | where {|l| not ($l | is-empty)}
    )
    mut saw_code_file = false
    for path in $paths {
        let family = (file_family $path)
        if $family == "non-code" { continue }
        $saw_code_file = true
        let verdict = (classify_file $base $head $path $family)
        if $verdict == "code" { return "code" }
    }
    if $saw_code_file { "comments-only" } else { "non-code" }
}

# SPEC-10.315: six-case self-test

# Self-test: build a fresh tempdir with a tiny git repo, make a comment-only
# change, a code change, a docs-only change, and assert the classifier
# returns the expected verdict each time.
def self_test [] {
    let dir = (^mktemp --directory --tmpdir classify-diff-test.XXXXXX | str trim)
    cd $dir
    ^git init --quiet .
    ^git config user.email "test@test"
    ^git config user.name "test"
    "fn main() {\n    // first line\n    let x = 1;\n}\n" | save -f src.rs
    "# original\n" | save -f README.md
    ^git add .
    ^git commit --quiet -m "base"
    let base = (^git rev-parse HEAD | str trim)

    # Case 1: change only a comment -> "comments-only".
    "fn main() {\n    // first line, revised\n    let x = 1;\n}\n" | save -f src.rs
    ^git commit --quiet -am "comment"
    let head1 = (^git rev-parse HEAD | str trim)
    let v1 = (classify_diff $base $head1)
    assert_eq $v1 "comments-only" "C-family comment-only"

    # Case 2: change a code line -> "code".
    "fn main() {\n    // first line, revised\n    let x = 2;\n}\n" | save -f src.rs
    ^git commit --quiet -am "code"
    let head2 = (^git rev-parse HEAD | str trim)
    let v2 = (classify_diff $head1 $head2)
    assert_eq $v2 "code" "C-family code-change"

    # Case 3: change only docs -> "non-code".
    "# revised\n" | save -f README.md
    ^git commit --quiet -am "docs"
    let head3 = (^git rev-parse HEAD | str trim)
    let v3 = (classify_diff $head2 $head3)
    assert_eq $v3 "non-code" "docs-only"

    # Case 4: hash-family (yaml) comment-only.
    "# config\nkey: value\n" | save -f cfg.yml
    ^git add cfg.yml
    ^git commit --quiet -m "add yaml"
    let head4a = (^git rev-parse HEAD | str trim)
    "# config revised\nkey: value\n" | save -f cfg.yml
    ^git commit --quiet -am "yaml comment"
    let head4 = (^git rev-parse HEAD | str trim)
    let v4 = (classify_diff $head4a $head4)
    assert_eq $v4 "comments-only" "hash-family comment-only"

    # Case 5: whitespace-only change in a code file -> "comments-only".
    "fn main() {\n    // first line, revised\n    let x = 2;\n    \n}\n" | save -f src.rs
    ^git commit --quiet -am "whitespace"
    let head5 = (^git rev-parse HEAD | str trim)
    let v5 = (classify_diff $head4 $head5)
    assert_eq $v5 "comments-only" "whitespace-only in code file"

    # Case 6: mixed - one comment, one code line -> "code".
    "fn main() {\n    // revised again\n    let x = 3;\n}\n" | save -f src.rs
    ^git commit --quiet -am "mixed"
    let head6 = (^git rev-parse HEAD | str trim)
    let v6 = (classify_diff $head5 $head6)
    assert_eq $v6 "code" "mixed comment + code change"

    cd ..
    rm -rf $dir
    print "classify-diff.nu self-test passed"
}

def assert_eq [got: string, want: string, label: string] {
    if $got != $want {
        error make {msg: $"self-test '($label)' failed: got '($got)', want '($want)'"}
    }
    print $"ok: ($label) -> ($got)"
}

# SPEC-10.310: CLI contract and exit codes

def main [
    base?: string
    head?: string
    --self-test  # run built-in classifier tests instead of classifying a real diff
] {
    if $self_test { self_test; return }
    if ($base | is-empty) or ($head | is-empty) {
        print --stderr "usage: nu classify-diff.nu <base-ref> <head-ref>  OR  --self-test"
        exit 2
    }
    print (classify_diff $base $head)
}
