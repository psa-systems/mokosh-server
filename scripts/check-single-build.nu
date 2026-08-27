#!/usr/bin/env nu

# Single-build guard for .forgejo/workflows (DEV-612).
#
# Invariant: a commit travelling from pull request to main is compiled once, by
# a job that gates the merge. A workflow that compiles must therefore declare
# `pull_request` on main (the gate) and must NOT also declare `push` on main: a
# merge commit carries the same tree as the head it merges, so the push run
# recompiles what the pull-request run just compiled. Before this gate that cost
# 189s (check.yml) + 440s (integration.yml) of runner time on every merge.
#
# "Compiles" is read from the step bodies rather than from a hand-kept list, so
# a new workflow is classified by what it runs. e2e.yml declares both triggers
# and is correct: it compiles nothing, and its two runs do different work (a
# deploy-sync poll after the merge, a reachability check on the pull request).
#
# Comment lines are excluded: this file's own rationale names the patterns.

const COMPILE_PATTERNS = [
    "cargo build"
    "cargo check"
    "cargo clippy"
    "cargo test"
    "docker buildx build"
]

def branches-for [on: record, event: string] {
    let ev = ($on | get --optional $event)
    if $ev == null { return [] }
    let b = ($ev | get --optional branches)
    if $b == null { [] } else { $b }
}

def classify-workflow [file: string] {
    let body = (
        open --raw $file
        | decode utf-8
        | lines
        | where {|l| not (($l | str trim) | str starts-with "#") }
        | str join "\n"
    )
    let compiles = ($COMPILE_PATTERNS | any {|p| $body | str contains $p })
    let on = (open $file | get on)
    let push_main = ("main" in (branches-for $on "push"))
    let pr_main = ("main" in (branches-for $on "pull_request"))

    let verdict = if not $compiles {
        "n/a (compiles nothing)"
    } else if $push_main and $pr_main {
        "VIOLATING (builds the same tree twice)"
    } else if $pr_main {
        "compliant (gates the merge, builds once)"
    } else {
        "compliant (single trigger)"
    }

    {
        workflow: ($file | path basename),
        compiles: $compiles,
        push_main: $push_main,
        pull_request_main: $pr_main,
        verdict: $verdict,
    }
}

def main [] {
    let files = (glob .forgejo/workflows/*.yml | sort)
    if ($files | is-empty) {
        print --stderr "ERROR: no workflow found under .forgejo/workflows/"
        exit 1
    }

    let rows = ($files | each {|f| classify-workflow $f })
    mut errors = []

    for row in ($rows | where verdict =~ "VIOLATING") {
        $errors = ($errors | append $"($row.workflow): compiles and declares both `push: main` and `pull_request: main`, so every merge rebuilds the tree the pull-request run already built")
    }

    # The merge gate itself must survive: dropping `push: main` is only safe
    # while a compiling workflow still runs on pull requests into main.
    let gates = ($rows | where {|r| $r.compiles and $r.pull_request_main })
    if ($gates | is-empty) {
        $errors = ($errors | append "no compiling workflow runs on `pull_request` into main, so nothing stops an unbuildable commit from merging")
    }

    print ($rows | table --width 120)

    if ($errors | is-empty) {
        print $"Single build OK: ($gates | length) compiling workflow\(s) gate the merge, none build twice"
    } else {
        print --stderr "ERROR: single-build rule violated (DEV-612)."
        print --stderr "A compiling workflow gates the merge on `pull_request` into main and never repeats that build on `push: main`."
        for e in $errors { print --stderr $"  ($e)" }
        exit 1
    }
}
