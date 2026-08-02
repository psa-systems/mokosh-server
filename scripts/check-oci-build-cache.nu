#!/usr/bin/env nu

# OCI build-cache guard for .forgejo/workflows (PMS-720, GOV-20).
#
# Invariant: every workflow that runs `docker buildx build` uses the governance
# `type=gha` runner-cache pattern - a `docker-container` buildx driver (the
# default `docker` driver exports no cache at all), the
# crazy-max/ghaction-github-runtime step that re-exports ACTIONS_CACHE_URL /
# ACTIONS_RUNTIME_TOKEN, and `type=gha` cache_from / cache_to with
# `mode=max,ignore-error=true`.
#
# The retired patterns are the failure this pins: `type=inline` carries only the
# final layer's metadata and misses the dependency build, and `type=registry` on
# a `:buildcache` tag round-tripped ~1.7 GiB over the WAN every build. Both go
# green on a fresh run, so a regression is invisible without this check.
#
# Comment lines are excluded on purpose: the workflow's own comments name the
# retired backends when explaining why they were dropped.

const REQUIRED = [
    [what pattern];
    ["docker-container buildx driver" "--driver docker-container"]
    ["Actions runtime-env export step" "crazy-max/ghaction-github-runtime@v3"]
    ["gha cache_from" 'cache_from = "type=gha"']
    ["gha cache_to with mode=max,ignore-error" 'cache_to = "type=gha,mode=max,ignore-error=true"']
    ["--cache-from on the buildx build" "--cache-from"]
    ["--cache-to on the buildx build" "--cache-to"]
]

const FORBIDDEN = [
    [what pattern];
    ["inline cache export" "type=inline"]
    ["registry cache backend" "type=registry"]
    ["dedicated :buildcache tag" ":buildcache"]
]

def main [] {
    let files = (
        glob .forgejo/workflows/*.yml
        | sort
        | where {|f| (open --raw $f | decode utf-8) | str contains "docker buildx build" }
    )
    if ($files | is-empty) {
        print --stderr "ERROR: no workflow under .forgejo/workflows/ runs `docker buildx build`"
        exit 1
    }

    mut errors = []

    for file in $files {
        let code = (
            open --raw $file
            | decode utf-8
            | lines
            | enumerate
            | where {|row| not (($row.item | str trim) | str starts-with "#") }
        )
        let body = ($code | each {|row| $row.item } | str join "\n")

        for req in $REQUIRED {
            if not ($body | str contains $req.pattern) {
                $errors = ($errors | append $"($file): missing ($req.what) \(expected `($req.pattern)`\)")
            }
        }

        for bad in $FORBIDDEN {
            for row in ($code | where {|row| $row.item | str contains $bad.pattern }) {
                $errors = ($errors | append $"($file):($row.index + 1): ($bad.what) is retired; use type=gha")
            }
        }
    }

    if ($errors | is-empty) {
        print $"OCI build cache OK: ($files | length) buildx workflow\(s) on the type=gha runner cache"
    } else {
        print --stderr "ERROR: OCI build-cache rule violated (governance GOV-20)."
        print --stderr "Every `docker buildx build` workflow uses the docker-container driver + type=gha cache."
        for e in $errors { print --stderr $"  ($e)" }
        exit 1
    }
}
