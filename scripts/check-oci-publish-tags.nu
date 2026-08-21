#!/usr/bin/env nu

# Publish-tag guard for the OCI image build (PMS-733).
#
# Invariant: `:latest` is reachable only from `main`, and a branch publishes an
# image only if it is on `BRANCH_ALLOW_LIST` in oci-build/get-tags.nu.
#
# Three places have to agree on that list - the push trigger's `branches:`
# filter, the job's ref guard, and the tag resolver - and a disagreement is
# silent: a branch added to the trigger but not the resolver would resolve
# `latest` and overwrite the tag production tracks, and a branch added to the
# guard but not the trigger simply never builds. So the resolver's const is the
# single source of truth and this check fails the build when the workflow drifts
# from it. It also exercises the resolver itself, since every publish decision
# is made there.

use ../oci-build/get-tags.nu
use ../oci-build/get-tags.nu BRANCH_ALLOW_LIST

const WORKFLOW = ".forgejo/workflows/build-oci-image.yml"
const JOB = "build-and-push"

# The `:latest` half of the ref guard, byte for byte. This issue adds a publish
# path; it does not relax the existing one, so the original expression must
# survive verbatim as the leading term.
const LATEST_GUARD = "github.ref == 'refs/heads/main' || startsWith(github.ref, 'refs/tags/v')"

def check-workflow [] {
    let workflow = (open $WORKFLOW)
    let allowed = ($BRANCH_ALLOW_LIST | sort)
    mut errors = []

    let trigger_branches = ($workflow | get on.push.branches)
    let expected_branches = (["main"] ++ $allowed)
    if ($trigger_branches | sort) != ($expected_branches | sort) {
        $errors = ($errors | append $"($WORKFLOW): push trigger builds ($trigger_branches | str join ', '); the allow-list says ($expected_branches | str join ', ')")
    }

    let guard = ($workflow | get jobs | get $JOB | get if)
    if not ($guard | str starts-with $LATEST_GUARD) {
        $errors = ($errors | append $"($WORKFLOW): the :latest ref guard must stay verbatim as the leading term of the ($JOB) `if:`. Expected it to start with `($LATEST_GUARD)`, found `($guard)`")
    }
    let guard_branches = (
        $guard
        | parse --regex "refs/heads/(?<branch>[^']+)"
        | get branch
        | where {|b| $b != "main" }
        | sort
    )
    if $guard_branches != $allowed {
        $errors = ($errors | append $"($WORKFLOW): the ($JOB) ref guard admits branches ($guard_branches | str join ', '); the allow-list says ($allowed | str join ', ')")
    }

    $errors
}

# Every publish decision the workflow can reach, asserted on the resolver.
def check-resolver [] {
    let branch = ($BRANCH_ALLOW_LIST | first)
    let cases = [
        [what, args, tag];
        ["a version tag push publishes the version only" { mode: "release", ref_name: "v1.2.3" } "v1.2.3"]
        ["a main push publishes latest only" { mode: "latest", ref_name: "main" } "latest"]
        ["an allow-listed branch push publishes its branch tag only" { mode: "branch", ref_name: $branch } $branch]
        ["a manual run off main resolves the latest train" { mode: "dry-run", ref_name: "main" } "latest"]
        ["a manual run with simulate_tag resolves the release train" { mode: "dry-run", ref_name: "main", simulate_tag: "v9.9.9" } "v9.9.9"]
        ["a manual run off an allow-listed branch resolves that branch, never latest" { mode: "dry-run", ref_name: $branch } $branch]
    ]

    mut errors = []
    for case in $cases {
        let simulate = ($case.args.simulate_tag? | default "")
        let got = (try {
            (get-tags --mode $case.args.mode --ref-name $case.args.ref_name --simulate-tag $simulate).tag
        } catch {|e|
            $"<error: ($e.msg)>"
        })
        if $got != $case.tag {
            $errors = ($errors | append $"get-tags ($case.args | to nuon): expected tag `($case.tag)` \(($case.what)\), got `($got)`")
        }
    }

    # A branch outside the allow-list must fail loud, not fall back to latest.
    let stray = (try {
        (get-tags --mode "branch" --ref-name "feat/not-allow-listed").tag
    } catch {
        null
    })
    if $stray != null {
        $errors = ($errors | append $"get-tags: a branch outside the allow-list resolved tag `($stray)` instead of failing")
    }

    # `/` is illegal in an OCI tag, so a namespaced branch flattens to `-`.
    let flattened = (get-tags branch-tag "feat/PMS-733-example")
    if $flattened != "feat-PMS-733-example" {
        $errors = ($errors | append $"get-tags branch-tag: expected `feat-PMS-733-example`, got `($flattened)`")
    }

    $errors
}

def main [] {
    let errors = ((check-workflow) ++ (check-resolver))

    if ($errors | is-empty) {
        print $"OCI publish tags OK: :latest from main only, branch tags for ($BRANCH_ALLOW_LIST | str join ', ')"
    } else {
        print --stderr "ERROR: OCI publish-tag rule violated (PMS-733)."
        print --stderr "`:latest` publishes from main only, and a branch publishes only if oci-build/get-tags.nu allow-lists it."
        for e in $errors { print --stderr $"  ($e)" }
        exit 1
    }
}
