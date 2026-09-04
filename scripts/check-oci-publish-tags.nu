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
#
# A fourth place has to agree since PMS-825: check.yml's push filter. An
# allow-listed branch is long-lived and has no pull request into main, so
# without that entry its commits publish an image that never ran fmt, clippy or
# the tests. `main` is the opposite case and must NOT be there (DEV-612): every
# main commit arrives through a pull request, which check.yml already gates.

use ../oci-build/get-tags.nu
use ../oci-build/get-tags.nu BRANCH_ALLOW_LIST

const WORKFLOW = ".forgejo/workflows/build-oci-image.yml"
const JOB = "build-and-push"
const CHECK_WORKFLOW = ".forgejo/workflows/check.yml"

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

# PMS-825: every commit that can publish an image has had the check suite run
# against it. Containment, not equality: check.yml running on an extra branch
# costs a CI minute, while a publishing branch missing from it ships unchecked.
# main is covered by the pull_request trigger rather than the push filter
# (DEV-612); scripts/check-single-build.nu is what keeps it out of the latter.
def check-gate [] {
    let on = (open $CHECK_WORKFLOW | get on)
    let branches = (($on | get --optional push.branches) | default [])
    let pr_branches = (($on | get --optional pull_request.branches) | default [])
    mut errors = []

    if "main" not-in $pr_branches {
        $errors = ($errors | append $"($CHECK_WORKFLOW): pull_request trigger must include `main`, found ($pr_branches | str join ', ')")
    }
    let missing = ($BRANCH_ALLOW_LIST | where {|b| $b not-in $branches })
    if ($missing | is-not-empty) {
        $errors = ($errors | append $"($CHECK_WORKFLOW): publishing branches ($missing | str join ', ') are missing from the push trigger, so their commits publish an image the check suite never ran on")
    }

    $errors
}

# Every publish decision the workflow can reach, asserted on the resolver.
def check-resolver [] {
    let base_cases = [
        [what, args, tag];
        ["a version tag push publishes the version only" { mode: "release", ref_name: "v1.2.3" } "v1.2.3"]
        ["a main push publishes latest only" { mode: "latest", ref_name: "main" } "latest"]
        ["a manual run off main resolves the latest train" { mode: "dry-run", ref_name: "main" } "latest"]
        ["a manual run with simulate_tag resolves the release train" { mode: "dry-run", ref_name: "main", simulate_tag: "v9.9.9" } "v9.9.9"]
    ]
    # The allow-list is empty whenever no branch is being staged, which is the
    # steady state; only add the branch cases when there is a branch to assert.
    let cases = if ($BRANCH_ALLOW_LIST | is-empty) {
        $base_cases
    } else {
        let branch = ($BRANCH_ALLOW_LIST | first)
        $base_cases ++ [
            [what, args, tag];
            ["an allow-listed branch push publishes its branch tag only" { mode: "branch", ref_name: $branch } $branch]
            ["a manual run off an allow-listed branch resolves that branch, never latest" { mode: "dry-run", ref_name: $branch } $branch]
        ]
    }

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
    let errors = ((check-workflow) ++ (check-gate) ++ (check-resolver))

    if ($errors | is-empty) {
        let allowed = if ($BRANCH_ALLOW_LIST | is-empty) {
            "no branch allow-listed"
        } else {
            $"branch tags for ($BRANCH_ALLOW_LIST | str join ', ')"
        }
        print $"OCI publish tags OK: :latest from main only, ($allowed)"
    } else {
        print --stderr "ERROR: OCI publish-tag rule violated (PMS-733)."
        print --stderr "`:latest` publishes from main only, and a branch publishes only if oci-build/get-tags.nu allow-lists it."
        print --stderr "An allow-listed branch must also run the check gate (PMS-825), or it publishes an unchecked image."
        for e in $errors { print --stderr $"  ($e)" }
        exit 1
    }
}
