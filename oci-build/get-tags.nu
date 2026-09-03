#!/usr/bin/env nu

# Resolve the single publish tag and train for the build workflow.
#
# The publish MODE is derived from the workflow TRIGGER (not from `git
# describe`) and passed in via --mode:
# - release: an exact `v*` tag push. Publishes ONLY the immutable <version> artifact.
# - latest:  a push to main. Publishes ONLY the rolling `latest` artifact.
# - branch:  a push to an allow-listed feature branch. Publishes ONLY that
#            branch's own tag, never `latest` (PMS-733).
# - dry-run: a workflow_dispatch. The caller builds and prints but mutates nothing.
#
# Deriving the mode from the trigger is what removes the twin-publish race
# (governance GOV-13 / claude-run CLAUDE-122). The release commit is
# simultaneously a push to `main` AND the `v*` tag push, so both workflow
# events fire. With `git describe` as the source of truth, both runs resolved
# the identical `[vX.Y.Z, latest]` set and raced to write the same destination
# (a 409 on immutable generic-package files, an overwrite race on the OCI
# `latest` tag). Trigger-derived modes return DISJOINT tag sets: the tag-push
# run publishes only `vX.Y.Z`, the branch-push run publishes only `latest`, so
# the two runs never write the same destination.
#
# A dry-run still resolves to a real publish train so the caller can exercise
# any path, and it resolves the SAME train the equivalent push would:
# - --simulate-tag v9.9.9  -> resolve the `release` train (prints the exact
#                             <version> URLs a tag build would write).
# - --ref-name <allow-listed branch> -> resolve the `branch` train. A manual run
#                             from a feature branch must never resolve `latest`,
#                             or `--dry-run false` would publish branch code to
#                             the tag production tracks (PMS-733).
# - otherwise -> resolve the `latest` train.
#
# Returns a record { mode, train, tag, describe }:
# - train: release | latest | branch (the effective publish train)
# - tag:   <version> for release (e.g. v1.2.3), the branch-derived tag for
#          branch, or `latest` for latest
# - describe: `git describe --tags --always`, kept for build-metadata /
#             diagnostics only; it no longer decides the train.
#
# When used as a module (`use get-tags.nu`) it returns the record. When run as a
# script for a workflow step, pass --json to serialize the record for capture
# (e.g. `^nu oci-build/get-tags.nu --mode latest --json | from json`).

# Branches other than `main` that may publish an image. An explicit allow-list,
# not "any branch": a stray push must not fill the registry. This is the single
# source of truth - scripts/check-oci-publish-tags.nu fails the build when the
# workflow's push filter or its ref guard disagrees with it.
export const BRANCH_ALLOW_LIST = ["mokosh-contact-login"]

# The registry tag a branch publishes: the branch name with `/` replaced by `-`,
# because an OCI tag may not contain `/`.
export def branch-tag [ref_name: string] {
    $ref_name | str replace --all "/" "-"
}

export def main [
    --mode: string                  # release | latest | branch | dry-run (from the trigger)
    --ref-name: string = ""         # tag ref name for release mode (e.g. v1.2.3), branch name for branch mode
    --simulate-tag: string = ""      # dry-run only: simulate a release of this version
    --json(-j)                       # Serialize the record to JSON for shell capture
] {
    use std log
    let describe = (^git describe --tags --always | str trim)
    log info $"[get-tags] mode: ($mode) ref-name: ($ref_name) simulate-tag: ($simulate_tag) describe: ($describe)"

    # Resolve the effective publish train and its version (if any). A dry-run
    # maps onto a real train so both publish paths can be exercised without a
    # registry mutation.
    let effective = if $mode == "release" {
        { train: "release", version: $ref_name }
    } else if $mode == "latest" {
        { train: "latest", version: "" }
    } else if $mode == "branch" {
        { train: "branch", version: $ref_name }
    } else if $mode == "dry-run" {
        if ($simulate_tag | is-not-empty) {
            { train: "release", version: $simulate_tag }
        } else if ($ref_name | is-not-empty) and $ref_name != "main" {
            { train: "branch", version: $ref_name }
        } else {
            { train: "latest", version: "" }
        }
    } else {
        error make { msg: $"[get-tags] Unknown mode: '($mode)'. Expected release|latest|branch|dry-run." }
    }

    if $effective.train == "release" and ($effective.version | is-empty) {
        error make { msg: "[get-tags] release train requires a non-empty version (--ref-name for a tag build, or --simulate-tag for a dry-run)." }
    }

    # Fail loud rather than silently falling back to `latest`: a branch that is
    # not on the allow-list has no tag of its own, and publishing it as `latest`
    # is the exact failure the workflow's ref guard exists to prevent.
    if $effective.train == "branch" and ($effective.version not-in $BRANCH_ALLOW_LIST) {
        error make { msg: $"[get-tags] Branch '($effective.version)' is not on the publish allow-list ($BRANCH_ALLOW_LIST | str join ', '). Add it there before building an image from it." }
    }

    let tag = if $effective.train == "release" {
        $effective.version
    } else if $effective.train == "branch" {
        (branch-tag $effective.version)
    } else {
        "latest"
    }
    log info $"[get-tags] Resolved train: ($effective.train) tag: ($tag)"

    let resolved = {
        mode: $mode
        train: $effective.train
        tag: $tag
        describe: $describe
    }

    if $json { $resolved | to json --raw } else { $resolved }
}
