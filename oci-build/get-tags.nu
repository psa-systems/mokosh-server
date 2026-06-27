#!/usr/bin/env nu

# Resolve the single publish tag and train for the build workflow.
#
# The publish MODE is derived from the workflow TRIGGER (not from `git
# describe`) and passed in via --mode:
# - release: an exact `v*` tag push. Publishes ONLY the immutable <version> artifact.
# - latest:  a push to main. Publishes ONLY the rolling `latest` artifact.
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
# A dry-run still resolves to one of the two real publish trains so the caller
# can exercise either path:
# - --simulate-tag v9.9.9  -> resolve the `release` train (prints the exact
#                             <version> URLs a tag build would write).
# - --simulate-tag "" (default) -> resolve the `latest` train.
#
# Returns a record { mode, train, tag, describe }:
# - train: release | latest (the effective publish branch)
# - tag:   <version> for release (e.g. v1.2.3) or `latest` for latest
# - describe: `git describe --tags --always`, kept for build-metadata /
#             diagnostics only; it no longer decides the train.
#
# When used as a module (`use get-tags.nu`) it returns the record. When run as a
# script for a workflow step, pass --json to serialize the record for capture
# (e.g. `^nu oci-build/get-tags.nu --mode latest --json | from json`).
export def main [
    --mode: string                  # release | latest | dry-run (from the trigger)
    --ref-name: string = ""         # tag ref name for release mode (e.g. v1.2.3)
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
    } else if $mode == "dry-run" {
        if ($simulate_tag | is-not-empty) {
            { train: "release", version: $simulate_tag }
        } else {
            { train: "latest", version: "" }
        }
    } else {
        error make { msg: $"[get-tags] Unknown mode: '($mode)'. Expected release|latest|dry-run." }
    }

    if $effective.train == "release" and ($effective.version | is-empty) {
        error make { msg: "[get-tags] release train requires a non-empty version (--ref-name for a tag build, or --simulate-tag for a dry-run)." }
    }

    let tag = if $effective.train == "release" { $effective.version } else { "latest" }
    log info $"[get-tags] Resolved train: ($effective.train) tag: ($tag)"

    let resolved = {
        mode: $mode
        train: $effective.train
        tag: $tag
        describe: $describe
    }

    if $json { $resolved | to json --raw } else { $resolved }
}
