#!/usr/bin/env nu

# Runner-label guard for .forgejo/workflows (PMS-719, PMS-1286).
#
# The dev label is for jobs that compile on the runner: only that image ships
# `cc` / `gcc` / `ld` plus glibc and OpenSSL headers. The base label is for
# everything else. A native cargo job on the base label dies at `linker cc not
# found` on a cold cache (PMS-705, PMS-706, CLAUDE-203), and the fix is the
# label, never a run-time `zypper install gcc`.
#
# Fails when a workflow installs a C toolchain at run time, when a workflow
# JOB that runs cargo natively requests the base label, or when a `runs-on:`
# line carries no comment justifying its label (an unannotated label is
# indistinguishable from an unaudited one, which is how this defect spread).
#
# The compile check is scoped to the enclosing job, not the whole file: a
# non-compiling job (e.g. a secrets scanner that only invokes a composite
# action) can live beside a cargo job without inheriting its label.

const TOOLCHAIN_PKGS = [
    "gcc"
    "binutils"
    "glibc-devel"
    "libopenssl-devel"
    "build-essential"
]

const PKG_MANAGERS = ["zypper" "apt-get" "dnf " "apk "]

const DEV_LABEL = "RUNS_ON_OPENSUSE_BASE_HEAVY"

# Strip a leading `run:` so a one-line step and a block-scalar line look alike.
def command-body [line: string] {
    $line | str trim | str replace --regex '^run:\s*' '' | str trim
}

# A line that opens a job under `jobs:`: indent exactly 2, ends with `:`,
# key is a bare identifier.
def is-job-header [line: string] {
    if not ($line | str starts-with "  ") { return false }
    if ($line | str starts-with "   ") { return false }
    let trimmed = ($line | str trim)
    if ($trimmed | str starts-with "#") { return false }
    if not ($trimmed | str ends-with ":") { return false }
    let name = ($trimmed | str substring 0..(($trimmed | str length) - 1))
    ($name | find --regex '^[A-Za-z_][A-Za-z0-9_-]*$' | is-not-empty)
}

def main [] {
    let files = (glob .forgejo/workflows/*.yml | sort)
    if ($files | is-empty) {
        print --stderr "ERROR: no workflows found under .forgejo/workflows/"
        exit 1
    }

    mut errors = []

    for file in $files {
        let lines = (open --raw $file | decode utf-8 | lines)

        # Partition the file into jobs. Only lines after a top-level `jobs:`
        # header are considered; everything above (on:, env:, defaults:) is
        # out of scope for this guard.
        let jobs_start = (
            $lines
            | enumerate
            | where {|r| ($r.item | str starts-with "jobs:") }
            | first 1
            | get index.0?
        )
        if $jobs_start == null { continue }

        mut job_ranges = []
        mut current_start = null
        for row in ($lines | enumerate | skip ($jobs_start + 1)) {
            if (is-job-header $row.item) {
                if $current_start != null {
                    $job_ranges = ($job_ranges | append { start: $current_start, end: $row.index })
                }
                $current_start = $row.index
            }
        }
        if $current_start != null {
            $job_ranges = ($job_ranges | append { start: $current_start, end: ($lines | length) })
        }

        for job in $job_ranges {
            let slice_rows = (
                $lines
                | enumerate
                | where {|r| ($r.index >= $job.start) and ($r.index < $job.end) }
            )

            let installs = (
                $slice_rows
                | where {|row|
                    let body = (command-body $row.item)
                    (
                        (not ($body | str starts-with "#")) and
                        ($PKG_MANAGERS | any {|m| $body | str contains $m }) and
                        ($body | str contains "install") and
                        ($TOOLCHAIN_PKGS | any {|p| $body | str contains $p })
                    )
                }
                | each {|row| $"($file):($row.index + 1): run-time toolchain install; request the dev label instead" }
            )
            $errors = ($errors | append $installs)

            let compiles = (
                $slice_rows | any {|row|
                    let body = (command-body $row.item)
                    (not ($body | str starts-with "#")) and ($body | str starts-with "cargo ")
                }
            )

            let runs_on = (
                $slice_rows
                | where {|r| (($r.item | str trim) | str starts-with "runs-on:") }
            )

            for row in $runs_on {
                let lineno = $row.index + 1
                let is_dev = ($row.item | str contains $DEV_LABEL)

                if $compiles and (not $is_dev) {
                    $errors = ($errors | append $"($file):($lineno): compiles cargo natively but does not request ($DEV_LABEL)")
                }

                let prev = (
                    $lines
                    | first $row.index
                    | where {|l| ($l | str trim) != "" }
                    | last 1
                )
                let annotated = (
                    (not ($prev | is-empty)) and (($prev | first | str trim) | str starts-with "#")
                )
                if not $annotated {
                    $errors = ($errors | append $"($file):($lineno): runs-on has no comment justifying its label")
                }
            }
        }
    }

    if ($errors | is-empty) {
        print $"runner labels OK: ($files | length) workflows, every runs-on annotated, no run-time toolchain installs"
    } else {
        print --stderr "ERROR: runner-label rule violated."
        print --stderr "Dev label = compiles on the runner; base label = everything else."
        for e in $errors { print --stderr $"  ($e)" }
        exit 1
    }
}
