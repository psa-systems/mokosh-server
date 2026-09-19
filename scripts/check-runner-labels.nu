#!/usr/bin/env nu

# Runner-label guard for .forgejo/workflows (PMS-719, DEV-769).
#
# Two labels, chosen per JOB by what its steps run:
# - HEAVY (`RUNS_ON_OPENSUSE_BASE_HEAVY`, the dev image on the large runners)
#   for a job that compiles (cargo), builds an image (`docker build` /
#   `docker buildx build`), runs Playwright, or calls the shared Rust check.
#   Only the dev image ships `cc` / `ld`, OpenSSL headers and the browsers; a
#   native cargo job on the base image dies at `linker cc not found` (PMS-705,
#   PMS-706), and the fix is the label, never a run-time `zypper install gcc`.
# - MEDIUM (`RUNS_ON_OPENSUSE_BASE_MEDIUM`, the base image) for everything else.
#
# Fails when a job is on the wrong one of those two, when a retired `*_LATEST`
# label appears, when a workflow installs a C toolchain at run time, or when a
# `runs-on:` line carries no comment justifying its label (an unannotated label
# is indistinguishable from an unaudited one, which is how this defect spread).

const TOOLCHAIN_PKGS = [
    "gcc"
    "binutils"
    "glibc-devel"
    "libopenssl-devel"
    "build-essential"
]

const PKG_MANAGERS = ["zypper" "apt-get" "dnf " "apk "]

const HEAVY_LABEL = "RUNS_ON_OPENSUSE_BASE_HEAVY"
const MEDIUM_LABEL = "RUNS_ON_OPENSUSE_BASE_MEDIUM"
const RETIRED_LABELS = 'RUNS_ON_OPENSUSE_(BASE|DEV)_LATEST'

# A command line (comments excluded) that makes a job HEAVY.
const HEAVY_COMMANDS = ["cargo " "docker build" "docker buildx build" "playwright "]

# Strip a leading `run:` so a one-line step and a block-scalar line look alike.
def command-body [line: string] {
    $line | str trim | str replace --regex '^run:\s*' '' | str trim
}

# True when a step's `run:` text invokes a heavy command on a non-comment line.
def run-is-heavy [text: string] {
    $text | lines | any {|l|
        let body = (command-body $l)
        (not ($body | str starts-with "#")) and ($HEAVY_COMMANDS | any {|c|
            ($body | str starts-with $c) or ($body | str contains $" ($c)") or ($body | str contains $"^($c)")
        })
    }
}

def job-is-heavy [job: record] {
    let uses = ($job.uses? | default "")
    if ($uses | str ends-with "/.forgejo/workflows/check.yml@main") {
        return true
    }
    ($job.steps? | default [] | any {|step| run-is-heavy ($step.run? | default "") })
}

def main [] {
    let files = (glob .forgejo/workflows/*.yml | sort)
    if ($files | is-empty) {
        print --stderr "ERROR: no workflows found under .forgejo/workflows/"
        exit 1
    }

    mut errors = []
    mut jobs_seen = 0

    for file in $files {
        let lines = (open --raw $file | decode utf-8 | lines)

        let installs = (
            $lines
            | enumerate
            | where {|row|
                let body = (command-body $row.item)
                (
                    (not ($body | str starts-with "#")) and
                    ($PKG_MANAGERS | any {|m| $body | str contains $m }) and
                    ($body | str contains "install") and
                    ($TOOLCHAIN_PKGS | any {|p| $body | str contains $p })
                )
            }
            | each {|row| $"($file):($row.index + 1): run-time toolchain install; request ($HEAVY_LABEL) instead" }
        )
        $errors = ($errors | append $installs)

        for row in ($lines | enumerate) {
            let body = ($row.item | str trim)
            if (not ($body | str starts-with "#")) and ($body =~ $RETIRED_LABELS) {
                $errors = ($errors | append $"($file):($row.index + 1): retired *_LATEST label; use ($HEAVY_LABEL) or ($MEDIUM_LABEL)")
            }
        }

        let runs_on = ($lines | enumerate | where {|row| ($row.item | str trim) | str starts-with "runs-on:" })
        for row in $runs_on {
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
                $errors = ($errors | append $"($file):($row.index + 1): runs-on has no comment justifying its label")
            }
        }

        let jobs = (open $file | get jobs? | default {} | transpose name job)
        for entry in $jobs {
            $jobs_seen = $jobs_seen + 1
            let runs = ($entry.job.runs-on? | default "" | into string)
            let want = if (job-is-heavy $entry.job) { $HEAVY_LABEL } else { $MEDIUM_LABEL }
            if not ($runs | str contains $want) {
                $errors = ($errors | append $"($file): job `($entry.name)` must request ($want), has `($runs)`")
            }
        }
    }

    if ($errors | is-empty) {
        print $"runner labels OK: ($files | length) workflows, ($jobs_seen) jobs on heavy/medium by their work, every runs-on annotated, no run-time toolchain installs"
    } else {
        print --stderr "ERROR: runner-label rule violated."
        print --stderr $"($HEAVY_LABEL) = compiles, builds an image or runs Playwright; ($MEDIUM_LABEL) = everything else."
        for e in $errors { print --stderr $"  ($e)" }
        exit 1
    }
}
