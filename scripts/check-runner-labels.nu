#!/usr/bin/env nu

# Runner-label guard for .forgejo/workflows (PMS-719).
#
# The dev label is for jobs that compile on the runner: only that image ships
# `cc` / `gcc` / `ld` plus glibc and OpenSSL headers. The base label is for
# everything else. A native cargo job on the base label dies at `linker cc not
# found` on a cold cache (PMS-705, PMS-706, CLAUDE-203), and the fix is the
# label, never a run-time `zypper install gcc`.
#
# Fails when a workflow installs a C toolchain at run time, when a workflow that
# runs cargo natively requests the base label, or when a `runs-on:` line carries
# no comment justifying its label (an unannotated label is indistinguishable
# from an unaudited one, which is how this defect spread).

const TOOLCHAIN_PKGS = [
    "gcc"
    "binutils"
    "glibc-devel"
    "libopenssl-devel"
    "build-essential"
]

const PKG_MANAGERS = ["zypper" "apt-get" "dnf " "apk "]

const DEV_LABEL = "RUNS_ON_OPENSUSE_DEV_LATEST"

# Strip a leading `run:` so a one-line step and a block-scalar line look alike.
def command-body [line: string] {
    $line | str trim | str replace --regex '^run:\s*' '' | str trim
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
            | each {|row| $"($file):($row.index + 1): run-time toolchain install; request the dev label instead" }
        )
        $errors = ($errors | append $installs)

        let compiles = (
            $lines | any {|l|
                let body = (command-body $l)
                (not ($body | str starts-with "#")) and ($body | str starts-with "cargo ")
            }
        )

        let runs_on = ($lines | enumerate | where {|row| ($row.item | str trim) | str starts-with "runs-on:" })

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

    if ($errors | is-empty) {
        print $"runner labels OK: ($files | length) workflows, every runs-on annotated, no run-time toolchain installs"
    } else {
        print --stderr "ERROR: runner-label rule violated."
        print --stderr "Dev label = compiles on the runner; base label = everything else."
        for e in $errors { print --stderr $"  ($e)" }
        exit 1
    }
}
