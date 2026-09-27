#!/usr/bin/env nu

# Build-target storage guard (PMS-973).
#
# Invariant: the cargo target directory lives on a disk-backed filesystem, never
# on a memory-backed one (tmpfs, ramfs). The shared development machines have a
# large tmpfs at /tmp (46 GB on desktop-02), so a target directory pointed there
# by an environment variable or a config file spends real memory on build
# artifacts. Memory is the scarce resource on those hosts and storage is not: two
# drives were added in August 2026 precisely so it would not be.
#
# Why a guard rather than a setting. The fix nobody can forget is the one that is
# checked: `CARGO_TARGET_DIR` is an environment variable, so it can be set by a
# shell profile, a systemd unit, a container, an editor, an agent or a one-off
# `export` in the session that runs the build, and none of those travel with the
# checkout. This script does not decide WHERE the target goes; it refuses the one
# place it must not be, and it resolves the path exactly as cargo does so what it
# checks is what the build will actually use.
#
# It deliberately does NOT fail on a full-but-disk-backed filesystem. Running out
# of disk is loud and recoverable; a build quietly eating memory the running
# application needs is neither. Where the target directories actually sit per
# host, and the separate question of /home crowding on desktop-02, are in
# docs/dev-docs/build-storage.md.

# What cargo calls a memory-backed filesystem, as `stat --file-system` names it.
const MEMORY_BACKED = ["tmpfs" "ramfs"]

# Set this when the target directory is SUPPOSED to be in memory: an ephemeral CI
# runner whose whole workspace is a tmpfs it throws away is not the thing this
# guards. It warns rather than failing so the reason stays visible in the log.
const ALLOW_VAR = "MOKOSH_ALLOW_TMPFS_TARGET"

# Resolve the target directory the way cargo does, highest precedence first:
# `CARGO_TARGET_DIR`, then `CARGO_BUILD_TARGET_DIR` (the environment form of
# `build.target-dir`), then `build.target-dir` from the nearest config file, then
# the default `<workspace root>/target`. Returns the path and how it was chosen,
# because "which of these set it" is the first question when one is wrong.
def resolve-target-dir [repo: string] {
    let from_env = ($env | get --optional CARGO_TARGET_DIR)
    if $from_env != null and ($from_env | str trim | is-not-empty) {
        return { path: ($from_env | str trim), source: "CARGO_TARGET_DIR" }
    }

    let from_build_env = ($env | get --optional CARGO_BUILD_TARGET_DIR)
    if $from_build_env != null and ($from_build_env | str trim | is-not-empty) {
        return { path: ($from_build_env | str trim), source: "CARGO_BUILD_TARGET_DIR" }
    }

    # The repo's own config wins over the user's, which is cargo's order.
    let configs = [
        { file: ($repo | path join ".cargo" "config.toml"), label: ".cargo/config.toml" }
        { file: ($nu.home-dir | path join ".cargo" "config.toml"), label: "~/.cargo/config.toml" }
    ]
    for candidate in $configs {
        if ($candidate.file | path exists) {
            let configured = (open $candidate.file | get --optional build.target-dir)
            if $configured != null and ($configured | str trim | is-not-empty) {
                return {
                    path: ($configured | str trim)
                    source: $"build.target-dir in ($candidate.label)"
                }
            }
        }
    }

    { path: ($repo | path join "target"), source: "cargo's default, <repo>/target" }
}

# The filesystem type of `path`, or of its nearest existing ancestor: the target
# directory does not exist before the first build, and the filesystem it would
# land on is a property of the parent either way.
def filesystem-of [path: string] {
    mut probe = ($path | path expand --no-symlink)
    while not ($probe | path exists) {
        let parent = ($probe | path dirname)
        if $parent == $probe { break }
        $probe = $parent
    }
    {
        probed: $probe
        fstype: (^stat --file-system --format=%T $probe | str trim)
    }
}

def main [] {
    let repo = (pwd)
    let resolved = (resolve-target-dir $repo)
    let absolute = (
        if ($resolved.path | path type) == "dir" or ($resolved.path | str starts-with "/") {
            $resolved.path | path expand --no-symlink
        } else {
            # A relative `target-dir` is relative to the directory holding the
            # config file, which for both candidates above is a repo or home
            # root; resolving against the repo is the case that occurs.
            $repo | path join $resolved.path | path expand --no-symlink
        }
    )
    let fs = (filesystem-of $absolute)

    print $"cargo target dir: ($absolute)"
    print $"  chosen by:      ($resolved.source)"
    print $"  filesystem:     ($fs.fstype) \(probed at ($fs.probed))"

    if ($fs.fstype not-in $MEMORY_BACKED) {
        print $"Build target storage OK: ($fs.fstype) is disk-backed, so build artifacts do not spend memory"
        return
    }

    let raw_allow = ($env | get --optional $ALLOW_VAR)
    let allowed = ($raw_allow != null and ($raw_allow | default "" | str trim | str downcase) in ["1" "true" "yes"])
    if $allowed {
        print $"WARNING: the target dir is on ($fs.fstype), allowed by ($ALLOW_VAR)."
        print "  Build artifacts are being written to memory. That is only safe on a host whose memory nothing else needs."
        return
    }

    print --stderr $"ERROR: the cargo target directory is on ($fs.fstype), a memory-backed filesystem \(PMS-973)."
    print --stderr $"  Path:      ($absolute)"
    print --stderr $"  Chosen by: ($resolved.source)"
    print --stderr "  Build artifacts for this workspace run to tens of gigabytes, and on the shared development"
    print --stderr "  machines memory is the scarce resource while storage is not. Point the target directory at a"
    print --stderr "  disk-backed path instead: unset the variable to use <repo>/target, or set it to a directory on"
    print --stderr "  one of the added drives. docs/dev-docs/build-storage.md has where each host keeps them."
    print --stderr $"  If the target really is meant to be in memory \(an ephemeral CI runner), set ($ALLOW_VAR)=true."
    exit 1
}
