#!/usr/bin/env nu

# PMS-785: `[workspace.dependencies]` is the workspace's version registry, so it
# must describe what the workspace actually shares.
#
# A workspace dependency only reaches the build graph when a member writes
# `<crate> = { workspace = true }`. An entry nobody inherits is invisible drift:
# `tower-http` sat there pinning `["cors", "trace"]` while the root package
# independently pinned a six-feature superset, and a reader had no way to tell
# which pin the build used. `cargo machete` does not cover this - it only reads
# each package's own dependency tables - so this fails a PR that:
#
#   - adds a `[workspace.dependencies]` entry no member inherits, or
#   - re-declares a crate with its own version/features when the workspace
#     table already pins it.

const ROOT_MANIFEST = 'Cargo.toml'
const DEP_TABLES = ['dependencies' 'dev-dependencies' 'build-dependencies']

# Resolve a `workspace.members` entry to its manifest path.
def member-manifest [member: string]: nothing -> string {
    if $member == '.' { $ROOT_MANIFEST } else { $'($member)/Cargo.toml' }
}

# Every dependency a member declares, flagged by whether it inherits the
# workspace pin. A spec is either a bare version string or a table.
def member-deps [manifest_path: string] {
    let manifest = (open --raw $manifest_path | decode utf-8 | from toml)
    $DEP_TABLES
    | each {|table|
        $manifest
        | get --optional $table
        | default {}
        | transpose crate spec
        | each {|row|
            let inherits = (
                ($row.spec | describe | str starts-with 'record')
                and (($row.spec | get --optional workspace | default false) == true)
            )
            {manifest: $manifest_path, table: $table, crate: $row.crate, inherits: $inherits}
        }
    }
    | flatten
}

def main [] {
    let root = (open --raw $ROOT_MANIFEST | decode utf-8 | from toml)
    let pinned = ($root.workspace.dependencies | columns)

    let manifests = (
        $root.workspace.members
        | each {|member|
            let path = (member-manifest $member)
            if not ($path | path exists) {
                print --stderr $"ERROR: workspace member '($member)' has no manifest at ($path)."
                exit 1
            }
            $path
        }
    )

    let declared = ($manifests | each {|path| member-deps $path } | flatten)
    let inherited = ($declared | where inherits | get crate | uniq)

    let unreferenced = (
        $pinned
        | where {|crate| $crate not-in $inherited }
        | each {|crate| {crate: $crate, manifest: $ROOT_MANIFEST, problem: 'no member inherits it'} }
    )

    let redeclared = (
        $declared
        | where {|dep| (not $dep.inherits) and ($dep.crate in $pinned) }
        | each {|dep| {crate: $dep.crate, manifest: $'($dep.manifest) [($dep.table)]', problem: 'own pin shadows the workspace pin'} }
    )

    let violations = ($unreferenced | append $redeclared)

    if ($violations | is-empty) {
        print $"workspace-deps OK: all ($pinned | length) [workspace.dependencies] entries are inherited, and no member re-pins one"
    } else {
        print --stderr "ERROR: [workspace.dependencies] does not match what the workspace shares (PMS-785)."
        print --stderr "Delete an entry no member inherits, or make the member inherit it with"
        print --stderr "`<crate> = { workspace = true }` so the table's version and features are the ones the build uses."
        # One line per violation, not a `table`: the manifest column is wide and
        # a CI terminal elides it into `...`.
        $violations | each {|v| print --stderr $"  ($v.crate): ($v.problem) \(($v.manifest)\)" }
        exit 1
    }
}
