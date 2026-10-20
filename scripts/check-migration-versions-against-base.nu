#!/usr/bin/env nu

# PMS-1402: catch a prefix collision that only appears after the merge.
#
# `common/scripts/check-migration-versions.nu` scans the migrations
# directory on the current checkout. On a `pull_request` run that is
# the PR branch, so two branches both picking the same prefix (e.g.
# both opening 300_foo.sql and 300_bar.sql) each pass alone and only
# collide when the second one lands. The post-merge push-to-main
# trigger that caught this before DEV-612 removed it (which rolled
# the check.yml compile+test cost on every merge) is not coming back
# as-is; this guard reads the base ref's migration list, unions the
# PR branch's, and re-asserts prefix uniqueness over the merged set
# WITHOUT the compile cost.
#
# Exits 0 on no collision between HEAD and the base ref's migrations.
# Exits 1 naming every collision. Exits 2 when git itself fails.
def main [
    migrations_dir: string = "migrations" # directory to scan
    base_ref: string = "origin/main" # ref whose migrations union with HEAD's
] {
    # The base ref's migration filenames (one per line, repo-relative).
    let base_ls = (
        ^git ls-tree -r --name-only $base_ref -- $"($migrations_dir)/"
        | complete
    )
    if $base_ls.exit_code != 0 {
        print --stderr $"FAIL: git ls-tree ($base_ref) failed \(exit ($base_ls.exit_code)\):"
        print --stderr $base_ls.stderr
        exit 2
    }
    let base_files = (
        $base_ls.stdout
        | lines
        | where ($it | str ends-with ".sql")
        | each { |p| $p | path basename }
    )

    # HEAD's migration filenames (what the PR branch has on disk now).
    let head_files = if ($migrations_dir | path exists) {
        glob ($migrations_dir | path join "*.sql")
        | each { |p| $p | path basename }
    } else {
        []
    }

    # Dedup names so a file carried unchanged on both sides is counted
    # once; what we care about is "two DIFFERENT files sharing a prefix".
    let all_names = ($base_files | append $head_files | uniq | sort)

    mut by_prefix: table<prefix: string, file: string> = []
    for name in $all_names {
        let m = ($name | parse --regex '^(?<prefix>[0-9]+)_')
        if ($m | is-empty) {
            # Not a prefix-shaped filename; the sibling script's wider
            # check catches that. Skip here.
            continue
        }
        $by_prefix = ($by_prefix | append { prefix: ($m | first | get prefix), file: $name })
    }

    let groups = ($by_prefix | group-by prefix)
    mut collisions = []
    for g in ($groups | columns) {
        let hits = ($groups | get $g)
        if ($hits | length) > 1 {
            let files = ($hits | get file | sort | str join ", ")
            $collisions = ($collisions | append $"prefix ($g): ($files)")
        }
    }

    if ($collisions | is-empty) {
        let n = ($all_names | length)
        print $"migrations clean against ($base_ref): ($n) files, no post-merge prefix collisions"
        return
    }

    print --stderr $"FAIL: ($collisions | length) prefix collision\(s\) would land on main after this merge:"
    for c in $collisions {
        print --stderr $"  ($c)"
    }
    print --stderr ""
    print --stderr "Pick an unused prefix for this PR's migration and rename, then push."
    exit 1
}
