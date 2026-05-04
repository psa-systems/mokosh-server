#!/usr/bin/env nu

# Get image tags from git describe.
# Returns a list of tags to publish:
# - Tagged commit (e.g. v0.1.0):          [v0.1.0, latest]
# - After a tag (e.g. v0.1.0-1-g1b66909): [v0.1.0, latest]
# - No tag at all:                         [latest]
#
# When used as a module (`use get-tags.nu`), returns list<string>.
# When run as a script, use --joined to get comma-separated output
# suitable for capturing in a subprocess.
export def main [
    --joined(-j)  # Output as comma-separated string instead of a list
] {
    use std log
    let describe = (^git describe --tags --always | str trim)
    log info $"[get-tags] git describe: ($describe)"

    # Try to parse as <tag>-<N>-g<hash> format (commits after a tag)
    let parts = ($describe | parse --regex '^(?<tag>.+)-\d+-g[0-9a-f]+$')

    let tags = if ($parts | is-not-empty) {
        let tag = $parts.tag.0
        log info $"[get-tags] Resolved tags: [($tag), latest]"
        [$tag, "latest"]
    } else if ($describe | str starts-with "v") {
        # Exact tag match (no commits after tag)
        log info $"[get-tags] Exact tag. Resolved tags: [($describe), latest]"
        [$describe, "latest"]
    } else {
        # No tag — just latest
        log info $"[get-tags] No tag. Resolved tags: [latest]"
        ["latest"]
    }

    if $joined { $tags | str join "," } else { $tags }
}
