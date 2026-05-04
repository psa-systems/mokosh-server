#!/usr/bin/env nu

# Get image tags from git describe. Pinned SemVer only.
#
# Returns a list of tags to publish:
# - Tagged commit (e.g. v0.1.0):          [v0.1.0]
# - Anywhere else (post-tag, no tags):    []
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

    # Detect post-tag commit format <tag>-<N>-g<hash>
    let post_tag = ($describe | parse --regex '^(?<tag>.+)-\d+-g[0-9a-f]+$')

    let tags = if ($post_tag | is-not-empty) {
        log info $"[get-tags] Post-tag commit ($describe). No SemVer tag at HEAD; skipping push."
        []
    } else if ($describe | str starts-with "v") {
        log info $"[get-tags] Exact SemVer tag at HEAD. Tags: [($describe)]"
        [$describe]
    } else {
        log info $"[get-tags] No tag at HEAD ($describe). Skipping push."
        []
    }

    if $joined { $tags | str join "," } else { $tags }
}
