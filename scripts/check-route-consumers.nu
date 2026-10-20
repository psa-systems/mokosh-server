#!/usr/bin/env nu

# PMS-1263: a mounted route needs a caller or a dated reason it has none.
#
# For every `.route("<path>", ...)` literal under any src/modules/*/*.rs file
# (PMS-1498: not just the literal filename `routes.rs` - a module's router can
# live in a differently named file, e.g. auth/grant_invitations_routes.rs)
# this looks for the path in the SPA source (`mokosh-apps/src/`, a sibling
# checkout, or $MOKOSH_APPS_DIR). A route the SPA never names fails unless its
# file carries a "parity record" comment (the PMS-840 convention) that
# includes an ISO date. The match is deliberately loose: the first static
# segment of the path plus every later static segment must each appear in the
# client source, because the client builds URLs with format! and the `{id}`
# holes differ. A trailing `#[cfg(test)]` module is stripped before scanning,
# so a router built inside a test fixture (e.g. a 404-after-unmount regression
# test) is never mistaken for a mounted route.
#
# No client checkout means nothing to compare against: it says so and exits 0.
#
#   nu scripts/check-route-consumers.nu             # check
#   nu scripts/check-route-consumers.nu --self-test # fixtures, no client needed

def static_segments [path: string] {
    $path | split row '/' | where {|s| ($s | is-not-empty) and (not ($s | str contains '{')) }
}

def has_record [text: string] {
    # A "parity record" comment block that names a date.
    $text | lines | any {|l|
        ($l | str trim | str starts-with '//') and ($l | str contains 'parity record')
    } | if $in { $text =~ '\d{4}-\d{2}-\d{2}' } else { false }
}

def strip_test_code [text: string] {
    # Rust convention in this codebase: a `#[cfg(test)]` module sits once at
    # the end of a file, with any further `#[cfg(test)]` on individual items
    # nested inside it. Cutting at the first top-level occurrence drops the
    # whole test tail without touching production code before it.
    let lines = ($text | lines)
    let hits = ($lines | enumerate | where item == '#[cfg(test)]')
    if ($hits | is-empty) {
        $text
    } else {
        let cut = ($hits | get 0 | get index)
        $lines | first $cut | str join "\n"
    }
}

def routes_in [text: string] {
    $text | parse --regex '\.route\(\s*"(?P<path>[^"]*)"' | get path
}

def consumed [path: string, client: string] {
    let segs = (static_segments $path)
    if ($segs | is-empty) { return true }
    # MAPPS-986: match each static segment on an identifier boundary rather
    # than as a plain substring, so a route segment that happens to be a
    # substring of an unrelated client struct field (`capabilities` inside
    # `supported_capabilities`) cannot pass silently. The first segment
    # anchors on its leading slash; later segments must appear flanked by a
    # non-identifier character (or line edge).
    ($segs | enumerate | all {|s|
        if $s.index == 0 {
            $client | str contains $"/($s.item)"
        } else {
            let left = '(?:^|[^A-Za-z0-9_])'
            let right = '(?:[^A-Za-z0-9_]|$)'
            let bounded = $left + $s.item + $right
            ($client | parse --regex $bounded | is-not-empty)
        }
    })
}

def unconsumed_in [files: list<string>, client: string] {
    $files | each {|f|
        let text = (strip_test_code (open --raw $f | decode utf-8))
        if (has_record $text) { [] } else {
            routes_in $text | where {|p| not (consumed $p $client) } | each {|p| {file: $f, route: $p} }
        }
    } | flatten
}

def read_client [dir: string] {
    glob $"($dir)/**/*.rs" | each {|f| open --raw $f | decode utf-8 } | str join "\n"
}

def self_test [] {
    let d = (mktemp -d)
    mkdir $"($d)/a" $"($d)/b" $"($d)/c" $"($d)/d"
    'Router::new().route("/things/{id}/frob", get(x)).route("/used", get(y))' | save $"($d)/a/routes.rs"
    '// parity record 2026-09-18: unbuilt\nRouter::new().route("/nope", get(x))' | save $"($d)/b/routes.rs"
    # MAPPS-986: a route whose later static segment is a substring of an
    # unrelated client identifier (`capabilities` inside
    # `supported_capabilities`) must still be reported as unconsumed. The
    # old `str contains` match passed this silently.
    'Router::new().route("/integrations/capabilities", get(x))' | save $"($d)/c/routes.rs"
    # PMS-1498: a route-mounting file named anything other than `routes.rs`
    # (e.g. `grant_invitations_routes.rs`) must still be scanned, and a
    # `.route(...)` inside its trailing `#[cfg(test)]` module must not be,
    # so an in-test fixture route can't be mistaken for a mounted one.
    (
        'Router::new().route("/grants/{id}", delete(x));' +
        "\n#[cfg(test)]\nmod tests {\n" +
        '    fn t() { Router::new().route("/not-a-real-route", get(x)); }' +
        "\n}\n"
    ) | save $"($d)/d/grant_invitations_routes.rs"
    let client = (
        'get("/used"); format!("/things/{}", id);' +
        ' pub supported_capabilities: Vec<X>; pub enabled_capabilities: Vec<X>;' +
        ' let _ = "/integrations";'
    )
    let files = [
        $"($d)/a/routes.rs" $"($d)/b/routes.rs" $"($d)/c/routes.rs" $"($d)/d/grant_invitations_routes.rs"
    ]
    let got = (unconsumed_in $files $client)
    rm -r $d
    let routes = ($got | get route | sort)
    let expected = (['/integrations/capabilities' '/things/{id}/frob' '/grants/{id}'] | sort)
    if $routes != $expected {
        error make {msg: $"self-test failed: ($got | to nuon)"}
    }
    print "route-consumers self-test ok"
}

def main [--self-test] {
    if $self_test { return (self_test) }
    let dir = ($env.MOKOSH_APPS_DIR? | default '../mokosh-apps')
    if not ($"($dir)/src" | path exists) {
        # In CI, no client checkout means the guard is not running, which is
        # the very drift it was written to catch. Fail loud there, and keep
        # the skip on a developer box where the sibling is legitimately
        # absent.
        let msg = $"route consumers: no client checkout at ($dir)/src \(set MOKOSH_APPS_DIR\)"
        if ($env.CI? | default '' | is-not-empty) {
            print $"($msg); refusing to skip under CI"
            exit 1
        }
        print $"($msg): SKIPPED"
        return
    }
    let bad = (unconsumed_in (glob src/modules/*/*.rs) (read_client $"($dir)/src"))
    if ($bad | is-not-empty) {
        print "Routes with no caller in mokosh-apps/src/ and no dated parity record:"
        $bad | each {|b| print $"  ($b.file): ($b.route)" }
        print "Wire the route, remove it, or add a `// ... parity record <YYYY-MM-DD>` comment to its routes.rs stating why it stays."
        exit 1
    }
    print "route consumers ok"
}
