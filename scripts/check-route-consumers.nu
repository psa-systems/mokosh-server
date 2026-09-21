#!/usr/bin/env nu

# PMS-1263: a mounted route needs a caller or a dated reason it has none.
#
# For every `.route("<path>", ...)` literal under src/modules/*/routes.rs this
# looks for the path in the SPA source (`mokosh-apps/src/`, a sibling checkout,
# or $MOKOSH_APPS_DIR). A route the SPA never names fails unless its file
# carries a "parity record" comment (the PMS-840 convention) that includes an
# ISO date. The match is deliberately loose: the first static segment of the
# path plus every later static segment must each appear in the client source,
# because the client builds URLs with format! and the `{id}` holes differ.
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

def routes_in [text: string] {
    $text | parse --regex '\.route\(\s*"(?P<path>[^"]*)"' | get path
}

def consumed [path: string, client: string] {
    let segs = (static_segments $path)
    if ($segs | is-empty) { return true }
    ($segs | enumerate | all {|s|
        let needle = if $s.index == 0 { $"/($s.item)" } else { $s.item }
        $client | str contains $needle
    })
}

def unconsumed_in [files: list<string>, client: string] {
    $files | each {|f|
        let text = (open --raw $f | decode utf-8)
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
    mkdir $"($d)/a" $"($d)/b"
    'Router::new().route("/things/{id}/frob", get(x)).route("/used", get(y))' | save $"($d)/a/routes.rs"
    '// parity record 2026-09-18: unbuilt\nRouter::new().route("/nope", get(x))' | save $"($d)/b/routes.rs"
    let client = 'get("/used"); format!("/things/{}", id)'
    let got = (unconsumed_in [$"($d)/a/routes.rs" $"($d)/b/routes.rs"] $client)
    rm -r $d
    if ($got | length) != 1 or $got.0.route != '/things/{id}/frob' {
        error make {msg: $"self-test failed: ($got | to nuon)"}
    }
    print "route-consumers self-test ok"
}

def main [--self-test] {
    if $self_test { return (self_test) }
    let dir = ($env.MOKOSH_APPS_DIR? | default '../mokosh-apps')
    if not ($"($dir)/src" | path exists) {
        print $"route consumers: SKIPPED, no client checkout at ($dir)/src \(set MOKOSH_APPS_DIR\)"
        return
    }
    let bad = (unconsumed_in (glob src/modules/*/routes.rs) (read_client $"($dir)/src"))
    if ($bad | is-not-empty) {
        print "Routes with no caller in mokosh-apps/src/ and no dated parity record:"
        $bad | each {|b| print $"  ($b.file): ($b.route)" }
        print "Wire the route, remove it, or add a `// ... parity record <YYYY-MM-DD>` comment to its routes.rs stating why it stays."
        exit 1
    }
    print "route consumers ok"
}
