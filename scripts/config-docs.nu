#!/usr/bin/env nu

# Renders and checks docs/configuration.md from src/config/registry.rs and src/config/variables.toml (PMS-1442).
# Subcommands: generate | check | since <version> | release-notes <version> [--ref] | self-test.

const REGISTRY_FILE = "src/config/registry.rs"
const VARIABLES_FILE = "src/config/variables.toml"
const DOC_FILE = "docs/configuration.md"
const REPO_URL = "https://dev.a8n.run/psa-systems/mokosh-server"
const WINDOW = 5
const BEGIN = "<!-- BEGIN GENERATED: recently-added (just config-docs) -->"
const END = "<!-- END GENERATED: recently-added -->"
const LIST_HEADING = "## All variables"
const GROUPS = ["Added" "Changed" "Deprecated" "Removed"]
# Keys that predate the first tag are dated here; nothing upgrades into it.
const BASELINE = "v0.1.0"

# Names the code reads that are not server configuration, each with its reason.
const NOT_SERVER_CONFIG = {
    CARGO_PKG_VERSION: "build-time, set by cargo"
    MOKOSH_GIT_HASH: "build-time, injected by build.rs"
    MOKOSH_GIT_DESCRIBE: "build-time, injected by build.rs"
    MOKOSH_BUILD_DATE: "build-time, injected by build.rs"
    SOURCE_DATE_EPOCH: "build-time reproducible-build input"
    MOKOSH_ENV_FILE: "host-side mokosh-bootstrap CLI flag default"
    MOKOSH_QA_TENANT_ID: "host-side qa-seed / qa-teardown argument fallback"
    MOKOSH_SHOWCASE_TENANT_ID: "host-side showcase-* argument fallback"
    INFISICAL_URL: "host-side bootstrap CLI"
    INFISICAL_ADMIN_EMAIL: "host-side bootstrap CLI"
    INFISICAL_ADMIN_PASSWORD: "host-side bootstrap CLI"
    INFISICAL_ADMIN_FIRST_NAME: "host-side bootstrap CLI"
    INFISICAL_ADMIN_LAST_NAME: "host-side bootstrap CLI"
    INFISICAL_IDENTITY_NAME: "host-side bootstrap CLI"
    INFISICAL_PROJECT_NAME: "host-side bootstrap CLI"
}

# -- Versions -------------------------------------------------------------------

def vnum [v: string] {
    let p = ($v | parse --regex '^v(?<a>\d+)\.(?<b>\d+)\.(?<c>\d+)$')
    if ($p | is-empty) { error make { msg: $"($v) is not a vX.Y.Z release" } }
    (($p.a.0 | into int) * 1000000) + (($p.b.0 | into int) * 1000) + ($p.c.0 | into int)
}

def is-version [v: any] {
    ($v | describe) == "string" and ($v =~ '^v\d+\.\d+\.\d+$')
}

def release-tags [] {
    ^git tag --list "v*" | lines | where {|t| is-version $t }
}

def slug [name: string] {
    $"var-($name | str downcase | str replace --all '_' '-')"
}

def release-anchor [v: string] {
    $"release-($v | str replace --all '.' '-')"
}

# -- Inputs ---------------------------------------------------------------------

# Every `declare_keys!` declaration as {name, since, required, required_since}.
def parse-registry [text: string] {
    let rows = (
        $text
        | parse --regex '(?m)^\s*(?:Bootstrap|Application)\s+(?<ident>[A-Z][A-Z0-9_]*)\s*=\s*"(?<name>[A-Z][A-Z0-9_]*)"\s*,\s*since\s+"(?<since>[^"]*)"\s*,\s*(?<req>required|optional)(?:\s+"(?<req_since>[^"]*)")?\s*;'
    )
    let declared = ($text | parse --regex '(?m)^\s*(?:Bootstrap|Application)\s+[A-Z]' | length)
    if ($rows | length) != $declared or $declared == 0 {
        error make { msg: $"($REGISTRY_FILE): parsed ($rows | length) of ($declared) declarations; the declare_keys! shape changed" }
    }
    $rows | each {|r|
        {
            name: $r.name
            since: $r.since
            required: ($r.req == "required")
            required_since: (if ($r.req_since | is-empty) { null } else { $r.req_since })
            source: "registry"
            deprecated: null
            removed: null
        }
    }
}

# Registry keys plus variables.toml's variables and tombstones, one row each.
def build-catalog [registry: list, meta: record] {
    let vars = ($meta.variable? | default [] | each {|v|
        {
            name: $v.name
            since: $v.since
            required: ($v.required? | default false)
            required_since: ($v.required_since? | default null)
            source: "variables.toml"
            deprecated: ($v.deprecated? | default null)
            removed: null
        }
    })
    let removed = ($meta.removed? | default [] | each {|v|
        {
            name: $v.name
            since: $v.since
            required: false
            required_since: null
            source: "removed"
            deprecated: null
            removed: { release: $v.removed, issue: ($v.issue? | default ""), action: ($v.action? | default "") }
        }
    })
    $registry | append $vars | append $removed
}

def catalog-errors [catalog: list] {
    mut errors = []
    let dupes = ($catalog | group-by name | items {|k, v| { name: $k, n: ($v | length) } } | where n > 1)
    for d in $dupes {
        $errors = ($errors | append $"($d.name) is declared ($d.n) times across ($REGISTRY_FILE) and ($VARIABLES_FILE)")
    }
    for v in $catalog {
        for field in [$v.since $v.required_since ($v.deprecated?.release?) ($v.removed?.release?)] {
            if $field != null and not (is-version $field) {
                $errors = ($errors | append $"($v.name): '($field)' is not a vX.Y.Z release")
            }
        }
        if $v.required_since != null and (is-version $v.required_since) and (is-version $v.since) {
            if not $v.required or (vnum $v.required_since) <= (vnum $v.since) {
                $errors = ($errors | append $"($v.name): required_since needs `required` and a release after since")
            }
        }
    }
    $errors
}

# -- Changelog entries -----------------------------------------------------------

def default-action [e: record] {
    if $e.group != "Added" { return "" }
    if $e.required { "Required: set it before the server starts." } else { "Optional. Leave it unset to keep the default." }
}

# Every changelog entry the facts imply, with authored wording attached.
def build-entries [catalog: list, meta: record] {
    mut auto = []
    for v in $catalog {
        let at_add = ($v.required and $v.required_since == null)
        let breaking = ($at_add and $v.since != $BASELINE)
        $auto = ($auto | append { release: $v.since, group: "Added", var: $v.name, required: $at_add, breaking: $breaking, issue: "", action: "" })
        if $v.required_since != null {
            $auto = ($auto | append { release: $v.required_since, group: "Changed", var: $v.name, required: true, breaking: true, issue: "", action: "" })
        }
        if $v.deprecated != null {
            let d = $v.deprecated
            $auto = ($auto | append { release: $d.release, group: "Deprecated", var: $v.name, required: false, breaking: false, issue: ($d.issue? | default ""), action: $"Renamed to `($d.replacement)`. The old name still works and logs a warning naming the new one; rename it at your next compose edit." })
        }
        if $v.removed != null {
            let r = $v.removed
            $auto = ($auto | append { release: $r.release, group: "Removed", var: $v.name, required: false, breaking: true, issue: $r.issue, action: $r.action })
        }
    }

    mut errors = []
    mut explicit = []
    let names = ($catalog | get name)
    for c in ($meta.change? | default []) {
        if not ($c.group in $GROUPS) {
            $errors = ($errors | append $"change record for ($c.release): group '($c.group)' is not one of ($GROUPS | str join ', ')")
            continue
        }
        for var in ($c.variables? | default []) {
            if not ($var in $names) {
                $errors = ($errors | append $"change record ($c.release) ($c.group) names ($var), which is neither a registry key nor in ($VARIABLES_FILE)")
                continue
            }
            let hit = ($auto | enumerate | where {|e| $e.item.release == $c.release and $e.item.group == $c.group and $e.item.var == $var })
            if ($hit | is-empty) {
                if $c.group != "Changed" {
                    $errors = ($errors | append $"change record ($c.release) ($c.group) ($var) does not match the facts: check its since / deprecated / removed release")
                    continue
                }
                let v = ($catalog | where name == $var | first)
                let req = ($v.required and ($v.required_since == null or (vnum $v.required_since) <= (vnum $c.release)))
                $explicit = ($explicit | append { release: $c.release, group: "Changed", var: $var, required: $req, breaking: ($c.breaking? | default false), issue: ($c.issue? | default ""), action: ($c.action? | default "") })
            } else {
                let i = $hit.0.index
                let e = $hit.0.item
                $auto = ($auto | update $i ($e | merge {
                    issue: ($c.issue? | default $e.issue)
                    action: ($c.action? | default $e.action)
                    breaking: ($e.breaking or ($c.breaking? | default false))
                }))
            }
        }
    }

    let all = ($auto | append $explicit | each {|e|
        if ($e.action | is-empty) { $e | update action (default-action $e) } else { $e }
    })
    for e in $all {
        if $e.breaking and (($e.action | is-empty) or not ($e.issue =~ '^[A-Z]+-\d+$')) {
            $errors = ($errors | append $"Breaking ($e.group) ($e.var) in ($e.release) needs a [[change]] record in ($VARIABLES_FILE) with the operator action and the issue that introduced it")
        }
        if ($e.issue | is-not-empty) and not ($e.issue =~ '^[A-Z]+-\d+$') {
            $errors = ($errors | append $"($e.var) in ($e.release): issue '($e.issue)' is not an issue id")
        }
    }
    { entries: $all, errors: $errors }
}

# The releases the Recently added section covers: unreleased versions named by
# the facts, then the newest five tags.
def window [entries: list, tags: list] {
    let sorted = ($tags | sort-by {|t| vnum $t } --reverse)
    let latest = if ($sorted | is-empty) { 0 } else { vnum $sorted.0 }
    let unreleased = ($entries | get release | uniq | where {|r| (vnum $r) > $latest } | sort-by {|r| vnum $r } --reverse)
    { unreleased: $unreleased, released: ($sorted | first ([$WINDOW ($sorted | length)] | math min)) }
}

def entry-sort [rows: list] {
    $rows | sort-by {|e| $"(if $e.breaking { 0 } else { 1 })(if $e.required { 0 } else { 1 })($e.var)" }
}

def render-entry [e: record] {
    let mark = if $e.breaking { "**Breaking:** " } else { "" }
    let req = if $e.required { "yes" } else { "no" }
    let issue = if ($e.issue | is-empty) { "" } else { $" \(($e.issue))" }
    $"- ($mark)[`($e.var)`]\(#(slug $e.var)) \(Required: ($req)) - ($e.action)($issue)"
}

def render-recent [entries: list, tags: list] {
    let w = (window $entries $tags)
    mut out = [
        $BEGIN
        ""
        $"Configuration changes in the last ($WINDOW) releases, newest first, rendered by `just config-docs` from `src/config/registry.rs` and `src/config/variables.toml` \(edit those, not this section). **Breaking** marks a change that stops the server starting, or turns off a feature that worked, unless the operator acts first; each one names the action and the issue that introduced it. Upgrading across more releases than this? Run `just config-since <running version>`."
    ]
    let versions = ($w.unreleased | each {|v| { v: $v, label: $"Unreleased \(($v))" } } | append ($w.released | each {|v| { v: $v, label: $v } }))
    for r in $versions {
        $out = ($out | append ["" $"<a id=\"(release-anchor $r.v)\"></a>" "" $"### ($r.label)"])
        let rows = ($entries | where release == $r.v)
        if ($rows | is-empty) {
            $out = ($out | append ["" "No configuration changes."])
            continue
        }
        for g in $GROUPS {
            let group_rows = (entry-sort ($rows | where group == $g))
            if ($group_rows | is-empty) { continue }
            $out = ($out | append ["" $"#### ($g)" ""] | append ($group_rows | each {|e| render-entry $e }))
        }
    }
    $out | append ["" $END] | str join "\n"
}

# -- The full list ----------------------------------------------------------------

def expected-required [v: record] {
    if $v.required { "yes" } else { "no" }
}

def expected-added [v: record] {
    mut cell = $v.since
    if $v.required_since != null { $cell = $"($cell); required since ($v.required_since)" }
    if $v.deprecated != null { $cell = $"($cell); deprecated in ($v.deprecated.release), use `($v.deprecated.replacement)`" }
    if $v.removed != null { $cell = $"($cell); removed in ($v.removed.release)" }
    $cell
}

const ROW_RE = '^\| <a id="(?<anchor>[^"]*)"></a>`(?<var>[A-Z][A-Z0-9_]*)` \| (?<req>[^|]*?) \| (?<added>[^|]*?) \| (?<rest>.*)$'

# Line indexes bounding the "All variables" section.
def list-bounds [lines: list] {
    let start = ($lines | enumerate | where item == $LIST_HEADING | get 0?.index)
    if $start == null { return null }
    let after = ($lines | skip ($start + 1) | enumerate | where {|r| $r.item starts-with "## " } | get 0?.index)
    let stop = if $after == null { $lines | length } else { $start + 1 + $after }
    { start: $start, stop: $stop }
}

def recent-bounds [lines: list] {
    let b = ($lines | enumerate | where item == $BEGIN | get index)
    let e = ($lines | enumerate | where item == $END | get index)
    if ($b | length) != 1 or ($e | length) != 1 or $b.0 > $e.0 { return null }
    { start: $b.0, stop: $e.0 }
}

# -- Check ----------------------------------------------------------------------

def check-list [lines: list, catalog: list] {
    let bounds = (list-bounds $lines)
    if $bounds == null { return [$"($DOC_FILE): no '($LIST_HEADING)' section"] }
    mut errors = []
    mut seen = []
    for line in ($lines | skip ($bounds.start + 1) | first ($bounds.stop - $bounds.start - 1)) {
        if not ($line starts-with "| ") or ($line starts-with "| Variable") or ($line starts-with "| ---") { continue }
        let row = ($line | parse --regex $ROW_RE)
        if ($row | is-empty) {
            $errors = ($errors | append $"($DOC_FILE): a row in '($LIST_HEADING)' is not `| <a id=...></a>`NAME` | Required | Added in | ...`: ($line | str substring 0..80)")
            continue
        }
        let r = $row.0
        $seen = ($seen | append $r.var)
        let found = ($catalog | where name == $r.var)
        if ($found | is-empty) {
            $errors = ($errors | append $"($DOC_FILE): row ($r.var) names a variable the registry does not declare and ($VARIABLES_FILE) does not list as removed or renamed")
            continue
        }
        let v = $found.0
        if $r.anchor != (slug $r.var) {
            $errors = ($errors | append $"($DOC_FILE): row ($r.var) has anchor '($r.anchor)', expected '(slug $r.var)'")
        }
        let req = ($r.req | parse --regex '^(?<t>yes|no)\b' | get 0?.t)
        if $req != (expected-required $v) {
            $errors = ($errors | append $"($DOC_FILE): row ($r.var) says Required '($r.req)', the facts say '(expected-required $v)'")
        }
        if $r.added != (expected-added $v) {
            $errors = ($errors | append $"($DOC_FILE): row ($r.var) says Added in '($r.added)', the facts say '(expected-added $v)'")
        }
    }
    for v in $catalog {
        let n = ($seen | where {|s| $s == $v.name } | length)
        if $n == 0 { $errors = ($errors | append $"($DOC_FILE): ($v.name) \(($v.source)) has no row in '($LIST_HEADING)'; run `just config-docs`, then describe it") }
        if $n > 1 { $errors = ($errors | append $"($DOC_FILE): ($v.name) has ($n) rows") }
    }
    $errors
}

const ENTRY_RE = '^- (?<b>\*\*Breaking:\*\* )?\[`(?<var>[A-Z][A-Z0-9_]*)`\]\(#(?<anchor>[a-z0-9-]+)\) \(Required: (?<req>yes|no)\) - (?<text>.+)$'

def check-recent [lines: list, entries: list, tags: list] {
    let bounds = (recent-bounds $lines)
    if $bounds == null { return [$"($DOC_FILE): the Recently added markers are missing or out of order; run `just config-docs`"] }
    let anchors = ($lines | str join "\n" | parse --regex '<a id="(?<id>[^"]+)"></a>' | get id)
    mut errors = []
    mut found = []
    mut release: any = null
    mut group: any = null
    for line in ($lines | skip ($bounds.start + 1) | first ($bounds.stop - $bounds.start - 1)) {
        if ($line starts-with "### ") {
            $release = ($line | parse --regex '(?<v>v\d+\.\d+\.\d+)' | get 0?.v)
            $group = null
            continue
        }
        if ($line starts-with "#### ") {
            $group = ($line | str replace "#### " "" | str trim)
            continue
        }
        if not ($line starts-with "- ") { continue }
        let p = ($line | parse --regex $ENTRY_RE)
        if ($p | is-empty) or $release == null or not ($group in $GROUPS) {
            $errors = ($errors | append $"($DOC_FILE): malformed Recently added entry: ($line | str substring 0..80)")
            continue
        }
        let d = $p.0
        let exp = ($entries | where {|e| $e.release == $release and $e.group == $group and $e.var == $d.var })
        if ($exp | is-empty) {
            $errors = ($errors | append $"($DOC_FILE): ($release) ($group) ($d.var) is not a change the registry or ($VARIABLES_FILE) records")
            continue
        }
        let e = $exp.0
        $found = ($found | append $"($release)|($group)|($d.var)")
        let req = if $e.required { "yes" } else { "no" }
        if $d.req != $req {
            $errors = ($errors | append $"($DOC_FILE): ($release) ($group) ($d.var) says Required: ($d.req), the facts say ($req)")
        }
        if ($d.b | is-not-empty) != $e.breaking {
            $errors = ($errors | append $"($DOC_FILE): ($release) ($group) ($d.var) Breaking mark is wrong \(expected ($e.breaking))")
        }
        if $e.breaking and not ($d.text | str contains $e.issue) {
            $errors = ($errors | append $"($DOC_FILE): ($release) Breaking ($d.var) does not name its issue ($e.issue)")
        }
        if $d.anchor != (slug $d.var) or not ($d.anchor in $anchors) {
            $errors = ($errors | append $"($DOC_FILE): ($release) ($d.var) links to #($d.anchor), which is not that variable's row anchor")
        }
    }
    let w = (window $entries $tags)
    let covered = ($w.unreleased | append $w.released)
    for e in ($entries | where {|e| $e.release in $covered }) {
        if not ($"($e.release)|($e.group)|($e.var)" in $found) {
            let what = if $e.breaking { "Breaking " } else { "" }
            $errors = ($errors | append $"($DOC_FILE): ($what)($e.group) ($e.var) in ($e.release) is missing from Recently added; run `just config-docs`")
        }
    }
    $errors
}

# -- Guard: variables read outside the registry ------------------------------------

# Every env name a Rust source reads, by the read shapes this tree uses.
def discover [files: list] {
    mut names = []
    mut consts = {}
    mut const_uses = []
    for f in $files {
        let t = $f.text
        $names = ($names | append ($t | parse --regex 'env::var(?:_os)?\(\s*"(?<n>[A-Z][A-Z0-9_]*)"' | get n))
        $names = ($names | append ($t | parse --regex '\b(?:require_env|required_env|required)\(\s*"(?<n>[A-Z][A-Z0-9_]*)"' | get n))
        $names = ($names | append ($t | parse --regex 'parse_tenant_arg_env\([^,()]*,\s*"(?<n>[A-Z][A-Z0-9_]*)"' | get n))
        if ($t =~ 'EnvFilter::(?:try_)?from_default_env') { $names = ($names | append "RUST_LOG") }
        if ($f.path | str ends-with "src/storage/env.rs") {
            $names = ($names | append ($t | parse --regex '(?:name|deprecated):\s*(?:Some\()?"(?<n>[A-Z][A-Z0-9_]*)"' | get n))
        }
        if ($f.path | str ends-with "src/app_secrets/mod.rs") {
            $names = ($names | append ($t | parse --regex 'Self::\w+\s*=>\s*"(?<n>[A-Z][A-Z0-9_]*)"' | get n))
        }
        for row in ($t | parse --regex 'const\s+(?<ident>[A-Z][A-Z0-9_]*)\s*:\s*&[^=\n]*str\s*=\s*"(?<n>[A-Z][A-Z0-9_]*)"') {
            $consts = ($consts | upsert $row.ident $row.n)
        }
        $const_uses = ($const_uses | append ($t | parse --regex '(?:var|var_os|require_env|required_env|required)\(&?(?<ident>[A-Z][A-Z0-9_]*)\)' | get ident))
    }
    for ident in ($const_uses | uniq) {
        let n = ($consts | get --optional $ident)
        if $n != null { $names = ($names | append $n) }
    }
    $names | uniq | sort
}

def guard-errors [discovered: list, catalog: list] {
    let registry = ($catalog | where source == "registry" | get name)
    let listed = ($catalog | where source == "variables.toml" | get name)
    mut errors = []
    for n in $discovered {
        if ($n in $registry) or ($n in $listed) or ($n in ($NOT_SERVER_CONFIG | columns)) { continue }
        $errors = ($errors | append $"($n) is read outside crate::config::get but is not in ($VARIABLES_FILE); add a [[variable]] with since and required, or a NOT_SERVER_CONFIG reason in scripts/config-docs.nu")
    }
    for n in ($NOT_SERVER_CONFIG | columns) {
        if not ($n in $discovered) {
            $errors = ($errors | append $"NOT_SERVER_CONFIG: ($n) is no longer read; drop the entry")
        }
    }
    for n in $listed {
        if not ($n in $discovered) {
            $errors = ($errors | append $"($VARIABLES_FILE): ($n) is listed but no source reads it; move it to [[removed]] or drop it")
        }
        if ($n in $registry) {
            $errors = ($errors | append $"($VARIABLES_FILE): ($n) is also a registry key; declare it once")
        }
    }
    $errors
}

# -- Generate -------------------------------------------------------------------

def generate-doc [doc: string, catalog: list, entries: list, tags: list] {
    mut lines = ($doc | lines)
    let rb = (recent-bounds $lines)
    if $rb == null { error make { msg: $"($DOC_FILE): add the two marker lines under '## Recently added' first:\n($BEGIN)\n($END)" } }
    let recent = (render-recent $entries $tags | lines)
    $lines = ($lines | first $rb.start | append $recent | append ($lines | skip ($rb.stop + 1)))

    let lb = (list-bounds $lines)
    if $lb == null { error make { msg: $"($DOC_FILE): no '($LIST_HEADING)' section" } }
    mut seen = []
    mut last_row: any = null
    for i in ($lb.start + 1)..<($lb.stop) {
        let line = ($lines | get $i)
        let row = ($line | parse --regex $ROW_RE)
        if ($row | is-empty) { continue }
        let r = $row.0
        $last_row = $i
        $seen = ($seen | append $r.var)
        let found = ($catalog | where name == $r.var)
        if ($found | is-empty) { continue }
        let v = $found.0
        let req = ($r.req | str replace --regex '^(yes|no)\b' (expected-required $v))
        let req = if ($req =~ '^(yes|no)\b') { $req } else { expected-required $v }
        $lines = ($lines | update $i $"| <a id=\"(slug $r.var)\"></a>`($r.var)` | ($req) | (expected-added $v) | ($r.rest)")
    }
    let missing = ($catalog | where {|v| not ($v.name in $seen) })
    if ($missing | is-not-empty) {
        if $last_row == null { error make { msg: $"($DOC_FILE): '($LIST_HEADING)' has no table to add rows to" } }
        let new_rows = ($missing | each {|v| $"| <a id=\"(slug $v.name)\"></a>`($v.name)` | (expected-required $v) | (expected-added $v) | `.env` | Not described yet: say what it does. |" })
        $lines = ($lines | first ($last_row + 1) | append $new_rows | append ($lines | skip ($last_row + 1)))
    }
    $"($lines | str join "\n")\n"
}

# -- Repo plumbing ----------------------------------------------------------------

def load-repo [] {
    let registry = (parse-registry (open --raw $REGISTRY_FILE | decode utf-8))
    let meta = (open --raw $VARIABLES_FILE | decode utf-8 | from toml)
    let catalog = (build-catalog $registry $meta)
    let built = (build-entries $catalog $meta)
    { catalog: $catalog, entries: $built.entries, errors: ((catalog-errors $catalog) | append $built.errors), tags: (release-tags) }
}

def repo-sources [] {
    glob src/**/*.rs | append (glob crates/**/*.rs) | each {|p| { path: ($p | path relative-to $env.PWD), text: (open --raw $p | decode utf-8) } }
}

def fail-on [errors: list, what: string] {
    if ($errors | is-empty) { return }
    print --stderr $"ERROR: ($what)"
    for e in $errors { print --stderr $"  ($e)" }
    exit 1
}

def main [] {
    print "usage: nu scripts/config-docs.nu <generate|check|since <version>|release-notes <version>|self-test>"
}

def "main generate" [] {
    let repo = (load-repo)
    fail-on $repo.errors "the configuration facts are inconsistent"
    let doc = (open --raw $DOC_FILE | decode utf-8)
    let next = (generate-doc $doc $repo.catalog $repo.entries $repo.tags)
    if $next == $doc { print $"($DOC_FILE) is current"; return }
    $next | save --force $DOC_FILE
    print $"rewrote the generated parts of ($DOC_FILE)"
}

def "main check" [] {
    let repo = (load-repo)
    let lines = (open --raw $DOC_FILE | decode utf-8 | lines)
    let errors = (
        $repo.errors
        | append (guard-errors (discover (repo-sources)) $repo.catalog)
        | append (check-list $lines $repo.catalog)
        | append (check-recent $lines $repo.entries $repo.tags)
    )
    fail-on $errors "docs/configuration.md disagrees with the configuration facts (PMS-1442)"
    print $"config docs OK: ($repo.catalog | length) variables, ($repo.entries | length) changelog entries"
}

def "main since" [
    version: string   # the release you run now, e.g. v0.13.0
] {
    let repo = (load-repo)
    let after = ($repo.entries | where {|e| (vnum $e.release) > (vnum $version) })
    if ($after | is-empty) { print $"No configuration changes after ($version)."; return }
    let rows = ($after | sort-by {|e| $"((vnum $e.release) + 1000000000)(if $e.breaking { 0 } else { 1 })($e.var)" } | each {|e|
        {
            release: $e.release
            change: $e.group
            variable: $e.var
            required: (if $e.required { "REQUIRED" } else { "no" })
            breaking: (if $e.breaking { "BREAKING" } else { "" })
            issue: $e.issue
            action: $e.action
        }
    })
    print ($rows | table --expand --width 200)
    let breaking = ($rows | where breaking == "BREAKING" | length)
    print $"($rows | length) changes after ($version), ($breaking) breaking: apply every BREAKING action before restarting."
}

def "main release-notes" [
    version: string    # the release being cut, e.g. v0.17.0
    --ref: string      # git ref the doc link points at (default: the version tag)
] {
    let repo = (load-repo)
    let ref = ($ref | default $version)
    let rows = ($repo.entries | where release == $version)
    let link = $"($REPO_URL)/src/tag/($ref)/($DOC_FILE)#(release-anchor $version)"
    let link = if $ref == $version { $link } else { $"($REPO_URL)/src/branch/($ref)/($DOC_FILE)#(release-anchor $version)" }
    print "## Configuration changes"
    print ""
    if ($rows | is-empty) {
        print $"No configuration changes in ($version). Full list: [docs/configuration.md]\(($link))."
        return
    }
    let breaking = ($rows | where breaking)
    print $"[Configuration changes in ($version)]\(($link)): ($rows | length) entries, ($breaking | length) breaking."
    if ($breaking | is-not-empty) {
        print ""
        for e in $breaking { print $"- **Breaking:** `($e.var)` - ($e.action) \(($e.issue))" }
    }
}

# -- Self-test --------------------------------------------------------------------

def fixture [] {
    let registry_text = '
    Bootstrap OLD_KEY = "OLD_KEY", since "v0.1.0", required;
    Application OPT_KEY = "OPT_KEY", since "v9.1.0", optional;
    Application LATE_REQ = "LATE_REQ", since "v9.0.0", required "v9.1.0";
'
    let meta = {
        variable: [{ name: "BOOT_KEY", since: "v9.1.0", required: false, reader: "src/x.rs" }]
        removed: [{ name: "GONE_KEY", since: "v9.0.0", removed: "v9.1.0", issue: "PMS-2", action: "Delete it." }]
        change: [{ release: "v9.1.0", group: "Changed", variables: ["LATE_REQ"], issue: "PMS-1", breaking: true, action: "Set it." }]
    }
    { registry_text: $registry_text, meta: $meta, tags: ["v0.1.0" "v9.0.0" "v9.1.0"] }
}

def fixture-doc [] {
    [
        "# Configuration"
        ""
        "## Recently added"
        ""
        $BEGIN
        $END
        ""
        $LIST_HEADING
        ""
        "| Variable | Required | Added in | Where set | Purpose |"
        "| --- | --- | --- | --- | --- |"
        '| <a id="var-old-key"></a>`OLD_KEY` | yes | v0.1.0 | `.env` | Old. |'
        '| <a id="var-opt-key"></a>`OPT_KEY` | no, default `1` | v9.1.0 | `.env` | Opt. |'
        '| <a id="var-late-req"></a>`LATE_REQ` | yes | v9.0.0; required since v9.1.0 | `.env` | Late. |'
        '| <a id="var-boot-key"></a>`BOOT_KEY` | no | v9.1.0 | `.env` | Boot. |'
        '| <a id="var-gone-key"></a>`GONE_KEY` | no | v9.0.0; removed in v9.1.0 | `.env` | Gone. |'
        ""
    ] | str join "\n"
}

def all-errors [registry_text: string, meta: record, tags: list, doc: string] {
    let catalog = (build-catalog (parse-registry $registry_text) $meta)
    let built = (build-entries $catalog $meta)
    let lines = ($doc | lines)
    (catalog-errors $catalog) | append $built.errors | append (check-list $lines $catalog) | append (check-recent $lines $built.entries $tags)
}

def generated [f: record] {
    let catalog = (build-catalog (parse-registry $f.registry_text) $f.meta)
    let built = (build-entries $catalog $f.meta)
    generate-doc (fixture-doc) $catalog $built.entries $f.tags
}

def "main self-test" [] {
    let f = (fixture)
    let good = (generated $f)
    let new_req = ($f.registry_text + '    Application NEW_REQ = "NEW_REQ", since "v9.1.0", required;' + "\n")
    let new_req_meta = ($f.meta | update change ($f.meta.change | append { release: "v9.1.0", group: "Added", variables: ["NEW_REQ"], issue: "PMS-3", action: "Set it first." }))
    let new_req_doc = (generated { registry_text: $new_req, meta: $new_req_meta, tags: $f.tags })
    let cases = [
        [name, errors, expect];
        ["a generated doc passes", (all-errors $f.registry_text $f.meta $f.tags $good), 0]
        ["generating twice changes nothing", (do {
            let catalog = (build-catalog (parse-registry $f.registry_text) $f.meta)
            let again = (generate-doc $good $catalog (build-entries $catalog $f.meta).entries $f.tags)
            if $again == $good { [] } else { ["the second run rewrote the doc"] }
        }), 0]
        ["a key without a row fails", (all-errors $f.registry_text $f.meta $f.tags ($good | lines | where {|l| not ($l | str contains '`OPT_KEY` |') } | str join "\n")), 1]
        ["a Required mismatch fails", (all-errors $f.registry_text $f.meta $f.tags ($good | str replace '`OLD_KEY` | yes' '`OLD_KEY` | no')), 1]
        ["an Added in mismatch fails", (all-errors $f.registry_text $f.meta $f.tags ($good | str replace '`OPT_KEY` | no, default `1` | v9.1.0' '`OPT_KEY` | no, default `1` | v9.0.0')), 1]
        ["an unknown row fails", (all-errors $f.registry_text $f.meta $f.tags ($good | str replace "| <a id=\"var-boot-key\">" "| <a id=\"var-mystery\"></a>`MYSTERY` | no | v9.1.0 | `.env` | ? |\n| <a id=\"var-boot-key\">")), 1]
        ["a removed row with its note passes", (all-errors $f.registry_text $f.meta $f.tags $good | where {|e| $e | str contains "GONE_KEY" }), 0]
        ["a new required key passes with its Breaking entry", (all-errors $new_req $new_req_meta $f.tags $new_req_doc), 0]
        ["a new required key missing from the changelog fails", (all-errors $new_req $new_req_meta $f.tags ($new_req_doc | lines | where {|l| not (($l starts-with "- ") and ($l | str contains "NEW_REQ")) } | str join "\n")), 1]
        ["a new required key without its Breaking mark fails", (all-errors $new_req $new_req_meta $f.tags ($new_req_doc | str replace '- **Breaking:** [`NEW_REQ`]' '- [`NEW_REQ`]')), 1]
        ["a Breaking change without an issue and action fails", (build-entries (build-catalog (parse-registry $new_req) $f.meta) $f.meta | get errors), 1]
        ["a wrong Required flag in the changelog fails", (all-errors $f.registry_text $f.meta $f.tags ($good | str replace '[`OPT_KEY`](#var-opt-key) (Required: no)' '[`OPT_KEY`](#var-opt-key) (Required: yes)')), 1]
        ["an entry linking to a missing anchor fails", (all-errors $f.registry_text $f.meta $f.tags ($good | str replace '[`OPT_KEY`](#var-opt-key)' '[`OPT_KEY`](#var-nope)')), 1]
        ["a read outside the registry that is not listed fails", (guard-errors ["BOOT_KEY" "SURPRISE_KEY"] (build-catalog (parse-registry $f.registry_text) $f.meta)), 1]
        ["a listed variable nothing reads fails", (guard-errors [] (build-catalog (parse-registry $f.registry_text) $f.meta)), 1]
        ["discover finds env::var, helpers, consts and EnvFilter", (do {
            let src = [{ path: "src/a.rs", text: "const K: &str = \"CONST_KEY\";\nstd::env::var(K);\nstd::env::var(\"LIT_KEY\");\nrequired(\"HELPER_KEY\");\nEnvFilter::try_from_default_env()" }]
            let found = (discover $src)
            ["CONST_KEY" "LIT_KEY" "HELPER_KEY" "RUST_LOG"] | where {|n| not ($n in $found) }
        }), 0]
    ]
    mut failed = 0
    for c in $cases {
        let n = ($c.errors | length)
        if ($c.expect == 0 and $n == 0) or ($c.expect > 0 and $n > 0) {
            print $"self-test: ($c.name)"
        } else {
            let want = if $c.expect == 0 { "no errors" } else { "an error" }
            print --stderr $"self-test: FAIL \(($c.name): expected ($want), got ($n))"
            for e in $c.errors { print --stderr $"    ($e)" }
            $failed += 1
        }
    }
    if $failed > 0 { exit 1 }
    print "config-docs self-test: clean"
}
