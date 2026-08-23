#!/usr/bin/env nu

# Environment-variable parity guard (PMS-836).
#
# Three sets have to agree:
#   CODE     every env var `src/` and `crates/` read at run time
#   TEMPLATE every key assigned in .env.example, commented-out lines included
#   COMPOSE  every key in the `server` service's environment map in
#            compose.dev.yml
#
# A var in CODE with no TEMPLATE key is undiscoverable: an operator has no way
# to learn it exists. A var in CODE with no COMPOSE line cannot be set in dev at
# all, because that map enumerates the container's environment - the operator
# edits .env, gets no error, and the feature silently stays off. That is how
# SPA_BASE_URL, ABUSE_CONTACT_EMAIL, PUBLIC_API_BASE_URL and TENANT_LOGO_MAX_BYTES
# shipped unreachable. A TEMPLATE key nothing consumes is the mirror defect: it
# reads as configuration and is inert (STRIPE_SECRET_KEY, PMS-836 CF-13).
#
# Every deliberate asymmetry is listed in ALLOWLIST below with its reason.

# Rust helpers that take an env var NAME as a string literal. A read through one
# of these is a read, and missing them is how BUNYIP_WEBHOOK_SECRET stayed
# invisible to a plain `env::var` grep.
const ENV_HELPERS = ["require_env" "required_env" "resolve_secret"]

# Same idea, for helpers that take the env var NAME as their SECOND argument.
# `parse_tenant_arg_env(args, "MOKOSH_SHOWCASE_TENANT_ID", "showcase")` is a
# read, and the first-argument regex above could not see it (PMS-853).
const ENV_HELPERS_ARG2 = ["parse_tenant_arg_env"]

# Names in CODE that deliberately have no .env.example key.
const CODE_NOT_IN_TEMPLATE = {
    CARGO_PKG_VERSION: "build-time, set by cargo itself"
    MOKOSH_GIT_HASH: "build-time, injected by build.rs / the OCI build ARG"
    MOKOSH_GIT_DESCRIBE: "build-time, injected by build.rs / the OCI build ARG"
    MOKOSH_BUILD_DATE: "build-time, injected by build.rs / the OCI build ARG"
    SOURCE_DATE_EPOCH: "build-time reproducible-build input, never a runtime setting"
    MOKOSH_ENV_FILE: "host-side mokosh-bootstrap CLI flag default, not server config"
    MOKOSH_QA_TENANT_ID: "host-side qa-seed / qa-teardown CLI argument fallback"
    MOKOSH_SHOWCASE_TENANT_ID: "host-side showcase-seed / -refresh / -teardown CLI argument fallback"
    INFISICAL_ADMIN_EMAIL: "host-side bootstrap CLI; lives in .env.infisical"
    INFISICAL_ADMIN_PASSWORD: "host-side bootstrap CLI; lives in .env.infisical"
    INFISICAL_ADMIN_FIRST_NAME: "host-side bootstrap CLI; lives in .env.infisical"
    INFISICAL_ADMIN_LAST_NAME: "host-side bootstrap CLI; lives in .env.infisical"
    INFISICAL_IDENTITY_NAME: "host-side bootstrap CLI; lives in .env.infisical"
    INFISICAL_PROJECT_NAME: "host-side bootstrap CLI; lives in .env.infisical"
    INFISICAL_ADDRESS: "container-side name; .env carries it as MOKOSH_SERVER_INFISICAL_ADDRESS so the host-side and in-network URLs stay separate (PMS-707)"
    OIDC_ISSUER: "dev value is derived from ${USER} in compose.dev.yml so it always matches the Traefik route; compose does not interpolate a .env override, so a key here would be inert. Both names and the reason are documented in the .env.example prose block above OIDC_DEFAULT_TENANT_ID (PMS-853)"
    OIDC_AUDIENCE: "dev value is derived from ${USER} in compose.dev.yml so it always matches the Traefik route; compose does not interpolate a .env override, so a key here would be inert. Both names and the reason are documented in the .env.example prose block above OIDC_DEFAULT_TENANT_ID (PMS-853)"
}

# Names in CODE that deliberately have no compose.dev.yml server line.
const CODE_NOT_IN_COMPOSE = {
    CARGO_PKG_VERSION: "build-time, set by cargo itself"
    MOKOSH_GIT_HASH: "build-time, injected by build.rs / the OCI build ARG"
    MOKOSH_GIT_DESCRIBE: "build-time, injected by build.rs / the OCI build ARG"
    MOKOSH_BUILD_DATE: "build-time, injected by build.rs / the OCI build ARG"
    SOURCE_DATE_EPOCH: "build-time reproducible-build input, never a runtime setting"
    MOKOSH_ENV_FILE: "host-side mokosh-bootstrap CLI flag default, not server config"
    MOKOSH_QA_TENANT_ID: "host-side qa-seed / qa-teardown CLI argument fallback"
    MOKOSH_SHOWCASE_TENANT_ID: "host-side showcase-* CLI argument fallback"
    INFISICAL_URL: "host-side bootstrap CLI runs on the host, not in the server container"
    INFISICAL_ADMIN_EMAIL: "host-side bootstrap CLI runs on the host"
    INFISICAL_ADMIN_PASSWORD: "host-side bootstrap CLI runs on the host"
    INFISICAL_ADMIN_FIRST_NAME: "host-side bootstrap CLI runs on the host"
    INFISICAL_ADMIN_LAST_NAME: "host-side bootstrap CLI runs on the host"
    INFISICAL_IDENTITY_NAME: "host-side bootstrap CLI runs on the host"
    INFISICAL_PROJECT_NAME: "host-side bootstrap CLI runs on the host"
}

# Keys in TEMPLATE that no Rust file and no compose.dev.yml interpolation reads.
#
# PMS-853 emptied this: the eight integration credentials (TACTICAL_RMM_*,
# TWILIO_*, SLACK_*, TEAMS_WEBHOOK_URL) were deleted from .env.example because
# nothing reads them, and the dead host-side Infisical key was renamed onto
# INFISICAL_URL, which the bootstrap CLI has always read. An entry belongs here
# only when a key must stay in the template despite having no reader; there is
# no such key today.
const TEMPLATE_UNREAD = {}

# Extract every env var name the Rust sources read.
def code-reads [] {
    let files = (glob src/**/*.rs | append (glob crates/**/*.rs) | sort)
    if ($files | is-empty) {
        print --stderr "ERROR: no Rust sources found under src/ or crates/"
        exit 1
    }

    let helper_regex = (
        ['(?:' ($ENV_HELPERS | str join '|') ')\(\s*"(?<name>[A-Z][A-Z0-9_]*)"'] | str join ''
    )
    let helper_arg2_regex = (
        ['(?:' ($ENV_HELPERS_ARG2 | str join '|') ')\([^,()]*,\s*"(?<name>[A-Z][A-Z0-9_]*)"']
        | str join ''
    )

    # One regex pass per pattern per FILE, not per line: `parse --regex` returns
    # every non-overlapping match in the whole string, and the per-line version
    # of this took 85s on this tree.
    mut names = []
    mut const_names = {}
    mut const_uses = []

    for file in $files {
        let text = (open --raw $file | decode utf-8)
        # std::env::var("NAME") / env::var_os("NAME")
        $names = ($names | append (
            $text | parse --regex 'env::var(?:_os)?\(\s*"(?<name>[A-Z][A-Z0-9_]*)"' | get name
        ))
        # require_env("NAME") and friends
        $names = ($names | append ($text | parse --regex $helper_regex | get name))
        # parse_tenant_arg_env(args, "NAME", label) and friends
        $names = ($names | append ($text | parse --regex $helper_arg2_regex | get name))
        # const ALLOWLIST_VAR: &str = "NAME";  read as  env::var(ALLOWLIST_VAR)
        for row in ($text | parse --regex 'const\s+(?<ident>[A-Z][A-Z0-9_]*)\s*:\s*&[^=\n]*str\s*=\s*"(?<name>[A-Z][A-Z0-9_]*)"') {
            $const_names = ($const_names | insert $row.ident $row.name)
        }
        $const_uses = ($const_uses | append (
            $text | parse --regex 'env::var(?:_os)?\(\s*(?<ident>[A-Z][A-Z0-9_]*)\s*\)' | get ident
        ))
    }

    for ident in ($const_uses | uniq) {
        let resolved = ($const_names | get --optional $ident)
        if $resolved != null { $names = ($names | append $resolved) }
    }

    $names | uniq | sort
}

# Every key assigned in .env.example, commented-out assignments included.
def template-keys [] {
    open --raw .env.example
    | decode utf-8
    | lines
    | each {|line| $line | parse --regex '^\s*#?\s*(?<key>[A-Z][A-Z0-9_]*)\s*=' | get key? }
    | flatten
    | uniq
    | sort
}

# Every key in the `server` service's environment map.
def compose-keys [] {
    open compose.dev.yml | get services.server.environment | columns | sort
}

# Every name compose.dev.yml interpolates anywhere, so a .env key consumed only
# by compose (the Infisical sidecars, the Postgres knobs) counts as read.
def compose-interpolations [] {
    open --raw compose.dev.yml
    | decode utf-8
    | lines
    | each {|line| $line | parse --regex '\$\{(?<name>[A-Z][A-Z0-9_]*)' | get name }
    | flatten
    | uniq
    | sort
}

def main [] {
    let code = (code-reads)
    let template = (template-keys)
    let compose = (compose-keys)
    let interpolated = (compose-interpolations)

    mut errors = []

    for name in $code {
        if not ($name in $template) and not ($name in ($CODE_NOT_IN_TEMPLATE | columns)) {
            $errors = ($errors | append $".env.example: ($name) is read by the code but has no key; add it \(a commented-out `# ($name)=` counts\) or allowlist it in CODE_NOT_IN_TEMPLATE with a reason")
        }
        if not ($name in $compose) and not ($name in ($CODE_NOT_IN_COMPOSE | columns)) {
            $errors = ($errors | append $"compose.dev.yml: ($name) is read by the code but the server service does not forward it, so it cannot be set in dev; add `($name): ${($name):-}` or allowlist it in CODE_NOT_IN_COMPOSE with a reason")
        }
    }

    for key in $template {
        if ($key in $code) or ($key in $interpolated) { continue }
        if ($key in ($TEMPLATE_UNREAD | columns)) { continue }
        $errors = ($errors | append $".env.example: ($key) is assigned but no Rust file and no compose.dev.yml interpolation reads it; delete it or allowlist it in TEMPLATE_UNREAD with a reason")
    }

    # An allowlist entry that no longer describes a real asymmetry is stale
    # documentation of a fixed problem, and it silently re-permits the defect if
    # the name comes back.
    for entry in ($CODE_NOT_IN_TEMPLATE | columns) {
        if ($entry in $template) {
            $errors = ($errors | append $"CODE_NOT_IN_TEMPLATE: ($entry) is in .env.example now; drop the allowlist entry")
        }
    }
    for entry in ($CODE_NOT_IN_COMPOSE | columns) {
        if ($entry in $compose) {
            $errors = ($errors | append $"CODE_NOT_IN_COMPOSE: ($entry) is forwarded now; drop the allowlist entry")
        }
    }
    for entry in ($TEMPLATE_UNREAD | columns) {
        if not ($entry in $template) {
            $errors = ($errors | append $"TEMPLATE_UNREAD: ($entry) is gone from .env.example; drop the allowlist entry")
        }
        if ($entry in $code) or ($entry in $interpolated) {
            $errors = ($errors | append $"TEMPLATE_UNREAD: ($entry) has a reader now; drop the allowlist entry")
        }
    }

    if ($errors | is-empty) {
        print $"env parity OK: ($code | length) vars read by code, ($template | length) keys in .env.example, ($compose | length) forwarded to the dev server"
    } else {
        print --stderr "ERROR: environment-variable parity broken."
        print --stderr "Every var the code reads needs a .env.example key AND a compose.dev.yml server line."
        for e in $errors { print --stderr $"  ($e)" }
        exit 1
    }
}
