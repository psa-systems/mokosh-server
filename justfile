# Mokosh Server - Task Runner

compose_file := "compose.dev.yml"

# List available recipes
default:
    @just --list

# Create .env from .env.dev if missing
[private]
[group: 'hooks']
ensure-env:
    @test -f .env || cp .env.dev .env

# Bring up the dev stack (mokosh-server + Postgres + Valkey (no Infisical — use just dev-infisical)). Trailing args go to `docker compose up` (e.g. --detach).
[doc("Start the dev stack in Docker. Trailing args go to `docker compose up` (e.g. --detach).")]
[group: 'dev']
dev *args: ensure-env
    #!/usr/bin/env nu
    let bind_ip = (
        sys net
        | where name =~ 'eth0|br0'
        | get ip
        | flatten
        | where protocol == 'ipv4' and $it.loop == false
        | get address.0
    )
    let user_name = (^whoami | str trim)
    print $"Binding mokosh-server host port to ($bind_ip) as user ($user_name)"
    let updated = (
        open .env --raw
        | lines
        | where not ($it | str starts-with 'MOKOSH_HOST_BIND_IP=')
        | where not ($it | str starts-with 'USER=')
        | append $"MOKOSH_HOST_BIND_IP=($bind_ip)"
        | append $"USER=($user_name)"
        | str join "\n"
    )
    if ('.env.new' | path exists) { rm .env.new }
    $"($updated)\n" | save .env.new
    mv .env.new .env
    docker compose --file {{ compose_file }} up {{ args }}

# Start only Infisical + its Postgres (opt-in; not started by `just dev`).
[doc("Start Infisical and its Postgres sidecar (compose profile: infisical)")]
[group: 'dev']
dev-infisical *args: ensure-env
    docker compose --file {{ compose_file }} --profile infisical up {{ args }} infisical infisical-postgres

# Generate the dev OIDC Ed25519 keypair (kid=dev-key) if missing.
# Each per-developer instance must generate its own; the repo does not
# ship private keys (see secrets/ in .gitignore). Without these the
# server crash-loops with "Failed to read OIDC private key".
[private]
ensure-oidc-keys:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -f secrets/dev-key.pem ] && [ -f secrets/dev-key.pub.pem ]; then
        exit 0
    fi
    bash ./scripts/gen-oidc-key.sh dev-key

# Per-developer Traefik-routed instance for SSO testing.
#   API:  https://{USER}-mokosh-api.a8n.run
# Run `just dev-sso` here AND in mokosh-clients to get both ends up.
# Each per-developer stack gets its OWN private network,
# `dev-mokosh-private-${USER}`, matching the name compose.dev.yml
# assigns. The dev-sso overlay marks that network external (it only
# ATTACHES rather than owning it), so compose will not create it. We
# create it defensively here (idempotent: skipped if it already
# exists). The name MUST match the base/overlay name or the server
# lands on a different network than Postgres and crash-loops on DB
# connect. Without this step a clean host would have nothing to attach
# to and `docker compose up` would error.
[private]
ensure-private-network:
    @docker network inspect dev-mokosh-private-${USER} >/dev/null 2>&1 || docker network create dev-mokosh-private-${USER} >/dev/null

[doc("Start the SSO dev stack (Traefik-routed at *.a8n.run)")]
[group: 'dev']
dev-sso: ensure-env ensure-oidc-keys ensure-private-network
    docker compose --file {{ compose_file }} --file compose.dev-sso.yml up --build --detach
    @echo ""
    @echo "Mokosh API (OIDC IdP):"
    @echo "  https://{{env('USER')}}-mokosh-api.a8n.run"
    @echo "  https://{{env('USER')}}-mokosh-api.a8n.run/.well-known/openid-configuration"
    @echo ""
    @echo "Next:"
    @echo "  1. (cd ../mokosh-clients && just dev-sso)"
    @echo "  2. just register-client     # registers mokosh-clients-web in oauth_clients"
    @echo "  3. Set MOKOSH_OIDC_CLIENT_ID in mokosh-clients/.env to the printed UUID"

# Stop the SSO dev stack.
[doc("Stop the SSO dev stack")]
[group: 'dev']
dev-sso-down: ensure-env
    docker compose --file {{ compose_file }} --file compose.dev-sso.yml down

# Bring the SSO dev stack down and back up. Useful after pulling a
# code change or editing compose env vars: `down` waits for containers
# to fully terminate before `dev-sso` starts the fresh ones, so the
# rebuild picks up the new state. `down` is synchronous (docker
# compose down blocks until removal completes) and `dev-sso` uses
# `--detach`, so this returns once the new stack is up.
[doc("Stop the dev stack and start dev-sso fresh.")]
[group: 'dev']
restart: down dev-sso

# Register mokosh-clients as a public OIDC client. Run once after
# `just dev-sso` is up. Prints the client_id UUID; copy it into
# mokosh-clients/.env as MOKOSH_OIDC_CLIENT_ID.
[doc("Register bunyip-web as a public OIDC client (one-shot, idempotent on (name))")]
register-bunyip-client: ensure-env
    #!/usr/bin/env nu
    let user = $env.USER
    let api_origin = $"https://($user)-mokosh-api.a8n.run"
    let hub_origin = $"https://($user)-bunyip.a8n.run"
    let database_url = ($env.DATABASE_URL_IN_CONTAINER? | default "postgres://postgres:postgres@postgres:5432/mokosh")
    docker compose --file {{ compose_file }} --file compose.dev-sso.yml exec --env $"DATABASE_URL=($database_url)" --env "MOKOSH_CLIENT_NAME=bunyip-web" --env "MOKOSH_CLIENT_TYPE=public" --env $"MOKOSH_CLIENT_REDIRECT_URIS=($hub_origin)/auth/callback" --env $"MOKOSH_CLIENT_POST_LOGOUT_URIS=($hub_origin)/" --env "MOKOSH_CLIENT_SCOPES=openid email offline_access" --env "MOKOSH_CLIENT_GRANT_TYPES=authorization_code refresh_token" --env "MOKOSH_CLIENT_AUTH_METHOD=none" --env $"MOKOSH_CLIENT_AUDIENCE=($api_origin)" --env "MOKOSH_CLIENT_ACCESS_TOKEN_TTL=1800" server cargo run --quiet --bin mokosh-bootstrap -- clients register

# Register lets-chat as a confidential OIDC client. Run once after
# `just dev-sso` is up. Prints the client_id UUID + client_secret;
# capture both:
#   client_id     -> lets-chat/.env LETS_CHAT_SSO_CLIENT_ID
#   client_secret -> lets-chat/.env LETS_CHAT_SSO_CLIENT_SECRET (gitignored)
# The secret cannot be retrieved later, only rotated. Lose it = re-run
# this recipe + update .env.
[doc("Register lets-chat as a confidential OIDC client (one-shot, idempotent on (name))")]
register-lets-chat-client: ensure-env
    #!/usr/bin/env nu
    let user = $env.USER
    let api_origin = $"https://($user)-mokosh-api.a8n.run"
    let chat_origin = $"https://($user)-chat.a8n.run"
    let database_url = ($env.DATABASE_URL_IN_CONTAINER? | default "postgres://postgres:postgres@postgres:5432/mokosh")
    docker compose --file {{ compose_file }} --file compose.dev-sso.yml exec --env $"DATABASE_URL=($database_url)" --env "MOKOSH_CLIENT_NAME=lets-chat" --env "MOKOSH_CLIENT_TYPE=confidential" --env "MOKOSH_CLIENT_AUTH_METHOD=client_secret_basic" --env $"MOKOSH_CLIENT_REDIRECT_URIS=($chat_origin)/auth/sso/default/callback" --env $"MOKOSH_CLIENT_POST_LOGOUT_URIS=($chat_origin)/" --env "MOKOSH_CLIENT_SCOPES=openid email profile" --env "MOKOSH_CLIENT_GRANT_TYPES=authorization_code" --env $"MOKOSH_CLIENT_AUDIENCE=($api_origin)" --env "MOKOSH_CLIENT_DESCRIPTION=Real-time team chat" --env $"MOKOSH_CLIENT_ICON_URL=($chat_origin)/static/lets-chat.png" --env "MOKOSH_CLIENT_ACCESS_TOKEN_TTL=1800" server cargo run --quiet --bin mokosh-bootstrap -- clients register

[doc("Register mokosh-clients as a public OIDC client (one-shot, idempotent on (name))")]
register-client: ensure-env
    #!/usr/bin/env nu
    let user = $env.USER
    let api_origin = $"https://($user)-mokosh-api.a8n.run"
    let app_origin = $"https://($user)-mokosh.a8n.run"
    # In-network DNS: the postgres compose service is reachable at the
    # short name `postgres` from inside any container on the private
    # network. The DATABASE_URL_IN_CONTAINER value in .env is not
    # exported to the host shell (compose reads it for interpolation),
    # so we hardcode the in-network URL here as the canonical fallback.
    let database_url = ($env.DATABASE_URL_IN_CONTAINER? | default "postgres://postgres:postgres@postgres:5432/mokosh")
    docker compose --file {{ compose_file }} --file compose.dev-sso.yml exec --env $"DATABASE_URL=($database_url)" --env "MOKOSH_CLIENT_NAME=PSA-Mokosh-Clients" --env "MOKOSH_CLIENT_TYPE=public" --env $"MOKOSH_CLIENT_REDIRECT_URIS=($app_origin)/auth/callback" --env $"MOKOSH_CLIENT_POST_LOGOUT_URIS=($app_origin)/" --env "MOKOSH_CLIENT_SCOPES=openid email offline_access" --env "MOKOSH_CLIENT_GRANT_TYPES=authorization_code refresh_token" --env "MOKOSH_CLIENT_AUTH_METHOD=none" --env $"MOKOSH_CLIENT_AUDIENCE=($api_origin)" --env "MOKOSH_CLIENT_DESCRIPTION=PSA tools for the day-to-day" --env $"MOKOSH_CLIENT_ICON_URL=($app_origin)/assets/icon.svg" --env "MOKOSH_CLIENT_ACCESS_TOKEN_TTL=1800" server cargo run --quiet --bin mokosh-bootstrap -- clients register

# Stop everything this repo runs (both LAN-IP and SSO modes), regardless
# of which `just dev*` you started with. Volumes preserved.
# `--remove-orphans` cleans up containers from one compose file that the
# other file does not declare (e.g. the SSO postgres if you only ran
# `just dev` historically).
[doc("Stop the entire dev stack (LAN-IP and SSO modes). Volumes preserved.")]
[group: 'dev']
down: ensure-env
    docker compose --file {{ compose_file }} --file compose.dev-sso.yml down --remove-orphans

# Stop the dev stack (compose.dev.yml). Volumes preserved.
[doc("Stop the dev stack (volumes preserved)")]
[group: 'dev']
dev-down: ensure-env
    docker compose --file {{ compose_file }} down

# Wipe the dev stack: stop, remove volumes, remove .env. Preserves .env.infisical.
[doc("Wipe Infisical volumes and .env. Preserves .env.infisical.")]
[group: 'dev']
dev-clean: ensure-env
    #!/usr/bin/env nu
    docker compose --file {{ compose_file }} down --volumes
    if ('.env' | path exists) { rm .env }

# Bootstrap Infisical for the dev stack (run once after `just dev`).
[doc("Bootstrap Infisical for the dev stack (run once after `just dev`)")]
infisical-bootstrap: ensure-env
    #!/usr/bin/env nu
    let env_file = ".env.infisical"
    let envs = if ($env_file | path exists) {
        open $env_file
        | lines
        | where $it !~ '^#'
        | where ($it | is-not-empty)
        | parse '{name}={value}'
        | transpose --header-row --as-record
    } else {
        {}
    }
    with-env $envs {
        cargo run --quiet --bin mokosh-bootstrap -- bootstrap-infisical
    }

# Run all checks (compile, clippy, fmt)
[group: 'check']
check: check-compile check-clippy check-fmt

# Check compilation
[group: 'check']
check-compile:
    cargo check --all-targets

# Run clippy lints
[group: 'check']
check-clippy:
    cargo clippy --all-targets

# Check formatting
[group: 'check']
check-fmt:
    cargo fmt --all --check

# Format code
[group: 'format']
fmt:
    cargo fmt --all

# Run tests
[group: 'test']
test:
    cargo test

# Run the Playwright E2E suite against staging (or $E2E_BASE_URL). Trailing args
# pass through to `playwright test`, e.g. `just test-e2e --headed`. PMS-140.
[group: 'test']
test-e2e *args:
    cd e2e && npm ci && npx playwright install --with-deps chromium && npx playwright test {{args}}

# Build release binaries
[group: 'build']
build:
    cargo build --release --bins

# Build OCI image for validation (builder stage)
[group: 'check']
check-docker:
    #!/usr/bin/env nu
    let git_hash = (^git rev-parse --short=12 HEAD | str trim)
    let git_describe = (^git describe --tags --always --dirty | str trim)
    let build_date = (date now | format date '%Y-%m-%dT%H:%M:%SZ')
    docker buildx build --target builder --build-arg $"MOKOSH_GIT_HASH=($git_hash)" --build-arg $"MOKOSH_GIT_DESCRIBE=($git_describe)" --build-arg $"MOKOSH_BUILD_DATE=($build_date)" --tag mokosh-server:check --file oci-build/Dockerfile .

# Build OCI image
[group: 'build']
build-docker:
    #!/usr/bin/env nu
    let git_hash = (^git rev-parse --short=12 HEAD | str trim)
    let git_describe = (^git describe --tags --always --dirty | str trim)
    let build_date = (date now | format date '%Y-%m-%dT%H:%M:%SZ')
    docker buildx build --build-arg $"MOKOSH_GIT_HASH=($git_hash)" --build-arg $"MOKOSH_GIT_DESCRIBE=($git_describe)" --build-arg $"MOKOSH_BUILD_DATE=($build_date)" --tag mokosh-server:local --file oci-build/Dockerfile .

# Run database migrations against the running database
[group: 'db']
migrate-run:
    sqlx migrate run

# Create a new migration
[group: 'db']
migrate-create name:
    sqlx migrate add {{ name }}

# Create a release: bump version, push branch, print PR link
[group: 'release']
create-release bump:
    #!/usr/bin/env nu
    let bump = "{{ bump }}"

    let status = git status --porcelain | str trim
    if ($status | is-not-empty) {
        print $"(ansi red)Working tree is dirty. Please stash or commit your changes first.(ansi reset)"
        exit 1
    }

    let branch = git branch --show-current | str trim
    if $branch != "main" {
        print $"Switching from ($branch) to main..."
        git checkout main
    }

    git pull --rebase origin main

    let current = (open Cargo.toml | get package.version | split row "." | each { into int })
    let next = match $bump {
        "major" => [$"($current.0 + 1)" "0" "0"],
        "minor" => [$"($current.0)" $"($current.1 + 1)" "0"],
        "hotfix" => [$"($current.0)" $"($current.1)" $"($current.2 + 1)"],
        _ => { print $"(ansi red)Usage: just create-release <major|minor|hotfix>(ansi reset)"; exit 1 }
    }
    let bare = ($next | str join ".")
    let tag = $"v($bare)"
    let release_branch = $"release/($tag)"

    git checkout -b $release_branch
    open Cargo.toml | update package.version $bare | to toml | collect | save --force Cargo.toml
    git add Cargo.toml
    git commit --signoff --message $"Release ($tag)"

    git push --set-upstream origin $release_branch

    # Open the release PR via fj. Body lives in a tempfile so the
    # changelog can grow later without inline escaping pain.
    let body_file = (mktemp --tmpdir --suffix .md)
    [
        $"Automated release PR for ($tag)."
        ""
        $"After merge, `.forgejo/workflows/create-release.yml` tags and publishes ($tag) to the Generic Packages registry."
    ] | str join "\n" | save --force $body_file
    let fj_result = (^fj --host dev.a8n.run pr create $"Release ($tag)" --body-file $body_file | complete)
    rm $body_file
    if $fj_result.exit_code != 0 {
        print $"(ansi red)fj pr create failed(ansi reset)"
        print $fj_result.stderr
        exit 1
    }

    # `fj pr create` prints `created pull request #N: <title>` on success.
    # Parse the number out and build the PR URL from `origin`.
    let pr_num = (
        $fj_result.stdout
        | str trim
        | parse --regex 'created pull request #(?P<num>\d+)'
        | get num.0?
    )
    let remote = (git remote get-url origin | str trim)
    let base_url = if ($remote | str starts-with "ssh://") {
        $remote | str replace "ssh://git@" "https://" | str replace "git.a8n.run" "dev.a8n.run" | str replace ".git" ""
    } else {
        $remote | str replace --regex "git@([^:]+):" "https://$1/" | str replace "git.a8n.run" "dev.a8n.run" | str replace ".git" ""
    }
    print $"(ansi green)Pushed ($release_branch)(ansi reset)"
    if ($pr_num | is-not-empty) {
        print $"PR: ($base_url)/pulls/($pr_num)"
    } else {
        # fj output format drifted; fall back to whatever it said.
        print $"fj output: ($fj_result.stdout | str trim)"
    }
    print $"After merging, the create-release workflow will tag and release ($tag) automatically."
