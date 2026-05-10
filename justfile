# Mokosh Server - Task Runner

compose_file := "compose.dev.yml"

# List available recipes
default:
    @just --list

# Create .env from .env.dev if missing
[private]
ensure-env:
    @test -f .env || cp .env.dev .env

# Bring up the dev stack (mokosh-server + Infisical + Postgres + Valkey). Trailing args go to `docker compose up` (e.g. --detach).
[doc("Start the dev stack in Docker. Trailing args go to `docker compose up` (e.g. --detach).")]
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

# Stop the dev secrets-management stack. Volumes are preserved.
[doc("Stop Infisical and its sidecars (volumes preserved)")]
dev-down: ensure-env
    docker compose --file {{ compose_file }} down

# Wipe the dev secrets-management stack: stop, remove volumes, remove .env.
[doc("Wipe Infisical volumes and .env. Preserves .env.infisical.")]
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
check: check-compile check-clippy check-fmt

# Check compilation
check-compile:
    cargo check --all-targets

# Run clippy lints
check-clippy:
    cargo clippy --all-targets

# Check formatting
check-fmt:
    cargo fmt --all --check

# Format code
fmt:
    cargo fmt --all

# Run tests
test:
    cargo test

# Build release binaries
build:
    cargo build --release --bins

# Build OCI image for validation (builder stage)
check-docker:
    #!/usr/bin/env nu
    let git_hash = (^git rev-parse --short=12 HEAD | str trim)
    let git_describe = (^git describe --tags --always --dirty | str trim)
    let build_date = (date now | format date '%Y-%m-%dT%H:%M:%SZ')
    docker buildx build --target builder --build-arg $"MOKOSH_GIT_HASH=($git_hash)" --build-arg $"MOKOSH_GIT_DESCRIBE=($git_describe)" --build-arg $"MOKOSH_BUILD_DATE=($build_date)" --tag mokosh-server:check --file oci-build/Dockerfile .

# Build OCI image
build-docker:
    #!/usr/bin/env nu
    let git_hash = (^git rev-parse --short=12 HEAD | str trim)
    let git_describe = (^git describe --tags --always --dirty | str trim)
    let build_date = (date now | format date '%Y-%m-%dT%H:%M:%SZ')
    docker buildx build --build-arg $"MOKOSH_GIT_HASH=($git_hash)" --build-arg $"MOKOSH_GIT_DESCRIBE=($git_describe)" --build-arg $"MOKOSH_BUILD_DATE=($build_date)" --tag mokosh-server:local --file oci-build/Dockerfile .

# Run database migrations against the running database
migrate-run:
    sqlx migrate run

# Create a new migration
migrate-create name:
    sqlx migrate add {{ name }}

# Create a release: bump version, push branch, print PR link
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

    let remote = git remote get-url origin
    let base_url = if ($remote | str starts-with "ssh://") {
        $remote | str replace "ssh://git@" "https://" | str replace "git.a8n.run" "dev.a8n.run" | str replace ".git" ""
    } else {
        $remote | str replace --regex "git@([^:]+):" "https://$1/" | str replace "git.a8n.run" "dev.a8n.run" | str replace ".git" ""
    }
    print $"(ansi green)Pushed ($release_branch)(ansi reset)"
    print $"Create PR: ($base_url)/compare/main...($release_branch)"
    print $"After merging, the create-release workflow will tag and release ($tag) automatically."
