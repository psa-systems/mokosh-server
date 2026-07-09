# General Task Runner

compose_file := "compose.dev.yml"

# List available recipes
default:
    @just --list

# -- Hooks ------------------------------------------------------------------

# Install the git pre-commit hook (run once per fresh clone). Writes a stub at .git/hooks/pre-commit that execs `just pre-commit`. Bypass with `git commit --no-verify`.
[group: 'hooks']
install-hooks:
    #!/usr/bin/env nu
    let hook = ".git/hooks/pre-commit"
    # Remove first so a leftover symlink from an older install does not get
    # written through to its target file. `try` swallows the not-found case.
    try { rm $hook }
    "#!/usr/bin/env sh\nexec just pre-commit\n" | save $hook
    ^chmod +x $hook
    print $"Wrote ($hook) -> just pre-commit"

# Mirrors check.yml one-to-one so a green hook means a green Check run. The
# Postgres-backed suite is NOT run here; use `just test-integration` (mirrors
# integration.yml) for that. PMS-267.
# Run the fast, database-free checks inside the dev compose `server` container.
[group: 'hooks']
pre-commit: ensure-env
    #!/usr/bin/env nu
    print "\n[pre-commit] cargo fmt --all --check"
    ^docker compose --file {{ compose_file }} run --rm --no-deps server cargo fmt --all --check
    print "\n[pre-commit] cargo clippy --all-targets -- -D warnings"
    ^docker compose --file {{ compose_file }} run --rm --no-deps -e SQLX_OFFLINE=true server cargo clippy --all-targets -- -D warnings
    print "\n[pre-commit] cargo check --all-targets"
    ^docker compose --file {{ compose_file }} run --rm --no-deps -e SQLX_OFFLINE=true server cargo check --all-targets
    print "\n[pre-commit] unit tests"
    ^docker compose --file {{ compose_file }} run --rm --no-deps -e SQLX_OFFLINE=true server cargo test --lib
    print "\n[pre-commit] doc tests"
    ^docker compose --file {{ compose_file }} run --rm --no-deps -e SQLX_OFFLINE=true server cargo test --doc
    print "\n[pre-commit] all checks passed"

# -- Checks ----------------------------------------------------------------------

# Umbrella check: build + clippy + fmt + docker builder stage.
[group: 'check']
check: check-compile check-clippy check-fmt check-migrations

# Enforce unique migration prefixes (PMS-198). Fails if two migrations
# share a numeric prefix (sqlx keys its ledger on that prefix).
[group: 'check']
check-migrations:
    nu scripts/check-migration-prefixes.nu

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

# Mirrors .forgejo/workflows/integration.yml one-to-one. Unlike `just pre-commit`
# this omits `--no-deps`, so the compose `postgres` dependency starts; the
# `server` dev service already exports a usable DATABASE_URL. PMS-267.
# Run the Postgres-backed integration suite in the dev compose `server` container.
[group: 'test']
test-integration: ensure-env
    docker compose --file {{ compose_file }} run --rm -e SQLX_OFFLINE=true server cargo test --tests -- --test-threads=4

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

# Create .env from the committed .env.example if missing, generating a strong
# random value for every self-owned secret so a generic password never lands in
# .env (PMS-490). Only the create path generates; an existing .env is left
# untouched, so the recipe stays idempotent as a dependency of other recipes.
# Third-party credentials (Google, Stripe, Twilio, Slack, Infisical client) stay
# empty placeholders because they cannot be generated. Passwords that get
# interpolated into postgres:// URLs are hex (URL-safe alphanumeric); the URL
# lines are rebuilt from the same generated values so host-side tools (sqlx-cli)
# stay consistent with the container roles compose provisions from the knobs.
[private]
[group: 'hooks']
ensure-env:
    #!/usr/bin/env nu
    if ('.env' | path exists) { return }
    # Self-owned secrets. DB passwords are hex (URL-safe, >= 24 chars) so they
    # interpolate raw into postgres:// URLs; ENCRYPTION_KEY = 64 hex (32 bytes);
    # JWT_SECRET = 64 hex (256-bit); INFISICAL_ENCRYPTION_KEY = 32 hex (16 bytes);
    # INFISICAL_AUTH_SECRET = base64 of 32 random bytes.
    let pg_password = (^openssl rand -hex 24 | str trim)
    let migrator_password = (^openssl rand -hex 24 | str trim)
    let app_password = (^openssl rand -hex 24 | str trim)
    let jwt_secret = (^openssl rand -hex 32 | str trim)
    let encryption_key = (^openssl rand -hex 32 | str trim)
    let infisical_pg_password = (^openssl rand -hex 24 | str trim)
    let infisical_encryption_key = (^openssl rand -hex 16 | str trim)
    let infisical_auth_secret = (^openssl rand -base64 32 | str trim)
    # Scalar KEY=value replacements plus URL lines rebuilt from the same passwords.
    let overrides = {
        MOKOSH_PG_PASSWORD: $pg_password
        MOKOSH_MIGRATOR_PASSWORD: $migrator_password
        MOKOSH_APP_PASSWORD: $app_password
        JWT_SECRET: $jwt_secret
        ENCRYPTION_KEY: $encryption_key
        INFISICAL_PG_PASSWORD: $infisical_pg_password
        INFISICAL_ENCRYPTION_KEY: $infisical_encryption_key
        INFISICAL_AUTH_SECRET: $infisical_auth_secret
        DATABASE_URL: $"postgres://postgres:($pg_password)@localhost:5433/mokosh"
        MOKOSH_ADMIN_DATABASE_URL: $"postgres://postgres:($pg_password)@localhost:5433/mokosh"
        MOKOSH_APP_DATABASE_URL: $"postgres://mokosh_app:($app_password)@localhost:5433/mokosh"
        INFISICAL_DB_CONNECTION_URI: $"postgres://infisical:($infisical_pg_password)@infisical-postgres:5432/infisical"
    }
    let keys = ($overrides | columns)
    let rendered = (
        open .env.example --raw
        | lines
        | each {|line|
            let key = ($line | split row '=' | get 0?)
            if ($key != null) and ($key in $keys) {
                $"($key)=($overrides | get $key)"
            } else {
                $line
            }
        }
        | str join "\n"
    )
    $"($rendered)\n" | save .env
    print "ensure-env: created .env with freshly generated self-owned secrets"

# Bring up the Traefik-routed dev stack (mokosh-server + Postgres + mailpit; no Infisical — use just dev-infisical). Routed at https://{USER}-mokosh-api.a8n.run. Trailing args go to `docker compose up` (e.g. --build --detach).
[doc("Start the Traefik-routed dev stack in Docker. Trailing args go to `docker compose up` (e.g. --build --detach).")]
[group: 'dev']
dev *args: ensure-env
    #!/usr/bin/env nu
    # Discover candidate IPv4 addresses on the LAN interfaces, then keep ONLY
    # private (RFC1918) ones. On some hosts br0 carries a PUBLIC address, and a
    # prior version bound dev services to it - exposing postgres:postgres to the
    # internet, where it was popped by the PG_MEM botnet. Binding the host port
    # to a public IP is never intended, so reject anything non-private and fall
    # back to loopback. Containers still reach each other over the Docker network.
    let candidates = (
        sys net
        | where name =~ 'eth0|br0'
        | get ip
        | flatten
        | where protocol == 'ipv4' and $it.loop == false
        | get address
    )
    let private = (
        $candidates
        | where (($it | str starts-with '10.')
            or ($it =~ '^172\.(1[6-9]|2[0-9]|3[01])\.')
            or ($it | str starts-with '192.168.'))
    )
    let bind_ip = (if ($private | is-empty) { '127.0.0.1' } else { $private | first })
    if $bind_ip == '127.0.0.1' {
        print 'WARNING: no private LAN IPv4 on eth0/br0 (interface may be public). Binding host ports to loopback only.'
    }
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

# Stop the dev stack. Volumes preserved. `--remove-orphans` cleans up any
# stray containers left over from an older multi-file layout.
[doc("Stop the dev stack (volumes preserved)")]
[group: 'dev']
down: ensure-env
    docker compose --file {{ compose_file }} down --remove-orphans

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
        cargo run --quiet --bin mokosh-server -- bootstrap-infisical
    }

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

# -- Cleanup ------------------------------------------------------------------

# Tear down this repo's dev footprint: stop the dev stack (compose.dev.yml) with its network, remove this repo's named volumes (Postgres data, Infisical Postgres data, cargo build target), delete the local target/ build dir, and remove the generated .env. Scoped to this repo via the ${USER}-suffixed volume names; safe on a shared host.
[group: 'cleanup']
dev-clean: ensure-env
    #!/usr/bin/env nu
    docker compose --file {{ compose_file }} down --remove-orphans
    let suffix = $env.USER
    let vols = [
        $"dev-mokosh-postgres-data-($suffix)"
        $"dev-mokosh-infisical-postgres-data-($suffix)"
        $"dev-mokosh-server-target-($suffix)"
    ]
    let existing = docker volume ls --quiet | lines
    for vol in $vols {
        if $vol in $existing {
            docker volume rm $vol
        }
    }
    let paths = [target]
    for p in $paths {
        if ($p | path exists) {
            rm --recursive $p
            print $"removed ($p)"
        }
    }
    if ('.env' | path exists) {
        rm .env
        print "removed .env"
    }
    print "dev-clean: done"

# Everything dev-clean does, plus remove the Docker images this repo builds and prune its buildx cache. Run for a from-scratch rebuild.
[group: 'cleanup']
dev-clean-all: dev-clean
    #!/usr/bin/env nu
    let images = [
        "mokosh-server:check"
        "mokosh-server:local"
    ]
    for img in $images {
        let present = (do { ^docker image inspect $img } | complete).exit_code == 0
        if $present {
            docker image rm $img
        }
    }
    docker buildx prune --force
    print "dev-clean-all: done"

# -- Release ------------------------------------------------------------------

# Create a release: bump major (vx.0.0), minor (v0.x.0), or hotfix (v0.0.x), push the branch, and open the PR via fj.
# After the PR merges, the create-release workflow creates the tag and release automatically.
[group: 'release']
create-release bump: ensure-env
    #!/usr/bin/env nu
    let bump = "{{ bump }}"

    # Abort if there are uncommitted changes
    let status = git status --porcelain | str trim
    if ($status | is-not-empty) {
        print $"(ansi red)Working tree is dirty. Please stash or commit your changes first.(ansi reset)"
        exit 1
    }

    # Switch to main if not already there
    let branch = git branch --show-current | str trim
    if $branch != "main" {
        print $"Switching from ($branch) to main..."
        git checkout main
    }

    # Pull latest changes
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
    # Targeted version bump: rewrite only the `version = "..."` line so the
    # Cargo.toml comments and PMS docs survive. Round-tripping the whole file
    # through `to toml` stripped every comment on each release. Stage through a
    # tempfile + external mv so we never reach for `save --force`, per the repo
    # no-force safety policy.
    let toml_tmp = (mktemp --tmpdir --suffix .toml)
    open Cargo.toml --raw | str replace --regex '(?m)^version = "[^"]*"' $'version = "($bare)"' | save --append $toml_tmp
    ^mv $toml_tmp Cargo.toml
    # PMS-642: sync Cargo.lock to the bumped version so the lock never drifts
    # from Cargo.toml (a --locked build otherwise fails, and every build
    # re-dirties the lock, masking real lock changes in diffs). Dev boxes have no
    # host cargo, so run the one cargo step in the dev `server` container.
    # `--workspace` limits the change to the workspace members' own versions - no
    # transitive dependency churn.
    ^docker compose --file {{ compose_file }} run --rm --no-deps -e SQLX_OFFLINE=true server cargo update --workspace
    git add Cargo.toml Cargo.lock
    git commit --signoff --message $"Release ($tag)"

    # Push release branch
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
    # Parse the number out and build the PR URL from `origin` so the user
    # gets a clickable link instead of just the fj line.
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

