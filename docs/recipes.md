# Recipes

Every task in this repository runs through [`just`](https://github.com/casey/just). `just --list` prints the grouped view straight from the `justfile` and is the source of truth if it and this page ever disagree; the annotated tour below is grouped the same way.

```nu
# General
just                        # the `default` recipe: list every recipe
just install-hooks          # install the git pre-commit hook (once per fresh clone) -> runs `just pre-commit`
just pre-commit             # check.yml's cargo checks (fmt/clippy/compile/unit/doc) in the dev `server` container

# Dev stack
just dev [args]             # start the Traefik-routed dev stack (args go to `docker compose up`, e.g. --build --detach)
just dev-infisical [args]   # start Infisical and its Postgres sidecar (compose profile: infisical)
just down                   # stop the dev stack (volumes preserved)
just dev-clean              # stop the stack, remove this repo's volumes and target/, delete .env (keeps .env.infisical)
just dev-clean-all          # everything dev-clean does, plus remove this repo's images and prune its buildx cache
just infisical-bootstrap    # one-time: drive Infisical first-run setup and fill INFISICAL_* in .env

# Checks
just check                  # umbrella: every check.yml step except its cargo test steps (see below)
just check-compile          # cargo check --all-targets
just check-clippy           # cargo clippy --all-targets -- -D warnings (same as check.yml)
just check-fmt              # cargo fmt --all --check
just check-docker           # build the OCI image's builder stage only (validation; NOT in `just check`)
just check-migrations       # fail if two migrations share a numeric prefix
just check-migration-immutability # fail if a migration already on main is modified or deleted
just check-pool-safety      # fail if a serving `.pool()` call lacks its `// SAFETY` note
just check-validate-parity  # fail if a Create*Request and its Update*Request validate a field differently
just check-mail-copy        # fail if a `Mailer` helper duplicates a seeded template's copy
just check-rate-limit-helper # fail if a 429 response is built outside the shared builder
just check-runner-labels    # fail if a CI job requests the wrong runner label
just check-oci-cache        # fail if the OCI build leaves the type=gha runner cache
just check-oci-publish-tags # fail if the publish tags drift from oci-build/get-tags.nu
just check-single-build     # fail if a compiling workflow builds the same tree twice
just check-workspace-deps   # fail if [workspace.dependencies] and its members disagree
just check-unused-deps      # cargo-machete: fail on a dependency with no call site
just check-env-example      # fail if a var the code reads is missing from .env.example or compose.dev.yml
just check-doc-recipes      # fail if a guarded doc names a recipe the justfile lacks
just check-config-doc-paths # fail if a docs/ path in .env.example, compose.dev.yml or the justfile is missing
just check-doc-links        # fail if a relative Markdown link does not resolve to an existing path

# CI history (not part of `just check`: needs the network)
just ci-stalls [days]       # report CI runs that outlived their job's timeout-minutes; needs FORGEJO_TOKEN
just ci-stalls-self-test    # prove the stall report still reports, on fixtures, with no token

# Format, test, build
just fmt                    # cargo fmt --all
just test                   # cargo test
just test-integration       # Postgres-backed tests/*.rs suite in the dev `server` container (mirrors CI integration.yml)
just verify-demo            # the demo-critical subset of the integration suite (seed_demo + data_transfer)
just test-e2e [args]        # Playwright E2E suite against staging or $E2E_BASE_URL (args go to `playwright test`)
just build                  # cargo build --release --bins
just build-docker           # build the production OCI image (oci-build/Dockerfile)

# Database
just migrate-run            # apply pending migrations against $DATABASE_URL
just migrate-create <name>  # create a new migration file

# Release
just create-release <bump>  # bump version (major|minor|hotfix), push release branch, print PR link
```

`ensure-env` is the one `[private]` recipe: it generates `.env` on first run and is a dependency of the recipes that need it, so it never has to be run by hand.

`just check` plus `just pre-commit` together cover every step of `.forgejo/workflows/check.yml`; neither covers it alone. [`dev-docs/local-vs-ci-checks.md`](dev-docs/local-vs-ci-checks.md) maps the workflow onto the recipes step by step and states why `check-docker`, `test-integration`, `verify-demo` and `test-e2e` stay outside the umbrella.

Release mechanics, from the version bump to the published tag, are on [`architecture.md`](architecture.md).
