# Local gates versus the CI Check workflow

What `just check`, `just pre-commit` and `just pre-push` run, next to what
[`.forgejo/workflows/check.yml`](../../.forgejo/workflows/check.yml) runs, so a
contributor can tell before pushing which failures a local run will catch.

`check.yml` spells its steps out instead of calling `just`, so the two sides can
drift without anything failing. This file is the mapping they have to agree
with; update it in the same change that adds or moves a check (PMS-851).

## The one-line version

`just check` runs every `check.yml` step except the two cargo test steps.
`just pre-commit` runs only `check-tree-ownership` plus a fmt-only check, by
default (`hook_layout := "pre-push"`, PC-80); the clippy, compile and unit-test
steps live in `just pre-push` instead, which runs the full suite with no scope
guard, inside the dev compose `server` container. Run `just check` and `just
pre-push` and you have run all of `check.yml` except its doc tests, which since
PMS-786 only CI runs (see the note below).

## Step by step

| `check.yml` step | Command | `just check` | `just pre-commit` | `just pre-push` |
| --- | --- | --- | --- | --- |
| Migration prefix uniqueness | `nu scripts/check-migration-prefixes.nu` | `check-migrations` | no | no |
| Migration immutability | `just check-migration-immutability` | `check-migration-immutability` | no | no |
| No duplicate mail copy | `nu scripts/check-no-duplicate-mail-copy.nu` | `check-mail-copy` | no | no |
| Pool safety (RLS tenant GUC) | `nu scripts/check-pool-safety.nu` | `check-pool-safety` | no | no |
| Create/update validate parity | `nu scripts/check-create-update-validate-parity.nu` | `check-validate-parity` | no | no |
| Rate-limit helper | `nu scripts/check-rate-limit-helper.nu` | `check-rate-limit-helper` | no | no |
| Runner labels | `nu scripts/check-runner-labels.nu` | `check-runner-labels` | no | no |
| OCI build cache | `nu scripts/check-oci-build-cache.nu` | `check-oci-cache` | no | no |
| OCI publish tags | `nu scripts/check-oci-publish-tags.nu` | `check-oci-publish-tags` | no | no |
| Single build per commit | `nu scripts/check-single-build.nu` | `check-single-build` | no | no |
| Workspace dependency table | `nu scripts/check-workspace-deps.nu` | `check-workspace-deps` | no | no |
| Environment-variable parity | `nu scripts/check-env-example.nu` | `check-env-example` | no | no |
| Build target storage | `nu scripts/check-build-target-storage.nu` | `check-build-target-storage` | no | no |
| Documented just recipes | `nu scripts/check-doc-recipes.nu` | `check-doc-recipes` | no | no |
| Config doc paths | `nu scripts/check-config-doc-paths.nu` | `check-config-doc-paths` | no | no |
| Markdown link targets | `nu scripts/check-doc-links.nu` | `check-doc-links` | no | no |
| CLAUDE.md index budget | `nu scripts/check-claude-md.nu` (plus `--self-test`) | `check-claude-md` | no | no |
| Unused dependencies | `cargo machete` | `check-unused-deps` | no | no |
| Check formatting | `cargo fmt --all --check` | `check-fmt` | yes | yes |
| Clippy | `cargo clippy --workspace --all-targets -- -D warnings` | `check-clippy` | no | yes |
| Compile check | `cargo check --workspace --all-targets` | `check-compile` | no | yes |
| Unit tests | `cargo test --workspace --lib` | no | no | yes |
| Doc tests | `cargo test --workspace --doc` | no | no | **no** (see below) |

`check.yml`'s remaining steps (clone, `CARGO_BUILD_JOBS` cap, `rust-cache`) set
the runner up and check nothing, so no recipe mirrors them.

## Where the two sides deliberately differ

- **The unit tests are not in `just check`.** They are in `just pre-push`,
  which the git hook from `just install-hooks` runs on every push rather than
  every commit (`hook_layout := "pre-push"`, the default since PC-80), so
  putting them in the `check` umbrella as well would only make the slower
  recipe slower. `just test` runs the whole `cargo test` set, including the
  `tests/*.rs` suite that needs Postgres.
- **The doc tests are CI-only since PMS-786.** `pre-commit` and `pre-push` now
  come from `common/common.just` rather than being forked here, and the shared
  `pre-push` recipe runs exactly one `cargo test {{ test_args }}`; `cargo`
  refuses `--lib` and `--doc` in one invocation, so `test_args := "--workspace
  --lib"` can express the unit tests or the doc tests but not both. The doc
  tests stay in `check.yml`, so nothing stopped gating them - what changed is
  that a broken doc test now surfaces in CI rather than at push time. PC-70
  asks common for a second test invocation; when it lands, this row goes back
  to `yes` and the justfile carries both.
- **The guard scripts are not in `just pre-commit` or `just pre-push`.** They
  are Nushell scripts run on the host, while every cargo step of `pre-commit`
  and `pre-push` runs in the dev compose `server` container. `just check` is
  where they belong.
- **`cargo machete` needs a host install.** `check-unused-deps` fails with the
  `cargo install --locked cargo-machete` hint rather than installing it for you;
  `check.yml` downloads a pinned, checksum-verified release binary instead
  (PMS-1251), so the CI version is not necessarily what a local `cargo install`
  gets you.
- **`check-migration-immutability` needs `origin/main` with history.**
  `check.yml` clones with `fetch-depth: 0`. On a shallow local clone, run
  `git fetch origin main` first or the script fails loud rather than passing.

## Local recipes with no `check.yml` counterpart

These are gates in their own right, and no step of `check.yml` covers them.

| Recipe | Covered in CI by | Why it is not in `just check` |
| --- | --- | --- |
| `check-docker` | [`build-oci-image.yml`](../../.forgejo/workflows/build-oci-image.yml) | Builds the OCI builder stage: minutes per run, needs a Docker builder and the crates.io network. Run it by hand when touching `oci-build/Dockerfile`. |
| `test-integration` | [`integration.yml`](../../.forgejo/workflows/integration.yml) | Needs a Postgres container. PMS-267 split it out of `check.yml` for the same reason. Both run `cargo nextest` with the `ci` profile in [`.config/nextest.toml`](../../.config/nextest.toml) (PMS-1177): CI builds a nextest archive in a step of its own and runs the suite from it with `cargo nextest run --archive-file`, which cannot recompile, so the timed step never recompiles what the build step just built; the recipe runs `cargo nextest run` directly, install-and-run, in the dev compose `server` container. Budget is 10 minutes wall clock for the whole CI job on a warm cache; a stuck case is reported and terminated by nextest's own `slow-timeout`/`terminate-after` rather than a shell `timeout` wrapper. CI installs nextest from a pinned, checksum-verified release archive rather than `cargo install` (PMS-1251, avoids compiling nextest's ~330-crate dependency tree from source on a cache miss); the recipe still uses `cargo install`, but pinned to the same version with `--version`, so the two do not drift apart silently. The Postgres service in `integration.yml` also runs with `fsync`/`synchronous_commit`/`full_page_writes` off (PMS-1251), because that instance is destroyed with the job; the dev cluster `test-integration` runs against keeps full durability, which is why that change lives in `integration.yml` and not in `scripts/test-db-roles.sql`. |
| `test-integration-unsupported` | [`integration-unsupported.yml`](../../.forgejo/workflows/integration-unsupported.yml) | PMS-1394 split the Postgres-backed suite in two. `test-integration` runs the SUPPORTED set on every pull request; this recipe runs its complement, the tests for functionality nothing currently uses, which CI runs weekly (Monday 06:00 UTC) and on `workflow_dispatch` rather than per pull request. Today that is `tests/s3_storage.rs` alone: `STORAGE_PROVIDER` defaults to `local` and no deployment sets `s3`, while running it means pulling a MinIO image, extracting and checksumming its server binary and health-polling it before a single assertion, from a third-party rehost of an archived upstream that retracted anonymous pulls once already and broke the job on every branch at once (PMS-1390). Which suites are in which half is decided in [`.config/nextest.toml`](../../.config/nextest.toml) and nowhere else, as a `default-filter` on the `ci` and `unsupported` profiles, so neither workflow nor recipe names a suite and the two halves stay complements. The code and the tests are unchanged and still COMPILED by the pull-request job, because `cargo nextest archive` builds every `tests/*.rs` binary whatever the filter says; only the assertions moved. Locally this recipe needs `just dev-s3` to have filled the blank `STORAGE_S3_*` keys in `.env`, and without them the suite skips loudly rather than failing. |
| `verify-demo` | none | Targeted subset of `test-integration` (`seed_demo` + `data_transfer`), same Postgres requirement (PMS-677). |
| `test-e2e` | [`e2e.yml`](../../.forgejo/workflows/e2e.yml) | Playwright against staging or `$E2E_BASE_URL`: needs a deployed environment (PMS-140). |

<!-- PMS-1437 -->

## How the two recipes relate

`just check` and `just pre-push` are complements: together they cover every step of `.forgejo/workflows/check.yml` except its doc tests, and neither covers it alone. `pre-commit`, `pre-push`, `install-hooks` and `create-release` come from `psa-systems/common`, vendored as the `common` submodule and imported by the root justfile (PMS-786), so a fresh clone needs `git submodule update --init` before `just` resolves. Under the default `hook_layout := "pre-push"` (PC-80), `just install-hooks` writes both a `pre-commit` hook (fmt check plus `check-tree-ownership`, cheap, runs on every commit) and a `pre-push` hook (the full suite, no scope guard, runs on every push); a developer bumping past this change must re-run `just install-hooks` once to pick up the new `pre-push` hook. They are configured through the variables at the top of the justfile, never by redefining the recipe: `check-justfile` fails the build on a local copy of a protected recipe, which is how a new shared guard reaches every repo at once. The one thing the shared recipe cannot express is this repo's second test invocation, so `cargo test --workspace --doc` is CI-only now (PC-70 asks common for it; `docs/dev-docs/local-vs-ci-checks.md` carries the detail). `docs/dev-docs/local-vs-ci-checks.md` maps the workflow onto the recipes step by step and states why `check-docker`, `test-integration`, `verify-demo` and `test-e2e` stay outside the umbrella recipe (PMS-851). Adding a step to `check.yml` means adding the matching recipe to `just check` (or `just pre-push`), the row in that file, and its line in `docs/recipes.md`.
