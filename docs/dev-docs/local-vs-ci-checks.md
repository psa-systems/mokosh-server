# Local gates versus the CI Check workflow

What `just check` and `just pre-commit` run, next to what
[`.forgejo/workflows/check.yml`](../../.forgejo/workflows/check.yml) runs, so a
contributor can tell before pushing which failures a local run will catch.

`check.yml` spells its steps out instead of calling `just`, so the two sides can
drift without anything failing. This file is the mapping they have to agree
with; update it in the same change that adds or moves a check (PMS-851).

## The one-line version

`just check` runs every `check.yml` step except the two cargo test steps.
`just pre-commit` runs those two plus fmt, clippy and compile, inside the dev
compose `server` container. Run both and you have run `check.yml`. Run either
one alone and you have not.

## Step by step

| `check.yml` step | Command | `just check` | `just pre-commit` |
| --- | --- | --- | --- |
| Migration prefix uniqueness | `nu scripts/check-migration-prefixes.nu` | `check-migrations` | no |
| Migration immutability | `nu scripts/check-migration-immutability.nu` | `check-migration-immutability` | no |
| No duplicate mail copy | `nu scripts/check-no-duplicate-mail-copy.nu` | `check-mail-copy` | no |
| Pool safety (RLS tenant GUC) | `nu scripts/check-pool-safety.nu` | `check-pool-safety` | no |
| Create/update validate parity | `nu scripts/check-create-update-validate-parity.nu` | `check-validate-parity` | no |
| Rate-limit helper | `nu scripts/check-rate-limit-helper.nu` | `check-rate-limit-helper` | no |
| Runner labels | `nu scripts/check-runner-labels.nu` | `check-runner-labels` | no |
| OCI build cache | `nu scripts/check-oci-build-cache.nu` | `check-oci-cache` | no |
| OCI publish tags | `nu scripts/check-oci-publish-tags.nu` | `check-oci-publish-tags` | no |
| Workspace dependency table | `nu scripts/check-workspace-deps.nu` | `check-workspace-deps` | no |
| Environment-variable parity | `nu scripts/check-env-example.nu` | `check-env-example` | no |
| Documented just recipes | `nu scripts/check-doc-recipes.nu` | `check-doc-recipes` | no |
| Config doc paths | `nu scripts/check-config-doc-paths.nu` | `check-config-doc-paths` | no |
| Markdown link targets | `nu scripts/check-doc-links.nu` | `check-doc-links` | no |
| Unused dependencies | `cargo machete` | `check-unused-deps` | no |
| Check formatting | `cargo fmt --all --check` | `check-fmt` | yes |
| Clippy | `cargo clippy --workspace --all-targets -- -D warnings` | `check-clippy` | yes |
| Compile check | `cargo check --workspace --all-targets` | `check-compile` | yes |
| Unit tests | `cargo test --workspace --lib` | no | yes |
| Doc tests | `cargo test --workspace --doc` | no | yes |

`check.yml`'s remaining steps (clone, `CARGO_BUILD_JOBS` cap, `rust-cache`) set
the runner up and check nothing, so no recipe mirrors them.

## Where the two sides deliberately differ

- **The unit and doc tests are not in `just check`.** They are in
  `just pre-commit`, which the git hook from `just install-hooks` runs on every
  commit, so putting them in the pre-push umbrella as well would only make the
  slower recipe slower. `just test` runs the whole `cargo test` set, including
  the `tests/*.rs` suite that needs Postgres.
- **The guard scripts are not in `just pre-commit`.** They are Nushell scripts
  run on the host, while every step of `pre-commit` runs in the dev compose
  `server` container. `just check` is where they belong.
- **`cargo machete` needs a host install.** `check-unused-deps` fails with the
  `cargo install --locked cargo-machete` hint rather than installing it for you;
  `check.yml` installs it in the step (a no-op once `rust-cache` restores it).
- **`check-migration-immutability` needs `origin/main` with history.**
  `check.yml` clones with `fetch-depth: 0`. On a shallow local clone, run
  `git fetch origin main` first or the script fails loud rather than passing.

## Local recipes with no `check.yml` counterpart

These are gates in their own right, and no step of `check.yml` covers them.

| Recipe | Covered in CI by | Why it is not in `just check` |
| --- | --- | --- |
| `check-docker` | [`build-oci-image.yml`](../../.forgejo/workflows/build-oci-image.yml) | Builds the OCI builder stage: minutes per run, needs a Docker builder and the crates.io network. Run it by hand when touching `oci-build/Dockerfile`. |
| `test-integration` | [`integration.yml`](../../.forgejo/workflows/integration.yml) | Needs a Postgres container. PMS-267 split it out of `check.yml` for the same reason. |
| `verify-demo` | none | Targeted subset of `test-integration` (`seed_demo` + `data_transfer`), same Postgres requirement (PMS-677). |
| `test-e2e` | [`e2e.yml`](../../.forgejo/workflows/e2e.yml) | Playwright against staging or `$E2E_BASE_URL`: needs a deployed environment (PMS-140). |
