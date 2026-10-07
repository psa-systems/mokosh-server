# Release and deploy runbook: the three-repo chain

This is the Mokosh-specific release and deploy procedure. Before PMS-1404 it lived only in David's head, transferred verbally at the 2026-09-18 standup; this page is that transfer in writing, so cutting a release does not depend on asking him. The generic infra-side restart and rollback mechanics (not specific to these three repos) stay in the `docker` repo's `docs/runbooks/deploy.md` (DEV-613); this page owns the parts that are specific to Mokosh server, Mokosh apps and Bunyip, and the order they have to happen in.

## The three repos release together

Three Forgejo repositories under the `psa-systems` organisation release as one unit: **Mokosh server** (this repo, the API), **Mokosh apps** (the SPA), and **Bunyip** (the identity/OIDC provider, which builds and publishes *two* images of its own: `bunyip-api` and `bunyip-web`). A version bump in one is only meaningful alongside compatible versions of the other two, so cut all three releases in the same sitting. Mokosh apps has fewer CI checks than the server (no integration-test suite, no backend compile), so it typically finishes first; do not treat that as a sign the chain is done.

The three repos do **not** all release off the same trigger shape:

- **Mokosh server** and **Mokosh apps** release off a *merged release pull request*: `.forgejo/workflows/create-release.yml` fires on `pull_request: closed`, gated on `github.event.pull_request.merged == true && startsWith(head.ref, 'release/v')`.
- **Bunyip** releases off a *pushed `release/v*` tag*, not the PR merge itself: its `create-release.yml` triggers on `push: tags: ['release/v*']`. Merging Bunyip's release PR alone does not start anything; `just publish-release` still has to run afterward to push that tag.

Both shapes call the same reusable workflow in `psa-systems/common` (`common/.forgejo/workflows/create-release.yml`), which creates the `vX.Y.Z` git tag and the Forgejo release via the API. That tag creation is what each repo's build workflow is actually watching for (`tags: ["v*"]` in `build-oci-image.yml` for the server and apps, `build-api.yml` + `build-web.yml` for Bunyip) - so for the server and apps the tag+release is created automatically right after the PR-merge event, and for Bunyip it only happens after the explicit `just publish-release` push.

## Prerequisites

Before starting, on each repo you intend to release:

- Forgejo CLI (`fj`) installed and authenticated against `dev.a8n.run`: `fj --host dev.a8n.run whoami` succeeds. If not, add a token with `write:repository` scope: `fj --host dev.a8n.run auth add-key <your Forgejo username>`.
- A clean working tree (`git status --porcelain` is empty) - `just create-release` refuses to run otherwise and will not stash anything for you.
- `main` checked out and up to date; `just create-release` switches to `main` and runs `git pull --rebase origin main` itself, but start from a branch-free, unambiguous state so that rebase cannot land on the wrong history.

## Cutting a release

In each repo's working tree, run:

```
just create-release minor
```

(`major` and `hotfix` are the other two valid bump kinds; `minor` is what a routine three-repo release uses.) Before anything on disk changes, the recipe enforces, in order: `fj` is installed, `fj` has a working login for `dev.a8n.run`, and `fj` can read this repository with its stored credential (a read-only token still fails later, at PR creation, after the push). Only then does it: abort on a dirty tree, switch to and pull `main`, bump the version in the manifest (`Cargo.toml` here; the equivalent version file in Mokosh apps and Bunyip), sync `Cargo.lock` where applicable, commit as `Release vX.Y.Z`, push `release/vX.Y.Z`, and open the release PR with `fj pr create`. Re-running it after a failed or already-merged attempt is safe: it detects and cleans up a leftover local or remote `release/vX.Y.Z` branch rather than erroring on raw git output.

### Configuration changes in the release

Before opening the release PR, the release's configuration facts have to be complete, because the deploy step below works from them (PMS-1442). Every change that adds a required variable, removes or renames one, or makes one required carries a `[[change]]` record in `src/config/variables.toml` with the operator action and the issue that introduced it, and `just check-config-docs` (part of `just check` and the required `Check` job) refuses a Breaking entry without both. Until the tag exists, `docs/configuration.md`'s Recently added section lists those changes under `Unreleased (vX.Y.Z)`, where `vX.Y.Z` is the `since` the change declared; the first `just config-docs` after the tag drops the "Unreleased" label.

Once the Forgejo release exists, edit its notes and add the block `just config-release-notes vX.Y.Z` prints: a link to the release's entry in `docs/configuration.md` at that tag, and each Breaking change with its variables, action and issue. The release-notes generator in `psa-systems/common` does not emit it yet, so this is a manual step.

## The release PR, and what merging it triggers

Review and merge the release PR like any other PR - the required checks (`Check`, `E2E`, `Integration`) still gate it. What happens next differs by repo (see "The three repos release together" above):

- **Mokosh server / Mokosh apps**: merging the PR directly fires `create-release.yml`, which creates the `vX.Y.Z` tag and Forgejo release. That tag push is what `build-oci-image.yml` (or the apps' equivalent) is watching for, so the image build starts automatically.
- **Bunyip**: after the PR merges, run `just publish-release` on `main` (it refuses a dirty tree, a non-main branch, or local `main` behind `origin/main`). That pushes the `release/vX.Y.Z` tag on the merged commit, which fires Bunyip's `create-release.yml`, which creates the `vX.Y.Z` tag and release, which in turn fires `build-api.yml` and `build-web.yml`.

## The build, the registry, and how a tag becomes a deployable image

The build job (`build-oci-image.yml` and its per-repo equivalents) resolves its publish mode from the trigger, never from `git describe`: a `vX.Y.Z` tag push resolves mode `release` and publishes the image tagged `:vX.Y.Z` only; a `main` push resolves mode `latest` and publishes `:latest` only. There is no separate "build number" - the semantic version from the release commit's manifest *is* the image tag, and that is the exact string you pin in the deploy compose file.

Each repository publishes to the Forgejo Container Registry under the **psa-systems** private organisation, one package per image: `mokosh-server`, `mokosh-apps` (or its image name), `bunyip-api`, and `bunyip-web`. Confirm a build landed by checking that organisation's package list on `dev.a8n.run`, or by reading the build job's log for the `importing cache manifest` / push lines.

## Staleness and the update-branch-by-merge / merge-on-green remedy

`main`'s branch protection on every one of these repos requires "Block merge if pull request is outdated" (`block_on_outdated_branch`, PMS-1056) alongside the required `Check` / `E2E` / `Integration` checks. A release PR left open while other PRs merge into `main` goes stale and Forgejo refuses the merge button until it is caught up. The remedy is the platform's own "Update branch" action (a merge of `main` into the release branch, not a rebase - rebasing would rewrite the already-pushed `release/vX.Y.Z` branch's history), followed by waiting for the required checks to go green again on the updated head before merging ("merge on green"). Do not try to merge around a red or pending check on a release PR: the whole point of the required-check set is that a release that has not gone green has not been verified against the commit it will actually tag.

## Staging-then-production deploy procedure

This is the procedure David dictated at the 2026-10-06 standup, specifically for Mokosh server and Mokosh apps (Bunyip's own promotion is covered by its own ops notes, not this page):

1. **Back up the database first.** A production deploy is not a 10-minute job if a bad migration forces a restore from nothing.
2. Restart staging so it is running the current `main` (`:latest`).
3. Verify everything works in staging - sign in, and exercise the features the release touched.
4. If staging looks good, cut the release (see above), which starts the CI build.
5. **Read the configuration changes before touching production.** From a checkout of the new release tag, run `just config-since <version production runs now>` (or open the release's entry under "Recently added" in `docs/configuration.md`). Apply every `BREAKING` action to the deploy repo's compose variables and secrets, and set every newly `REQUIRED` variable, in the same change as the version bump. Do not restart production while a Breaking entry is unhandled: a missing required variable stops the server at boot.
6. When the build is done, update the deploy repo's compose variables with the new version. **Bump the server pin before the apps pin, then restart**, in that order - the 2026-09-29 production break came from bumping Mokosh apps while the server stayed pinned at an older version whose compose secrets did not match what the new apps release expected, compounded by Traefik listing routers for networks that no longer existed.
7. After restarting production, check the Traefik routers resolve (no routes pointing at a network or service that no longer exists) and verify sign-in works, the same way it was verified in staging.
8. Work through any issues or breaking changes found at that point before calling the deploy done.

Server and apps versions are **not** required to be pinned equal - Mokosh apps ships its own patch releases independently of the server, and production has run mismatched-but-compatible pairs before (e.g. `mokosh-server:v0.15.0` with `mokosh-www:v0.15.1`). Record the *compatible pair* that was actually deployed together for a release, rather than enforcing version equality.

Every PR should be tested before merge, and every release (or every couple of releases) should get a full manual pass through every feature with realistic data - both agreed at the 2026-10-06 standup after a run of quickly merged PRs during crash recovery broke several features in production.

## Known failure modes (first seen cutting v0.14.0, 2026-09-18)

These three blocked the v0.14.0 release chain (tracked together under PMS-1362) and are worth checking for by name if a release stalls the same way again:

- **OCI image build fails with a rootfs mount error** ("OCI runtime create error: ... error mounting ... unable to create a directory"), reproduced for both Mokosh server and Mokosh apps, deterministic rather than a flake. Tracked and fixed in PMS-1360 (resolved; a check now covers the same class of mount failure).
- **A Mokosh server integration test panics** instead of failing with a readable assertion, blocking the release PR from going green; a rerun panics again. Tracked and fixed in PMS-1361.
- **Bunyip's E2E deployment check in staging returns HTTP 429** during the release window, caused by unrelated audit traffic exhausting Bunyip's rate-limit budget before the E2E suite gets its turn, not by a test defect. Tracked in BUNYIP-804.

If a release stalls on one of these again after they are reopened or regress, check that issue first before re-diagnosing from scratch.

## See also

- [`docs/architecture.md`](../architecture.md#releases) - this repo's own release mechanics in more depth (the `common`-shared recipe and workflow, changelog format).
- [`docs/invariants/ci-release.md`](../invariants/ci-release.md) - branch, runner-label, cache, publish-tag, single-build and migration-version conventions that a release PR is held to.
- `docker` repo's `docs/runbooks/deploy.md` (DEV-613) - the generic, non-Mokosh-specific restart/rollback runbook this page does not duplicate.
