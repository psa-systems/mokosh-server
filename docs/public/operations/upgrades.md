# Upgrades

A Mokosh upgrade is a container image swap. Migrations run embedded, so there is no separate migration step the operator triggers. The release-and-deploy page covers the chain across Mokosh server, Mokosh apps and Bunyip; this page covers the Mokosh server side.

## Normal upgrade

1. Read the release notes for the version you are moving to. Look for any entry marked **Breaking: won't start** or **Breaking: feature off** in the configuration changelog; those name an operator action you take before restarting.
2. Pull the new image:
   ```nu
   docker pull dev.a8n.run/psa-systems-private/mokosh-server:vX.Y.Z
   ```
3. Update `compose.yml` to the new tag.
4. Bring the service back up:
   ```nu
   docker compose up --detach server
   ```
5. The server runs its embedded migrations at startup. Watch the log until you see the service listening.
6. Smoke-check `/api/v1/health`.

Most upgrades need nothing else. The breaking changelog is short and specific.

## Migrations are immutable

Every migration committed on `main` is immutable. Once a migration has been applied to a database, it is never edited, renamed or deleted. If a bug in a migration surfaces, the fix is a new migration that corrects the state.

The server verifies migration checksums at startup. A database that recorded a migration with a different checksum (because an older release of Mokosh applied an edited version) refuses to come up with the error `migration N was previously applied but has been modified`. This is almost always one of three things:

- The deployment is coming back up against a database restored from a different version with incompatible history. The fix is to boot against the matching server version and then upgrade.
- An older release built an edited migration locally and applied it. The fix is to restore the committed checksum: the operator knows which checksum the committed migration carries.
- Two different migrations share the same version number. `just check-migration-versions` catches this before it ships; a database that got hit by it needs manual repair.

Never edit a migration to clear the error. The immutability guarantee is why upgrade is as simple as it is.

## Upgrade blocked by duplicates

A small number of migrations build a unique index over data that predates them. When a client has duplicate rows the new index would reject (two contacts with the same email, two companies with the same tax id), the upgrade fails on that specific migration.

See [upgrade blocked by duplicates](upgrade-blocked-by-duplicates.md) for the five known cases, each with a detect query and a repair query. The repair is never part of the migration because deciding which duplicate to keep is a business decision, not a schema change.

## Configuration changes in a release

The configuration reference carries a changelog of every added, changed, and removed environment variable, with the release that introduced the change. Two change levels matter:

- **Breaking: won't start**: the server refuses to boot after upgrade until the operator acts. Apply the change before restarting.
- **Breaking: feature off**: the server comes up but a named feature stops working or changes shape. Review the change before restarting; decide whether the feature should stay on.

Both carry the operator action in the entry. A change not marked breaking needs no action unless you relied on the old behavior.

## Rollback

A Mokosh server release is an immutable container image. Rolling back is pulling and starting the previous tag. The database is a separate consideration:

- If the previous release's migrations are a strict prefix of the new one's (the normal case), the previous server boots cleanly against the already-migrated database. Nothing to undo.
- If the newer release introduced a destructive migration (a column dropped, data remapped), rollback is not a container swap; it is restoring a pre-migration database backup. Destructive migrations are rare; the changelog names them explicitly.

Decide before cutting a release: if a migration is destructive, the upgrade is one-way.

## Scheduled jobs at upgrade

The scheduler runs inside the server process. Bringing the server down stops scheduled jobs; bringing it back up restarts them from the next scheduled tick. A job that was mid-run when the server stopped is logged as interrupted and runs again on its next tick.

One-shot startup corrections (schema repair steps the server runs once per boot) are idempotent: re-running them does nothing on a database that already carries the correction. This is why they are safe to re-execute on every boot.

## Verifying after upgrade

- `/api/v1/health` returns `{"status":"ok"}`. A super-admin bearer sees `version`, `git_hash`, `build_date`.
- The provider status endpoint reports every provider live.
- A sign-in through the SPA succeeds.
- A test invoice renders (the PDF path exercises the biggest code change surface).

If any of the four fails, the server log carries the specifics. See [log inspection](log-inspection.md).
