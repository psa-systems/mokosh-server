# Backups

Three things need backing up on a running Mokosh deployment: the Postgres database, uploaded documents in the storage root, and (when Infisical is in the loop) Infisical's own state.

## Database

The database is the source of truth for every record: tenants, users, tickets, time entries, invoices, articles, settings, audit log. Everything else is either derivable from it or re-fetchable.

Backup strategy:

- `pg_dump` the server's database on a regular schedule (hourly or daily, depending on tolerance). Store the dump off-host.
- For point-in-time recovery, enable PostgreSQL WAL archiving and take a weekly base backup. This is standard Postgres operation; Mokosh has no quirks here.
- Test a restore periodically against a staging deployment. A backup that has never been restored is not a backup.

Restoring:

1. Create a fresh empty database.
2. Restore the dump into it with `pg_restore` (or `psql` for a plain-SQL dump).
3. Boot Mokosh against the restored database. The server verifies schema versions on startup; a restore from a different version refuses to come up until it migrates.

The restore is schema-aware: committed migrations in Mokosh are immutable, so a dump taken against release vX.Y.Z restores cleanly to a server built against vX.Y.Z or later. Restoring an older dump to a newer server runs the delta migrations on startup.

## Uploaded documents

Documents stored under the retention kind "financial document" (invoices, credit notes) are kept for seven years by tenant policy. Other uploaded files (ticket attachments, KB images, branding logos) persist while they are referenced.

Depending on your storage provider:

- **Filesystem** (`STORAGE_PROVIDER=filesystem`): back up `STORAGE_ROOT` as a regular file tree. A nightly rsync to an off-host target works; so does an LVM snapshot plus copy.
- **S3** (`STORAGE_PROVIDER=s3`): enable versioning on the bucket and lifecycle rules for the retention your policy requires. Consider cross-region replication for geographic redundancy.

Restoring a document store is a file-level restore: put the bytes back where the storage provider expects them, with the paths unchanged. Mokosh stores the full path on the ledger row that references the file, so a file restored under a different path is not found.

## Infisical state

If `SECRET_BACKEND=infisical` or `APP_SECRET_BACKEND=infisical`, Infisical holds secrets the deployment cannot start without. The server reads them at boot and caches them in memory for the process lifetime.

Infisical's own documentation covers backing up Infisical. From Mokosh's angle: if Infisical is lost and no backup exists, the operator has to re-populate the secrets by hand before the deployment can boot again. Infisical bootstrap credentials are regenerable (`mokosh-bootstrap bootstrap-infisical`), but the secrets held in Infisical are what they are.

## Order of restore

In a full-site recovery:

1. Postgres first. Mokosh will not start without it.
2. Infisical (if in use) next, so the Mokosh boot can read secrets.
3. Storage next; documents become retrievable.
4. Mokosh server last. The server verifies migrations and starts handling requests.

## What does not need backing up

- Docker images are pulled from the registry.
- Compose and environment files are committed to version control; back up the version control system, not the deployed copies.
- The Bunyip identity provider is a separate deployment with its own backup plan.
