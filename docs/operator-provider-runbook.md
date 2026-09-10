# Provider runbook: moving `SMTP_PASSWORD` to a new provider

This is the six-step provider-migration workflow from `docs/providers.md`,
walked once end to end for the SMTP relay password. Every command runs
inside the `mokosh-server` binary; PMS-1012 folded the operator surface
into the server binary on purpose, so a migration tool cannot re-implement
the providers.

The example moves the value FROM the database provider TO the file
provider. The shape is identical for any pair the two tiers accept
(`environment`, `file`, `database`, `infisical` for secrets; `environment`,
`file`, `database`, `bunyip` for configuration).

## Assumptions

- The deployment is up and healthy today. Everything below runs against
  the running deployment; making a failed boot the discovery mechanism is
  what this whole workflow exists to prevent.
- `SECRET_BACKEND=database` right now, and `SMTP_PASSWORD` lives in
  `app_secrets` (see migration 207).
- The new provider's construction inputs are already present in the
  environment (for the file provider that is `APP_SECRETS_DIR` pointing at
  a mounted directory).

## Step 1: enable the new provider at a higher priority

Provider ENABLEMENT is bootstrap configuration and lives in the operator's
environment (`docs/providers.md`, "Where each is configured"). Set:

```
APP_SECRETS_DIR=/run/secrets/app
```

Leave `SECRET_BACKEND=database` for now. Restart the process so the file
provider is built at boot beside the database one. Boot logs report both.

## Step 2: check what each provider holds

```
mokosh-server provider-status
```

The command renders a per-key, per-provider presence matrix; the SMTP row
should look like this:

```
SMTP_PASSWORD
  holds:      database
  not enabled:
  serving:    database
```

Values are never printed. The row shows only the provider NAMES that hold
the key.

## Step 3: migrate

```
mokosh-server provider-migrate --from database --to file
```

The command copies every key the source holds into the target, one key at
a time, with a read-back and compare. The source is NEVER cleared; that is
what makes the migration reversible up to the purge step. A key the target
already holds is reported as `already-present`; a write or read-back that
fails is named with the reason and the key stays in the source.

## Step 4: verify

```
mokosh-server provider-status
```

The row should now name both providers as holding the key:

```
SMTP_PASSWORD
  holds:      database, file
  serving:    database
```

If any key is missing from the target, `provider-migrate` will have said
so above; re-run it before going further.

## Step 5: cut over

Change `SECRET_BACKEND=file` in the operator's environment and restart.
Boot logs report the new selection; `provider-status` now shows:

```
SMTP_PASSWORD
  holds:      database, file
  serving:    file
```

Exercise a path that sends mail (a password-reset request is a good one).
It has to go through the target provider now.

## Step 6: purge the old copy

Only after step 5 verifies:

```
mokosh-server provider-purge --provider database
```

The default is dry-run. The output lists every key the command WOULD
delete, refusing per key unless both:

1. The provider being purged is DISABLED (not selected as `SECRET_BACKEND`
   any more).
2. The key is verified LIVE in the provider now serving it.

When both hold, the dry-run line reads `would delete (dry-run; rerun with
--confirm)`. Otherwise the line names the reason: `target provider
database is enabled`, or `key not verified live in the serving provider
(file)`.

To actually delete:

```
mokosh-server provider-purge --provider database --confirm
```

There is no `--force` flag. A refused key means the migration is not
finished; fix the refusal and re-run.

## Rollback

Up to and including step 4 the source still holds the value, so switching
`SECRET_BACKEND` back to the old provider and restarting is enough. After
step 6 with `--confirm` the old copy is gone, so a rollback needs another
`provider-migrate --from file --to database` first.
