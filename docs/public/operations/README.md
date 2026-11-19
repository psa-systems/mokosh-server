# Operations

The operator-facing side of running Mokosh server.

- [First-run onboarding](first-run-onboarding.md): how the first administrator reaches the system, including the SMTP-not-yet-configured case.
- [Backups](backups.md): what to back up, what order to restore in.
- [Upgrades](upgrades.md): pulling a new image, migration behavior at startup, what to do when a release fails to boot.
- [Log inspection](log-inspection.md): log levels, the job runs table, finding a specific tenant's error.
- [Provider runbook](provider-runbook.md): moving a secret or configuration key between providers without downtime.
- [Delegated invoicing](delegated-invoicing.md): standing up Xero or QuickBooks delegation across the four gates (deployment app, integration, per-tenant connect, per-client mapping).
- [Release and deploy](release-and-deploy.md): cutting a release across the Mokosh server, Mokosh apps and Bunyip chain, and the known failure modes.
- [Postgres security](postgres-security.md): roles, extensions, row-level security.
- [Upgrade blocked by duplicates](upgrade-blocked-by-duplicates.md): detect-and-repair queries for the five known cases where a migration cannot build a unique index over rows that predate it.

For public-facing feature docs (billing, time tracking, knowledge base), see the top-level pages.
