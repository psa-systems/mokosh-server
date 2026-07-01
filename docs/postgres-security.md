# Postgres provisioning and RLS: a working conversation

A summarized transcription of a design conversation about how Mokosh provisions its
Postgres roles, installs extensions, and enforces row-level security (RLS) in dev and
prod. It is preserved in question/answer form because the *path* to the answer (and one
wrong turn) is the lesson, not just the conclusion.

Verified facts in this document were checked against the real `postgres:18.2-alpine3.23`
image during the conversation, not recalled from memory. That distinction is the whole
point (see Q5).

---

## Q1. The `postgres` service overrides the entrypoint to set up RLS. Is there a way that does NOT change the entrypoint? Can't the superuser do the same?

The entrypoint override bundled three separate jobs:

1. **Password-drift reset** - re-`ALTER USER`s `POSTGRES_PASSWORD` on every start, because the image only honours that variable on first volume init.
2. **RLS role split** - creates `mokosh_migrator` (BYPASSRLS) and `mokosh_app` (NOBYPASSRLS).
3. **Superuser-only bootstrap** - `CREATE EXTENSION` and a database-level grant.

The standard alternative is the image's own first-run hook, `/docker-entrypoint-initdb.d/`,
where scripts run as the superuser over the trusted local socket. The reason the original
author reached for an entrypoint override instead is timing: initdb.d runs **once** on an
empty data dir, whereas the entrypoint runs on **every** start. The only job that genuinely
needs every-start is the password-drift reset.

## Q2. Password drift is not needed - that is the wrong trade-off for dev. Remove it. Keep RLS but move it to `/docker-entrypoint-initdb.d/00-init.sh`. Is there anything else in the entrypoint besides those two?

Yes - a hidden third item. Besides the password reset and the RLS roles, the entrypoint
also did `CREATE EXTENSION` for four extensions (`uuid-ossp`, `pg_trgm`, `citext`,
`pgcrypto`) and `GRANT CREATE ON DATABASE` to the migrator. The stated justification was
"these extensions are untrusted, so only a superuser can create them." That claim was taken
from the existing code comment and accepted at face value.

This became issue **PMS-488**: a `scripts/pg-init.sh` mounted into initdb.d, the entrypoint
removed, password-drift handling dropped. It was implemented and merged.

## Q3. Where is the production `compose.yml` with the extra volume for `pg-init.sh`?

There is none. The repo only has dev compose files. Production provisions roles with a
separate one-shot CLI, `mokosh-bootstrap provision-roles`, not an init script. Surfacing
this also exposed an asymmetry: `pg-init.sh` created the extensions and granted
`CREATE ON DATABASE`, but `provision-roles` did neither.

## Q4. The PR is merged. Are you saying a second (privileged) connection could add the extensions without an init script at all?

Here the conversation went to the source of truth. Querying the real image:

- All four extensions are **trusted** in PostgreSQL 13+ (`pg_available_extension_versions.trusted = t`).
- A `NOSUPERUSER NOBYPASSRLS` role can install them **itself**, provided it holds
  `CREATE ON DATABASE`. Without that privilege: `permission denied to create extension`.

So the "untrusted, superuser-only" premise was **false**. The migrations already contain
`CREATE EXTENSION IF NOT EXISTS`, so the migrator can self-install them - no init script and
no superuser required for that step.

## Q5. That was my very first question. You answered from a wrong premise, built a plan, an issue, and a PR on it, and only found the real answer three messages later. You did not verify the source of truth. How do we fix that?

This was the key failure and the most important lesson. The root cause: a **load-bearing,
constraint-asserting claim** ("extensions are untrusted") was trusted because a code comment
said so. That single claim is what made an init-time hook look mandatory and pruned the
simpler options.

The fix, now recorded as a persistent rule:

1. Before any plan, issue, or PR, list the **load-bearing premises** - the claims that, if
   false, change the answer.
2. For each, identify its **real** source of truth (the database, the image, the registry)
   and query it live. A code comment or doc is a secondary source, not the truth.
3. Distrust comments that justify a workaround ("we do X because Y forbids the simple
   way") - Y is exactly the thing to test.
4. Verify first, build second.

A 30-second `docker run ... psql -c "SELECT trusted FROM pg_available_extension_versions"`
up front would have replaced a merged PR built on a guess.

## Q6. Will two connection strings work - one superuser that runs migrations / installs extensions / sets up RLS, and one for the app?

Yes, and the codebase already follows that shape. Checking the migrations confirmed:

- No superuser-only DDL anywhere except `CREATE EXTENSION` (no event triggers, no
  `ALTER SYSTEM`, etc.).
- `FORCE ROW LEVEL SECURITY` is used, which makes RLS apply even to a table's owner.

Two consequences: you do **not** need a true superuser for the migration role - a role with
`BYPASSRLS` (because of FORCE RLS and cross-tenant workers) plus `CREATE ON DATABASE` is
enough. And RLS enforcement is decided entirely by the **app** role's attributes
(`NOSUPERUSER`, `NOBYPASSRLS`, not the table owner), independent of how privileged the
migration role is.

## Q7. If dev needs only two connection strings, why does production need `mokosh-bootstrap`? What does it do that two strings cannot?

The premise hides a third identity. Both strings authenticate **as roles**
(`mokosh_migrator`, `mokosh_app`), and something must `CREATE` those roles first - you cannot
connect as a role to create that same role. In dev, that creation is done by the in-container
`postgres` superuser. So dev secretly uses three identities, not two.

What the two app strings genuinely cannot do, because of a bootstrap circularity and a
privilege floor:

1. `CREATE ROLE` (and setting `BYPASSRLS`) - requires a superuser.
2. `GRANT ... ON DATABASE` - requires the database owner or a superuser.

`mokosh-bootstrap provision-roles` is exactly that one-time, more-privileged step.

## Q8. If dev drops the init script, will a third connection string provision the two roles? And what does "dev gets a free passwordless superuser inside the container" mean?

Both confirmed against the real image. The image's generated `pg_hba.conf`:

```
local  all  all                  trust            # unix socket  -> no password
host   all  all  127.0.0.1/32    trust            # loopback TCP -> no password
host   all  all  ::1/128         trust
host   all  all  all             scram-sha-256    # everything else -> password required
```

"Free passwordless superuser inside the container" means: a process **inside** the postgres
container can connect as the `postgres` superuser over the socket with no credentials
(`trust`). `pg-init.sh` exploits this. It is only free *inside* that container - the app
server runs in a different container, crosses the network, hits `scram-sha-256`, and needs
the password. Production has no equivalent, which is why it must be handed real admin
credentials.

And yes: a third connection string pointed at the `postgres` superuser over TCP (with the
password) creates the two roles with no init script and no socket. That makes dev and prod
identical.

**The unified, three-identity model:**

- **admin** (superuser) - used once to `CREATE ROLE` x2 and `GRANT CREATE ON DATABASE`.
- **`DATABASE_URL`** (migrator: `BYPASSRLS` + `CREATE ON DATABASE`) - runs migrations, which
  self-install the trusted extensions and create the schema.
- **`MOKOSH_APP_DATABASE_URL`** (app: `NOSUPERUSER NOBYPASSRLS`) - request serving, RLS
  enforced.

The only difference between environments is where the admin string comes from, and that
difference disappears once the init script is dropped.

## Q9-10. (Reprint request, then:) Create the YT issues to implement this, and include a `compose.prod.yml`.

Four decisions were needed first (issue split, prod-compose scope, how provisioning runs,
admin-string convention). They were asked in prose rather than by building on assumptions.

## Q11. Add a requirement: `ensure-env` must GENERATE all passwords in `.env`. A generic password should never be used.

`ensure-env` already existed but only copied `.env.example` verbatim, so generic dev
passwords landed in `.env`. The secrets split into two classes: **self-owned** (DB
passwords, JWT/encryption keys - generate strong random values) and **external**
(third-party API keys - cannot be generated, stay empty). Generation must be idempotent
(generate once, never rotate, or it breaks an existing volume - the same drift problem
removed earlier).

## Q12. Decisions: separate issues are fine; `compose.prod.yml` is an actual production deployment; remove `mokosh-bootstrap` and `pg-init.sh` (the three strings ARE the bootstrap); treat prod and dev the same, differing only in environment variables.

Three issues were filed:

- **PMS-489** - the server self-provisions roles at startup from a `MOKOSH_ADMIN_DATABASE_URL`,
  removing both `pg-init.sh` and `provision-roles`; the migrator self-installs extensions.
- **PMS-490** - `ensure-env` generates all self-owned secrets.
- **PMS-491** - add `compose.prod.yml` mirroring dev, differing only in environment-specific
  values.

## Q13. Remove the whole binary unless there is hidden functionality to surface. Production is always Docker - managed Postgres is not supported.

There *was* hidden functionality: `mokosh-bootstrap` has three other subcommands beyond
`provision-roles` (`bootstrap-infisical`, `clients register`, `qa-seed`/`qa-teardown`), each
wired into `just` recipes. So the binary cannot simply be deleted. The managed-Postgres
caveats were removed from the issues, since prod always runs Postgres in-container with a
true superuser available.

## Q14. Open an issue to migrate each functionality out of the binary, depending on the binary removal. Defer the per-feature decisions to when it is worked.

Two final issues:

- **PMS-493** - remove the `mokosh-bootstrap` binary (delete the source, the `Cargo.toml`
  bin target, the Dockerfile copy). Depends on PMS-489.
- **PMS-494** - migrate the three remaining features out (fold into `mokosh-server`, or drop
  if obsolete - decided at implementation time). Depends on PMS-493.

---

## Key takeaways

- **Verify load-bearing premises against the real system before designing.** The single
  wrong belief ("these extensions are untrusted") drove an entire plan, issue, and merged PR
  down the wrong path. One live query would have prevented it.
- **Code comments are secondary sources.** A comment that justifies a workaround is the first
  thing to test, not trust.
- **Trusted extensions (PG13+).** `uuid-ossp`, `pg_trgm`, `citext`, `pgcrypto` are all
  trusted; any role with `CREATE ON DATABASE` can install them. No superuser needed for that.
- **RLS enforcement depends on the *app* role**, not on how privileged the migration role is.
  The app role must be `NOSUPERUSER`, `NOBYPASSRLS`, and not the table owner; with
  `FORCE ROW LEVEL SECURITY`, even owners are subject to policy.
- **There are always three identities, not two.** Two unprivileged runtime roles
  (migrator, app) plus one privileged bootstrap connection that creates them. You cannot get
  below three, because you cannot authenticate as a role to create that same role, and
  `CREATE ROLE` / `GRANT ... ON DATABASE` need elevated rights the runtime roles deliberately
  lack.
- **Dev's "free superuser" is just the in-container `postgres` user over a trust-auth
  socket.** Production has no equivalent and must be given real admin credentials; making the
  admin connection explicit in both environments is what unifies them.
