# Providers

A **provider** is one implementation of a capability the application needs. The capability is a trait; each
implementation is a provider; the application picks between them from configuration and never knows which one it
got.

This is the same idea as Traefik's file, Docker and Kubernetes providers, or Forgejo's authentication sources. The
word is already used this way in the codebase for `PaymentProvider` and `RmmProvider`.

The rest of this page is the contract: what the kinds are, where each is configured, what wins when two providers
hold the same value, what the application does at boot, and how to move a value from one provider to another
without losing it.

## The kinds

| Kind | Trait | Providers | Tier | Refreshable |
|---|---|---|---|---|
| Configuration | `ConfigProvider` | environment, file, database, Bunyip | bootstrap + application | application only |
| Secrets (deployment) | `AppSecretProvider` | environment, file, database, Infisical | application | yes |
| Secrets (tenant) | `SecretProvider` | database, Infisical | tenant | yes |
| Storage | `ObjectProvider` | local, S3 | tenant | no |
| Authentication | `AuthProvider` | Bunyip OIDC, local | application | no (PMS-981: seam landed dormant; wiring lands with the deprecation of the legacy path) |
| Email | `Mailer` | smtp, log, Bunyip relay | application | yes |

Payment (`PaymentProvider`) and RMM (`RmmProvider`) are also providers, but they are chosen per tenant as an
integration rather than per deployment as infrastructure, so they do not appear in the tables below.

`src/config/`, `src/secrets/`, `src/storage/` and `src/app_secrets/` implement the kinds above. `src/app_secrets/`
(PMS-988) is Mokosh's application-tier `AppSecretProvider`, with a `GovernedSecret` registry that starts at
`SMTP_PASSWORD` and grows the day another deployment-wide secret joins it. Its selection variable is `SECRET_BACKEND`,
the same variable the tenant tier reads: both tiers pick the same provider on purpose.
[ROADMAP.md](ROADMAP.md) links the phase, and the issue, for every kind.

## The three tiers

The tiers are separated by **bootstrap order**, not by how secret a value is. That is the only line that can be
drawn without arguing about each key.

**Bootstrap** is what the process needs in order to build a provider at all: `DATABASE_URL`, `ENCRYPTION_KEY`, the
Infisical address and machine identity. It cannot come from a provider, because it is what a provider is made
from. The database cannot hold the credential used to reach the database.

**Application** is everything else the deployment configures: SMTP settings, feature flags, which providers are
enabled for the other kinds. Any enabled provider may serve it.

**Tenant** is what belongs to one MSP tenant rather than to the deployment: a tenant's payment-gateway
credentials, a tenant's logo. These are addressed by a key that carries the tenant (`SecretKey`, `ObjectKey`), so
one tenant's key cannot name another tenant's value.

## The registry, and the one read path

A trait alone does not prevent the incident. Bunyip had a working Infisical client and still read secrets from the
database, because nothing forced the read through the seam. Two things do, and a kind is not finished until it has
both:

- **A declared registry.** Every key the application may read is declared, with its tier, in one place. An
  undeclared key is not a runtime miss; it does not compile, because the read takes a declared key rather than a
  string. `src/config/registry.rs` is the configuration kind's, and `scripts/check-env-example.nu` compares it
  against `.env.example` and the dev compose environment in both directions.
- **A read path that cannot be bypassed.** A read that goes around the provider fails the build. For
  configuration that is `config::guard`, which fails `cargo test --lib` on an environment read outside
  `src/config/` and the entry points it names, each with one stated reason.

An entry point is narrow, and there are only two kinds of it. A **bootstrap entry point** runs before there is an
application to configure. A **provider of record** is the one reader of its own selection variable, or of the
values a provider is constructed from: a provider cannot be built out of what it is being built to serve.

## Where each is configured

| What | Configured in | Changed by |
|---|---|---|
| Bootstrap values | environment, or a file | restart |
| Which providers are enabled, and their priority | environment, or a file | restart |
| Application values | any enabled configuration or secret provider | refresh |
| Tenant values | the tenant's own provider, through the app | immediately |

Provider enablement is bootstrap configuration. Configuration that says where to find configuration cannot live
inside the thing it locates.

## Priority

Several providers of one kind can be enabled at once. That is not an edge case; it is how a value moves from one
provider to another without a flag day.

A value resolves to the **first enabled provider, in priority order, that holds it**. The application records
which provider that was, per key, so "where did this value come from" always has an answer.

## What happens at boot

For every declared key, the application checks which enabled providers hold it, and reports one of four things:

| Situation | What happens |
|---|---|
| The highest-priority provider holds it | Used. Recorded. |
| No provider holds it, and the registry names a feature its absence disables | Warning, naming the feature that will not work |
| No provider holds it, and the registry names no such feature | Silent (the key is legitimately unset by design; see the module note in `src/config/registry.rs`) |
| More than one provider holds it | Warning per duplicate, naming the purge command |
| The highest-priority provider does not hold it, a lower one does | **Fatal.** The process exits. |

The last row is the important one. It is the shape of the Bunyip production incident that this model exists to
prevent: secrets sat in the database while Infisical was configured and serving nothing, and no layer said so.
Configuring a provider and then not using it is now a startup failure, not a surprise six weeks later.

An unrecognised provider name is also fatal. An operator who typed a provider name asked for that provider, and
quietly giving them the default is the same silence in a smaller package.

## Refresh

Bootstrap values resolve once per process. Changing one means a restart.

Application values are held in a numbered **generation** carrying the resolution timestamp, the actor, and the
per-key record of which provider served it. A refresh builds a complete new generation and swaps it in atomically.

- If any required key fails to resolve, the refresh fails as a whole and the previous generation stays live. There
  is no half-applied state where the SMTP host is new and the password is old.
- One request sees exactly one generation.
- Refresh is an explicit action, not a file watcher. A watcher reads half-written files, fires twice, behaves
  differently on different mounts, and records nobody as the actor.

This is what makes testing an SMTP change tolerable: change the value, refresh, verify, without a restart.

**PMS-986** landed the atomic-swap-or-rollback contract as `config::try_refresh(RefreshRequest)` in code. The
caller names the actor (`RefreshActor::System` for a boot resolution or a scheduled refresh,
`RefreshActor::Operator(login)` for an admin-triggered one) and lists the keys that MUST resolve. A required key
that no provider holds returns `RefreshOutcome::Rejected` naming the unresolved keys and the providers that were
consulted (never a value), and the previous generation stays live: the generation-number counter is not consumed,
because it counts installed generations rather than attempts. A required key whose tier is `Bootstrap` is refused
before any I/O, because a provider is already built from it; `config::refuse_refresh_of_bootstrap(&key)` is the
per-key helper an admin endpoint calls before threading a key into a request. Per-request stability is one call:
a handler calls `config::snapshot()` once at entry and reads through the returned `Arc<Generation>` for the length
of the request, so a refresh mid-request is invisible to that handler. `config::refresh()` keeps its previous
signature and semantics: it is a thin wrapper around `try_refresh(RefreshRequest::system())` that ignores the
outcome, so every existing best-effort caller behaves unchanged. The admin endpoint that calls `try_refresh` with
required keys lands in a follow-up PR; PMS-986 is the seam it plugs into.

### Staleness report

Refresh alone is not enough. An operator can change a value in a provider and the running process keeps serving the
previous generation with nothing on screen saying so. The staleness report is the OBSERVATION half of that loop;
`try_refresh` is the ACTION half. They live at the same URL when the admin endpoint lands (PMS-989 / PMS-1012),
and the operator's job is to spot the divergent-keys list and refresh.

`config::check_staleness()` returns a `StalenessReport` that pairs the recorded generation (number, resolved-at,
actor) with a live presence probe (checked-at, one row per declared key, the provider's `list()` outcome). Each
`StalenessRow` carries the RECORDED serving provider AND the LIVE presence result as two facts: `recorded_served_by`
is what the current generation says served the key at resolution, `live_holds` is what the current provider says
today, and `state` is derived from the two. `StalenessReport::divergent_keys()` returns the subset whose state is
anything other than `Unchanged`, which is the list the admin surface names.

The report is side-effect-free beyond `Utc::now()`: it never mutates a generation, never calls `try_refresh`, and
never reads a value. Only `ConfigProvider::has`, `ConfigProvider::list`, `ConfigProvider::name` and
`Generation::served_by` are consulted. `StalenessRow`, `StalenessReport` and `EnumerationStatus` have hand-rolled
`Debug` implementations that print only names, provider names, booleans, timestamps and the recorded actor, so
capturing a report to a log line cannot leak a value. A source-scan test in `src/config/mod.rs` refuses a `value:`
or `resolved_value:` field on `StalenessRow` with a stated reason, the way `finance_gate::UNGATED` refuses an
untagged financial route.

An `EnumerationStatus::Unsupported` and an empty `EnumerationStatus::Supported(vec![])` are DIFFERENT facts and
never collapse into each other, matching the "I cannot see is not there is nothing there" rule the presence
matrix already follows. `StalenessState` carries a fourth variant, `ChangedProviderSinceResolution`, that today's
single-provider slot cannot itself produce; it is derived from the shape so the PMS-987 chain wiring lights it up
without another API-shape change. Wiring the report into an HTTP handler or CLI is the follow-up: PMS-989 renders
the admin endpoint and PMS-1012 the CLI, and PMS-984 is the data model each of those calls into.

## Moving a value to a different provider

The order matters, and the tooling enforces the parts that are dangerous to get wrong. The three commands land
in PMS-1012 as subcommands of `mokosh-server`, so an external migration tool cannot re-implement the providers.

1. Enable the new provider at a higher priority. Leave the old one enabled and lower.
2. `mokosh-server provider-migrate --from <old> --to <new>`. It writes, reads back, compares, and never deletes
   from the source. A key the target already holds is skipped and reported as `already-present`; a key the
   source does not hold is silently skipped; a write or read-back failure is named with the key and the reason.
3. `mokosh-server provider-status`. Every key must be present in the new provider before going further. The
   report is a per-key, per-provider presence matrix plus the provider now serving each key; `--json` outputs
   the same shape for a supervisor to aggregate across a fleet.
4. Restart. Boot provenance now shows the new provider serving each key.
5. Disable the old provider (unset its selection or drop it from `CONFIG_PROVIDERS`). Restart. Verify the
   application works.
6. `mokosh-server provider-purge --provider <old>`. Dry-run by default; `--confirm` is required to write.

Step 6 refuses, per key, unless **both** the provider being purged is disabled **and** the key is verified
present, live, in the provider now serving it. That interlock is why "I deleted the old copies and email broke"
cannot happen. There is no `--force` flag on any of the three commands; a refused purge is named with the
reason and means the migration is not finished. See `docs/operator-provider-runbook.md` for the walk-through
that turns the six steps into commands.

Not every provider can purge. The environment provider cannot (a process cannot unset a variable for its own
next boot, and mounted secret files are read-only), and neither can an object store the operator owns. Where
purge is unsupported, the application reports what to delete and where (the `{NAME}_FILE` path, the object key)
and claims nothing it did not do.

## Seeing what is in use

`provider-status` renders the presence matrix: every declared key, which providers hold it, and which one is
serving it.

```
KEY                    environment  database  infisical  serving
SMTP_PASSWORD          -            yes       yes        infisical
STRIPE_SECRET_KEY      -            yes       -          database   (!)
```

The `(!)` row is a value the declared provider does not hold. Presence is checked live, so it reflects the
providers now, not what they held at boot; the serving column reflects the current generation. When those two
disagree, that is the signal, which is why they are shown as two columns and never merged into one.

The same information is served as JSON for Bunyip to aggregate across the suite, and as an admin page for
self-hosted deployments where there is no Bunyip. Values are never shown, only provenance and presence.

A provider that cannot list its contents reports enumeration as `unsupported`, never as empty. "I cannot see" and
"there is nothing there" are different facts.

## Hosting profiles

One binary, two shapes, selected by `MOKOSH_DEPLOYMENT_MODE`:

- `self-hosted` (the default) starts with providers that need no external service: local storage, database
  secrets, environment configuration, local authentication. The customer image works out of the box.
- `saas` starts with the hosted platform's providers.

The profile supplies defaults only. Explicit configuration overrides it per kind, and the status report shows both
the active profile and every deviation from it.

## A note on names

The environment variables `SECRET_BACKEND` and `STORAGE_BACKEND` still say "backend" and will keep saying it.
Renaming them would break every running deployment for a vocabulary change. In code and in documentation the word
is provider.

## Where this is going

Sequencing and the issue for each phase are in [ROADMAP.md](ROADMAP.md).
