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
| Secrets (deployment) | `SecretProvider` | environment, file, database, Infisical | application | yes |
| Secrets (tenant) | `SecretProvider` | database, Infisical | tenant | yes |
| Storage | `ObjectProvider` | local, S3 | tenant | no |
| Authentication | `AuthProvider` | Bunyip OIDC, local | application | no |
| Email | `Mailer` | smtp, log, Bunyip relay | application | yes |

Payment (`PaymentProvider`) and RMM (`RmmProvider`) are also providers, but they are chosen per tenant as an
integration rather than per deployment as infrastructure, so they do not appear in the tables below.

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
| No provider holds it | Warning, naming the feature that will not work |
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

## Moving a value to a different provider

The order matters, and the tooling enforces the parts that are dangerous to get wrong.

1. Enable the new provider at a higher priority. Leave the old one enabled and lower.
2. `provider-migrate --from <old> --to <new>`. It writes, reads back, compares, and never deletes from the source.
3. `provider-status`. Every key must be present in the new provider before going further.
4. Restart. Boot provenance now shows the new provider serving each key.
5. Disable the old provider. Restart. Verify the application works.
6. `provider-purge --provider <old>`. Dry run by default; confirmation required to write.

Step 6 refuses, per key, unless **both** the provider being purged is disabled **and** the key is verified present,
live, in the provider now serving it. That interlock is why "I deleted the old copies and email broke" cannot
happen. There is no force flag; a refused purge means the migration is not finished.

Not every provider can purge. The environment provider cannot (a process cannot unset a variable for its own next
boot, and mounted secret files are read-only), and neither can an object store the operator owns. Where purge is
unsupported, the application reports what to delete and where, and claims nothing it did not do.

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
