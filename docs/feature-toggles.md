# Feature toggles

PMS-1414, ported from BUNYIP-840. Every major feature ships behind an on/off switch: off in production,
on in staging, flipped from an admin surface with no deploy. The point is that unfinished work merges
dark instead of living on a branch.

## The two halves

The **registry** (`src/modules/features/registry.rs`) is the list of features. One `Feature` variant per
switch, each with a stable key, a label, help text and its owning issue.

The **table** (`feature_toggles`, migration 261) records only what somebody changed. Two rules follow and
both matter:

- **A missing row reads as off.** A fresh database, a restored backup and a newly added variant all
  behave the same, and no upgrade has to seed a row per feature.
- **An unknown key is ignored**, with one warning per process, and is kept rather than deleted. A row
  nothing matches is a deployment that ran a newer build and rolled back; deleting it would lose the
  operator's intent, and failing on it would make the rollback unbootable.

## Adding one

1. Add a `Feature` variant with its key, label, help and issue. The key is `snake_case` (migration 261's
   CHECK enforces it, and a unit test checks the enum against that shape so a bad key fails at
   `cargo test --lib` rather than when an admin presses the switch).
2. Gate the behaviour on `FeatureSnapshot::is_enabled`.
3. Nothing else. No migration, no seed row, no config key, and no `NiceGuyIT/docker` pull request.

**Never rename a key.** It is the `feature_toggles.key` value and the wire name on the public probe, so a
rename does not migrate anything: the old row stops matching, reads as unknown, and the feature goes off
on every deployment that had it on. If a key must change, write a migration that moves the row.

## The surfaces

| | |
|---|---|
| `GET /api/v1/settings/feature-toggles` | Every registered feature with its stored state. Operator only. |
| `PUT /api/v1/settings/feature-toggles/{key}` | Flip one. 404 on a key no variant matches, audited in the same transaction as the upsert. Operator only. |
| `GET /api/v1/public/config` | `{"features": {key: bool}}`. No session. |

`/settings/*` and `DeploymentOperator` rather than bunyip's `/admin/*` and super-admin, because that is
where mokosh's other deployment-wide settings already live (PMS-638's email relay, PMS-789's product
name) and a feature toggle is the same kind of thing. The read is operator-only as well as the write: a
readable list of unfinished features on a deployment where only the operator can flip them is a map of
what to try next.

The probe is public because a client needs flags BEFORE it has a session, so a feature gating part of
the sign-in path could be gated at all. That is why it publishes keys and booleans only, with no label,
help, `updated_at` or `updated_by`.

## Staleness, stated

The state is a process-wide snapshot, refreshed every 60 seconds by a scheduler job
(`features::job::FeatureToggleRefresh`). A flip is immediate in the process that served the `PUT`, which
swaps its own snapshot, and visible to a sibling container within the interval. For a switch whose
purpose is "turn it on in staging and go look", a minute is not worth a cache-invalidation protocol.

A failed refresh logs and keeps the previous value, so a database blip leaves the deployment on the
switches it had rather than turning everything off.

## Not the same thing as `config::flags`

[`src/config/flags.rs`](../src/config/flags.rs) (PMS-983) is for a switch whose value belongs to the
deployment's CONFIGURATION: it comes from the configuration provider, can be set before the database
exists, and changing it is a deploy. `LOGIN_APPROVAL_ENABLED` is that shape, and nobody should be able to
flip it from a web page while a suspicious login is in flight.

A feature toggle is for work in progress. PMS-1414 deliberately leaves the two existing flags where they
are; BUNYIP-840 made the same call about `tier_config.orgs_enabled`, because a port that also rewires
live behaviour cannot be reverted by reverting it.

Per-tenant entitlement is a third thing again: that is `ModuleGate`, and it answers "has this customer
bought it" rather than "is this finished".
