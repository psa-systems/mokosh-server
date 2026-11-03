# Roadmap

Durable narrative only: goals, phases, sequencing, and the reasoning behind the order. Status lives in YouTrack and
is never restated here. Each phase links to its owning issue; open the issue for what is done.

## Providers

Epic: [PMS-1009](https://youtrack.a8n.run/issue/PMS-1009). Model: [providers.md](providers.md).

### Why

A Bunyip production deployment kept its integration secrets in the database while Infisical was configured. The
Infisical client worked. The readiness probe was green. Nothing in any layer reported that the configured provider
was serving nothing, and the discrepancy was found only when a feature broke. Migrating out of it then failed
halfway, because there was no way to ask a provider whether it actually held a given secret.

The abstraction was not what was missing; Bunyip had one. What was missing was a declared registry of keys, a read
path that could not be bypassed, a recorded answer to "which provider served this", and a purge that refuses to
delete a value that is not safely somewhere else.

Mokosh had the same exposure. `src/secrets/` and `src/storage/` were the right shape already, but configuration,
application secrets, authentication and email each reached their dependencies a different way, and every
environment read went around whatever seam existed. Phase 3 below covers the configuration half of that; phases 5
and 9 cover application secrets, authentication and email.

### Sequencing

The order is chosen so that each phase is usable on its own and no phase depends on one after it.

**1. Write it down.** [PMS-980](https://youtrack.a8n.run/issue/PMS-980) produces `providers.md` and this file. It
comes first because the vocabulary and the tier rule are what every later phase is judged against.

**2. Settle the vocabulary.** [PMS-1010](https://youtrack.a8n.run/issue/PMS-1010) renames `SecretStore` and
`ObjectStore` to `SecretProvider` and `ObjectProvider`. Early and cheap: every later phase either uses these names
or adds to the confusion. Bunyip's matching rename is
[BUNYIP-642](https://youtrack.a8n.run/issue/BUNYIP-642).

**3. The configuration seam.** [PMS-982](https://youtrack.a8n.run/issue/PMS-982) adds `ConfigProvider`
(`src/config/`), the declared key registry with a tier on each key, and the build-time guard that fails on an
environment read outside the provider and its named entry points. This is the phase that actually prevents the
incident, because it is the one that makes bypassing impossible. Everything after it depends on the seam
existing. It landed with every read moved and no allowlist of exceptions, which is why
[PMS-1024](https://youtrack.a8n.run/issue/PMS-1024) was folded into it rather than sequenced after it: a
follow-up whose every criterion named an artefact this phase creates could not run on its own.

**4. More configuration providers.** [PMS-987](https://youtrack.a8n.run/issue/PMS-987) adds file, database and
Bunyip implementations with declared priority and several enabled at once. Multiple providers of one kind is a
requirement, not a luxury: it is the only way a value moves between providers without a flag day.

**5. Application secrets.** [PMS-988](https://youtrack.a8n.run/issue/PMS-988) adds the governed-secret registry
and its providers, adopting Bunyip's boot contract rather than inventing a second one. The tenant tier in
`src/secrets/` is untouched.

**6. Deployment shape.** [PMS-1011](https://youtrack.a8n.run/issue/PMS-1011) extends the existing
`DeploymentMode` so a hosting profile supplies default providers. One binary, two profiles, no cargo feature.

**7. Refresh.** [PMS-986](https://youtrack.a8n.run/issue/PMS-986) makes application configuration re-resolvable as
an atomic generation swap, and [PMS-984](https://youtrack.a8n.run/issue/PMS-984) surfaces staleness and the
refresh control. Together these are what remove the edit-restart-hope loop.

**8. The operator tooling.** [PMS-1012](https://youtrack.a8n.run/issue/PMS-1012) adds `provider-status`,
`provider-migrate` and `provider-purge` with the verified purge interlock. This is the phase that answers the
original incident end to end, and it needs the providers from phases 4 and 5 to have something to move between.

**9. The remaining kinds.** [PMS-981](https://youtrack.a8n.run/issue/PMS-981) makes authentication a selectable
provider, keeping both current paths enabled for backward compatibility.
[PMS-1013](https://youtrack.a8n.run/issue/PMS-1013) makes the email provider chosen by name instead of inferred
from whether `SMTP_HOST` is set, and adds verify. [PMS-983](https://youtrack.a8n.run/issue/PMS-983) moves feature
flags onto the configuration provider.

**10. Visibility.** [PMS-989](https://youtrack.a8n.run/issue/PMS-989) serves the provider status as JSON for
Bunyip and as an admin page for self-hosted deployments, from one collector.

**11. Share what proved common.** [PMS-1014](https://youtrack.a8n.run/issue/PMS-1014) extracts the shared traits
and the status contract into a crate, deliberately last. Extracting from three working implementations is a
smaller and better-informed job than designing an abstraction for three that do not exist yet.

### Across the suite

The same model is being adopted in all three applications, and Bunyip is the reference rather than a follower: its
secrets governance (`SecretsStorage`, `GovernedSecret`, `secrets-status` / `secrets-migrate` / `secrets-purge`)
already implements most of what phases 5 and 8 add here.

- Bunyip: [BUNYIP-641](https://youtrack.a8n.run/issue/BUNYIP-641) covers the vocabulary, configuration providers
  ([BUNYIP-643](https://youtrack.a8n.run/issue/BUNYIP-643)), and the aggregated view of the whole suite
  ([BUNYIP-634](https://youtrack.a8n.run/issue/BUNYIP-634)).
- Drillmark: [DMARC-40](https://youtrack.a8n.run/issue/DMARC-40) covers providers and the registry
  ([DMARC-42](https://youtrack.a8n.run/issue/DMARC-42)), serving the status contract
  ([DMARC-41](https://youtrack.a8n.run/issue/DMARC-41)), and authentication selection once Mokosh's interface has
  shipped ([DMARC-43](https://youtrack.a8n.run/issue/DMARC-43)).

The status contract is versioned and defined once, in BUNYIP-634. All three applications serve the same shape, so
Bunyip can show them on one page and a discrepancy is visible without anyone knowing to go looking for it.

## Specification

Epic: [PMS-1592](https://youtrack.a8n.run/issue/PMS-1592).

### Why

`docs/specification.md` was prose with no requirement ids, and nothing in the source tree cited it, so a reader
had no way to tell a described behavior from an undescribed one, or a requirement from the code that satisfies
it. The fix is a numbered, normative requirement set with a `// SPEC-<section>.<n>` comment at every implementing
site, built one module group at a time so each PR stays small enough to read in full.

### Sequencing

Each phase owns its own sections of `docs/specification.md` and its own slice of the source tree, so the phases
can land in any order without colliding on content; only this file and `CLAUDE.md`'s one-line pointer to the
specification are shared.

1. [PMS-1593](https://youtrack.a8n.run/issue/PMS-1593): sections 1-2, foundation and server core.
2. [PMS-1594](https://youtrack.a8n.run/issue/PMS-1594): section 3, providers and secrets.
3. [PMS-1595](https://youtrack.a8n.run/issue/PMS-1595): section 4, utilities, PDF and wire types.
4. [PMS-1596](https://youtrack.a8n.run/issue/PMS-1596): section 5, identity, tenancy and audit.
5. [PMS-1597](https://youtrack.a8n.run/issue/PMS-1597): section 6, billing and time.
6. [PMS-1598](https://youtrack.a8n.run/issue/PMS-1598): section 7, service desk.
7. [PMS-1599](https://youtrack.a8n.run/issue/PMS-1599): section 8, remaining modules.
8. [PMS-1600](https://youtrack.a8n.run/issue/PMS-1600): section 9, data model and migrations. Done.
9. [PMS-1601](https://youtrack.a8n.run/issue/PMS-1601): section 10, build, CI and deployment.
10. [PMS-1602](https://youtrack.a8n.run/issue/PMS-1602): section 11, the cross-cutting index, sequenced last
    because it is the only phase that reads every other section's final id range.
