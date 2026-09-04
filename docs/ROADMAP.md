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

Mokosh has the same exposure. `src/secrets/` and `src/storage/` are the right shape already, but configuration,
application secrets, authentication and email each reach their dependencies a different way, and 76 `env::var`
reads go around every seam that exists.

### Sequencing

The order is chosen so that each phase is usable on its own and no phase depends on one after it.

**1. Write it down.** [PMS-980](https://youtrack.a8n.run/issue/PMS-980) produces `providers.md` and this file. It
comes first because the vocabulary and the tier rule are what every later phase is judged against.

**2. Settle the vocabulary.** [PMS-1010](https://youtrack.a8n.run/issue/PMS-1010) renames `SecretStore` and
`ObjectStore` to `SecretProvider` and `ObjectProvider`. Early and cheap: every later phase either uses these names
or adds to the confusion. Bunyip's matching rename is
[BUNYIP-642](https://youtrack.a8n.run/issue/BUNYIP-642).

**3. The configuration seam.** [PMS-982](https://youtrack.a8n.run/issue/PMS-982) adds `ConfigProvider`, the
declared key registry with a tier on each key, and the build-time guard that fails on an `env::var` read outside
the provider. This is the phase that actually prevents the incident, because it is the one that makes bypassing
impossible. Everything after it depends on the seam existing.

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
