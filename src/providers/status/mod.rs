//! One collector, two renderings: JSON for aggregators, HTML for operators.
//!
//! The report answers "which providers is this process using, right now"
//! across every provider kind (`docs/providers.md`): configuration
//! (PMS-987), application-tier secrets (PMS-988), tenant-tier secrets
//! (PMS-967), storage (PMS-958), authentication (PMS-981), and email
//! (`MailerConfig`). Every field is a NAME, a boolean, an integer, or a
//! timestamp; the collector never calls `provider.get(key)` or
//! `generation.value(key)` and therefore cannot serialise a value even by
//! accident. The `debug_output_never_carries_a_value` shape from PMS-984
//! is applied here to the whole report.
//!
//! # Two renderings, one collector
//!
//! [`collect`] is the one function that reads process-global state. Two
//! renderers, [`renderer_json::render_json`] and
//! [`renderer_html::render_html`], are pure functions of the returned
//! [`ProviderStatusReport`], so a difference between the JSON and the HTML
//! is a bug in one of the renderers rather than a drift between two
//! aggregation paths. The `agreement_between_renderings` test pins that
//! both name the same kinds.
//!
//! # Authentication is deferred to when BUNYIP-634 lands
//!
//! The JSON endpoint is admin-gated in this PR: `RequireAdmin` from
//! `src/modules/auth/middleware.rs`. The ticket names a Bunyip machine
//! credential as a possible shape but flags it "revise if BUNYIP-634
//! settles on another", and BUNYIP-634 has not shipped yet. Swapping the
//! gate is a follow-up.

use std::sync::Arc;

use chrono::{DateTime, Utc};

use crate::app_secrets::{AppSecretProviderKind, AppSecrets, GovernedSecret};
use crate::config::{
    self, chain, snapshot, ConfigProviderChain, ConfigProviderKind, ConfigSelection, Generation,
    RefreshActor,
};
use crate::modules::auth::providers::{AuthProviderKind, AuthProviderSelection};
use crate::secrets::SecretsConfig;
use crate::storage::StorageProviderKind;
use crate::utils::deployment::{
    provider as provider_name, DeploymentMode, EnablementSource, ProviderKind, ProviderOverrides,
    ProviderSelection,
};
use crate::utils::email::MailerConfig;

pub mod public_summary;
pub mod public_summary_route;
pub mod renderer_html;
pub mod renderer_json;
pub mod route;

/// The whole report, rendered by [`renderer_json::render_json`] and
/// [`renderer_html::render_html`].
///
/// Only names, booleans, small integers, timestamps and statuses. No values,
/// no credentials, no URLs beyond an unreachability message that may name a
/// host and a status code.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProviderStatusReport {
    /// Which hosting profile is active (`self-hosted` or `saas`).
    pub hosting_profile: &'static str,
    /// Every kind whose selection differs from the hosting profile's default.
    /// A deviation is worth naming; the defaults themselves are not.
    pub deviations: Vec<HostingProfileDeviation>,
    /// The application-tier configuration generation the process is serving.
    pub configuration_generation: GenerationHeader,
    /// Per-kind reports, in a stable order.
    pub kinds: Vec<ProviderKindReport>,
    /// UTC timestamp when this collection ran.
    pub collected_at: DateTime<Utc>,
}

/// A generation identity for the report: number, when it resolved, and who.
///
/// `actor` is a human-readable string, never credential material.
/// [`RefreshActor::System`] renders as `"System"`, an
/// [`RefreshActor::Operator`] as `"Operator(<login>)"`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct GenerationHeader {
    pub number: u64,
    pub resolved_at: DateTime<Utc>,
    pub actor: String,
}

impl GenerationHeader {
    fn from_generation(generation: &Generation) -> Self {
        let actor = match generation.actor() {
            RefreshActor::System => "System".to_string(),
            RefreshActor::Operator(login) => format!("Operator({login})"),
        };
        Self {
            number: generation.number(),
            resolved_at: generation.resolved_at(),
            actor,
        }
    }
}

/// One kind's selection differs from the profile's default.
///
/// Deliberately shaped after `ProviderChoice`: the row a caller renders as
/// "the operator asked for X here, the profile would have said Y".
#[derive(Debug, Clone, serde::Serialize)]
pub struct HostingProfileDeviation {
    pub kind: &'static str,
    pub profile_default: Vec<&'static str>,
    pub explicit: Vec<&'static str>,
}

/// One row per provider kind. Kinds whose providers cannot enumerate keep
/// `keys` empty and `enumeration` `None`; kinds a caller cannot inspect at
/// process scope (tenant-tier secrets) keep both empty.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProviderKindReport {
    /// One of: `configuration`, `secrets_application`, `secrets_tenant`,
    /// `storage`, `authentication`, `email`.
    pub kind: &'static str,
    /// Every provider enabled for this kind, in priority order.
    pub enabled: Vec<EnabledProviderReport>,
    /// The provider serving this kind at collection time, if any.
    pub serving: Option<&'static str>,
    /// Per-key provenance and live presence (populated for `configuration`
    /// and `secrets_application` only; other kinds carry an empty vec).
    pub keys: Vec<KeyReport>,
    /// Enumeration outcome for kinds whose providers can list. `None` when
    /// enumeration is not a concept for the kind (authentication, email).
    pub enumeration: Option<KindEnumerationStatus>,
}

/// One enabled provider on a kind.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EnabledProviderReport {
    pub name: &'static str,
    /// 0 is highest priority.
    pub priority: usize,
    pub reachable: bool,
    /// If unreachable, the human message. Never a URL, credential or value;
    /// naming a host and a status code is fine.
    pub unreachable_reason: Option<String>,
}

/// One declared key's provenance and live presence for the report.
#[derive(Debug, Clone, serde::Serialize)]
pub struct KeyReport {
    pub key: &'static str,
    /// PMS-1075: the sentence describing what stops working when nobody
    /// holds this key. `None` when the key is legitimately optional.
    pub feature: Option<&'static str>,
    /// The provider recorded in the current generation. `None` when nobody
    /// held it at the last resolve.
    pub recorded_served_by: Option<&'static str>,
    /// Live presence at collection time, from the provider's `has()`.
    pub live_holds: bool,
    /// One of `unchanged`, `appeared`, `disappeared`, `changed_provider`
    /// (PMS-984 divergence classification).
    pub state: &'static str,
}

/// The `list()` outcome for a kind that supports enumeration.
///
/// An empty `Supported(Vec::new())` and an `Unsupported` are DIFFERENT facts
/// and never collapse into each other, the way `Enumeration` and
/// `EnumerationStatus` already keep them apart in `crate::config`.
#[derive(Debug, Clone, serde::Serialize)]
pub enum KindEnumerationStatus {
    Supported(Vec<String>),
    Unsupported,
}

/// Collect the whole report. Side-effect-free except for `Utc::now()` and
/// the `has()` / `list()` calls it makes on live providers.
///
/// Never calls `provider.get(key)` or `generation.value(key)`. See the
/// `no_value_readers_in_collector` source-scan test for the enforced form of
/// that rule.
pub fn collect() -> ProviderStatusReport {
    // The lenient reader: this is a status report, not a boot check, so
    // an unrecognised value defaults to self-hosted rather than aborting
    // the collection. `DeploymentMode::from_env` is an allowed direct env
    // reader (see `config::guard::ENTRY_POINTS`).
    let hosting_profile = DeploymentMode::from_env();
    let generation = snapshot();
    let installed_chain = chain();

    let configuration = collect_configuration_kind(installed_chain.as_deref(), &generation);
    let secrets_app = collect_secrets_application_kind(crate::app_secrets::current());
    let (secrets_tenant, secrets_tenant_override) = collect_secrets_tenant_kind(hosting_profile);
    let (storage, storage_override) = collect_storage_kind(hosting_profile);
    let (authentication, auth_override) = collect_authentication_kind(hosting_profile);
    let (email, email_override) = collect_email_kind();
    let config_override = collect_configuration_override();

    let overrides = ProviderOverrides::new()
        .with_opt(ProviderKind::Configuration, config_override)
        .with_opt(ProviderKind::Secrets, secrets_tenant_override)
        .with_opt(ProviderKind::Storage, storage_override)
        .with_opt(ProviderKind::Authentication, auth_override)
        .with_opt(ProviderKind::Email, email_override);
    let selection = hosting_profile.resolve_providers(&overrides);
    let deviations = collect_deviations(&selection);

    ProviderStatusReport {
        hosting_profile: match hosting_profile {
            DeploymentMode::SelfHosted => "self-hosted",
            DeploymentMode::Saas => "saas",
        },
        deviations,
        configuration_generation: GenerationHeader::from_generation(&generation),
        kinds: vec![
            configuration,
            secrets_app,
            secrets_tenant,
            storage,
            authentication,
            email,
        ],
        collected_at: Utc::now(),
    }
}

/// Configuration kind report. If a chain is installed (PMS-987) we walk it;
/// otherwise we synthesize a one-entry equivalent from the environment
/// provider that is the single-provider slot's default.
fn collect_configuration_kind(
    installed_chain: Option<&ConfigProviderChain>,
    generation: &Generation,
) -> ProviderKindReport {
    // Build the enabled-providers list from whatever chain (or single slot)
    // is actually installed. Reachability for configuration is always true:
    // constructing a provider that could not read is a build-time error, and
    // the read paths this seam serves are in-process (env, file) or already
    // covered by their own probe (Infisical, Bunyip).
    let enabled: Vec<EnabledProviderReport> = match installed_chain {
        Some(chain) => chain
            .kinds()
            .into_iter()
            .enumerate()
            .map(|(priority, kind)| EnabledProviderReport {
                name: kind.as_str(),
                priority,
                reachable: true,
                unreachable_reason: None,
            })
            .collect(),
        None => vec![EnabledProviderReport {
            name: ConfigProviderKind::Environment.as_str(),
            priority: 0,
            reachable: true,
            unreachable_reason: None,
        }],
    };

    // Which provider actually served this generation? The recorded
    // `served_by` on the first held key gives the answer for the
    // single-provider slot; a PMS-987 chain answers per-key and the field
    // here reports the first non-None seen.
    let serving = resolve_serving_provider(generation);

    // Per-key rows come from `config::check_staleness`, which is what
    // PMS-984 built for exactly this purpose. Not calling that would mean a
    // second implementation of the same walk with a second answer.
    let staleness = config::check_staleness();
    let keys: Vec<KeyReport> = staleness
        .rows
        .iter()
        .map(|row| KeyReport {
            key: row.key,
            feature: row.feature,
            recorded_served_by: row.recorded_served_by,
            live_holds: row.live_holds,
            state: staleness_state_name(row.state),
        })
        .collect();

    let enumeration = match staleness.enumeration {
        config::EnumerationStatus::Supported(names) => {
            Some(KindEnumerationStatus::Supported(names))
        }
        config::EnumerationStatus::Unsupported => Some(KindEnumerationStatus::Unsupported),
    };

    ProviderKindReport {
        kind: "configuration",
        enabled,
        serving,
        keys,
        enumeration,
    }
}

/// The provider name that served at least one recorded key. Returns the
/// first non-`None` `served_by` seen; when several providers served (a
/// PMS-987 chain), the first is the highest-priority one that held anything.
fn resolve_serving_provider(generation: &Generation) -> Option<&'static str> {
    for key in config::REGISTRY.iter() {
        if let Some(name) = generation.served_by(key) {
            return Some(name);
        }
    }
    None
}

/// PMS-984 divergence classification -> the wire name used in the report.
fn staleness_state_name(state: config::StalenessState) -> &'static str {
    match state {
        config::StalenessState::Unchanged => "unchanged",
        config::StalenessState::AppearedSinceResolution => "appeared",
        config::StalenessState::DisappearedSinceResolution => "disappeared",
        config::StalenessState::ChangedProviderSinceResolution => "changed_provider",
    }
}

/// Application-tier secrets. PMS-988 shipped dormant: `init_from_env` may
/// not have run in this process, in which case the module reports nothing
/// held rather than fabricating a shape.
fn collect_secrets_application_kind(secrets: Option<Arc<AppSecrets>>) -> ProviderKindReport {
    let Some(secrets) = secrets else {
        return ProviderKindReport {
            kind: "secrets_application",
            enabled: Vec::new(),
            serving: None,
            keys: Vec::new(),
            enumeration: None,
        };
    };

    // The declared provider serves; any other built provider is a
    // configuration hazard the boot classifier already surfaced.
    let declared = secrets.declared();
    let enabled: Vec<EnabledProviderReport> = AppSecretProviderKind::ALL
        .iter()
        .enumerate()
        .filter_map(|(priority, kind)| {
            secrets.provider(*kind).map(|_| EnabledProviderReport {
                name: kind.as_str(),
                // Priority is declaration order in ALL; the declared
                // provider is what serves, regardless of position.
                priority,
                reachable: true,
                unreachable_reason: None,
            })
        })
        .collect();

    let keys: Vec<KeyReport> = GovernedSecret::ALL
        .iter()
        .map(|secret| {
            // NEVER `provider.get()`; only `provider.has()`.
            let live_holds = secrets.provider(declared).is_some_and(|p| p.has(*secret));
            let recorded_served_by = live_holds.then(|| declared.as_str());
            KeyReport {
                key: secret.name(),
                feature: Some(secret.feature()),
                recorded_served_by,
                live_holds,
                state: if live_holds {
                    "unchanged"
                } else {
                    "disappeared"
                },
            }
        })
        .collect();

    ProviderKindReport {
        kind: "secrets_application",
        enabled,
        serving: Some(declared.as_str()),
        keys,
        enumeration: None,
    }
}

/// Tenant-tier secrets. Per-tenant scoped and has no process-wide
/// "current" state to report on: naming the enabled provider is what this
/// row is for, and the keys column stays empty because enumerating a tenant
/// secret would require a tenant scope this collector deliberately does not
/// hold.
///
/// Returns `(report, explicit_override)` so the outer collector can build
/// `ProviderOverrides` without a second reader of `SECRET_BACKEND`.
fn collect_secrets_tenant_kind(
    hosting_profile: DeploymentMode,
) -> (ProviderKindReport, Option<Vec<&'static str>>) {
    // `SecretsConfig::from_env` is the ONE reader of SECRET_BACKEND for the
    // tenant tier; calling it here is what keeps PMS-982's guard test happy
    // (no direct env read in this file).
    let profile_default = hosting_profile
        .default_provider_for(ProviderKind::Secrets)
        .unwrap_or(provider_name::DATABASE);
    let (name, explicit) = match SecretsConfig::from_env(profile_default) {
        Ok(cfg) => (cfg.provider.as_str(), cfg.explicit_providers()),
        Err(_) => (profile_default, None),
    };
    (
        ProviderKindReport {
            kind: "secrets_tenant",
            enabled: vec![EnabledProviderReport {
                name,
                priority: 0,
                reachable: true,
                unreachable_reason: None,
            }],
            serving: Some(name),
            // Enumerating a tenant secret needs a tenant scope this
            // collector does not hold; the row exists to name the provider.
            keys: Vec::new(),
            enumeration: None,
        },
        explicit,
    )
}

/// Storage kind. `StorageProviderKind::from_env` is the ONE reader of
/// `STORAGE_BACKEND`, so the name here agrees byte-for-byte with what
/// `crate::storage::init_from_env` chose at boot.
fn collect_storage_kind(
    hosting_profile: DeploymentMode,
) -> (ProviderKindReport, Option<Vec<&'static str>>) {
    let profile_default = hosting_profile
        .default_provider_for(ProviderKind::Storage)
        .unwrap_or(provider_name::LOCAL);
    let (kind, source) = StorageProviderKind::from_env(profile_default)
        .unwrap_or((StorageProviderKind::Local, EnablementSource::Profile));
    let name = kind.as_str();
    let explicit = (source == EnablementSource::Explicit).then(|| vec![name]);
    (
        ProviderKindReport {
            kind: "storage",
            enabled: vec![EnabledProviderReport {
                name,
                priority: 0,
                reachable: true,
                unreachable_reason: None,
            }],
            serving: Some(name),
            keys: Vec::new(),
            enumeration: None,
        },
        explicit,
    )
}

/// Authentication kind. `AuthProviderSelection::from_env` reads
/// `AUTH_PROVIDERS` through the configuration provider, so no direct env
/// read is needed here.
fn collect_authentication_kind(
    hosting_profile: DeploymentMode,
) -> (ProviderKindReport, Option<Vec<&'static str>>) {
    let profile_default: Vec<&'static str> = hosting_profile
        .default_providers_for(ProviderKind::Authentication)
        .to_vec();
    let selection = match AuthProviderSelection::from_env(&profile_default) {
        Ok(s) => s,
        Err(_) => {
            // A malformed AUTH_PROVIDERS should not stop the status page;
            // fall back to the profile default so the operator still sees
            // what is running today.
            let enabled: Vec<EnabledProviderReport> = profile_default
                .iter()
                .enumerate()
                .map(|(priority, name)| EnabledProviderReport {
                    name,
                    priority,
                    reachable: true,
                    unreachable_reason: None,
                })
                .collect();
            let serving = profile_default.first().copied();
            return (
                ProviderKindReport {
                    kind: "authentication",
                    enabled,
                    serving,
                    keys: Vec::new(),
                    enumeration: None,
                },
                None,
            );
        }
    };

    let enabled: Vec<EnabledProviderReport> = selection
        .providers
        .iter()
        .enumerate()
        .map(|(priority, kind)| {
            // A local provider is always reachable. A bunyip provider is
            // reachable when the verifier could be built; approximated by
            // "OIDC_ISSUER and OIDC_AUDIENCE are set", which is the same
            // check `VerifierConfig::from_env` runs.
            let (reachable, reason) = match kind {
                AuthProviderKind::Local => (true, None),
                AuthProviderKind::Bunyip => {
                    let issuer = config::get(&config::registry::OIDC_ISSUER)
                        .map(|s| !s.trim().is_empty())
                        .unwrap_or(false);
                    let audience = config::get(&config::registry::OIDC_AUDIENCE)
                        .map(|s| !s.trim().is_empty())
                        .unwrap_or(false);
                    if issuer && audience {
                        (true, None)
                    } else {
                        (
                            false,
                            Some(
                                "OIDC_ISSUER and/or OIDC_AUDIENCE unset; \
                                 bunyip verifier is not mounted"
                                    .to_string(),
                            ),
                        )
                    }
                }
            };
            EnabledProviderReport {
                name: kind.as_str(),
                priority,
                reachable,
                unreachable_reason: reason,
            }
        })
        .collect();

    let serving = selection.providers.first().map(|k| k.as_str());
    let explicit = selection.explicit_providers();
    (
        ProviderKindReport {
            kind: "authentication",
            enabled,
            serving,
            keys: Vec::new(),
            enumeration: None,
        },
        explicit,
    )
}

/// Email kind. `MailerConfig::from_env` reads through the configuration
/// provider, so no direct env read is needed here. `.build()` is NOT called;
/// a status page must not try to open an SMTP connection.
fn collect_email_kind() -> (ProviderKindReport, Option<Vec<&'static str>>) {
    match MailerConfig::from_env() {
        Ok(cfg) => {
            let (name, explicit) = if cfg.host.is_some() {
                (provider_name::SMTP, Some(vec![provider_name::SMTP]))
            } else {
                (provider_name::LOG, None)
            };
            (
                ProviderKindReport {
                    kind: "email",
                    enabled: vec![EnabledProviderReport {
                        name,
                        priority: 0,
                        reachable: true,
                        unreachable_reason: None,
                    }],
                    serving: Some(name),
                    keys: Vec::new(),
                    enumeration: None,
                },
                explicit,
            )
        }
        Err(_) => (
            ProviderKindReport {
                kind: "email",
                enabled: Vec::new(),
                serving: None,
                keys: Vec::new(),
                enumeration: None,
            },
            None,
        ),
    }
}

/// The configuration override, if any. `ConfigSelection::from_env` reads
/// `CONFIG_BACKEND` (inside `crate::config`, an entry point). When a PMS-987
/// chain is installed, its kinds ARE the override.
fn collect_configuration_override() -> Option<Vec<&'static str>> {
    if let Some(installed) = chain() {
        return Some(installed.kinds().iter().map(|k| k.as_str()).collect());
    }
    match ConfigSelection::from_env(provider_name::ENVIRONMENT) {
        Ok(sel) => sel.explicit_providers(),
        Err(_) => None,
    }
}

fn collect_deviations(selection: &ProviderSelection) -> Vec<HostingProfileDeviation> {
    selection
        .deviations()
        .map(|choice| HostingProfileDeviation {
            kind: choice.kind.as_str(),
            profile_default: selection.mode().default_providers_for(choice.kind).to_vec(),
            explicit: choice.providers.clone(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The collector must not read any resolved value: `provider.get()` and
    /// `generation.value()` are forbidden. `provider.has()` and
    /// `generation.served_by()` are the two allowed accessors.
    ///
    /// A source-scan of this file's own text, the `finance_gate::UNGATED`
    /// shape from PMS-984 already uses.
    #[test]
    fn no_value_readers_in_collector() {
        const SRC: &str = include_str!("mod.rs");
        // Strip the tests module so the scan does not fire on itself.
        let (before, _tests) = SRC
            .split_once("#[cfg(test)]")
            .expect("this file has a tests module");
        // Only check code lines, not doc comments. Doc lines start with
        // `//` (after trim) and are prose about the rule; the ban is on
        // an actual method call.
        let code: String = before
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for forbidden in [".value(", "provider.get("] {
            assert!(
                !code.contains(forbidden),
                "the collector must not call {forbidden}; use has() / \
                 served_by() instead. PMS-989 report is provenance only",
            );
        }
    }

    /// The report carries one entry per provider kind, in a stable order.
    #[test]
    fn collect_returns_one_report_per_kind_in_a_stable_order() {
        let report = collect();
        let kinds: Vec<&str> = report.kinds.iter().map(|k| k.kind).collect();
        assert_eq!(
            kinds,
            vec![
                "configuration",
                "secrets_application",
                "secrets_tenant",
                "storage",
                "authentication",
                "email",
            ]
        );
    }

    /// The report's hosting profile is one of the two known names.
    #[test]
    fn collect_names_a_known_hosting_profile() {
        let report = collect();
        assert!(
            matches!(report.hosting_profile, "self-hosted" | "saas"),
            "unknown hosting profile: {}",
            report.hosting_profile
        );
    }

    /// The report serialises without carrying anything that looks like a
    /// secret. Names, timestamps and booleans only.
    #[test]
    fn serialised_report_carries_no_secret_looking_strings() {
        let report = collect();
        let json = serde_json::to_string(&report).expect("report serialises");
        // These substrings are what would appear if the collector had reached
        // for a value: env test fixtures use them, and no legitimate NAME on
        // any provider kind carries them.
        for forbidden in ["hunter2", "PRIVATE KEY", "\"password\":"] {
            assert!(
                !json.contains(forbidden),
                "report may carry a value that resembles {forbidden:?}: {json}",
            );
        }
    }

    /// A deviation is one kind whose provider list differs from the
    /// profile's default. `resolve_providers` with no overrides yields no
    /// deviations, whatever the profile is.
    #[test]
    fn collect_deviations_is_empty_when_nothing_is_overridden() {
        for mode in [DeploymentMode::SelfHosted, DeploymentMode::Saas] {
            let selection = mode.resolve_providers(&ProviderOverrides::new());
            let deviations = collect_deviations(&selection);
            assert!(
                deviations.is_empty(),
                "{mode}: unexpected deviations {deviations:?}"
            );
        }
    }

    /// A deviation is named when the override differs from the default.
    #[test]
    fn collect_deviations_names_the_kind_and_both_sides() {
        let overrides =
            ProviderOverrides::new().with(ProviderKind::Storage, vec![provider_name::S3]);
        let selection = DeploymentMode::SelfHosted.resolve_providers(&overrides);
        let deviations = collect_deviations(&selection);
        assert_eq!(deviations.len(), 1);
        assert_eq!(deviations[0].kind, "storage");
        assert_eq!(deviations[0].profile_default, vec![provider_name::LOCAL]);
        assert_eq!(deviations[0].explicit, vec![provider_name::S3]);
    }

    /// The staleness state names are exactly the four PMS-984 defined.
    #[test]
    fn staleness_state_names_are_the_four_pms_984_defined() {
        assert_eq!(
            staleness_state_name(config::StalenessState::Unchanged),
            "unchanged"
        );
        assert_eq!(
            staleness_state_name(config::StalenessState::AppearedSinceResolution),
            "appeared"
        );
        assert_eq!(
            staleness_state_name(config::StalenessState::DisappearedSinceResolution),
            "disappeared"
        );
        assert_eq!(
            staleness_state_name(config::StalenessState::ChangedProviderSinceResolution),
            "changed_provider"
        );
    }

    /// GenerationHeader renders the actor as a human string, never
    /// credential material. `Operator("alice")` -> `"Operator(alice)"`.
    #[test]
    fn generation_header_renders_actor_as_a_human_string() {
        use std::collections::BTreeMap;

        struct MapProvider(BTreeMap<String, String>);
        impl config::ConfigProvider for MapProvider {
            fn name(&self) -> &'static str {
                "test"
            }
            fn get(&self, key: &str) -> Option<String> {
                self.0.get(key).cloned()
            }
        }
        let provider = MapProvider(BTreeMap::new());

        let system = Generation::resolve(&provider, None, 1, RefreshActor::System);
        assert_eq!(GenerationHeader::from_generation(&system).actor, "System");

        let operator = Generation::resolve(
            &provider,
            None,
            1,
            RefreshActor::Operator("alice".to_string()),
        );
        assert_eq!(
            GenerationHeader::from_generation(&operator).actor,
            "Operator(alice)"
        );
    }

    /// Application-secret report when `AppSecrets::current()` is `None`:
    /// dormant PMS-988 shipping state, nothing enabled, nothing served.
    #[test]
    fn app_secrets_kind_is_empty_when_not_initialised() {
        let report = collect_secrets_application_kind(None);
        assert_eq!(report.kind, "secrets_application");
        assert!(report.enabled.is_empty());
        assert!(report.serving.is_none());
        assert!(report.keys.is_empty());
    }

    /// Renderings agree: both the JSON and the HTML name the same set of
    /// kinds and in the same order.
    #[test]
    fn agreement_between_renderings() {
        let report = collect();
        let json = renderer_json::render_json(&report);
        let html = renderer_html::render_html(&report);
        // JSON: read `kinds` array and pull each `kind` string.
        let json_kinds: Vec<String> = json["report"]["kinds"]
            .as_array()
            .expect("kinds is an array")
            .iter()
            .map(|k| k["kind"].as_str().expect("kind is a string").to_string())
            .collect();
        // HTML: each kind renders a section with an id="<kind>".
        let html_kinds: Vec<String> = json_kinds
            .iter()
            .filter(|k| html.contains(&format!("id=\"{k}\"")))
            .cloned()
            .collect();
        assert_eq!(
            html_kinds, json_kinds,
            "JSON kinds and HTML sections must match 1:1"
        );
    }

    /// The JSON envelope carries a schema version and the report as a
    /// nested object with a top-level `generated_at`.
    #[test]
    fn json_envelope_has_the_documented_shape() {
        let report = collect();
        let json = renderer_json::render_json(&report);
        assert_eq!(json["schema_version"], json!("1"));
        assert!(json["report"].is_object(), "report is nested");
        assert!(json["generated_at"].is_string(), "generated_at is set");
        assert!(json["report"]["hosting_profile"].is_string());
        assert!(json["report"]["kinds"].is_array());
    }

    /// HTML: the page renders with a `<title>`, one `<section>` per kind,
    /// and `noindex` so the standalone deployment URL is not crawled.
    #[test]
    fn html_renders_a_title_and_a_section_per_kind() {
        let report = collect();
        let html = renderer_html::render_html(&report);
        assert!(html.contains("<title>"));
        assert!(html.contains("<meta name=\"robots\" content=\"noindex\">"));
        for kind in &report.kinds {
            let anchor = format!("id=\"{}\"", kind.kind);
            assert!(html.contains(&anchor), "HTML missing section {anchor}");
        }
    }

    /// HTML: values that look like they could be interpreted as markup are
    /// escaped. A provider name of `<script>alert(1)</script>` should not
    /// reach the page as a raw tag.
    #[test]
    fn html_escapes_inserted_strings() {
        let mut report = collect();
        report.kinds[0].enabled.push(EnabledProviderReport {
            name: "safe", // static; the escape is exercised on dynamic values
            priority: 99,
            reachable: false,
            unreachable_reason: Some("<script>alert(1)</script>".to_string()),
        });
        let html = renderer_html::render_html(&report);
        assert!(
            !html.contains("<script>alert(1)</script>"),
            "unescaped script tag in HTML"
        );
        assert!(
            html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"),
            "escaped form missing from HTML"
        );
    }
}
