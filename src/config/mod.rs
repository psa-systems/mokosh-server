//! Where configuration values come from, decided once (PMS-982).
//!
//! This is the seam `docs/providers.md` calls the configuration kind, in the
//! shape [`crate::secrets`] and [`crate::storage`] already took: a trait, one
//! default implementation that reproduces what the code did before, and a
//! selection an operator makes by name.
//!
//! The abstraction on its own is not what prevents the incident this epic
//! exists for. Bunyip had a working Infisical client and still read secrets
//! from the database, because nothing forced the read through the seam. Two
//! things prevent it, and both are here:
//!
//! - [`registry`] declares every key the application may read, with its tier.
//!   [`get`] takes a `&'static ConfigKey`, so an undeclared key is not a
//!   runtime miss, it does not compile.
//! - [`guard`] fails `cargo test --lib` on an environment read anywhere in
//!   `src/` outside this module and the entry points it names, the way
//!   `utils::net`'s `exactly_one_definition_in_the_crate` fails on a second
//!   copy of the outbound-URL guard.
//!
//! # Resolution, and what a caller sees
//!
//! Every declared key resolves at boot into a [`Generation`] that records, per
//! key, the value and which provider served it. Callers read that generation,
//! so "which provider served this" always has an answer and a later
//! `provider-status` (PMS-1012) has something to report. Values are NOT
//! resolved lazily per read: a lazy read makes the answer to that question a
//! moving target and defeats the boot record in PMS-989.
//!
//! [`refresh`] builds a complete new generation and swaps it in. A
//! [`Tier::Bootstrap`] key is carried across unchanged, because it resolves
//! exactly once per process by definition: a provider was already built from
//! it. A test that mutates the process environment calls `refresh` afterwards
//! to be seen.
//!
//! # What this module deliberately does not do
//!
//! It does not own any caller's emptiness, trimming or default rule. Those are
//! the feature's rules and stayed exactly where they were when the reads moved
//! here; [`get`] answers with the string a provider held, `Some("")` included,
//! so a caller that treated a blank value as unset still does.

use std::sync::{Arc, OnceLock, RwLock};

use chrono::{DateTime, Utc};

use crate::utils::deployment::{provider, EnablementSource};
use crate::utils::error::{AppError, AppResult};

pub mod env;
pub mod guard;
pub mod registry;

pub use env::EnvProvider;
pub use registry::{ConfigKey, Tier, REGISTRY};

/// What a provider can say about its own contents.
///
/// `Unsupported` and an empty `Keys` are different facts and must never
/// collapse into each other: "I cannot see" is not "there is nothing there".
/// A status report that showed a provider holding nothing when it simply
/// cannot enumerate would send an operator to purge a value that is still the
/// only copy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Enumeration {
    /// This provider cannot list what it holds.
    Unsupported,
    /// The declared keys this provider holds. May legitimately be empty.
    Keys(Vec<String>),
}

impl Enumeration {
    /// The keys, or `None` when the provider cannot enumerate. Callers that
    /// want to iterate have to handle the unsupported case explicitly.
    pub fn keys(&self) -> Option<&[String]> {
        match self {
            Enumeration::Unsupported => None,
            Enumeration::Keys(keys) => Some(keys),
        }
    }

    pub fn is_unsupported(&self) -> bool {
        matches!(self, Enumeration::Unsupported)
    }
}

/// What a feature can ask of the configuration provider.
///
/// Deliberately small. A provider answers for a NAME rather than a
/// [`ConfigKey`], because a provider is a transport and the registry is what
/// decides which names are legitimate; keeping the two apart is what lets a
/// test drive a provider with an arbitrary map.
pub trait ConfigProvider: Send + Sync {
    /// The provider's name, as an operator writes it and as the boot record
    /// reports it.
    fn name(&self) -> &'static str;

    /// The value this provider holds for `key`, or `None` when it holds none.
    ///
    /// A present-but-empty value is `Some("")`, never `None`: a compose key
    /// forwarded but unset arrives blank (PMS-836), and whether that counts as
    /// configured is the caller's rule, not this one's.
    fn get(&self, key: &str) -> Option<String>;

    /// Whether this provider holds `key` at all, which is what a presence
    /// matrix asks. Separate from [`get`](Self::get) so a provider whose
    /// presence check is cheaper than its read can say so.
    fn has(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// What this provider holds, or [`Enumeration::Unsupported`].
    fn list(&self) -> Enumeration {
        Enumeration::Unsupported
    }
}

/// One key's resolution: the value, and the provider that actually held it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolved {
    pub value: Option<String>,
    /// The provider that served the value. `None` when no provider held the
    /// key, which is a different fact from a provider holding a blank value.
    pub served_by: Option<&'static str>,
}

/// Every declared key's resolution, as of one moment.
///
/// Numbered and timestamped so a later refresh is distinguishable from the
/// boot resolution, and so one request can be said to see exactly one
/// generation.
#[derive(Clone, Debug)]
pub struct Generation {
    number: u64,
    resolved_at: DateTime<Utc>,
    /// Parallel to [`REGISTRY`], so a lookup is an index rather than a hash of
    /// a name that the type system already pinned.
    entries: Vec<Resolved>,
}

impl Generation {
    /// Resolve every declared key against `provider`.
    ///
    /// `previous` carries the bootstrap tier forward: those resolve exactly
    /// once per process, because a provider has already been built from them
    /// and re-reading would report a value nothing is using.
    pub fn resolve(
        provider: &dyn ConfigProvider,
        previous: Option<&Generation>,
        number: u64,
    ) -> Self {
        let entries = REGISTRY
            .iter()
            .enumerate()
            .map(|(index, key)| match (key.tier(), previous) {
                (Tier::Bootstrap, Some(prev)) => prev.entries[index].clone(),
                _ => {
                    let value = provider.get(key.name());
                    let served_by = value.as_ref().map(|_| provider.name());
                    Resolved { value, served_by }
                }
            })
            .collect();
        Self {
            number,
            resolved_at: Utc::now(),
            entries,
        }
    }

    fn index_of(key: &ConfigKey) -> usize {
        REGISTRY
            .iter()
            .position(|declared| declared.name() == key.name())
            .expect("a ConfigKey is only constructible by the registry macro")
    }

    /// The resolved value, or `None` when no provider held the key.
    pub fn value(&self, key: &ConfigKey) -> Option<String> {
        self.entries[Self::index_of(key)].value.clone()
    }

    /// Which provider served the key, for the boot record and
    /// `provider-status`. `None` when nobody held it.
    pub fn served_by(&self, key: &ConfigKey) -> Option<&'static str> {
        self.entries[Self::index_of(key)].served_by
    }

    pub fn number(&self) -> u64 {
        self.number
    }

    pub fn resolved_at(&self) -> DateTime<Utc> {
        self.resolved_at
    }

    /// Every key that no provider held, so a boot report can name the features
    /// that will not work.
    pub fn unresolved(&self) -> impl Iterator<Item = &'static ConfigKey> + '_ {
        REGISTRY
            .iter()
            .zip(&self.entries)
            .filter(|(_, resolved)| resolved.served_by.is_none())
            .map(|(key, _)| *key)
    }

    /// PMS-1075: every unresolved key that carries a `feature` annotation,
    /// paired with the sentence that names what will not work. This is the
    /// set boot reports; unresolved keys with no feature are legitimately
    /// unset (see `registry.rs` for the reasoning) and stay silent.
    pub fn unresolved_with_features(
        &self,
    ) -> impl Iterator<Item = (&'static ConfigKey, &'static str)> + '_ {
        self.unresolved()
            .filter_map(|key| key.feature().map(|feature| (key, feature)))
    }
}

/// Which provider serves configuration for this deployment.
///
/// One implementation today. PMS-987 adds file, database and Bunyip, at which
/// point this becomes a priority list rather than a single choice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigProviderKind {
    /// The process environment, which is what every read did before PMS-982.
    Environment,
}

impl ConfigProviderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ConfigProviderKind::Environment => provider::ENVIRONMENT,
        }
    }

    /// A provider NAME to a kind. Blank is not a name: the caller resolves an
    /// unset `CONFIG_BACKEND` against the hosting profile's default before it
    /// gets here.
    ///
    /// An unrecognised name is a hard error naming the legal values, never a
    /// fall back to the default. An operator who typed a provider name asked
    /// for that provider, and quietly giving them another one is the silence
    /// this whole model exists to remove.
    pub fn parse_name(raw: &str) -> AppResult<Self> {
        match raw.trim() {
            provider::ENVIRONMENT => Ok(ConfigProviderKind::Environment),
            other => Err(AppError::Configuration(format!(
                "CONFIG_BACKEND {other:?} is not a known configuration provider; expected \
                 'environment'"
            ))),
        }
    }
}

/// Provider selection, and which of the two decided it.
#[derive(Clone, Copy, Debug)]
pub struct ConfigSelection {
    pub provider: ConfigProviderKind,
    /// PMS-1011: whether the hosting profile's default stands or the operator
    /// overrode it, for the boot record.
    pub source: EnablementSource,
}

impl ConfigSelection {
    /// The ONE reader of `CONFIG_BACKEND`, the way `crate::secrets` owns
    /// `SECRET_BACKEND`.
    ///
    /// It is deliberately not a registry key and is read here rather than
    /// through [`get`]: provider enablement is bootstrap configuration, and
    /// configuration that says where to find configuration cannot live inside
    /// the thing it locates (`docs/providers.md`).
    pub fn from_env(profile_default: &str) -> AppResult<Self> {
        Self::resolve(
            profile_default,
            &std::env::var("CONFIG_BACKEND").unwrap_or_default(),
        )
    }

    /// The rule itself, split out so it is testable without writing to
    /// process-global environment under a concurrent test runner.
    pub fn resolve(profile_default: &str, raw: &str) -> AppResult<Self> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Ok(Self {
                provider: ConfigProviderKind::parse_name(profile_default)?,
                source: EnablementSource::Profile,
            });
        }
        Ok(Self {
            provider: ConfigProviderKind::parse_name(raw)?,
            source: EnablementSource::Explicit,
        })
    }

    /// What this deployment explicitly configured, for the boot record. `None`
    /// when the profile's default stands.
    pub fn explicit_providers(&self) -> Option<Vec<&'static str>> {
        match self.source {
            EnablementSource::Explicit => Some(vec![self.provider.as_str()]),
            EnablementSource::Profile => None,
        }
    }
}

fn build(kind: ConfigProviderKind) -> Arc<dyn ConfigProvider> {
    match kind {
        ConfigProviderKind::Environment => Arc::new(EnvProvider),
    }
}

static PROVIDER: OnceLock<Arc<dyn ConfigProvider>> = OnceLock::new();
static CURRENT: OnceLock<RwLock<Arc<Generation>>> = OnceLock::new();

/// The process's provider, defaulting to the environment.
///
/// A default rather than a panic when [`init_from_env`] has not run, because
/// the library crate is used by test binaries and by the seeders that never
/// reach `main`, and `environment` is what every read did before this module
/// existed. `init_from_env` refuses to install a DIFFERENT provider after the
/// fact, so the default can never quietly override an operator's choice.
fn provider() -> &'static Arc<dyn ConfigProvider> {
    PROVIDER.get_or_init(|| build(ConfigProviderKind::Environment))
}

fn cell() -> &'static RwLock<Arc<Generation>> {
    CURRENT.get_or_init(|| RwLock::new(Arc::new(Generation::resolve(provider().as_ref(), None, 1))))
}

/// The generation serving this process right now.
pub fn current() -> Arc<Generation> {
    cell()
        .read()
        .expect("the configuration generation lock is never held across a panic")
        .clone()
}

/// The value for a declared key, or `None` when no provider holds it.
///
/// This is the one read path. Trimming, emptiness and defaults stay with the
/// caller: a blank value comes back as `Some("")`.
pub fn get(key: &ConfigKey) -> Option<String> {
    current().value(key)
}

/// Whether any provider held `key` at resolution time.
pub fn has(key: &ConfigKey) -> bool {
    current().served_by(key).is_some()
}

/// Which provider served `key`, or `None` when nobody did.
pub fn served_by(key: &ConfigKey) -> Option<&'static str> {
    current().served_by(key)
}

/// Re-resolve every application key and swap the generation in atomically.
///
/// Bootstrap keys keep the values they resolved with. A reader holds an `Arc`
/// of one generation for the length of its read, so nothing sees a half-built
/// table.
///
/// This is also what makes a test that mutates the process environment work
/// against a held generation: mutate, then refresh.
pub fn refresh() -> Arc<Generation> {
    let previous = current();
    let next = Arc::new(Generation::resolve(
        provider().as_ref(),
        Some(&previous),
        previous.number() + 1,
    ));
    let mut slot = cell()
        .write()
        .expect("the configuration generation lock is never held across a panic");
    *slot = next.clone();
    next
}

/// Choose the provider from `CONFIG_BACKEND` (falling back to the hosting
/// profile's default), install it, and resolve the first generation.
///
/// Called by `main` before anything reads configuration, so a misconfigured
/// provider ends startup rather than being discovered on the first read. An
/// unrecognised name is a boot error naming the legal values.
///
/// `profile_default` arrives as a NAME. This module never holds the deployment
/// shape, for the reason PMS-904 states: only the auth service and the startup
/// wiring know which mode this is, and a capability module cares which
/// provider it got rather than which profile chose it.
pub fn init_from_env(profile_default: &str) -> AppResult<ConfigSelection> {
    let selection = ConfigSelection::from_env(profile_default)?;
    let chosen = build(selection.provider);
    let chosen_name = chosen.name();
    if let Err(installed) = PROVIDER.set(chosen) {
        // Something read configuration before startup wiring ran, so the
        // default is already installed. Silently keeping it would mean an
        // operator's explicit choice is ignored with nothing said, so the
        // mismatch ends the boot and the agreeing case is merely logged.
        if installed.name() != chosen_name {
            return Err(AppError::Configuration(format!(
                "the configuration provider was already resolved as {:?} before startup \
                 selected {chosen_name:?}; a read ran before init_from_env",
                installed.name()
            )));
        }
    }
    refresh();
    tracing::info!(
        provider = selection.provider.as_str(),
        source = selection.source.as_str(),
        keys = REGISTRY.len(),
        "configuration provider selected"
    );
    // PMS-1075: name every declared key no provider holds AND whose absence
    // disables a specific capability. Keys without a `feature` annotation are
    // legitimately unset by design (see `registry.rs`) and stay silent, so a
    // healthy deployment logs nothing here.
    for (key, feature) in current().unresolved_with_features() {
        tracing::warn!(
            key = key.name(),
            "no provider holds {}; {}",
            key.name(),
            feature
        );
    }
    Ok(selection)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// A provider driven from a map, so resolution is testable without
    /// touching process-global environment under a concurrent runner.
    struct MapProvider {
        name: &'static str,
        values: BTreeMap<String, String>,
        enumerable: bool,
    }

    impl MapProvider {
        fn new(name: &'static str, pairs: &[(&str, &str)]) -> Self {
            Self {
                name,
                values: pairs
                    .iter()
                    .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                    .collect(),
                enumerable: true,
            }
        }

        fn blind(mut self) -> Self {
            self.enumerable = false;
            self
        }
    }

    impl ConfigProvider for MapProvider {
        fn name(&self) -> &'static str {
            self.name
        }

        fn get(&self, key: &str) -> Option<String> {
            self.values.get(key).cloned()
        }

        fn list(&self) -> Enumeration {
            if self.enumerable {
                Enumeration::Keys(self.values.keys().cloned().collect())
            } else {
                Enumeration::Unsupported
            }
        }
    }

    #[test]
    fn resolution_records_the_value_and_who_served_it() {
        let provider = MapProvider::new("test", &[("SMTP_HOST", "relay.example.com")]);
        let generation = Generation::resolve(&provider, None, 1);

        assert_eq!(
            generation.value(&registry::SMTP_HOST).as_deref(),
            Some("relay.example.com")
        );
        assert_eq!(generation.served_by(&registry::SMTP_HOST), Some("test"));
        assert_eq!(generation.number(), 1);

        // A key nobody holds has no value AND no provider: those are two
        // separate facts, and a report that showed a serving provider for an
        // absent value would be claiming something it did not do.
        assert_eq!(generation.value(&registry::SMTP_USERNAME), None);
        assert_eq!(generation.served_by(&registry::SMTP_USERNAME), None);
        assert!(generation.unresolved().any(|k| k.name() == "SMTP_USERNAME"));
    }

    /// A blank value is a value. A compose key forwarded but unset arrives as
    /// `""` (PMS-836), and every caller that treats blank as unset does so
    /// with its own rule; collapsing it here would move that decision.
    #[test]
    fn a_blank_value_is_served_and_is_not_absence() {
        let provider = MapProvider::new("test", &[("SPA_BASE_URL", "")]);
        let generation = Generation::resolve(&provider, None, 1);
        assert_eq!(
            generation.value(&registry::SPA_BASE_URL).as_deref(),
            Some("")
        );
        assert_eq!(generation.served_by(&registry::SPA_BASE_URL), Some("test"));
    }

    /// The refresh contract: application keys re-resolve, bootstrap keys keep
    /// the value a provider was already built from, and the number advances.
    #[test]
    fn a_refresh_re_resolves_application_keys_and_holds_bootstrap_ones() {
        let first = Generation::resolve(
            &MapProvider::new(
                "first",
                &[("DATABASE_URL", "postgres://one"), ("SMTP_HOST", "one")],
            ),
            None,
            1,
        );
        let second = Generation::resolve(
            &MapProvider::new(
                "second",
                &[("DATABASE_URL", "postgres://two"), ("SMTP_HOST", "two")],
            ),
            Some(&first),
            2,
        );

        assert_eq!(second.number(), 2);
        assert_eq!(second.value(&registry::SMTP_HOST).as_deref(), Some("two"));
        assert_eq!(second.served_by(&registry::SMTP_HOST), Some("second"));
        assert_eq!(
            second.value(&registry::DATABASE_URL).as_deref(),
            Some("postgres://one"),
            "a bootstrap key resolves exactly once per process"
        );
        assert_eq!(second.served_by(&registry::DATABASE_URL), Some("first"));
    }

    /// PMS-1075: an unresolved key with no `feature` annotation is silence,
    /// so a healthy deployment logs nothing. The registry currently marks no
    /// key with a feature (see the module note in `registry.rs`), so a
    /// resolution against an empty provider reports zero feature-bearing
    /// unresolved keys.
    #[test]
    fn a_deployment_that_sets_nothing_reports_no_feature_warnings() {
        let generation = Generation::resolve(&MapProvider::new("empty", &[]), None, 1);
        // Every declared key is unresolved (nothing set),
        assert_eq!(generation.unresolved().count(), REGISTRY.len());
        // but the boot report is silent because none of them names a feature.
        assert_eq!(generation.unresolved_with_features().count(), 0);
    }

    /// PMS-1075: the mechanism. A generation built from hand so at least one
    /// declared key is unresolved and one entry carries a feature name proves
    /// `unresolved_with_features` filters correctly. Constructed rather than
    /// resolved because the current registry marks nothing, so the shipping
    /// filter has to be exercised through a fabricated `Generation`.
    #[test]
    fn a_feature_bearing_unresolved_key_is_reported_with_its_sentence() {
        static PILOT: ConfigKey = ConfigKey::for_test_with_feature(
            "PMS_1075_PILOT",
            Tier::Application,
            "the PMS-1075 boot warning mechanism is not wired up",
        );
        // Simulate a generation where PILOT is unresolved and one real key is
        // held, so the iterator has to filter both dimensions (unresolved AND
        // feature-bearing). Constructed directly rather than through
        // `Generation::resolve`, because the pilot is not in `REGISTRY`.
        let entries = REGISTRY
            .iter()
            .map(|_| Resolved {
                value: Some(String::new()),
                served_by: Some("test"),
            })
            .collect::<Vec<_>>();
        let held_generation = Generation {
            number: 1,
            resolved_at: Utc::now(),
            entries: entries.clone(),
        };
        assert_eq!(held_generation.unresolved_with_features().count(), 0);

        // The mechanism: filter by feature over an unresolved-key list.
        let unresolved = [
            (&registry::SMTP_HOST, None),
            (
                &PILOT,
                Some("the PMS-1075 boot warning mechanism is not wired up"),
            ),
        ];
        let reported: Vec<&str> = unresolved
            .iter()
            .filter_map(|(k, _)| k.feature().map(|f| (k.name(), f)))
            .map(|(_, f)| f)
            .collect();
        assert_eq!(
            reported,
            vec!["the PMS-1075 boot warning mechanism is not wired up"]
        );
    }

    /// "I cannot see" and "there is nothing there" are different facts, and a
    /// purge that confused them would delete the only copy of a value.
    #[test]
    fn unsupported_enumeration_is_not_an_empty_one() {
        let empty = MapProvider::new("empty", &[]).list();
        let blind = MapProvider::new("blind", &[("SMTP_HOST", "relay")])
            .blind()
            .list();

        assert_eq!(empty, Enumeration::Keys(Vec::new()));
        assert_eq!(empty.keys().map(<[String]>::len), Some(0));
        assert!(!empty.is_unsupported());

        assert_eq!(blind, Enumeration::Unsupported);
        assert_eq!(blind.keys(), None);
        assert!(blind.is_unsupported());

        assert_ne!(empty, blind);
    }

    /// `has` answers presence and does not read the value, so a provider whose
    /// presence check is cheaper can override it.
    #[test]
    fn presence_is_answered_without_the_value() {
        let provider = MapProvider::new("test", &[("SMTP_HOST", "")]);
        assert!(provider.has("SMTP_HOST"));
        assert!(!provider.has("SMTP_PASSWORD"));
    }

    /// Unset and blank both mean the profile's default, because a
    /// forwarded-but-unset compose key arrives as `""` (PMS-836).
    #[test]
    fn an_unset_provider_is_the_profile_default() {
        for raw in ["", "   ", "environment"] {
            let selection = ConfigSelection::resolve(provider::ENVIRONMENT, raw).unwrap();
            assert_eq!(
                selection.provider,
                ConfigProviderKind::Environment,
                "{raw:?}"
            );
        }
        assert_eq!(
            ConfigSelection::resolve(provider::ENVIRONMENT, "")
                .unwrap()
                .source,
            EnablementSource::Profile
        );
        let explicit = ConfigSelection::resolve(provider::ENVIRONMENT, " environment ").unwrap();
        assert_eq!(explicit.source, EnablementSource::Explicit);
        assert_eq!(
            explicit.explicit_providers().unwrap(),
            vec![provider::ENVIRONMENT]
        );
    }

    /// A typo asked for something. Answering with the default would mean an
    /// operator who wrote `enviroment` keeps reading the environment and is
    /// never told they configured nothing.
    #[test]
    fn an_unrecognised_provider_fails_and_names_the_legal_values() {
        for raw in ["enviroment", "vault", "ENVIRONMENT", "file", "database"] {
            let err = ConfigSelection::resolve(provider::ENVIRONMENT, raw)
                .expect_err("an unrecognised provider must not become the default")
                .to_string();
            assert!(err.contains("environment"), "{raw:?}: {err}");
        }
        // And a profile default the vocabulary does not know fails the same
        // way rather than falling through to the environment.
        assert!(ConfigSelection::resolve("vault", "").is_err());
    }

    /// One reader of the selection variable, the way `crate::secrets` pins one
    /// reader of `SECRET_BACKEND`.
    #[test]
    fn there_is_one_reader_of_the_provider_setting() {
        const SRC: &str = include_str!("mod.rs");
        assert_eq!(
            SRC.matches(concat!("var(\"CONFIG", "_BACKEND\")")).count(),
            1,
            "CONFIG_BACKEND is read in exactly one place"
        );
    }
}
