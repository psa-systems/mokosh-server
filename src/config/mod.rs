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
//! # Atomic refresh, the actor, and per-request stability (PMS-986)
//!
//! PMS-986 made refresh all-or-nothing on [`try_refresh`]. The caller says who
//! triggered the refresh through [`RefreshRequest::actor`] and which
//! [`ConfigKey`]s MUST resolve for the new generation to be installed; when any
//! of those required keys does not resolve, the previous generation stays live
//! and the outcome is [`RefreshOutcome::Rejected`], which names the unresolved
//! keys and the providers that were consulted (never a value). A
//! [`Tier::Bootstrap`] key named in `required_keys` is refused before any I/O,
//! because a provider is already built from it; [`refuse_refresh_of_bootstrap`]
//! is the helper an admin endpoint calls per key so the refusal comes out of
//! the check rather than out of the swap.
//!
//! [`refresh`] is now a thin wrapper around
//! `try_refresh(RefreshRequest::system())` and its signature is unchanged, so
//! every existing best-effort caller behaves exactly as before: a rejected
//! outcome hands back the previous generation, an applied one hands back the
//! newly-installed one.
//!
//! Per-request stability is one call: [`snapshot`] hands back the current
//! generation as an `Arc`, and a handler reads through that snapshot for the
//! length of the request. A refresh that runs mid-handler swaps [`CURRENT`],
//! but the snapshot the handler holds is unchanged, so successive [`get`]s see
//! one generation.
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
pub mod flags;
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

/// Who caused a generation to be resolved.
///
/// [`RefreshActor::System`] is a boot resolution or a scheduled refresh;
/// [`RefreshActor::Operator`] is an admin-triggered one, and the wrapped
/// `String` is a short login identifier for the boot record. It is NEVER
/// credential material, so `Debug` prints the login verbatim: it is not
/// sensitive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RefreshActor {
    /// Boot resolution or a scheduled refresh with no operator to name.
    System,
    /// An admin-triggered refresh. The `String` is the operator's login.
    Operator(String),
}

/// The caller's contract with [`try_refresh`]: who triggered the refresh, and
/// which keys MUST resolve for the swap to happen.
///
/// A refresh with no required keys is a best-effort rebuild that always
/// succeeds; a refresh whose required keys do not all resolve leaves the
/// previous generation live. See [`try_refresh`] for the atomicity guarantee
/// this shape exists for.
pub struct RefreshRequest {
    pub actor: RefreshActor,
    pub required_keys: Vec<&'static ConfigKey>,
}

impl RefreshRequest {
    /// A system-actor refresh with no required keys. The shape [`refresh`]
    /// uses.
    pub fn system() -> Self {
        Self {
            actor: RefreshActor::System,
            required_keys: Vec::new(),
        }
    }

    /// An operator-actor refresh with no required keys yet. Add them with
    /// [`RefreshRequest::requiring`].
    pub fn operator(login: impl Into<String>) -> Self {
        Self {
            actor: RefreshActor::Operator(login.into()),
            required_keys: Vec::new(),
        }
    }

    /// Add a key that MUST resolve for the swap to happen. A bootstrap-tier
    /// key here is refused by [`try_refresh`] before any I/O.
    pub fn requiring(mut self, key: &'static ConfigKey) -> Self {
        self.required_keys.push(key);
        self
    }
}

impl std::fmt::Debug for RefreshRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshRequest")
            .field("actor", &self.actor)
            .field(
                "required_keys",
                &self
                    .required_keys
                    .iter()
                    .map(|k| k.name())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

/// The result of a [`try_refresh`] attempt.
///
/// [`RefreshOutcome::Applied`] carries the newly-installed generation and the
/// actor who caused it. [`RefreshOutcome::Rejected`] carries the reason and
/// the previous generation, which is still live: the caller can log the
/// pre-refresh state without a second round trip. No variant carries a value.
pub enum RefreshOutcome {
    Applied {
        generation: Arc<Generation>,
        actor: RefreshActor,
    },
    Rejected {
        reason: RefreshRejection,
        previous: Arc<Generation>,
    },
}

/// Redaction-safe `Debug`: prints the number and actor of any [`Generation`]
/// this outcome names, never the resolved values it holds. The `previous`
/// generation carried through a [`RefreshOutcome::Rejected`] IS handed to the
/// caller as an `Arc`, but its VALUES never reach a log line through this
/// impl.
impl std::fmt::Debug for RefreshOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RefreshOutcome::Applied { generation, actor } => f
                .debug_struct("RefreshOutcome::Applied")
                .field("generation.number", &generation.number())
                .field("generation.actor", generation.actor())
                .field("actor", actor)
                .finish(),
            RefreshOutcome::Rejected { reason, previous } => f
                .debug_struct("RefreshOutcome::Rejected")
                .field("reason", reason)
                .field("previous.number", &previous.number())
                .field("previous.actor", previous.actor())
                .finish(),
        }
    }
}

/// Why a refresh was rejected.
///
/// Names KEYS and PROVIDER NAMES only: never a resolved value, never
/// credential material. The `Debug` impl is redaction-safe on the same
/// grounds, so a caller can log the whole struct.
///
/// - `required_keys_unresolved`: the keys the caller marked required in
///   [`RefreshRequest::required_keys`] that no provider held in the candidate
///   generation.
/// - `bootstrap_keys_refused`: the keys the caller marked required whose tier
///   is [`Tier::Bootstrap`], refused before any I/O because a provider is
///   already built from them.
/// - `providers_consulted`: every provider name the candidate walked. Today a
///   single-provider list, shaped for the PMS-987 chain without a second
///   API-shape change.
#[derive(Debug, Clone)]
pub struct RefreshRejection {
    pub required_keys_unresolved: Vec<&'static ConfigKey>,
    pub bootstrap_keys_refused: Vec<&'static ConfigKey>,
    pub providers_consulted: Vec<&'static str>,
}

/// Every declared key's resolution, as of one moment.
///
/// Numbered and timestamped so a later refresh is distinguishable from the
/// boot resolution, and so one request can be said to see exactly one
/// generation. Carries the [`RefreshActor`] that caused it, so the boot record
/// and later `provider-status` (PMS-1012) can report who triggered each
/// generation.
#[derive(Clone, Debug)]
pub struct Generation {
    number: u64,
    resolved_at: DateTime<Utc>,
    /// Parallel to [`REGISTRY`], so a lookup is an index rather than a hash of
    /// a name that the type system already pinned.
    entries: Vec<Resolved>,
    /// Who caused this generation to be resolved. The boot generation records
    /// [`RefreshActor::System`].
    actor: RefreshActor,
}

impl Generation {
    /// Resolve every declared key against `provider`.
    ///
    /// `previous` carries the bootstrap tier forward: those resolve exactly
    /// once per process, because a provider has already been built from them
    /// and re-reading would report a value nothing is using. `actor` is who
    /// caused this resolution; boot passes [`RefreshActor::System`].
    pub fn resolve(
        provider: &dyn ConfigProvider,
        previous: Option<&Generation>,
        number: u64,
        actor: RefreshActor,
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
            actor,
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

    /// Who caused this generation to be resolved (PMS-986). Boot is
    /// [`RefreshActor::System`]; an operator-triggered refresh names the
    /// operator.
    pub fn actor(&self) -> &RefreshActor {
        &self.actor
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
    CURRENT.get_or_init(|| {
        RwLock::new(Arc::new(Generation::resolve(
            provider().as_ref(),
            None,
            1,
            RefreshActor::System,
        )))
    })
}

/// The generation serving this process right now.
pub fn current() -> Arc<Generation> {
    cell()
        .read()
        .expect("the configuration generation lock is never held across a panic")
        .clone()
}

/// A named alias for [`current`], for handlers that want per-request
/// generation stability (PMS-986).
///
/// A refresh mid-request would let successive [`get`]s see different
/// generations, so a handler calls `snapshot()` once at entry and reads
/// through the returned `Arc` for the length of the request. The semantics are
/// identical to [`current`]; the name signals intent at call sites.
pub fn snapshot() -> Arc<Generation> {
    current()
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
///
/// PMS-986: this is a thin wrapper around
/// `try_refresh(RefreshRequest::system())`. A rejected outcome hands back the
/// PREVIOUS generation (still live), matching current best-effort semantics.
pub fn refresh() -> Arc<Generation> {
    match try_refresh(RefreshRequest::system()) {
        RefreshOutcome::Applied { generation, .. } => generation,
        RefreshOutcome::Rejected { previous, .. } => previous,
    }
}

/// Rebuild the generation atomically, honouring the caller's required-key
/// contract (PMS-986).
///
/// The rules, in order:
///
/// 1. If any required key is [`Tier::Bootstrap`], refuse before any I/O. A
///    provider is already built from a bootstrap value, so "refresh it" cannot
///    mean anything; the rejection names the refused keys and leaves the
///    generation counter and [`CURRENT`] slot untouched.
/// 2. Build a candidate generation by walking the current provider and
///    resolving every declared key. The number is `previous.number() + 1`,
///    consumed only if the swap happens.
/// 3. Validate: every key in `request.required_keys` must have a serving
///    provider in the candidate. If any does not, hand back
///    [`RefreshOutcome::Rejected`] naming the unresolved keys and the
///    providers that were consulted, and DO NOT touch [`CURRENT`].
/// 4. On success, swap the candidate into [`CURRENT`] under the existing
///    write lock, and return [`RefreshOutcome::Applied`].
///
/// The `providers_consulted` field is shaped for the PMS-987 chain: today it
/// lists the single installed provider, but the shape survives without a
/// second API change.
pub fn try_refresh(request: RefreshRequest) -> RefreshOutcome {
    let previous = current();

    // Rule 1: refuse bootstrap-tier keys before any I/O.
    let bootstrap_refused: Vec<&'static ConfigKey> = request
        .required_keys
        .iter()
        .filter(|key| key.tier() == Tier::Bootstrap)
        .copied()
        .collect();
    if !bootstrap_refused.is_empty() {
        return RefreshOutcome::Rejected {
            reason: RefreshRejection {
                required_keys_unresolved: Vec::new(),
                bootstrap_keys_refused: bootstrap_refused,
                providers_consulted: Vec::new(),
            },
            previous,
        };
    }

    // Rule 2: build a candidate. The number is committed only on Applied.
    let provider = provider();
    let candidate = Generation::resolve(
        provider.as_ref(),
        Some(&previous),
        previous.number() + 1,
        request.actor.clone(),
    );

    // Rule 3: validate every required key resolved. On failure, DO NOT swap.
    let unresolved: Vec<&'static ConfigKey> = request
        .required_keys
        .iter()
        .filter(|key| candidate.served_by(key).is_none())
        .copied()
        .collect();
    if !unresolved.is_empty() {
        return RefreshOutcome::Rejected {
            reason: RefreshRejection {
                required_keys_unresolved: unresolved,
                bootstrap_keys_refused: Vec::new(),
                providers_consulted: vec![provider.name()],
            },
            previous,
        };
    }

    // Rule 4: atomic swap under the write lock.
    let installed = Arc::new(candidate);
    let actor = request.actor;
    let mut slot = cell()
        .write()
        .expect("the configuration generation lock is never held across a panic");
    *slot = installed.clone();
    RefreshOutcome::Applied {
        generation: installed,
        actor,
    }
}

/// Refuse a per-key refresh of a bootstrap-tier key (PMS-986).
///
/// The helper an admin endpoint calls before threading a key into a
/// [`RefreshRequest`], so the refusal comes out of the check rather than out
/// of [`try_refresh`]. Returns `Ok(())` for application-tier keys and an
/// [`AppError::Configuration`] naming the key for bootstrap-tier ones.
///
/// No such endpoint exists yet (PMS-1012 owns the CLI half; the admin
/// endpoint lands in its own PR), so this is the seam for that future
/// caller.
pub fn refuse_refresh_of_bootstrap(key: &'static ConfigKey) -> AppResult<()> {
    match key.tier() {
        Tier::Bootstrap => Err(AppError::Configuration(format!(
            "bootstrap keys cannot be refreshed; {} is Bootstrap tier",
            key.name()
        ))),
        Tier::Application => Ok(()),
    }
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
    use std::sync::Mutex;

    /// Serialises every test that touches the process-global CURRENT slot,
    /// because the unit-test harness runs cases concurrently and a
    /// try_refresh from a sibling case would swap the pointer the assertion
    /// captured. The tests that build a `MapProvider` and pass it to
    /// `Generation::resolve` directly do not need to take this lock and
    /// deliberately do not.
    static REFRESH_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn refresh_test_lock() -> std::sync::MutexGuard<'static, ()> {
        REFRESH_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

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
        let generation = Generation::resolve(&provider, None, 1, RefreshActor::System);

        assert_eq!(
            generation.value(&registry::SMTP_HOST).as_deref(),
            Some("relay.example.com")
        );
        assert_eq!(generation.served_by(&registry::SMTP_HOST), Some("test"));
        assert_eq!(generation.number(), 1);
        assert_eq!(generation.actor(), &RefreshActor::System);

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
        let generation = Generation::resolve(&provider, None, 1, RefreshActor::System);
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
            RefreshActor::System,
        );
        let second = Generation::resolve(
            &MapProvider::new(
                "second",
                &[("DATABASE_URL", "postgres://two"), ("SMTP_HOST", "two")],
            ),
            Some(&first),
            2,
            RefreshActor::System,
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
        let generation = Generation::resolve(
            &MapProvider::new("empty", &[]),
            None,
            1,
            RefreshActor::System,
        );
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
            actor: RefreshActor::System,
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

    // -- PMS-986: atomic try_refresh, actor, bootstrap refusal, snapshot ------

    /// A system-actor refresh with no required keys is best-effort: it always
    /// swaps, advances the number, and records the actor.
    #[test]
    fn try_refresh_applied_advances_the_number_and_records_the_actor() {
        let _guard = refresh_test_lock();
        let pre_number = current().number();
        let outcome = try_refresh(RefreshRequest::system());
        match outcome {
            RefreshOutcome::Applied { generation, actor } => {
                assert!(
                    generation.number() > pre_number,
                    "an applied refresh must advance the number: {} -> {}",
                    pre_number,
                    generation.number()
                );
                assert_eq!(actor, RefreshActor::System);
                assert_eq!(generation.actor(), &RefreshActor::System);
                // The returned Arc is the one that was installed.
                assert!(Arc::ptr_eq(&generation, &current()));
            }
            RefreshOutcome::Rejected { reason, .. } => {
                panic!("expected Applied with no required keys, got Rejected: {reason:?}")
            }
        }
    }

    /// A required key that no provider holds rejects the refresh, names the
    /// key and the providers consulted, and leaves the CURRENT slot pointing
    /// at the pre-attempt generation. The number is NOT consumed.
    #[test]
    fn try_refresh_rejected_when_a_required_key_is_unresolved() {
        let _guard = refresh_test_lock();
        // A key nothing in unit tests configures; boot never fatal-fails on
        // it (PMS-658), so the process environment reliably does not hold it.
        let request = RefreshRequest::system().requiring(&registry::IP2LOCATION_DB_PATH);

        let outcome = try_refresh(request);
        let RefreshOutcome::Rejected { reason, previous } = outcome else {
            panic!("expected Rejected for a required key nothing holds");
        };

        // The rejection names the KEY that did not resolve.
        assert_eq!(reason.required_keys_unresolved.len(), 1);
        assert_eq!(
            reason.required_keys_unresolved[0].name(),
            "IP2LOCATION_DB_PATH"
        );
        assert!(reason.bootstrap_keys_refused.is_empty());

        // And the providers that were consulted. Today one; the shape survives
        // the PMS-987 chain.
        assert!(!reason.providers_consulted.is_empty());
        assert!(reason.providers_consulted.contains(&provider::ENVIRONMENT));

        // CURRENT is unchanged from the pre-attempt generation: `previous` is
        // the Arc captured before the check ran, and current() still points
        // at it.
        assert!(Arc::ptr_eq(&previous, &current()));
    }

    /// A required bootstrap-tier key is refused BEFORE any I/O: the rejection
    /// names the key, the number is not consumed, and CURRENT is untouched.
    #[test]
    fn try_refresh_refuses_a_bootstrap_key_before_any_io() {
        let _guard = refresh_test_lock();
        let request = RefreshRequest::system().requiring(&registry::DATABASE_URL);

        let outcome = try_refresh(request);
        let RefreshOutcome::Rejected { reason, previous } = outcome else {
            panic!("expected Rejected for a bootstrap-tier required key");
        };

        assert!(reason.required_keys_unresolved.is_empty());
        assert_eq!(reason.bootstrap_keys_refused.len(), 1);
        assert_eq!(reason.bootstrap_keys_refused[0].name(), "DATABASE_URL");
        // No providers consulted: the refusal comes out of the check, not the
        // walk, so no name is reported.
        assert!(reason.providers_consulted.is_empty());

        // CURRENT is unchanged.
        assert!(Arc::ptr_eq(&previous, &current()));
    }

    /// The per-key helper an admin endpoint calls before threading a key into
    /// a [`RefreshRequest`]: application-tier passes, bootstrap-tier errors
    /// and names the key.
    #[test]
    fn refuse_refresh_of_bootstrap_is_the_per_key_check() {
        // Application-tier keys pass.
        assert!(refuse_refresh_of_bootstrap(&registry::SMTP_HOST).is_ok());
        assert!(refuse_refresh_of_bootstrap(&registry::LOGIN_APPROVAL_ENABLED).is_ok());

        // Bootstrap-tier keys error and name themselves.
        for key in [
            &registry::DATABASE_URL,
            &registry::MOKOSH_APP_DATABASE_URL,
            &registry::ENCRYPTION_KEY,
        ] {
            let err = refuse_refresh_of_bootstrap(key).expect_err("bootstrap keys must refuse");
            let message = err.to_string();
            assert!(
                message.contains(key.name()),
                "{}: refusal must name the key: {message}",
                key.name()
            );
            assert!(
                message.contains("Bootstrap"),
                "{}: refusal must name the tier: {message}",
                key.name()
            );
        }
    }

    /// Both actor shapes round-trip through the resolved generation, so the
    /// value the caller passed reaches the boot record intact.
    #[test]
    fn an_actor_round_trips_through_the_generation() {
        let map = MapProvider::new("test", &[]);

        let system = Generation::resolve(&map, None, 1, RefreshActor::System);
        assert_eq!(system.actor(), &RefreshActor::System);

        let alice = Generation::resolve(&map, None, 1, RefreshActor::Operator("alice".to_string()));
        assert_eq!(alice.actor(), &RefreshActor::Operator("alice".to_string()));
    }

    /// A handler that snapshots CURRENT once at request entry sees one
    /// generation for the length of the request: a refresh that runs
    /// afterwards swaps CURRENT but leaves the held snapshot untouched. The
    /// Arc is immutable, so the snapshot's contents cannot change; the swap
    /// moves current() to a different Arc.
    #[test]
    fn snapshot_is_stable_across_a_later_try_refresh() {
        let _guard = refresh_test_lock();
        let snap = snapshot();
        let snap_number = snap.number();
        let snap_actor = snap.actor().clone();

        // Something that DEFINITELY swaps: an operator-actor best-effort
        // refresh. The actor is unique to this call, so we can pin that the
        // installed generation is the one this call produced.
        let outcome = try_refresh(RefreshRequest::operator("pms-986-snapshot"));
        let RefreshOutcome::Applied { generation, .. } = outcome else {
            panic!("a system-shaped best-effort refresh must apply");
        };

        // The snapshot's contents are unchanged: it is an immutable
        // Arc<Generation>, and the swap did not touch it.
        assert_eq!(snap.number(), snap_number);
        assert_eq!(snap.actor(), &snap_actor);

        // The current() Arc is the newly-installed one, not the snapshot.
        assert!(!Arc::ptr_eq(&snap, &generation));
    }

    /// A rejected refresh does NOT consume the generation number: the number
    /// counts generations that were INSTALLED, not attempts. Two consecutive
    /// rejections see the same pre-attempt number.
    #[test]
    fn a_rejected_refresh_does_not_advance_the_number() {
        let _guard = refresh_test_lock();
        let request = || RefreshRequest::system().requiring(&registry::IP2LOCATION_DB_PATH);

        let outcome_a = try_refresh(request());
        let outcome_b = try_refresh(request());

        let (prev_a, prev_b) = match (outcome_a, outcome_b) {
            (
                RefreshOutcome::Rejected { previous: a, .. },
                RefreshOutcome::Rejected { previous: b, .. },
            ) => (a, b),
            other => panic!("expected two Rejected outcomes, got {other:?}"),
        };

        assert_eq!(
            prev_a.number(),
            prev_b.number(),
            "a rejected refresh must not advance the number counter"
        );
    }
}
