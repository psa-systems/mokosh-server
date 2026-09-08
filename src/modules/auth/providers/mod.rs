//! Authentication providers, named and selectable (PMS-981).
//!
//! Mokosh has two authentication paths, and both are always on by design
//! (PMS-295): the Bunyip Resource-Server verifier in
//! [`super::oidc_rs`] and the legacy HS256 cookie / bearer path in
//! [`super::middleware`]. This module gives those two paths NAMES, an
//! ordering, and a way for boot to say which is enabled by the operator vs
//! by the hosting profile's default. It follows the shape
//! `docs/providers.md` calls the [`crate::utils::deployment::ProviderKind::Authentication`]
//! kind, matching what [`crate::config`], [`crate::secrets`] and
//! [`crate::storage`] already did for their own kinds.
//!
//! # Dormant
//!
//! The seam lands DORMANT. `create_api_router` continues to mount both
//! authentication middlewares exactly as it did before, and no request is
//! routed through an [`AuthProvider`] in this change. What lands is:
//!
//! - the trait,
//! - a [`AuthProviderKind`] naming the two implementations an operator can
//!   ask for,
//! - a [`AuthProviderSelection`] that resolves `AUTH_PROVIDERS` against the
//!   hosting profile's default and records which of the two decided the
//!   list, and
//! - adapters ([`bunyip::BunyipOidcProvider`] and [`local::LocalProvider`])
//!   that HOLD their underlying path rather than reimplementing it.
//!
//! Wiring the trait into the request-authentication pipeline is a follow-up
//! that lands with the deprecation of the legacy path and the operator
//! runbook for it. That order is deliberate: this change ships the
//! NAMEABILITY surface, so a later change can flip the switch in one place
//! without changing what "byte-for-byte behaviour identical to today's"
//! means today. Every non-test caller of the chain is deliberately absent.
//!
//! # The trait is a NAMEABILITY and ENABLEMENT surface, not a pipeline
//!
//! [`AuthProvider`] does NOT define `authenticate(request) -> Principal` (or
//! any other function that couples the trait to axum / http / a request
//! extractor). Getting that signature right without an operator runbook is
//! the exact "byte-for-byte" violation this ticket forbids: the two existing
//! paths differ in what they read from a request (a bearer versus a cookie
//! that may or may not carry a bearer alongside it), what they produce
//! (`BunyipPrincipal` versus `AuthState`), and how they intercept a partial
//! failure (RFC 6750 `WWW-Authenticate` challenges, PMS-769). A trait that
//! flattened those differences would smuggle a behaviour change through what
//! is supposed to be a rename.
//!
//! What the trait DOES expose is enough for the boot record (PMS-989):
//! whether each provider is enabled in this process, and whether the
//! underlying credential path is reachable. The boot log records
//! `enabled AND !available` as a configuration hazard.

use crate::utils::deployment::{provider, EnablementSource};
use crate::utils::error::{AppError, AppResult};

pub mod bunyip;
pub mod local;

pub use bunyip::BunyipOidcProvider;
pub use local::LocalProvider;

/// A named authentication provider.
///
/// Deliberately small (see the module doc). One method names the provider
/// as an operator writes it, another says whether the process enabled it,
/// and a third says whether the underlying credential path is reachable.
/// A provider that is `is_enabled() && !is_available()` is a configuration
/// hazard: enabled but nothing can authenticate through it. The boot record
/// reports that state.
pub trait AuthProvider: Send + Sync {
    /// The provider's canonical name, as an operator writes it in
    /// `AUTH_PROVIDERS` and as [`AuthProviderKind::as_str`] returns.
    fn name(&self) -> &'static str;

    /// Whether this provider is enabled in the process.
    ///
    /// Enablement is bootstrap-configured, from `AUTH_PROVIDERS` else the
    /// hosting profile's default. Separate from whether the provider CAN
    /// run: a provider whose credential path is not reachable
    /// ([`is_available`](Self::is_available) is false) may still be enabled,
    /// which is the hazard the boot record surfaces.
    fn is_enabled(&self) -> bool;

    /// Whether the underlying credential path is reachable.
    ///
    /// For [`BunyipOidcProvider`] that is "the verifier was built"
    /// (`OIDC_ISSUER` + `OIDC_AUDIENCE` resolved). For [`LocalProvider`]
    /// that is always true, because the local path only needs the process
    /// itself and its Postgres, which the whole application already
    /// depends on.
    fn is_available(&self) -> bool;
}

/// Which authentication providers exist, as names an operator may write.
///
/// Two variants because two paths mount today. A third here would need its
/// own adapter beside [`bunyip`] and [`local`]; adding a variant with no
/// implementation would let `AUTH_PROVIDERS=<name>` name it and then panic
/// at construction, so the enum is the closed set the parser answers over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthProviderKind {
    /// Bunyip as the OP, tokens verified against Bunyip's JWKS.
    Bunyip,
    /// This instance's own plane: HS256 cookies, Argon2, `user_sessions`.
    Local,
}

impl AuthProviderKind {
    /// Every kind, in canonical priority order: Bunyip first, matching
    /// `SAAS_PROVIDER_DEFAULTS`' authentication row.
    pub const ALL: [AuthProviderKind; 2] = [AuthProviderKind::Bunyip, AuthProviderKind::Local];

    /// The name an operator writes and the boot record reports. Matches
    /// [`provider::BUNYIP`] and [`provider::LOCAL`] byte-for-byte, so the
    /// two vocabularies cannot drift.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bunyip => provider::BUNYIP,
            Self::Local => provider::LOCAL,
        }
    }

    /// Parse one provider name.
    ///
    /// An unrecognised name is a boot error naming the legal values, never
    /// a fallback: an operator who typed a provider name asked for that
    /// provider, and quietly giving them another one is exactly the silent
    /// degrade the model exists to remove. Blank is not a name; the caller
    /// resolves an unset `AUTH_PROVIDERS` against the hosting profile's
    /// default before it gets here.
    pub fn parse_name(raw: &str) -> AppResult<Self> {
        match raw.trim() {
            provider::BUNYIP => Ok(Self::Bunyip),
            provider::LOCAL => Ok(Self::Local),
            other => Err(AppError::Configuration(format!(
                "AUTH_PROVIDERS name {other:?} is not a known authentication provider; \
                 expected 'bunyip' or 'local'"
            ))),
        }
    }

    /// Parse a comma-separated priority list.
    ///
    /// Duplicates are refused: a priority list must be unambiguous, so
    /// `bunyip,bunyip` names nothing rather than two things sharing a slot.
    /// A blank name inside the list (`bunyip,,local`) is refused for the
    /// same reason a blank `AUTH_PROVIDERS` falls back to the profile: an
    /// empty name is not a provider.
    pub fn parse_list(raw: &str) -> AppResult<Vec<Self>> {
        let mut providers: Vec<Self> = Vec::new();
        for name in raw.split(',') {
            let trimmed = name.trim();
            if trimmed.is_empty() {
                return Err(AppError::Configuration(format!(
                    "AUTH_PROVIDERS list {raw:?} contains an empty name; \
                     expected one or more of 'bunyip', 'local'"
                )));
            }
            let kind = Self::parse_name(trimmed)?;
            if providers.contains(&kind) {
                return Err(AppError::Configuration(format!(
                    "AUTH_PROVIDERS list {raw:?} names {} twice; priority must be unambiguous",
                    kind.as_str()
                )));
            }
            providers.push(kind);
        }
        Ok(providers)
    }
}

/// Provider selection, and which of the two decided it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthProviderSelection {
    /// In priority order, first wins.
    pub providers: Vec<AuthProviderKind>,
    /// PMS-1011: whether the hosting profile's default stands or the
    /// operator overrode it. Reported in the boot record so a provider
    /// left on by a default is visible rather than assumed.
    pub source: EnablementSource,
}

impl AuthProviderSelection {
    /// Read `AUTH_PROVIDERS` through the configuration provider and
    /// resolve it against the hosting profile's default.
    ///
    /// `profile_default` arrives as a slice of names, matching
    /// [`crate::utils::deployment::DeploymentMode::default_providers_for`]
    /// for [`crate::utils::deployment::ProviderKind::Authentication`]. This
    /// module never holds the deployment shape, per the PMS-904 layering:
    /// only the auth service and the startup wiring know which mode this
    /// is, and a capability module cares which providers it got rather
    /// than which profile chose them.
    pub fn from_env(profile_default: &[&str]) -> AppResult<Self> {
        Self::resolve(
            profile_default,
            crate::config::get(&crate::config::registry::AUTH_PROVIDERS)
                .as_deref()
                .unwrap_or(""),
        )
    }

    /// The rule itself, split out so it is testable without touching
    /// process-global env under a concurrent runner.
    ///
    /// Rules, in order:
    ///
    /// - Unset or blank (after trim) resolves to `profile_default` with
    ///   `source = Profile`. This is deliberately not an empty selection:
    ///   disabling every authentication path is a wiring error, not a
    ///   valid state.
    /// - A non-empty list resolves to what the operator asked for, with
    ///   `source = Explicit`.
    /// - Unknown names, duplicates and empty entries are all refused with
    ///   an error that names the legal values, so a typo is a boot failure
    ///   rather than a silent fallback.
    pub fn resolve(profile_default: &[&str], raw: &str) -> AppResult<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Ok(Self {
                providers: parse_profile_default(profile_default)?,
                source: EnablementSource::Profile,
            });
        }
        let providers = AuthProviderKind::parse_list(trimmed)?;
        Ok(Self {
            providers,
            source: EnablementSource::Explicit,
        })
    }

    /// What this deployment explicitly configured, for the boot record.
    /// `None` when the profile's default stands.
    pub fn explicit_providers(&self) -> Option<Vec<&'static str>> {
        match self.source {
            EnablementSource::Explicit => Some(self.providers.iter().map(|k| k.as_str()).collect()),
            EnablementSource::Profile => None,
        }
    }

    /// Whether this kind is in the selection.
    pub fn contains(&self, kind: AuthProviderKind) -> bool {
        self.providers.contains(&kind)
    }
}

/// The resolved chain of authentication providers for this process.
///
/// A container over [`Box<dyn AuthProvider>`] rather than the trait objects
/// alone, so the boot record and any future wiring iterate in priority
/// order and can ask each element for its name / enablement / availability
/// without needing to know which concrete adapter it is.
pub struct AuthProviderChain {
    providers: Vec<Box<dyn AuthProvider>>,
    selection: AuthProviderSelection,
}

impl AuthProviderChain {
    /// The resolved selection, so callers reading the chain can see which
    /// providers are named and where the list came from without walking
    /// every element.
    pub fn selection(&self) -> &AuthProviderSelection {
        &self.selection
    }

    /// The providers in priority order.
    pub fn providers(&self) -> &[Box<dyn AuthProvider>] {
        &self.providers
    }

    /// Write one line per provider to the boot log: the provider's name,
    /// where the selection came from, and whether the credential path is
    /// actually reachable. A provider that is enabled but unavailable is a
    /// configuration hazard; the line makes it visible rather than
    /// assumed.
    ///
    /// Never logs credential material, JWT contents, or cookie values.
    pub fn record(&self) {
        for provider in &self.providers {
            tracing::info!(
                key = "AUTH_PROVIDERS",
                provider = provider.name(),
                source = self.selection.source.as_str(),
                enabled = provider.is_enabled(),
                available = provider.is_available(),
                "authentication provider selected",
            );
        }
    }
}

/// Build the resolved chain for this process (PMS-981, dormant).
///
/// `bunyip_verifier_present` is the boolean the startup wiring already
/// knows from `create_api_router` (`bunyip_verifier.is_some()`), threaded
/// in as data rather than as the verifier itself so this module holds no
/// axum / http / verifier state. It is what
/// [`BunyipOidcProvider::is_available`] returns.
///
/// NOTHING INSTALLS THIS. `create_api_router` does not call it, and
/// `src/main.rs` does not call it. It is the API a future wiring PR calls
/// so the switch flips in one place. Tests here exercise the shape.
pub fn from_env_with(
    profile_default: &[&str],
    bunyip_verifier_present: bool,
) -> AppResult<AuthProviderChain> {
    let selection = AuthProviderSelection::from_env(profile_default)?;
    let providers = build_chain(&selection, bunyip_verifier_present);
    Ok(AuthProviderChain {
        providers,
        selection,
    })
}

fn build_chain(
    selection: &AuthProviderSelection,
    bunyip_verifier_present: bool,
) -> Vec<Box<dyn AuthProvider>> {
    selection
        .providers
        .iter()
        .map(|kind| -> Box<dyn AuthProvider> {
            match kind {
                AuthProviderKind::Bunyip => Box::new(BunyipOidcProvider::new(
                    /* is_enabled = */ true,
                    /* verifier_present = */ bunyip_verifier_present,
                )),
                AuthProviderKind::Local => {
                    Box::new(LocalProvider::new(/* is_enabled = */ true))
                }
            }
        })
        .collect()
}

fn parse_profile_default(profile_default: &[&str]) -> AppResult<Vec<AuthProviderKind>> {
    if profile_default.is_empty() {
        return Err(AppError::Configuration(
            "hosting profile names no authentication provider; the default must not be empty"
                .to_string(),
        ));
    }
    let mut providers = Vec::with_capacity(profile_default.len());
    for name in profile_default {
        let kind = AuthProviderKind::parse_name(name)?;
        if providers.contains(&kind) {
            return Err(AppError::Configuration(format!(
                "hosting profile names {} twice in its authentication row",
                kind.as_str()
            )));
        }
        providers.push(kind);
    }
    Ok(providers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::deployment::{DeploymentMode, ProviderKind};

    /// The self-hosted profile defaults, spelled through
    /// `DeploymentMode::default_providers_for` so this test and the
    /// deployment table cannot drift.
    fn self_hosted_default() -> Vec<&'static str> {
        DeploymentMode::SelfHosted
            .default_providers_for(ProviderKind::Authentication)
            .to_vec()
    }

    fn saas_default() -> Vec<&'static str> {
        DeploymentMode::Saas
            .default_providers_for(ProviderKind::Authentication)
            .to_vec()
    }

    /// AC: an unset `AUTH_PROVIDERS` reproduces the hosting profile's
    /// default byte-for-byte, and the boot record says the profile
    /// decided it. This is the "byte-for-byte behaviour identical to
    /// today's" AC from PMS-981.
    #[test]
    fn an_unset_selection_reproduces_the_profile_default() {
        let saas = saas_default();
        let resolved = AuthProviderSelection::resolve(&saas, "").unwrap();
        assert_eq!(
            resolved
                .providers
                .iter()
                .map(|k| k.as_str())
                .collect::<Vec<_>>(),
            saas
        );
        assert_eq!(resolved.source, EnablementSource::Profile);
        assert!(resolved.explicit_providers().is_none());

        let self_hosted = self_hosted_default();
        let resolved = AuthProviderSelection::resolve(&self_hosted, "").unwrap();
        assert_eq!(
            resolved
                .providers
                .iter()
                .map(|k| k.as_str())
                .collect::<Vec<_>>(),
            self_hosted
        );
        assert_eq!(resolved.source, EnablementSource::Profile);
    }

    /// A blank value with whitespace is still unset: the compose forwarding
    /// convention (PMS-836) turns an unset compose key into `""`, and a
    /// selection with only whitespace must not be treated as "the operator
    /// asked for the empty list".
    #[test]
    fn whitespace_only_selection_is_the_profile_default() {
        for raw in ["", "   ", "\t\n"] {
            let resolved = AuthProviderSelection::resolve(&saas_default(), raw).unwrap();
            assert_eq!(resolved.source, EnablementSource::Profile, "{raw:?}");
            assert_eq!(
                resolved
                    .providers
                    .iter()
                    .map(|k| k.as_str())
                    .collect::<Vec<_>>(),
                saas_default()
            );
        }
    }

    /// An explicit selection that MATCHES the profile default still
    /// records `Explicit`: the operator wrote it, and PMS-1011's report
    /// exists so a provider left on by a default is distinguishable from
    /// one an operator chose deliberately.
    #[test]
    fn an_explicit_selection_matching_the_default_still_records_explicit() {
        let resolved = AuthProviderSelection::resolve(&saas_default(), "bunyip,local").unwrap();
        assert_eq!(
            resolved.providers,
            vec![AuthProviderKind::Bunyip, AuthProviderKind::Local]
        );
        assert_eq!(resolved.source, EnablementSource::Explicit);
        assert_eq!(
            resolved.explicit_providers().unwrap(),
            vec![provider::BUNYIP, provider::LOCAL]
        );
    }

    /// An explicit narrower list still records `Explicit`, and preserves
    /// its own order.
    #[test]
    fn an_explicit_narrower_list_records_explicit() {
        let resolved = AuthProviderSelection::resolve(&saas_default(), "local").unwrap();
        assert_eq!(resolved.providers, vec![AuthProviderKind::Local]);
        assert_eq!(resolved.source, EnablementSource::Explicit);

        let reversed = AuthProviderSelection::resolve(&saas_default(), "local,bunyip").unwrap();
        assert_eq!(
            reversed.providers,
            vec![AuthProviderKind::Local, AuthProviderKind::Bunyip]
        );
    }

    /// An unrecognised name refuses to boot and names the legal set. A typo
    /// asked for something, and quietly returning the profile default is
    /// exactly the silent-degrade this whole model exists to remove.
    #[test]
    fn an_unrecognised_name_is_refused_and_names_the_legal_set() {
        let err = AuthProviderSelection::resolve(&saas_default(), "bogus")
            .expect_err("an unknown provider must not become the default")
            .to_string();
        assert!(err.contains("bunyip"), "{err}");
        assert!(err.contains("local"), "{err}");
    }

    /// Duplicates are refused. Priority is a list; a duplicate makes the
    /// order meaningless.
    #[test]
    fn duplicates_are_refused() {
        let err = AuthProviderSelection::resolve(&saas_default(), "bunyip,bunyip")
            .expect_err("a duplicate must be refused")
            .to_string();
        assert!(
            err.contains("twice") || err.contains("unambiguous"),
            "{err}"
        );
    }

    /// An empty entry mid-list is refused: it names no provider, and
    /// tolerating it would make `bunyip,,local` a legal way to write
    /// `bunyip,local`, which is a silent normalisation the seam avoids
    /// everywhere else.
    #[test]
    fn an_empty_entry_in_the_list_is_refused() {
        assert!(AuthProviderSelection::resolve(&saas_default(), "bunyip,,local").is_err());
        assert!(AuthProviderSelection::resolve(&saas_default(), ",local").is_err());
    }

    /// A profile default the vocabulary does not know fails here too, not
    /// silently: a broken profile row is a boot error naming the legal
    /// values, matching what `SecretsConfig` and `ConfigSelection` do.
    #[test]
    fn an_unknown_profile_default_is_refused() {
        let err = AuthProviderSelection::resolve(&["vault"], "")
            .expect_err("a profile the vocabulary does not know must fail")
            .to_string();
        assert!(err.contains("vault") || err.contains("bunyip"), "{err}");
    }

    /// A profile row that names nothing is a wiring error. Every kind has
    /// a default by construction (see `deployment.rs`), so this asserts
    /// the parser's own guard rather than a shape the tree ever produces.
    #[test]
    fn an_empty_profile_default_is_refused() {
        assert!(AuthProviderSelection::resolve(&[], "").is_err());
    }

    /// A Bunyip provider constructed WITHOUT a verifier is `is_enabled() &&
    /// !is_available()`. The boot record classifies that as a
    /// configuration hazard: enabled but nothing can authenticate through
    /// it. Naming that state is the whole point of separating enablement
    /// from availability.
    #[test]
    fn a_bunyip_provider_without_a_verifier_is_a_configuration_hazard() {
        let hazard = BunyipOidcProvider::new(true, false);
        assert!(hazard.is_enabled());
        assert!(!hazard.is_available());
        assert_eq!(hazard.name(), provider::BUNYIP);

        let ready = BunyipOidcProvider::new(true, true);
        assert!(ready.is_available());
    }

    /// The chain builder honours the resolved selection.
    #[test]
    fn from_env_with_builds_one_boxed_provider_per_kind_in_priority_order() {
        let chain = from_env_with_selection(
            AuthProviderSelection {
                providers: vec![AuthProviderKind::Bunyip, AuthProviderKind::Local],
                source: EnablementSource::Explicit,
            },
            /* verifier_present = */ true,
        );
        let names: Vec<&str> = chain.providers().iter().map(|p| p.name()).collect();
        assert_eq!(names, vec![provider::BUNYIP, provider::LOCAL]);
        for provider in chain.providers() {
            assert!(provider.is_enabled());
        }
    }

    /// A `bunyip`-selection with no verifier boots (the trait is dormant),
    /// but the availability line the boot record writes flags the hazard.
    #[test]
    fn a_bunyip_selection_without_a_verifier_boots_and_flags_the_hazard() {
        let chain = from_env_with_selection(
            AuthProviderSelection {
                providers: vec![AuthProviderKind::Bunyip],
                source: EnablementSource::Explicit,
            },
            /* verifier_present = */ false,
        );
        let bunyip = &chain.providers()[0];
        assert_eq!(bunyip.name(), provider::BUNYIP);
        assert!(bunyip.is_enabled());
        assert!(!bunyip.is_available());
    }

    /// A local-only selection has one provider, and local is always
    /// available (see `LocalProvider::is_available`).
    #[test]
    fn a_local_only_selection_has_one_available_provider() {
        let chain = from_env_with_selection(
            AuthProviderSelection {
                providers: vec![AuthProviderKind::Local],
                source: EnablementSource::Profile,
            },
            /* verifier_present = */ false,
        );
        assert_eq!(chain.providers().len(), 1);
        assert_eq!(chain.providers()[0].name(), provider::LOCAL);
        assert!(chain.providers()[0].is_enabled());
        assert!(chain.providers()[0].is_available());
    }

    /// `ALL` is in the canonical priority order the profile default uses:
    /// Bunyip first, Local second. The list is closed at two entries
    /// because the enum is; a third variant would need its own adapter.
    #[test]
    fn all_lists_every_kind_in_canonical_priority_order() {
        assert_eq!(
            AuthProviderKind::ALL,
            [AuthProviderKind::Bunyip, AuthProviderKind::Local]
        );
        assert_eq!(AuthProviderKind::Bunyip.as_str(), provider::BUNYIP);
        assert_eq!(AuthProviderKind::Local.as_str(), provider::LOCAL);
    }

    /// Test helper: skip the environment read and drive the chain builder
    /// directly. `from_env_with` is what a future wiring PR calls; the
    /// pure-function form is what the unit tests exercise, matching the
    /// `SecretsConfig::resolve` / `ConfigSelection::resolve` split.
    fn from_env_with_selection(
        selection: AuthProviderSelection,
        bunyip_verifier_present: bool,
    ) -> AuthProviderChain {
        let providers = build_chain(&selection, bunyip_verifier_present);
        AuthProviderChain {
            providers,
            selection,
        }
    }
}
