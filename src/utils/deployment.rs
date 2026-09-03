//! How this instance is deployed, and what that changes (PMS-902).
//!
//! Mokosh runs in two shapes. A **self-hosted** instance owns its platform
//! identities: `users` rows with `password_hash`, the `/auth/*` local login,
//! and the account email that supports it (password reset, welcome). A
//! **SaaS** instance federates platform identity to Bunyip: the SPA runs the
//! PKCE flow against bunyip-api and mokosh is only a Resource Server for the
//! resulting `at+jwt` (`src/modules/auth/oidc_rs.rs`). There, a mokosh-side
//! password is not the credential anybody signs in with, so mail whose only
//! job is to service that password is mail about an account nobody uses.
//!
//! What this flag does NOT cover:
//!
//! - **Portal identity.** PMS-820 keeps `contacts.portal_password_hash` and
//!   `PortalAuthService` on a plane of their own, and that plane is not
//!   federated through Bunyip in either mode, so portal mail is unaffected.
//! - **Business notifications.** A quote, invoice, ticket, appointment or SLA
//!   email is about work, not about an account, and sends in both modes.
//! - **Whether the local endpoints still answer.** This gates dispatch only.
//!   `/auth/login`'s password branch and `/auth/forgot-password` still exist
//!   in `saas`; restricting them is PMS-905.
//!
//! PMS-903 will read the same flag to pick mail TRANSPORT (Bunyip's shared
//! mailer API instead of direct SMTP). This module deliberately carries no
//! transport knowledge: the two questions are independent, and PMS-903 landing
//! must not need to revisit anything here.
//!
//! # The mode is also the hosting profile (PMS-1011)
//!
//! Each mode carries a default provider table: one row per [`ProviderKind`],
//! naming the providers that kind starts with and the priority order they
//! resolve in. The table is data ([`SELF_HOSTED_PROVIDER_DEFAULTS`],
//! [`SAAS_PROVIDER_DEFAULTS`]), so a third mode later is a data addition
//! rather than a new `match` at every selection point, and there is no second
//! deployment-shape variable competing with `MOKOSH_DEPLOYMENT_MODE`.
//!
//! The profile supplies defaults and locks nothing. Explicit configuration
//! wins per kind, and [`DeploymentMode::resolve_providers`] records which of
//! the two decided each one ([`EnablementSource`]), so a provider left on by a
//! default is visible in the boot log rather than assumed. PMS-989 reports the
//! deviations from that record.
//!
//! ## The parse behaviour is split by consequence, deliberately
//!
//! Two functions read one variable with two different failure modes, which is
//! a trap unless the reason is written down, so:
//!
//! - [`DeploymentMode::parse`] and [`DeploymentMode::from_env`] warn and fall
//!   back to `self-hosted` on an unrecognised value. That protects **mail
//!   dispatch**, and the argument PMS-902 made for it still holds: a typo must
//!   not silently stop a self-hosted deployment's password-reset mail, and the
//!   opposite mistake costs a redundant email.
//! - [`DeploymentMode::parse_for_providers`] and
//!   [`DeploymentMode::from_env_for_providers`] refuse an unrecognised value
//!   and name the legal ones. That reasoning does NOT carry to **provider
//!   selection**: there the same typo would silently select a different set of
//!   providers, which is the failure this epic exists to remove, and a boot
//!   that ends with a message naming the legal values is far the cheaper
//!   failure.
//!
//! Call the lenient pair when the answer only gates behaviour that has a safe
//! default; call the strict pair when the answer chooses a provider.

use std::fmt;

use crate::utils::error::{AppError, AppResult};

/// The deployment shape, from `MOKOSH_DEPLOYMENT_MODE`.
///
/// `self-hosted` is the default, and an unset or unrecognised value resolves
/// to it. That direction is deliberate: the failure this ordering protects
/// against is a self-hosted operator's password-reset mail silently not
/// sending because of a typo in an env var, which presents as "the product is
/// broken and nothing says why". The opposite mistake - a SaaS instance
/// sending a reset mail it did not need to - is a redundant email, not a
/// lockout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeploymentMode {
    /// This instance owns its platform identities and its own mail.
    #[default]
    SelfHosted,
    /// Platform identity is federated to Bunyip SSO.
    Saas,
}

impl DeploymentMode {
    /// Read `MOKOSH_DEPLOYMENT_MODE`.
    ///
    /// Not a `FromStr` returning `Err`, because there is no caller that could
    /// do anything useful with a failure: boot has to continue, and the safe
    /// continuation is the self-hosted default. An unrecognised value is
    /// logged at `warn` so a typo is visible in the log rather than only in
    /// the absence of email a week later.
    pub fn from_env() -> Self {
        Self::parse(&raw_from_env())
    }

    /// The strict half, for provider selection: an unrecognised value is a
    /// boot failure naming the legal values rather than a silent fall back to
    /// a different set of providers. See the module doc for why the two
    /// readers disagree on purpose.
    pub fn from_env_for_providers() -> AppResult<Self> {
        Self::parse_for_providers(&raw_from_env())
    }

    /// The pure half of [`from_env`](Self::from_env), so the vocabulary is
    /// testable without touching the process environment.
    pub fn parse(raw: &str) -> Self {
        match Self::recognise(raw) {
            Some(mode) => mode,
            None => {
                tracing::warn!(
                    value = %raw.trim(),
                    "unrecognised MOKOSH_DEPLOYMENT_MODE; falling back to self-hosted. \
                     Valid values are `self-hosted` and `saas`",
                );
                Self::SelfHosted
            }
        }
    }

    /// The pure half of [`from_env_for_providers`](Self::from_env_for_providers).
    pub fn parse_for_providers(raw: &str) -> AppResult<Self> {
        Self::recognise(raw).ok_or_else(|| {
            AppError::Configuration(format!(
                "MOKOSH_DEPLOYMENT_MODE {:?} is not a known deployment mode; expected \
                 'self-hosted' or 'saas'. Provider selection refuses an unrecognised mode \
                 rather than starting on another profile's providers",
                raw.trim()
            ))
        })
    }

    /// The vocabulary, in one place, so the lenient and the strict reader
    /// cannot come to accept different values.
    fn recognise(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            // An empty value is what a forwarded-but-unset compose key looks
            // like (PMS-836), so it means "not configured", not "invalid".
            "" | "self-hosted" | "self_hosted" | "selfhosted" => Some(Self::SelfHosted),
            "saas" => Some(Self::Saas),
            _ => None,
        }
    }

    /// Whether platform identity is federated, i.e. whether a mokosh-side
    /// password is something anybody signs in with.
    ///
    /// Read this rather than matching on the variant at call sites: it is the
    /// question every gate is actually asking, and a third mode later would
    /// otherwise have to be added to every `match`.
    pub fn is_saas(self) -> bool {
        matches!(self, Self::Saas)
    }

    /// The mode's default provider table: one row per [`ProviderKind`], in
    /// [`ProviderKind::ALL`] order, each naming its providers in priority
    /// order.
    pub fn default_providers(self) -> &'static [ProviderDefaults] {
        match self {
            Self::SelfHosted => &SELF_HOSTED_PROVIDER_DEFAULTS,
            Self::Saas => &SAAS_PROVIDER_DEFAULTS,
        }
    }

    /// One row of that table. Never empty: every kind has a default, which is
    /// what makes "the deployment starts with something" true rather than
    /// dependent on the operator having configured it.
    pub fn default_providers_for(self, kind: ProviderKind) -> &'static [&'static str] {
        self.default_providers()[kind.index()].providers
    }

    /// Resolve the whole table against what the operator explicitly
    /// configured, recording per kind which of the two decided it.
    ///
    /// The profile supplies defaults and locks nothing, so an override always
    /// wins for its kind; the kinds nobody overrode keep the profile's row and
    /// are recorded as such, which is what makes a provider left on by a
    /// default visible rather than assumed.
    pub fn resolve_providers(self, overrides: &ProviderOverrides) -> ProviderSelection {
        let choices = ProviderKind::ALL
            .iter()
            .map(|&kind| match overrides.get(kind) {
                Some(providers) => ProviderChoice {
                    kind,
                    providers: providers.to_vec(),
                    source: EnablementSource::Explicit,
                },
                None => ProviderChoice {
                    kind,
                    providers: self.default_providers_for(kind).to_vec(),
                    source: EnablementSource::Profile,
                },
            })
            .collect();
        ProviderSelection {
            mode: self,
            choices,
        }
    }
}

/// The ONE reader of `MOKOSH_DEPLOYMENT_MODE`, shared by the lenient and the
/// strict entry point so they cannot come to read different variables.
///
/// An absent variable and a blank one collapse here on purpose: a
/// forwarded-but-unset compose key arrives as `""` (PMS-836), and both mean
/// "not configured".
fn raw_from_env() -> String {
    std::env::var("MOKOSH_DEPLOYMENT_MODE").unwrap_or_default()
}

/// A capability with exactly one selected provider per deployment.
///
/// One variant per capability named by PMS-1009. The kind is the trait, a
/// provider is an implementation of it, and a caller cannot tell which is
/// serving it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProviderKind {
    /// Where configuration values come from. The provider seam itself is
    /// PMS-982; today the only implementation is the process environment.
    Configuration,
    /// Where a tenant's secrets live (`crate::secrets`).
    Secrets,
    /// What authenticates a platform principal (`src/modules/auth`).
    Authentication,
    /// What carries outbound mail (`crate::utils::email`).
    Email,
    /// Where stored objects live (`crate::storage`).
    Storage,
}

impl ProviderKind {
    /// Every kind, in the order a profile table lists them and a boot record
    /// logs them.
    pub const ALL: [ProviderKind; 5] = [
        ProviderKind::Configuration,
        ProviderKind::Secrets,
        ProviderKind::Authentication,
        ProviderKind::Email,
        ProviderKind::Storage,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Configuration => "configuration",
            Self::Secrets => "secrets",
            Self::Authentication => "authentication",
            Self::Email => "email",
            Self::Storage => "storage",
        }
    }

    /// Every provider name this kind may name, so a table row or an override
    /// cannot quietly name a provider that does not exist.
    pub fn known_providers(self) -> &'static [&'static str] {
        match self {
            Self::Configuration => &[provider::ENVIRONMENT],
            Self::Secrets => &[provider::DATABASE, provider::INFISICAL],
            Self::Authentication => &[provider::LOCAL, provider::BUNYIP],
            Self::Email => &[provider::LOG, provider::SMTP],
            Self::Storage => &[provider::LOCAL, provider::S3],
        }
    }

    /// Position in [`ALL`](Self::ALL), which is also the row order of every
    /// profile table and the slot order of [`ProviderOverrides`].
    fn index(self) -> usize {
        match self {
            Self::Configuration => 0,
            Self::Secrets => 1,
            Self::Authentication => 2,
            Self::Email => 3,
            Self::Storage => 4,
        }
    }
}

impl fmt::Display for ProviderKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The provider names, spelled once.
///
/// They are the strings an operator already writes: `SECRET_BACKEND=database`,
/// `STORAGE_BACKEND=s3`. A profile row and an explicit setting therefore name
/// providers in one vocabulary rather than two.
pub mod provider {
    /// Configuration read from the process environment.
    pub const ENVIRONMENT: &str = "environment";
    /// Secrets in this deployment's own Postgres.
    pub const DATABASE: &str = "database";
    /// Secrets in Infisical.
    pub const INFISICAL: &str = "infisical";
    /// This instance's own plane: `users` rows for authentication, the
    /// filesystem for storage.
    pub const LOCAL: &str = "local";
    /// Bunyip: platform identity federated to it as the OP.
    pub const BUNYIP: &str = "bunyip";
    /// Mail written to the log instead of sent (`LogMailer`).
    pub const LOG: &str = "log";
    /// Mail sent through an SMTP relay (`SmtpMailer`).
    pub const SMTP: &str = "smtp";
    /// An S3-compatible object store.
    pub const S3: &str = "s3";
}

/// Providers a deployment cannot run without reaching something outside
/// itself.
///
/// The self-hosted profile names none of them, which is what "the customer
/// image boots and serves with no Bunyip, no Infisical and no object store"
/// means concretely; `the_self_hosted_defaults_need_no_external_service`
/// enforces it.
pub const EXTERNAL_SERVICE_PROVIDERS: &[&str] = &[
    provider::INFISICAL,
    provider::BUNYIP,
    provider::SMTP,
    provider::S3,
];

/// One row of a profile's default provider table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderDefaults {
    pub kind: ProviderKind,
    /// In priority order: a value resolves to the first enabled provider that
    /// holds it.
    pub providers: &'static [&'static str],
}

/// The `self-hosted` defaults.
///
/// Every provider here needs no external service, because the customer image
/// has to boot and serve on its own: local files, secrets in the deployment's
/// own Postgres, configuration from the environment, this instance's own
/// `users` rows, and mail to the log until an operator points it at a relay.
pub const SELF_HOSTED_PROVIDER_DEFAULTS: [ProviderDefaults; 5] = [
    ProviderDefaults {
        kind: ProviderKind::Configuration,
        providers: &[provider::ENVIRONMENT],
    },
    ProviderDefaults {
        kind: ProviderKind::Secrets,
        providers: &[provider::DATABASE],
    },
    ProviderDefaults {
        kind: ProviderKind::Authentication,
        providers: &[provider::LOCAL],
    },
    ProviderDefaults {
        kind: ProviderKind::Email,
        providers: &[provider::LOG],
    },
    ProviderDefaults {
        kind: ProviderKind::Storage,
        providers: &[provider::LOCAL],
    },
];

/// The `saas` defaults.
///
/// Authentication is the one row that differs, and it is the row this mode
/// exists for: bunyip first, with the legacy local path still enabled behind
/// it until PMS-981 deprecates it. That is what a `saas` instance does today,
/// since `create_api_router` mounts both.
///
/// The other four rows deliberately match `self-hosted`, and the reason is the
/// acceptance criterion itself: the `saas` defaults must reproduce CURRENT
/// deployed behaviour, and current deployed behaviour for secrets, storage,
/// email and configuration is whatever that deployment's own environment sets,
/// which explicit configuration continues to decide. Writing `infisical` or
/// `s3` in here would be a guess about an environment that is not in this
/// repository, and it would not be a merely inaccurate guess: a deployment
/// that sets neither would change backend on the next restart, and
/// `InfisicalSecretStore::from_env` refuses to build without its own
/// variables, so the guess would present as a deployment that no longer boots.
/// Moving those rows needs the deployed values read first, which is PMS-1018.
pub const SAAS_PROVIDER_DEFAULTS: [ProviderDefaults; 5] = [
    ProviderDefaults {
        kind: ProviderKind::Configuration,
        providers: &[provider::ENVIRONMENT],
    },
    ProviderDefaults {
        kind: ProviderKind::Secrets,
        providers: &[provider::DATABASE],
    },
    ProviderDefaults {
        kind: ProviderKind::Authentication,
        providers: &[provider::BUNYIP, provider::LOCAL],
    },
    ProviderDefaults {
        kind: ProviderKind::Email,
        providers: &[provider::LOG],
    },
    ProviderDefaults {
        kind: ProviderKind::Storage,
        providers: &[provider::LOCAL],
    },
];

/// Who decided a kind's providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnablementSource {
    /// Nobody configured this kind, so the hosting profile's default stands.
    Profile,
    /// The operator configured it, and it overrode the profile.
    Explicit,
}

impl EnablementSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Profile => "profile",
            Self::Explicit => "explicit",
        }
    }
}

impl fmt::Display for EnablementSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What the operator explicitly configured, per kind.
///
/// A kind with no entry takes the profile's default. This is deliberately not
/// an env reader: each capability already owns the one reader of its own
/// selection variable (`SECRET_BACKEND` in `crate::secrets`, `STORAGE_BACKEND`
/// in `crate::storage`, `SMTP_HOST` in `crate::utils::email`), and a second
/// reader here is exactly how two parts of one process come to disagree about
/// what is serving a capability. The callers hand over what they resolved, so
/// the record describes the selection rather than re-deriving it.
#[derive(Debug, Clone, Default)]
pub struct ProviderOverrides {
    per_kind: [Option<Vec<&'static str>>; ProviderKind::ALL.len()],
}

impl ProviderOverrides {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an explicit selection for one kind.
    pub fn with(self, kind: ProviderKind, providers: Vec<&'static str>) -> Self {
        self.with_opt(kind, Some(providers))
    }

    /// The same, for a caller holding an `Option` because the capability may
    /// simply not be configured. `None`, and an empty list, both mean "not
    /// configured" and leave the profile's default in place: an override that
    /// enables nothing is not an override, it is a kind nobody set.
    pub fn with_opt(mut self, kind: ProviderKind, providers: Option<Vec<&'static str>>) -> Self {
        self.per_kind[kind.index()] = providers.filter(|p| !p.is_empty());
        self
    }

    pub fn get(&self, kind: ProviderKind) -> Option<&[&'static str]> {
        self.per_kind[kind.index()].as_deref()
    }
}

/// One kind's resolved providers and where they came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderChoice {
    pub kind: ProviderKind,
    /// In priority order.
    pub providers: Vec<&'static str>,
    pub source: EnablementSource,
}

/// The resolved provider table for this process: one [`ProviderChoice`] per
/// kind, in [`ProviderKind::ALL`] order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderSelection {
    mode: DeploymentMode,
    choices: Vec<ProviderChoice>,
}

impl ProviderSelection {
    pub fn mode(&self) -> DeploymentMode {
        self.mode
    }

    pub fn choices(&self) -> &[ProviderChoice] {
        &self.choices
    }

    /// The resolution for one kind. Total, because [`resolve_providers`]
    /// produces one choice per kind and nothing else constructs this.
    ///
    /// [`resolve_providers`]: DeploymentMode::resolve_providers
    pub fn get(&self, kind: ProviderKind) -> &ProviderChoice {
        &self.choices[kind.index()]
    }

    /// The kind's highest-priority provider: the one that serves unless it
    /// does not hold the value.
    pub fn primary(&self, kind: ProviderKind) -> &'static str {
        self.get(kind).providers[0]
    }

    /// The kinds an operator configured away from the profile. PMS-989 reports
    /// these; a deployment that configured nothing yields an empty iterator.
    pub fn deviations(&self) -> impl Iterator<Item = &ProviderChoice> {
        self.choices
            .iter()
            .filter(|c| c.source == EnablementSource::Explicit)
    }

    /// Write the record to the boot log, one line per kind.
    ///
    /// Every kind is logged, not only the deviations: the point of recording
    /// the source is that a provider left on by a default is visible, and a
    /// log that only mentions what was overridden leaves the defaults to be
    /// assumed, which is the state this issue exists to end.
    pub fn record(&self) {
        for choice in &self.choices {
            tracing::info!(
                mode = %self.mode,
                kind = choice.kind.as_str(),
                providers = %choice.providers.join(","),
                source = choice.source.as_str(),
                "provider selected",
            );
        }
    }
}

impl fmt::Display for DeploymentMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::SelfHosted => "self-hosted",
            Self::Saas => "saas",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_is_self_hosted() {
        assert_eq!(DeploymentMode::default(), DeploymentMode::SelfHosted);
        assert!(!DeploymentMode::default().is_saas());
    }

    #[test]
    fn saas_is_recognised_however_it_is_cased_or_padded() {
        for raw in ["saas", "SaaS", "SAAS", "  saas  "] {
            assert_eq!(DeploymentMode::parse(raw), DeploymentMode::Saas, "{raw:?}");
        }
    }

    #[test]
    fn the_self_hosted_spellings_all_resolve() {
        for raw in ["self-hosted", "self_hosted", "selfhosted", "SELF-HOSTED"] {
            assert_eq!(
                DeploymentMode::parse(raw),
                DeploymentMode::SelfHosted,
                "{raw:?}"
            );
        }
    }

    #[test]
    fn an_empty_value_is_not_configured_rather_than_invalid() {
        // PMS-836: compose forwards every declared key, so a variable the
        // operator left blank arrives as `""` rather than absent. Treating
        // that as a bad value would log a warning on every boot of a stack
        // that is simply not using the flag.
        assert_eq!(DeploymentMode::parse(""), DeploymentMode::SelfHosted);
        assert_eq!(DeploymentMode::parse("   "), DeploymentMode::SelfHosted);
    }

    #[test]
    fn an_unrecognised_value_falls_back_to_self_hosted_not_saas() {
        // The asymmetry is the point. Falling back to `saas` on a typo would
        // silently stop a self-hosted deployment's password-reset mail, which
        // presents to the operator as a broken product with no error anywhere.
        // Falling back to `self-hosted` costs a SaaS instance a redundant
        // email at worst.
        for raw in ["cloud", "hosted", "sass", "true"] {
            assert_eq!(
                DeploymentMode::parse(raw),
                DeploymentMode::SelfHosted,
                "{raw:?}"
            );
        }
    }

    #[test]
    fn the_display_form_round_trips_through_parse() {
        for mode in [DeploymentMode::SelfHosted, DeploymentMode::Saas] {
            assert_eq!(DeploymentMode::parse(&mode.to_string()), mode);
        }
    }

    /// The lenient reader keeps PMS-902's fallback; the strict one refuses and
    /// says what it would have accepted. Both halves are asserted together so
    /// the split cannot be half-removed by a later edit.
    #[test]
    fn an_unrecognised_value_is_fatal_for_providers_and_not_for_mail() {
        for raw in ["cloud", "hosted", "sass", "true"] {
            assert_eq!(
                DeploymentMode::parse(raw),
                DeploymentMode::SelfHosted,
                "mail dispatch keeps the warn-and-default for {raw:?}"
            );
            let err = DeploymentMode::parse_for_providers(raw)
                .expect_err("provider selection must refuse {raw:?}")
                .to_string();
            assert!(err.contains("self-hosted"), "{err}");
            assert!(err.contains("saas"), "{err}");
        }
    }

    /// Unset, blank and every recognised spelling stay recognised by the
    /// strict reader too: it refuses typos, not configurations that work.
    #[test]
    fn the_strict_reader_accepts_everything_the_lenient_one_recognises() {
        for raw in ["", "   ", "self-hosted", "self_hosted", "SELF-HOSTED"] {
            assert_eq!(
                DeploymentMode::parse_for_providers(raw).unwrap(),
                DeploymentMode::SelfHosted,
                "{raw:?}"
            );
        }
        assert_eq!(
            DeploymentMode::parse_for_providers("  SaaS ").unwrap(),
            DeploymentMode::Saas
        );
    }

    #[test]
    fn every_profile_has_one_row_per_kind_in_kind_order() {
        for mode in [DeploymentMode::SelfHosted, DeploymentMode::Saas] {
            let table = mode.default_providers();
            assert_eq!(table.len(), ProviderKind::ALL.len(), "{mode}");
            for (row, kind) in table.iter().zip(ProviderKind::ALL) {
                assert_eq!(row.kind, kind, "{mode} rows are in ProviderKind::ALL order");
                assert!(!row.providers.is_empty(), "{mode} {kind} has no default");
                assert_eq!(mode.default_providers_for(kind), row.providers);
            }
        }
    }

    /// A row may not name a provider that does not exist. Without this the
    /// table is prose: it would happily declare `vault` and nothing would say
    /// otherwise until an operator's deployment failed to boot.
    #[test]
    fn every_default_names_a_provider_its_kind_knows() {
        for mode in [DeploymentMode::SelfHosted, DeploymentMode::Saas] {
            for row in mode.default_providers() {
                for name in row.providers {
                    assert!(
                        row.kind.known_providers().contains(name),
                        "{mode} {} names unknown provider {name:?}",
                        row.kind
                    );
                }
            }
        }
    }

    /// The acceptance criterion in executable form: the customer image boots
    /// and serves with no Bunyip, no Infisical and no object store, because
    /// nothing the self-hosted profile enables by default reaches outside the
    /// deployment.
    #[test]
    fn the_self_hosted_defaults_need_no_external_service() {
        for row in DeploymentMode::SelfHosted.default_providers() {
            for name in row.providers {
                assert!(
                    !EXTERNAL_SERVICE_PROVIDERS.contains(name),
                    "self-hosted {} defaults to {name:?}, which needs an external service",
                    row.kind
                );
            }
        }
    }

    /// The `saas` profile reproduces current deployed behaviour, which means
    /// it differs from `self-hosted` in exactly the one place the code already
    /// behaves differently today: `create_api_router` mounts bunyip alongside
    /// the legacy local path when the mode is `saas`. Every other kind is
    /// decided by that deployment's own explicit configuration, so its row
    /// must not move without the deployed values in hand.
    #[test]
    fn the_saas_defaults_differ_from_self_hosted_only_in_authentication() {
        for kind in ProviderKind::ALL {
            let self_hosted = DeploymentMode::SelfHosted.default_providers_for(kind);
            let saas = DeploymentMode::Saas.default_providers_for(kind);
            if kind == ProviderKind::Authentication {
                assert_eq!(self_hosted, [provider::LOCAL]);
                assert_eq!(saas, [provider::BUNYIP, provider::LOCAL]);
            } else {
                assert_eq!(saas, self_hosted, "{kind}");
            }
        }
    }

    #[test]
    fn an_unconfigured_kind_takes_the_profile_default_and_says_so() {
        let selection = DeploymentMode::Saas.resolve_providers(&ProviderOverrides::new());
        for kind in ProviderKind::ALL {
            let choice = selection.get(kind);
            assert_eq!(choice.kind, kind);
            assert_eq!(choice.source, EnablementSource::Profile, "{kind}");
            assert_eq!(
                choice.providers,
                DeploymentMode::Saas.default_providers_for(kind)
            );
        }
        assert_eq!(
            selection.primary(ProviderKind::Authentication),
            provider::BUNYIP
        );
        assert_eq!(selection.deviations().count(), 0);
    }

    #[test]
    fn an_explicit_selection_overrides_the_default_for_its_kind_only() {
        let overrides = ProviderOverrides::new()
            .with(ProviderKind::Secrets, vec![provider::INFISICAL])
            .with(ProviderKind::Storage, vec![provider::S3]);
        let selection = DeploymentMode::SelfHosted.resolve_providers(&overrides);

        assert_eq!(
            selection.get(ProviderKind::Secrets),
            &ProviderChoice {
                kind: ProviderKind::Secrets,
                providers: vec![provider::INFISICAL],
                source: EnablementSource::Explicit,
            }
        );
        assert_eq!(selection.primary(ProviderKind::Storage), provider::S3);
        // Untouched kinds keep the profile, and keep saying they did.
        assert_eq!(
            selection.get(ProviderKind::Email).source,
            EnablementSource::Profile
        );
        assert_eq!(selection.primary(ProviderKind::Email), provider::LOG);

        let deviations: Vec<_> = selection.deviations().map(|c| c.kind).collect();
        assert_eq!(
            deviations,
            [ProviderKind::Secrets, ProviderKind::Storage],
            "only the overridden kinds are deviations"
        );
    }

    /// `None` and an empty list are the same thing: a capability nobody
    /// configured. Recording an empty override as `Explicit` would report a
    /// deviation to nothing and leave `primary` with no provider to name.
    #[test]
    fn an_empty_override_is_not_an_override() {
        let overrides = ProviderOverrides::new()
            .with_opt(ProviderKind::Email, None)
            .with_opt(ProviderKind::Secrets, Some(Vec::new()));
        let selection = DeploymentMode::SelfHosted.resolve_providers(&overrides);
        for kind in [ProviderKind::Email, ProviderKind::Secrets] {
            assert_eq!(
                selection.get(kind).source,
                EnablementSource::Profile,
                "{kind}"
            );
            assert_eq!(
                selection.get(kind).providers,
                DeploymentMode::SelfHosted.default_providers_for(kind)
            );
        }
    }

    /// One reader of the mode variable, the way `crate::secrets` pins one
    /// reader of `SECRET_BACKEND`. Two readers is how the lenient and the
    /// strict entry point come to read different things.
    #[test]
    fn there_is_one_reader_of_the_mode_variable() {
        const SRC: &str = include_str!("deployment.rs");
        assert_eq!(
            SRC.matches(concat!("var(\"MOKOSH_DEPLOYMENT", "_MODE\")"))
                .count(),
            1,
            "MOKOSH_DEPLOYMENT_MODE is read in exactly one place"
        );
    }
}
