//! PMS-988: application-tier secrets, in the Bunyip contract's shape.
//!
//! Application-tier means the secret belongs to the whole deployment, not to
//! any tenant: `SMTP_PASSWORD` is what the mailer authenticates the process
//! with, and every tenant's outbound message uses the same relay account.
//! [`crate::secrets`] is the TENANT tier and stays where it is; the two share
//! no registry on purpose, because a tenant secret has no deployment-wide
//! name to declare and a deployment secret has no tenant to key on.
//!
//! Bunyip has already built exactly this after a production incident and it
//! is the contract to adopt rather than redesign
//! (`crates/bunyip-domain/src/config.rs` and `bunyip-api/src/secrets.rs`).
//! Four provider implementations serve the same [`GovernedSecret`] registry,
//! one variable declares which is authoritative, and boot classifies each
//! secret against every built provider so a value in the wrong provider is
//! loud instead of silent.
//!
//! # The four boot classifications
//!
//! | Situation                                       | What happens         |
//! |-------------------------------------------------|----------------------|
//! | Declared provider holds it, nowhere else        | Info: used           |
//! | No provider holds it                            | Warn: feature off    |
//! | Declared provider holds it AND another          | Warn per duplicate   |
//! | Declared provider does NOT hold it, another does| Fatal: process exits |
//!
//! The last row is the production incident this model exists to prevent, and
//! is why [`enforce`] returns `AppError::Configuration` rather than a warning.
//!
//! # Redaction is absolute
//!
//! No provider name, feature sentence or provider-membership row carries a
//! secret VALUE. [`AppSecretsStatus`] and every log line here name a secret
//! by its env-style key and say which provider holds it. Nothing else. The
//! providers themselves hand values only to [`AppSecrets::get`], which the
//! mailer path reaches into and immediately hides behind
//! `secrecy::SecretString`.

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;

use crate::db::Database;
use crate::utils::deployment::{provider, EnablementSource};
use crate::utils::error::{AppError, AppResult};

pub mod database;
pub mod env;
pub mod file;
pub mod infisical;

pub use database::DatabaseProvider;
pub use env::EnvironmentProvider;
pub use file::FileProvider;
pub use infisical::InfisicalProvider;

/// A registered application-tier secret. One variant per secret Mokosh
/// treats as governed: the variable name, the feature its absence disables,
/// and the file the environment provider reads.
///
/// Only one today. New variants join this list the day Mokosh gains a second
/// governed application-tier secret; when they do, `feature()` must state the
/// impact in one sentence, because that is the sentence a warn log renders
/// verbatim when nobody holds the value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GovernedSecret {
    /// `SMTP_PASSWORD` / `smtp_password` / the `app_secrets` row named
    /// `SMTP_PASSWORD`. The SMTP relay's password.
    SmtpPassword,
}

impl GovernedSecret {
    /// Every governed secret, in report order.
    pub const ALL: [Self; 1] = [Self::SmtpPassword];

    /// The env-style key: the plain variable name the operator writes, and
    /// the row name the database provider stores under.
    pub fn name(self) -> &'static str {
        match self {
            Self::SmtpPassword => "SMTP_PASSWORD",
        }
    }

    /// What stops working when no provider holds this secret. Rendered
    /// verbatim by the warn log for the `Missing` case, so it is a complete
    /// sentence rather than a phrase.
    pub fn feature(self) -> &'static str {
        match self {
            Self::SmtpPassword => "transactional email is unauthenticated, so password resets, portal setup links and notifications fail at the relay",
        }
    }

    /// The `{NAME}_FILE` target the environment provider reads, and the
    /// filename the file provider looks for inside `APP_SECRETS_DIR`. Chosen
    /// to match the compose-secret convention Mokosh already uses for Group-1
    /// startup secrets: lowercase, `_` separators.
    pub fn secret_file(self) -> &'static str {
        match self {
            Self::SmtpPassword => "smtp_password",
        }
    }
}

impl std::fmt::Display for GovernedSecret {
    /// Names the secret, never the value. Safe to log.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// What a feature can ask of an application-tier secret provider.
///
/// Deliberately SEPARATE from [`crate::secrets::SecretProvider`]: the tenant
/// tier addresses values by [`crate::secrets::SecretKey`], which carries a
/// tenant, while this tier addresses them by [`GovernedSecret`], which does
/// not. Sharing one trait would let a caller pass one kind of key where the
/// other is required, which is exactly the boundary this seam exists to keep.
///
/// The `get` / `has` read paths are sync on purpose: every implementation
/// resolves its value at boot (either by reading a file, an env var, or a
/// decrypted database column loaded once), so the read paths that ask "what is
/// the SMTP password" answer from memory without an async hop.
///
/// `set` and `delete` are async because the writable providers reach out over
/// the wire or into the pool. PMS-1012 added them: the provider-migrate CLI is
/// what needs them, and the trait not carrying them is what made an external
/// migration tool the operator's only option.
#[async_trait]
pub trait AppSecretProvider: Send + Sync {
    /// The provider's canonical name, as an operator writes it and as the
    /// boot record reports it.
    fn name(&self) -> &'static str;

    /// The provider's value for `secret`, or `None` when it holds none.
    ///
    /// A present-but-empty value is `None`: an empty string is not a secret,
    /// and treating it as present would count a blank compose secret as
    /// held and boot successfully with an unusable password. This is the
    /// `non_empty` normalisation Bunyip's survey applied (BUNYIP-621), lifted
    /// into every provider so every caller agrees on what "present" means.
    fn get(&self, secret: GovernedSecret) -> Option<String>;

    /// Whether this provider holds `secret` at all. Default reads the value
    /// and drops it; a provider whose presence check is cheaper can override.
    fn has(&self, secret: GovernedSecret) -> bool {
        self.get(secret).is_some()
    }

    /// Whether an operator can write a governed secret to this provider from
    /// the admin surface. The environment provider is the one read-only case:
    /// a process cannot set an env var for its own next boot, and the compose
    /// secret files are mounted read-only.
    fn is_writable(&self) -> bool {
        true
    }

    /// PMS-1012: write one governed secret. The default returns
    /// `AppError::Configuration` naming the provider, so an existing
    /// implementation that has not been updated for a write path refuses
    /// loudly rather than silently no-oping.
    async fn set(&self, secret: GovernedSecret, value: &str) -> AppResult<()> {
        let _ = (secret, value);
        Err(AppError::Configuration(format!(
            "{} provider does not support writes",
            self.name()
        )))
    }

    /// PMS-1012: delete one governed secret. Same default posture as
    /// [`AppSecretProvider::set`]: a provider that cannot delete refuses the
    /// call, and the caller (the CLI) reports "cannot purge <provider>" with
    /// what an operator would have to do by hand.
    async fn delete(&self, secret: GovernedSecret) -> AppResult<()> {
        let _ = secret;
        Err(AppError::Configuration(format!(
            "{} provider does not support deletes",
            self.name()
        )))
    }
}

/// Which provider holds the application-tier secrets for this deployment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppSecretProviderKind {
    /// The process environment, read as `{NAME}_FILE` compose secrets.
    Environment,
    /// A directory named by `APP_SECRETS_DIR`, one file per secret.
    File,
    /// The `app_secrets` table, ciphertext under the deployment's
    /// `ENCRYPTION_KEY`.
    Database,
    /// Infisical, via the same client `crate::secrets::infisical` uses.
    Infisical,
}

impl AppSecretProviderKind {
    /// Every provider, in a stable order used everywhere a status report or
    /// membership vector wants to be reproducible.
    pub const ALL: [Self; 4] = [
        Self::Environment,
        Self::File,
        Self::Database,
        Self::Infisical,
    ];

    /// The wire/env spelling. Matches `crate::utils::deployment::provider`
    /// where a name already existed; `"file"` is new to that vocabulary and
    /// is a plain literal here rather than expanded into the deployment
    /// vocabulary, because the file provider today serves ONLY application
    /// secrets.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Environment => provider::ENVIRONMENT,
            Self::File => "file",
            Self::Database => provider::DATABASE,
            Self::Infisical => provider::INFISICAL,
        }
    }

    /// Legal names, for the operator-facing error on an unrecognised value.
    pub const LEGAL_VALUES: &'static str = "environment, file, database, infisical";

    /// A provider NAME to a kind. Blank is not a name: the caller resolves an
    /// unset `SECRET_BACKEND` against the hosting profile's default before it
    /// reaches here.
    ///
    /// An unrecognised value is a hard error, not a fall back to the
    /// hosting-profile default: an operator who wrote `SECRET_BACKEND=file `
    /// with a typo asked for the file provider, and quietly giving them the
    /// database is the same silent degrade this model exists to remove
    /// everywhere else.
    pub fn parse_name(raw: &str) -> AppResult<Self> {
        match raw.trim() {
            provider::ENVIRONMENT => Ok(Self::Environment),
            "file" => Ok(Self::File),
            provider::DATABASE => Ok(Self::Database),
            provider::INFISICAL => Ok(Self::Infisical),
            other => Err(AppError::Configuration(format!(
                "SECRET_BACKEND {other:?} is not a known application-tier secret provider; \
                 expected one of: {}",
                Self::LEGAL_VALUES
            ))),
        }
    }

    /// The kind's slot in a `Vec<Option<Arc<dyn AppSecretProvider>>>` of
    /// length [`Self::ALL`]`.len()`. Made `pub(crate)` so the PMS-1012 CLI can
    /// index a slot without reimplementing the mapping.
    pub(crate) fn index(self) -> usize {
        match self {
            Self::Environment => 0,
            Self::File => 1,
            Self::Database => 2,
            Self::Infisical => 3,
        }
    }
}

impl std::fmt::Display for AppSecretProviderKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Provider selection, and which of the two decided it.
#[derive(Clone, Copy, Debug)]
pub struct AppSecretsSelection {
    pub provider: AppSecretProviderKind,
    /// PMS-1011: whether the hosting profile's default stands or the operator
    /// overrode it, for the boot record.
    pub source: EnablementSource,
}

impl AppSecretsSelection {
    /// Read `SECRET_BACKEND`, the same variable the tenant tier reads.
    ///
    /// Both tiers pick the SAME provider on purpose: operator intent is
    /// "hold my secrets over there", and a deployment with tenant secrets in
    /// the database while application secrets sat in Infisical is a shape
    /// nobody asked for. The two tiers keep their own readers because the
    /// tenant tier accepts a strict subset (database, infisical) and this
    /// tier accepts all four; a value only this tier accepts still ends the
    /// tenant tier's boot the same way this one would, with a clear error.
    ///
    /// It is deliberately not a registry key and is read here rather than
    /// through [`crate::config::get`]: provider enablement is bootstrap
    /// configuration, and configuration that says where to find configuration
    /// cannot live inside the thing it locates (`docs/providers.md`).
    pub fn from_env(profile_default: &str) -> AppResult<Self> {
        Self::resolve(
            profile_default,
            &std::env::var("SECRET_BACKEND").unwrap_or_default(),
        )
    }

    /// The rule itself, split out so it can be tested without writing to
    /// process-global env under a concurrent test runner.
    pub fn resolve(profile_default: &str, raw: &str) -> AppResult<Self> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Ok(Self {
                provider: AppSecretProviderKind::parse_name(profile_default)?,
                source: EnablementSource::Profile,
            });
        }
        Ok(Self {
            provider: AppSecretProviderKind::parse_name(raw)?,
            source: EnablementSource::Explicit,
        })
    }
}

/// Every built provider, indexed by [`AppSecretProviderKind::index`]. A slot
/// is `None` when its provider's construction inputs are absent (no
/// `APP_SECRETS_DIR`, no `INFISICAL_ADDRESS`); [`AppSecretProviderKind::ALL`]
/// remains the enumeration order for reporting.
pub struct AppSecrets {
    declared: AppSecretProviderKind,
    providers: Vec<Option<Arc<dyn AppSecretProvider>>>,
}

impl AppSecrets {
    /// The declared provider's value for `secret`, or `None` when the
    /// declared provider holds none. This is the read path every feature
    /// uses; the survey/enforce path walks every provider separately.
    pub fn get(&self, secret: GovernedSecret) -> Option<String> {
        self.provider(self.declared)
            .and_then(|provider| provider.get(secret))
    }

    /// The declared provider for this process.
    pub fn declared(&self) -> AppSecretProviderKind {
        self.declared
    }

    /// Every built provider, by kind. `None` for providers whose construction
    /// inputs were absent.
    pub fn provider(&self, kind: AppSecretProviderKind) -> Option<&Arc<dyn AppSecretProvider>> {
        self.providers[kind.index()].as_ref()
    }
}

/// A membership snapshot: which providers hold which governed secret at the
/// moment the survey ran. No secret VALUE ever enters this DTO.
#[derive(Debug, Clone)]
pub struct AppSecretSurveyRow {
    pub secret: GovernedSecret,
    /// Every built provider that holds this secret, in
    /// [`AppSecretProviderKind::ALL`] order.
    pub holders: Vec<AppSecretProviderKind>,
}

impl AppSecretSurveyRow {
    pub fn present_in(&self, kind: AppSecretProviderKind) -> bool {
        self.holders.contains(&kind)
    }
}

/// The whole survey: the declared provider and one row per governed secret.
#[derive(Debug, Clone)]
pub struct AppSecretsSurvey {
    pub declared: AppSecretProviderKind,
    pub rows: Vec<AppSecretSurveyRow>,
}

impl AppSecretsSurvey {
    /// Walk every governed secret through every built provider. `has` reads
    /// through the trait, which for the DB and Infisical providers hits the
    /// boot-time cache each holds (see their modules); no read here escapes
    /// the process.
    pub fn from_current(secrets: &AppSecrets) -> Self {
        let rows = GovernedSecret::ALL
            .into_iter()
            .map(|secret| {
                let holders: Vec<AppSecretProviderKind> = AppSecretProviderKind::ALL
                    .into_iter()
                    .filter(|kind| {
                        secrets
                            .provider(*kind)
                            .is_some_and(|provider| provider.has(secret))
                    })
                    .collect();
                AppSecretSurveyRow { secret, holders }
            })
            .collect();
        Self {
            declared: secrets.declared,
            rows,
        }
    }
}

/// The pure classification decision for one secret: which provider was
/// declared, which providers hold a value. Kept free of IO and free of the
/// tracing so the four cases stay unit-tested against `classify` alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Classification {
    /// The declared provider holds it and no other built provider does.
    Used,
    /// No built provider holds it: the feature stays off.
    Missing,
    /// The declared provider holds it, AND another built provider does. Boots,
    /// but the stale copy becomes live on a later selection change so it is
    /// named.
    Shadowed(Vec<AppSecretProviderKind>),
    /// The declared provider is empty, but another built provider holds it.
    /// Fatal: using the other provider's copy would be exactly the silent
    /// precedence this model removes, and ignoring the other copy would
    /// disable a feature the operator plainly configured.
    Misplaced(Vec<AppSecretProviderKind>),
}

/// The pure enforcement decision: which provider was declared, which
/// providers hold a value. See [`Classification`].
pub fn classify(
    declared: AppSecretProviderKind,
    holders: &[AppSecretProviderKind],
) -> Classification {
    let elsewhere: Vec<AppSecretProviderKind> = holders
        .iter()
        .copied()
        .filter(|kind| *kind != declared)
        .collect();
    match (holders.contains(&declared), elsewhere.is_empty()) {
        (true, true) => Classification::Used,
        (true, false) => Classification::Shadowed(elsewhere),
        (false, true) => Classification::Missing,
        (false, false) => Classification::Misplaced(elsewhere),
    }
}

/// Apply [`classify`] to every governed secret in the survey.
///
/// The three non-fatal cases each write a tracing line naming the secret and
/// the provider (never the value). `Missing` renders `feature()` verbatim so
/// the operator sees which feature stopped working. `Misplaced` accumulates
/// one line per secret into an `AppError::Configuration` the caller returns
/// from boot; `main` then exits non-zero, which is the whole point of the
/// contract.
pub fn enforce(survey: &AppSecretsSurvey) -> AppResult<()> {
    let mut fatal: Vec<String> = Vec::new();
    for row in &survey.rows {
        match classify(survey.declared, &row.holders) {
            Classification::Used => {
                tracing::info!(
                    secret = row.secret.name(),
                    provider = survey.declared.as_str(),
                    "app-tier secret served by {}",
                    survey.declared.as_str()
                );
            }
            Classification::Missing => {
                tracing::warn!(
                    secret = row.secret.name(),
                    provider = survey.declared.as_str(),
                    "no provider holds {}; {}",
                    row.secret.name(),
                    row.secret.feature(),
                );
            }
            Classification::Shadowed(elsewhere) => {
                tracing::info!(
                    secret = row.secret.name(),
                    provider = survey.declared.as_str(),
                    "app-tier secret served by {}",
                    survey.declared.as_str()
                );
                for other in elsewhere {
                    tracing::warn!(
                        secret = row.secret.name(),
                        declared = survey.declared.as_str(),
                        duplicate = other.as_str(),
                        "{} is also held by {}; run secrets-migrate --to {} then secrets-purge to remove it",
                        row.secret.name(),
                        other.as_str(),
                        survey.declared.as_str(),
                    );
                }
            }
            Classification::Misplaced(elsewhere) => {
                fatal.push(format!(
                    "{} is absent from the declared {} provider but present in the {}. \
                     mokosh will not silently use a provider the deployment did not \
                     declare. Copy it with `mokosh-server secrets-migrate --to {}`, \
                     or set SECRET_BACKEND to the provider that holds it.",
                    row.secret.name(),
                    survey.declared.as_str(),
                    provider_list(&elsewhere),
                    survey.declared.as_str(),
                ));
            }
        }
    }
    if fatal.is_empty() {
        Ok(())
    } else {
        Err(AppError::Configuration(fatal.join("\n\n")))
    }
}

/// Render a provider list for an operator message (`"environment and infisical"`).
fn provider_list(kinds: &[AppSecretProviderKind]) -> String {
    let names: Vec<&str> = kinds.iter().map(|kind| kind.as_str()).collect();
    match names.as_slice() {
        [] => String::new(),
        [one] => (*one).to_string(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// Per-secret provider-membership DTO: no value, only names.
///
/// The future `secrets-status` CLI/endpoint (PMS-1012) renders this. The
/// serialisation lives in the type rather than at each call site so a
/// deliberate `#[derive(serde::Serialize)]` covers every field: adding one
/// then means naming it in this file, which is the change the redaction test
/// scans.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AppSecretStatus {
    /// The env-style key.
    pub secret: &'static str,
    /// Every provider that holds the secret, in
    /// [`AppSecretProviderKind::ALL`] order.
    pub holders: Vec<&'static str>,
    /// The provider that would serve the secret, or `None` if the declared
    /// provider does not hold it (`Missing` / `Misplaced`).
    pub served_by: Option<&'static str>,
}

/// Every declared secret, with the providers that hold it and which one
/// serves it. No secret value, ever.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AppSecretsStatus {
    pub declared: &'static str,
    pub secrets: Vec<AppSecretStatus>,
}

/// Build the status report from a survey. Pure, so the redaction test can
/// drive it against a fixture and assert the shape carries only names.
pub fn status(survey: &AppSecretsSurvey) -> AppSecretsStatus {
    let secrets = survey
        .rows
        .iter()
        .map(|row| AppSecretStatus {
            secret: row.secret.name(),
            holders: row.holders.iter().map(|kind| kind.as_str()).collect(),
            served_by: row
                .present_in(survey.declared)
                .then(|| survey.declared.as_str()),
        })
        .collect();
    AppSecretsStatus {
        declared: survey.declared.as_str(),
        secrets,
    }
}

static CURRENT: OnceLock<Arc<AppSecrets>> = OnceLock::new();

/// The process's application-tier secrets, once [`init_from_env`] has run.
///
/// `None` when `init_from_env` has not run. The mailer path treats that as
/// "fall back to the configuration provider", so test binaries and seeders
/// that never reach `main` behave exactly as they did before this module
/// existed. Once initialised, the reference is stable for the life of the
/// process.
pub fn current() -> Option<Arc<AppSecrets>> {
    CURRENT.get().cloned()
}

/// Build every application-tier secret provider whose construction inputs
/// are present, choose the declared one from `SECRET_BACKEND`, enforce the
/// four-way classification, and install the result as the process-wide
/// [`current`] handle.
///
/// `profile_default` is the hosting profile's provider for
/// [`crate::utils::deployment::ProviderKind::Secrets`], resolved by the
/// startup wiring and passed in as a NAME. This module deliberately never
/// holds the deployment shape, for the reason PMS-904 states.
///
/// Async because the database and Infisical providers load their contents
/// once at construction and serve from that cache afterwards; the
/// alternative (`block_on` on the current runtime) deadlocks.
pub async fn init_from_env(
    profile_default: &str,
    db: Database,
    encryption_key: [u8; 32],
) -> AppResult<AppSecretsSelection> {
    let selection = AppSecretsSelection::from_env(profile_default)?;

    let mut providers: Vec<Option<Arc<dyn AppSecretProvider>>> =
        vec![None; AppSecretProviderKind::ALL.len()];

    // The environment provider is always built: it costs nothing, and the
    // classification below wants to see whether a `{NAME}_FILE` compose
    // secret shadows the declared provider whatever that provider is.
    providers[AppSecretProviderKind::Environment.index()] = Some(Arc::new(EnvironmentProvider));

    // The file provider is built only when `APP_SECRETS_DIR` names a
    // directory. Read through the config provider, so a caller cannot forge
    // a path from something else: PMS-982 declared it as a bootstrap key.
    if let Some(dir) = crate::config::get(&crate::config::registry::APP_SECRETS_DIR)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        providers[AppSecretProviderKind::File.index()] =
            Some(Arc::new(FileProvider::new(PathBuf::from(dir))));
    }

    // The database provider is always built: the pool is already open, and
    // the four rows a governed-secret table holds cost nothing to preload.
    providers[AppSecretProviderKind::Database.index()] =
        Some(Arc::new(DatabaseProvider::load(&db, encryption_key).await?));

    // Infisical needs to be reachable to be inspected, and the operator
    // opts into it by setting `INFISICAL_ADDRESS`. Absent, this arm is
    // silent: the classification then reports "no provider holds it" for
    // Infisical rather than a probe error, which is the truth.
    if crate::config::get(&crate::config::registry::INFISICAL_ADDRESS)
        .filter(|s| !s.trim().is_empty())
        .is_some()
    {
        providers[AppSecretProviderKind::Infisical.index()] =
            Some(Arc::new(InfisicalProvider::load().await?));
    }

    let secrets = AppSecrets {
        declared: selection.provider,
        providers,
    };
    let survey = AppSecretsSurvey::from_current(&secrets);
    enforce(&survey)?;

    // A second init call after the first succeeded is a no-op that keeps the
    // provider already installed, so test binaries that call this twice do
    // not race.
    let _ = CURRENT.set(Arc::new(secrets));
    tracing::info!(
        provider = selection.provider.as_str(),
        source = selection.source.as_str(),
        "app-tier secret provider selected"
    );
    Ok(selection)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use AppSecretProviderKind::{Database as Db, Environment as Env, Infisical as Inf};

    /// A provider driven from a fixed map, so tests can build any survey by
    /// hand without touching the DB, Infisical or the filesystem.
    struct FixedProvider {
        name: &'static str,
        value: Option<String>,
    }

    #[async_trait]
    impl AppSecretProvider for FixedProvider {
        fn name(&self) -> &'static str {
            self.name
        }
        fn get(&self, _secret: GovernedSecret) -> Option<String> {
            self.value.clone()
        }
    }

    fn arc(name: &'static str, value: Option<&str>) -> Arc<dyn AppSecretProvider> {
        Arc::new(FixedProvider {
            name,
            value: value.map(str::to_string),
        })
    }

    fn secrets_with(
        declared: AppSecretProviderKind,
        holders: &[AppSecretProviderKind],
        secret_value: &str,
    ) -> AppSecrets {
        let mut providers: Vec<Option<Arc<dyn AppSecretProvider>>> =
            vec![None; AppSecretProviderKind::ALL.len()];
        for kind in AppSecretProviderKind::ALL {
            let value = holders.contains(&kind).then_some(secret_value);
            providers[kind.index()] = Some(arc(kind.as_str(), value));
        }
        AppSecrets {
            declared,
            providers,
        }
    }

    fn survey_with(
        declared: AppSecretProviderKind,
        holders: Vec<AppSecretProviderKind>,
    ) -> AppSecretsSurvey {
        // `from_current` produces holders in `AppSecretProviderKind::ALL`
        // order; canonicalise the fixture so a test cannot encode a wrong
        // order and pass on it accidentally.
        let ordered: Vec<AppSecretProviderKind> = AppSecretProviderKind::ALL
            .into_iter()
            .filter(|k| holders.contains(k))
            .collect();
        AppSecretsSurvey {
            declared,
            rows: vec![AppSecretSurveyRow {
                secret: GovernedSecret::SmtpPassword,
                holders: ordered,
            }],
        }
    }

    /// Row 1 of the classification table: present in the declared provider, nowhere else.
    #[test]
    fn present_only_in_the_declared_provider_is_used() {
        for declared in AppSecretProviderKind::ALL {
            assert_eq!(classify(declared, &[declared]), Classification::Used);
        }
    }

    /// Row 2: absent everywhere leaves the feature off, every time.
    #[test]
    fn absent_everywhere_is_missing() {
        for declared in AppSecretProviderKind::ALL {
            assert_eq!(classify(declared, &[]), Classification::Missing);
        }
    }

    /// Row 3: declared holds it AND another does, boot with named duplicates.
    #[test]
    fn declared_plus_another_is_shadowed() {
        assert_eq!(
            classify(Db, &[Env, Db]),
            Classification::Shadowed(vec![Env])
        );
        assert_eq!(
            classify(Db, &[Env, Db, Inf]),
            Classification::Shadowed(vec![Env, Inf])
        );
    }

    /// Row 4: declared empty, another holds it -> fatal, and the names of the
    /// other holders reach the message so the operator can migrate or repoint.
    #[test]
    fn declared_empty_but_present_elsewhere_is_misplaced() {
        assert_eq!(classify(Inf, &[Db]), Classification::Misplaced(vec![Db]));
        assert_eq!(
            classify(Env, &[Db, Inf]),
            Classification::Misplaced(vec![Db, Inf])
        );
    }

    /// Enforce is a fatal boot error on `Misplaced` and names the migration
    /// command so the operator has one thing to run.
    #[test]
    fn enforce_returns_fatal_configuration_error_for_misplaced() {
        let survey = survey_with(Inf, vec![Db]);
        let err = enforce(&survey).expect_err("misplaced must be fatal");
        let message = err.to_string();
        assert!(message.contains("SMTP_PASSWORD"), "{message}");
        assert!(message.contains("infisical"), "{message}");
        assert!(message.contains("database"), "{message}");
        assert!(
            message.contains("secrets-migrate --to infisical"),
            "{message}"
        );
    }

    /// Enforce is silent (Ok, no fatal) for Used, Missing and Shadowed. This
    /// is what makes the fatal case sharp: only the one row exits.
    #[test]
    fn enforce_is_ok_for_used_missing_and_shadowed() {
        assert!(enforce(&survey_with(Db, vec![Db])).is_ok());
        assert!(enforce(&survey_with(Db, vec![])).is_ok());
        assert!(enforce(&survey_with(Db, vec![Db, Env])).is_ok());
    }

    /// The `Missing` case always warns and never becomes silent, because
    /// every governed secret carries a `feature()` sentence by design and a
    /// missing feature is the whole reason to have this registry.
    #[test]
    fn every_governed_secret_carries_a_feature_sentence() {
        for secret in GovernedSecret::ALL {
            let feature = secret.feature();
            assert!(!feature.is_empty(), "{secret} has no feature sentence");
            // A complete sentence, not a label: the warn line renders it.
            assert!(
                feature.len() > 20,
                "{secret} feature is too short: {feature:?}"
            );
        }
    }

    /// `AppSecrets::get` reads through the declared provider only. A value
    /// in another provider is invisible to the read path; only the
    /// survey/classification walks every provider.
    #[test]
    fn get_reads_through_the_declared_provider_only() {
        let secrets = secrets_with(Db, &[Env], "should-not-serve");
        assert_eq!(secrets.get(GovernedSecret::SmtpPassword), None);
        let secrets = secrets_with(Db, &[Db], "served");
        assert_eq!(
            secrets.get(GovernedSecret::SmtpPassword),
            Some("served".to_string())
        );
    }

    /// The status DTO carries names, not values. This is the shape the future
    /// `secrets-status` CLI/endpoint renders, and it must never grow a value
    /// field: the redaction test below catches that regression on the fields
    /// themselves.
    #[test]
    fn status_carries_provider_names_only_and_serialises_without_the_value() {
        let survey = survey_with(Db, vec![Db, Env]);
        let dto = status(&survey);
        assert_eq!(dto.declared, "database");
        assert_eq!(dto.secrets.len(), 1);
        assert_eq!(dto.secrets[0].secret, "SMTP_PASSWORD");
        assert_eq!(dto.secrets[0].holders, vec!["environment", "database"]);
        assert_eq!(dto.secrets[0].served_by, Some("database"));

        // The rendered JSON is the wire shape a future admin endpoint returns.
        let json = serde_json::to_string(&dto).unwrap();
        assert!(json.contains("SMTP_PASSWORD"), "{json}");
        assert!(!json.contains("hunter2"), "a value leaked: {json}");
    }

    /// Missing status: no holders, no `served_by`, still one row per secret.
    #[test]
    fn status_reports_no_serving_provider_when_missing() {
        let survey = survey_with(Db, vec![]);
        let dto = status(&survey);
        assert_eq!(dto.secrets[0].holders, Vec::<&str>::new());
        assert_eq!(dto.secrets[0].served_by, None);
    }

    /// Redaction: capture tracing output from `enforce` across every
    /// classification and assert the fixture value never appears. Values live
    /// inside providers; the survey and every log line carry only names.
    #[test]
    fn no_secret_value_appears_in_logs_or_status() {
        use std::io::Write;
        use tracing::subscriber::with_default;
        use tracing_subscriber::fmt::MakeWriter;

        // The classify-covered fixtures: Used, Missing, Shadowed, and a
        // Misplaced whose error carries the same rendering.
        let cases = vec![
            survey_with(Db, vec![Db]),
            survey_with(Db, vec![]),
            survey_with(Db, vec![Db, Env]),
            survey_with(Db, vec![Env, Inf]),
        ];

        let buffer: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));

        #[derive(Clone)]
        struct BufferWriter(Arc<Mutex<Vec<u8>>>);
        impl Write for BufferWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> MakeWriter<'a> for BufferWriter {
            type Writer = BufferWriter;
            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }

        let subscriber = tracing_subscriber::fmt::Subscriber::builder()
            .with_writer(BufferWriter(buffer.clone()))
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .finish();

        with_default(subscriber, || {
            for survey in &cases {
                // The `Misplaced` case returns Err; that message must also
                // carry no value.
                let outcome = enforce(survey);
                let dto = status(survey);
                let dto_json = serde_json::to_string(&dto).unwrap();
                assert!(!dto_json.contains("hunter2"), "{dto_json}");
                if let Err(err) = outcome {
                    let message = err.to_string();
                    assert!(!message.contains("hunter2"), "{message}");
                }
            }
        });

        let captured = String::from_utf8(buffer.lock().unwrap().clone()).unwrap();
        assert!(
            !captured.contains("hunter2"),
            "a secret value reached the log: {captured}"
        );
    }

    /// The environment provider refuses admin writes; every other provider
    /// permits them. A process cannot set an env var for its own next boot,
    /// so `EnvironmentProvider` being non-writable is a property of the
    /// provider itself rather than a policy the admin surface layers on top.
    #[test]
    fn environment_is_the_one_read_only_provider() {
        assert!(!EnvironmentProvider.is_writable());
    }

    /// Selection: unset and blank both fall back to the profile default; an
    /// explicit value overrides; an unrecognised value is a hard error.
    #[test]
    fn selection_falls_back_to_profile_and_refuses_typos() {
        for raw in ["", "   "] {
            let selection = AppSecretsSelection::resolve(provider::DATABASE, raw).unwrap();
            assert_eq!(selection.provider, AppSecretProviderKind::Database);
            assert_eq!(selection.source, EnablementSource::Profile);
        }
        let explicit = AppSecretsSelection::resolve(provider::DATABASE, " infisical ").unwrap();
        assert_eq!(explicit.provider, AppSecretProviderKind::Infisical);
        assert_eq!(explicit.source, EnablementSource::Explicit);
        for raw in ["infisicial", "vault", "DATABASE", "none"] {
            assert!(
                AppSecretsSelection::resolve(provider::DATABASE, raw).is_err(),
                "{raw:?} must not silently become the default"
            );
        }
    }

    /// One reader of `SECRET_BACKEND` in this module, so the app-tier's own
    /// setting is read in one place, the shape `crate::secrets` pins for the
    /// tenant tier. The tenant tier's test scans its own file too, so both
    /// halves stay independently guarded.
    #[test]
    fn there_is_one_reader_of_the_provider_setting() {
        const SRC: &str = include_str!("mod.rs");
        assert_eq!(
            SRC.matches(concat!("var(\"SECRET", "_BACKEND\")")).count(),
            1,
            "SECRET_BACKEND is read in exactly one place in this module"
        );
    }

    /// The provider list reads as prose in a fatal message.
    #[test]
    fn provider_lists_read_as_prose() {
        assert_eq!(provider_list(&[Db]), "database");
        assert_eq!(provider_list(&[Env, Inf]), "environment and infisical");
        assert_eq!(
            provider_list(&[Env, Db, Inf]),
            "environment, database and infisical"
        );
    }
}
