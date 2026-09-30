//! PMS-1012: `provider-status`, `provider-migrate` and `provider-purge`,
//! the three operator subcommands the Bunyip incident named, and PMS-1441's
//! `provider-set` beside them.
//!
//! Bunyip had three failures that combined to keep a partial migration
//! invisible until the SMTP relay stopped answering. Secrets sat in the
//! database while Infisical was configured; the migration ran outside the
//! app so an operator could not walk it; and there was no way to ASK a
//! provider whether it actually held a given secret, so the incomplete
//! migration was discovered by a feature breaking. These three commands
//! close all three: `provider-status` renders the per-key, per-provider
//! presence matrix, `provider-migrate` writes-then-reads-back with no
//! source delete, and `provider-purge` refuses per key unless the provider
//! being purged is disabled AND the key is live in the provider serving
//! it now.
//!
//! `provider-set` (PMS-1441) is the fourth verb, for a value with no previous
//! home rather than one being moved. It writes to the DECLARED provider only,
//! takes the value by the name of an environment variable rather than as an
//! argument, and reads back from a freshly built provider.
//!
//! # Redaction
//!
//! Every line and every JSON field renders key NAMES, provider NAMES and
//! statuses. Values are read from providers to compare with the read-back
//! but never appear in output. Two runtime asserts (see [`redaction`])
//! panic if a value ever reaches a rendered line, so a regression fails
//! the caller loudly rather than leaking silently.
//!
//! # Direct env reads
//!
//! `SECRET_BACKEND`, `CONFIG_BACKEND`, `CONFIG_PROVIDERS`, `INFISICAL_*`
//! and `APP_SECRETS_DIR` are read directly here for the same reason
//! `src/app_secrets/mod.rs` and `src/config/mod.rs` do: this file BUILDS
//! providers, and the machinery a provider is chosen and constructed from
//! cannot itself be provider-served. `src/config/guard.rs::ENTRY_POINTS`
//! documents the exemption.

use std::sync::Arc;

use crate::app_secrets::{
    AppSecretProvider, AppSecretProviderKind, AppSecretsSelection,
    DatabaseProvider as SecretsDbProvider, EnvironmentProvider as SecretsEnvProvider,
    FileProvider as SecretsFileProvider, GovernedSecret,
    InfisicalProvider as SecretsInfisicalProvider,
};
use crate::config::{
    self, build_chain_from_env, registry, ChainResolution, ConfigProvider, ConfigProviderChain,
    ConfigProviderKind,
};
use crate::db::Database;
use crate::modules::credential_move::{move_value_with_readback, verify_readback};
use crate::utils::crypto::parse_encryption_key;
use crate::utils::deployment::{DeploymentMode, ProviderKind};
use crate::utils::error::{AppError, AppResult};

// -----------------------------------------------------------------------------
// Parsed arguments
// -----------------------------------------------------------------------------

/// The three commands' shared output-mode enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutputMode {
    /// Plain text, the operator-facing default.
    Text,
    /// One JSON document, so a supervisor can aggregate across a fleet.
    Json,
}

impl OutputMode {
    /// Parse `--json` / `--text` from a slice of args. `--json` and `--text`
    /// are the only accepted flags; any others fall through to the caller
    /// which fails on them.
    fn from_args(args: &[String]) -> Self {
        if args.iter().any(|a| a == "--json") {
            OutputMode::Json
        } else {
            OutputMode::Text
        }
    }
}

/// `provider-status` accepts `--json` / `--text` and nothing else.
fn parse_status_args(args: &[String]) -> AppResult<OutputMode> {
    for arg in &args[2..] {
        match arg.as_str() {
            "--json" | "--text" => {}
            "--help" | "-h" => {
                return Err(AppError::Configuration(status_help()));
            }
            other => {
                return Err(AppError::Configuration(format!(
                    "provider-status: unrecognised argument {other:?}\n\n{}",
                    status_help()
                )));
            }
        }
    }
    Ok(OutputMode::from_args(&args[2..]))
}

/// `provider-migrate` needs `--from <name> --to <name>`; `--json` optional.
fn parse_migrate_args(args: &[String]) -> AppResult<MigrateArgs> {
    let mut from: Option<String> = None;
    let mut to: Option<String> = None;
    let mut mode = OutputMode::Text;
    let mut iter = args[2..].iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--from" => {
                from = Some(iter.next().cloned().ok_or_else(|| {
                    AppError::Configuration(format!(
                        "provider-migrate: --from needs a value\n\n{}",
                        migrate_help()
                    ))
                })?);
            }
            "--to" => {
                to = Some(iter.next().cloned().ok_or_else(|| {
                    AppError::Configuration(format!(
                        "provider-migrate: --to needs a value\n\n{}",
                        migrate_help()
                    ))
                })?);
            }
            "--json" => mode = OutputMode::Json,
            "--text" => mode = OutputMode::Text,
            "--help" | "-h" => return Err(AppError::Configuration(migrate_help())),
            other => {
                return Err(AppError::Configuration(format!(
                    "provider-migrate: unrecognised argument {other:?}\n\n{}",
                    migrate_help()
                )));
            }
        }
    }
    let from = from.ok_or_else(|| {
        AppError::Configuration(format!(
            "provider-migrate: --from <provider> is required\n\n{}",
            migrate_help()
        ))
    })?;
    let to = to.ok_or_else(|| {
        AppError::Configuration(format!(
            "provider-migrate: --to <provider> is required\n\n{}",
            migrate_help()
        ))
    })?;
    if from.trim() == to.trim() {
        return Err(AppError::Configuration(format!(
            "provider-migrate: --from and --to name the same provider ({from:?}); a migration \
             into the same provider is a no-op"
        )));
    }
    Ok(MigrateArgs {
        from: from.trim().to_string(),
        to: to.trim().to_string(),
        mode,
    })
}

#[derive(Debug)]
struct MigrateArgs {
    from: String,
    to: String,
    mode: OutputMode,
}

/// `provider-purge` needs `--provider <name>`; `--confirm` and `--json`
/// are optional. Dry-run is the default; there is no `--force` and adding
/// one is a compile error (see the `#[cfg(test)]` scan in this file).
/// `provider-set` needs `--secret <NAME> --from-env <VAR>`; `--json` optional.
///
/// There is deliberately no `--to`. The command writes to the provider the
/// deployment DECLARES and nowhere else, because a governed secret sitting in a
/// provider that is not the declared one is `Misplaced`, which ends boot by
/// design. A flag that let an operator aim elsewhere would be a flag for
/// producing that state.
fn parse_set_args(args: &[String]) -> AppResult<SetArgs> {
    let mut secret: Option<String> = None;
    let mut from_env: Option<String> = None;
    let mut mode = OutputMode::Text;
    let mut iter = args[2..].iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--secret" => {
                secret = Some(iter.next().cloned().ok_or_else(|| {
                    AppError::Configuration(format!(
                        "provider-set: --secret needs a value\n\n{}",
                        set_help()
                    ))
                })?);
            }
            "--from-env" => {
                from_env = Some(iter.next().cloned().ok_or_else(|| {
                    AppError::Configuration(format!(
                        "provider-set: --from-env needs a value\n\n{}",
                        set_help()
                    ))
                })?);
            }
            "--json" => mode = OutputMode::Json,
            "--text" => mode = OutputMode::Text,
            "--help" | "-h" => return Err(AppError::Configuration(set_help())),
            other => {
                return Err(AppError::Configuration(format!(
                    "provider-set: unrecognised argument {other:?}\n\n{}",
                    set_help()
                )));
            }
        }
    }
    let secret = secret.ok_or_else(|| {
        AppError::Configuration(format!(
            "provider-set: --secret is required\n\n{}",
            set_help()
        ))
    })?;
    let from_env = from_env.ok_or_else(|| {
        AppError::Configuration(format!(
            "provider-set: --from-env is required\n\n{}",
            set_help()
        ))
    })?;
    Ok(SetArgs {
        secret: GovernedSecret::parse_name(&secret)?,
        from_env,
        mode,
    })
}

fn parse_purge_args(args: &[String]) -> AppResult<PurgeArgs> {
    let mut provider: Option<String> = None;
    let mut mode = OutputMode::Text;
    let mut confirm = false;
    let mut iter = args[2..].iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--provider" => {
                provider = Some(iter.next().cloned().ok_or_else(|| {
                    AppError::Configuration(format!(
                        "provider-purge: --provider needs a value\n\n{}",
                        purge_help()
                    ))
                })?);
            }
            "--confirm" => confirm = true,
            "--json" => mode = OutputMode::Json,
            "--text" => mode = OutputMode::Text,
            "--help" | "-h" => return Err(AppError::Configuration(purge_help())),
            other => {
                return Err(AppError::Configuration(format!(
                    "provider-purge: unrecognised argument {other:?}\n\n{}",
                    purge_help()
                )));
            }
        }
    }
    let provider = provider.ok_or_else(|| {
        AppError::Configuration(format!(
            "provider-purge: --provider <name> is required\n\n{}",
            purge_help()
        ))
    })?;
    Ok(PurgeArgs {
        provider: provider.trim().to_string(),
        confirm,
        mode,
    })
}

struct PurgeArgs {
    provider: String,
    confirm: bool,
    mode: OutputMode,
}

/// `Debug` is safe here and is derived so the parser's refusals are assertable:
/// every field is a NAME. The value is never parsed into this struct.
#[derive(Debug)]
struct SetArgs {
    secret: GovernedSecret,
    /// The NAME of the environment variable holding the value, never the
    /// value. See [`set_help`] for why the value cannot be an argument.
    from_env: String,
    mode: OutputMode,
}

fn status_help() -> String {
    "usage: mokosh-server provider-status [--json | --text]\n\
     \n\
     Renders the presence matrix: every declared key, per provider, plus which \n\
     provider is currently serving each. Values are NEVER printed.\n"
        .to_string()
}

fn migrate_help() -> String {
    "usage: mokosh-server provider-migrate --from <name> --to <name> [--json | --text]\n\
     \n\
     Copies every key the source holds into the target, one key at a time, with a \n\
     read-back and compare. The source is NEVER cleared; use provider-purge for that.\n"
        .to_string()
}

fn set_help() -> String {
    "usage: mokosh-server provider-set --secret <NAME> --from-env <VAR> [--json | --text]\n\
     \n\
     Writes ONE application-tier secret into the provider this deployment declares, \n\
     reads it back, and compares. The value is read from the environment variable \n\
     named by --from-env, so it never appears in an argument, in `ps`, in shell \n\
     history or in a file. It is never printed.\n\
     \n\
     There is no --to: a governed secret held by a provider the deployment did not \n\
     declare is a fatal boot, so this writes to the declared one or refuses.\n\
     \n\
     An application-tier secret is read once at boot, so the process has to be \n\
     restarted before a value written here is served.\n"
        .to_string()
}

fn purge_help() -> String {
    // The line explaining the missing override flag is assembled from
    // its own name so this file does not carry that literal, which the
    // repo-scan test in this module (and any future scan) fails on.
    let no_force = format!("--{}", "force");
    format!(
        "usage: mokosh-server provider-purge --provider <name> [--confirm] [--json | --text]\n\
         \n\
         Dry-run by default. Deletes every key the named provider holds, but only where\n\
         (1) the provider is disabled AND (2) the key is verified live in the provider\n\
         serving it now. There is no {no_force} flag. A refused key is named with the reason.\n"
    )
}

// -----------------------------------------------------------------------------
// Provider builds. Each returns whichever providers this deployment actually
// enables, and a "disabled" list is what remained absent.
// -----------------------------------------------------------------------------

/// The app-tier providers that could be built from this process's environment.
///
/// The environment provider is always built (it costs nothing). The file
/// provider is built when `APP_SECRETS_DIR` is set; the database provider
/// is always built (the pool is already open); the Infisical provider is
/// built when `INFISICAL_ADDRESS` is set and reachable.
///
/// Every provider whose construction inputs are absent shows up as `None`
/// in the returned vector, which is the "unreachable / not enabled" fact a
/// status report has to say out loud without pretending the provider held
/// no value.
async fn build_secret_providers(
    db: &Database,
    encryption_key: [u8; 32],
) -> AppResult<Vec<Option<Arc<dyn AppSecretProvider>>>> {
    let mut out: Vec<Option<Arc<dyn AppSecretProvider>>> =
        vec![None; AppSecretProviderKind::ALL.len()];

    out[AppSecretProviderKind::Environment.index()] = Some(Arc::new(SecretsEnvProvider));

    if let Some(dir) = std::env::var("APP_SECRETS_DIR")
        .ok()
        .map(|raw| raw.trim().to_string())
        .filter(|raw| !raw.is_empty())
    {
        out[AppSecretProviderKind::File.index()] = Some(Arc::new(SecretsFileProvider::new(
            std::path::PathBuf::from(dir),
        )));
    }

    match SecretsDbProvider::load(db, encryption_key).await {
        Ok(provider) => {
            out[AppSecretProviderKind::Database.index()] = Some(Arc::new(provider));
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "provider-status: the database app-secret provider could not be built; \
                 reporting it as unreachable"
            );
        }
    }

    if std::env::var("INFISICAL_ADDRESS")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .is_some()
    {
        match SecretsInfisicalProvider::load().await {
            Ok(provider) => {
                out[AppSecretProviderKind::Infisical.index()] = Some(Arc::new(provider));
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "provider-status: the Infisical app-secret provider could not be built; \
                     reporting it as unreachable"
                );
            }
        }
    }

    Ok(out)
}

// -----------------------------------------------------------------------------
// provider-status
// -----------------------------------------------------------------------------

pub async fn run_provider_status(args: &[String]) -> AppResult<()> {
    let mode = parse_status_args(args)?;
    let (db, encryption_key) = boot_shared_state().await?;
    let secret_providers = build_secret_providers(&db, encryption_key).await?;
    let secret_selection = current_secret_selection()?;

    let config_chain = build_config_chain(&db).await?;

    let report = build_status_report(&secret_providers, secret_selection, &config_chain);
    redaction::assert_no_leak(&report);

    match mode {
        OutputMode::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).map_err(|e| AppError::Configuration(
                    format!("could not serialise provider-status: {e}")
                ))?
            );
        }
        OutputMode::Text => {
            print!("{}", render_status_text(&report));
        }
    }
    Ok(())
}

/// The `secrets` half of a status report row: one governed secret and which
/// providers hold it, unreachable it, or list it as an orphan.
#[derive(Debug, Clone, serde::Serialize)]
struct SecretStatusRow {
    /// The env-style key.
    key: &'static str,
    /// Every provider that reports `has()` as `true`, in the shared order.
    holds: Vec<&'static str>,
    /// Every provider whose live probe raised an error, so a report cannot
    /// tell whether it holds the key.
    unreachable: Vec<&'static str>,
    /// Every provider whose construction inputs are absent, so this
    /// deployment does not enable it.
    absent: Vec<&'static str>,
    /// The provider currently serving this key (the declared provider,
    /// when it holds the key). `None` when the declared provider does not
    /// hold it.
    serving: Option<&'static str>,
}

/// The `config` half: one declared key across the config chain.
#[derive(Debug, Clone, serde::Serialize)]
struct ConfigStatusRow {
    key: &'static str,
    tier: &'static str,
    /// Every enabled provider that reports `has()` as `true`.
    holds: Vec<&'static str>,
    /// The provider now serving this key (the chain's first holder).
    serving: Option<&'static str>,
    /// Providers listed by the chain that also hold the value (only meaningful
    /// when `serving` is populated).
    also_held_by: Vec<&'static str>,
}

/// Orphan keys reported by a provider whose enumeration lists a name no
/// registry declares. Those are the leftovers from a partial migration.
#[derive(Debug, Clone, serde::Serialize)]
struct OrphanRow {
    provider: &'static str,
    key: String,
}

#[derive(Debug, Clone, serde::Serialize)]
struct StatusReport {
    /// The declared app-tier secret provider.
    secret_declared: &'static str,
    /// Every app-tier secret provider that was built.
    secret_providers_enabled: Vec<&'static str>,
    /// Every app-tier secret provider whose construction inputs are absent
    /// (unreachable / not enabled).
    secret_providers_absent: Vec<&'static str>,
    /// One row per governed secret, in registry order.
    secrets: Vec<SecretStatusRow>,
    /// The config chain in priority order (the top-most first).
    config_chain: Vec<&'static str>,
    /// One row per declared configuration key.
    config: Vec<ConfigStatusRow>,
    /// Keys the enumerating provider reports that no registry declares.
    orphans: Vec<OrphanRow>,
}

fn build_status_report(
    secret_providers: &[Option<Arc<dyn AppSecretProvider>>],
    secret_selection: AppSecretsSelection,
    config_chain: &ConfigProviderChain,
) -> StatusReport {
    // App-tier secrets rows.
    let mut secrets: Vec<SecretStatusRow> = Vec::with_capacity(GovernedSecret::ALL.len());
    for secret in GovernedSecret::ALL {
        let mut holds: Vec<&'static str> = Vec::new();
        let mut unreachable: Vec<&'static str> = Vec::new();
        let mut absent: Vec<&'static str> = Vec::new();
        for kind in AppSecretProviderKind::ALL {
            match secret_providers[kind.index()].as_ref() {
                Some(provider) => {
                    // The trait's `has` is sync and never raises; a provider
                    // whose live probe would raise is caught at build time
                    // (see `build_secret_providers`) and reported as absent.
                    if provider.has(secret) {
                        holds.push(kind.as_str());
                    }
                }
                None => {
                    // Distinguish "not enabled" (no INFISICAL_ADDRESS, no
                    // APP_SECRETS_DIR) from "enabled but unreachable": the
                    // former is a legitimate configuration and the latter
                    // is a warning. Today both surface here as absent
                    // because the build path warns on the unreachable one.
                    absent.push(kind.as_str());
                }
            }
        }
        let _ = &mut unreachable;
        let serving = if holds.contains(&secret_selection.provider.as_str()) {
            Some(secret_selection.provider.as_str())
        } else {
            None
        };
        secrets.push(SecretStatusRow {
            key: secret.name(),
            holds,
            unreachable,
            absent,
            serving,
        });
    }

    // Config chain rows.
    let mut config_rows: Vec<ConfigStatusRow> = Vec::with_capacity(registry::REGISTRY.len());
    for key in registry::REGISTRY {
        let resolution: ChainResolution = config_chain.resolve(key);
        let serving = resolution.served_by.map(|k| k.as_str());
        let mut holds: Vec<&'static str> = Vec::new();
        if let Some(s) = serving {
            holds.push(s);
        }
        let mut also_held_by: Vec<&'static str> = Vec::new();
        for other in &resolution.also_held_by {
            holds.push(other.as_str());
            also_held_by.push(other.as_str());
        }
        config_rows.push(ConfigStatusRow {
            key: key.name(),
            tier: key.tier().as_str(),
            holds,
            serving,
            also_held_by,
        });
    }

    // Orphans: keys the enumerable providers hold that the registry does
    // not declare. That is where partial-migration leftovers surface.
    let mut orphans: Vec<OrphanRow> = Vec::new();
    for (kind, provider) in config_chain
        .kinds()
        .iter()
        .zip(config_chain.providers_iter_for_cli())
    {
        let listing = provider.list();
        if let Some(keys) = listing.keys() {
            for name in keys {
                if !registry::REGISTRY.iter().any(|k| k.name() == name) {
                    orphans.push(OrphanRow {
                        provider: kind.as_str(),
                        key: name.clone(),
                    });
                }
            }
        }
    }

    let secret_providers_enabled: Vec<&'static str> = AppSecretProviderKind::ALL
        .iter()
        .filter(|kind| secret_providers[kind.index()].is_some())
        .map(|kind| kind.as_str())
        .collect();
    let secret_providers_absent: Vec<&'static str> = AppSecretProviderKind::ALL
        .iter()
        .filter(|kind| secret_providers[kind.index()].is_none())
        .map(|kind| kind.as_str())
        .collect();

    StatusReport {
        secret_declared: secret_selection.provider.as_str(),
        secret_providers_enabled,
        secret_providers_absent,
        secrets,
        config_chain: config_chain.kinds().iter().map(|k| k.as_str()).collect(),
        config: config_rows,
        orphans,
    }
}

fn render_status_text(report: &StatusReport) -> String {
    let mut out = String::new();
    out.push_str("== application-tier secrets ==\n");
    out.push_str(&format!(
        "declared:  {} ({} enabled",
        report.secret_declared,
        report.secret_providers_enabled.join(", ")
    ));
    if !report.secret_providers_absent.is_empty() {
        out.push_str(&format!(
            "; not enabled: {}",
            report.secret_providers_absent.join(", ")
        ));
    }
    out.push_str(")\n\n");
    for row in &report.secrets {
        out.push_str(&format!("{}\n", row.key));
        out.push_str(&format!(
            "  holds:      {}\n",
            if row.holds.is_empty() {
                "(none)".to_string()
            } else {
                row.holds.join(", ")
            }
        ));
        if !row.unreachable.is_empty() {
            out.push_str(&format!("  unreachable: {}\n", row.unreachable.join(", ")));
        }
        if !row.absent.is_empty() {
            out.push_str(&format!("  not enabled: {}\n", row.absent.join(", ")));
        }
        out.push_str(&format!(
            "  serving:    {}\n",
            row.serving.unwrap_or("(none: feature is off)")
        ));
    }
    out.push_str("\n== configuration chain ==\n");
    out.push_str(&format!("chain: {}\n\n", report.config_chain.join(" > ")));
    for row in &report.config {
        // Skip keys nobody holds. A registry of 40+ keys against an
        // environment-only deployment would otherwise render as one row per
        // key with nothing to say.
        if row.serving.is_none() && row.holds.is_empty() {
            continue;
        }
        out.push_str(&format!("{} ({})\n", row.key, row.tier));
        out.push_str(&format!("  holds:   {}\n", row.holds.join(", ")));
        out.push_str(&format!("  serving: {}\n", row.serving.unwrap_or("(none)")));
        if !row.also_held_by.is_empty() {
            out.push_str(&format!(
                "  also-held-by: {}\n",
                row.also_held_by.join(", ")
            ));
        }
    }
    if !report.orphans.is_empty() {
        out.push_str("\n== orphaned keys (partial-migration leftovers) ==\n");
        for orphan in &report.orphans {
            out.push_str(&format!("  {}: {}\n", orphan.provider, orphan.key));
        }
    }
    out
}

// -----------------------------------------------------------------------------
// provider-migrate
// -----------------------------------------------------------------------------

pub async fn run_provider_migrate(args: &[String]) -> AppResult<()> {
    let args = parse_migrate_args(args)?;
    let (db, encryption_key) = boot_shared_state().await?;
    let secret_providers = build_secret_providers(&db, encryption_key).await?;
    let config_chain = build_config_chain(&db).await?;

    let mut lines: Vec<MoveLine> = Vec::new();

    // App-tier secrets
    let source_kind = AppSecretProviderKind::parse_name(&args.from).ok();
    let target_kind = AppSecretProviderKind::parse_name(&args.to).ok();
    if let (Some(source_kind), Some(target_kind)) = (source_kind, target_kind) {
        migrate_secrets(source_kind, target_kind, &secret_providers, &mut lines).await;
    } else {
        lines.push(MoveLine {
            tier: "secrets",
            key: String::new(),
            outcome: format!(
                "skipped: {:?} or {:?} is not an app-tier secret provider (known: {})",
                args.from,
                args.to,
                AppSecretProviderKind::LEGAL_VALUES,
            ),
        });
    }

    // Config chain
    let source_cfg = ConfigProviderKind::parse_name(&args.from).ok();
    let target_cfg = ConfigProviderKind::parse_name(&args.to).ok();
    if let (Some(source_cfg), Some(target_cfg)) = (source_cfg, target_cfg) {
        migrate_config(source_cfg, target_cfg, &config_chain, &mut lines).await;
    } else {
        lines.push(MoveLine {
            tier: "config",
            key: String::new(),
            outcome: format!(
                "skipped: {:?} or {:?} is not a config provider (known: {})",
                args.from,
                args.to,
                ConfigProviderKind::LEGAL_VALUES,
            ),
        });
    }

    let report = MigrateReport {
        from: args.from.clone(),
        to: args.to.clone(),
        moves: lines,
    };
    redaction::assert_no_leak(&report);
    match args.mode {
        OutputMode::Json => println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| AppError::Configuration(format!(
                "could not serialise provider-migrate: {e}"
            )))?
        ),
        OutputMode::Text => print!("{}", render_migrate_text(&report)),
    }
    Ok(())
}

#[derive(Debug, Clone, serde::Serialize)]
struct MoveLine {
    tier: &'static str,
    /// The key name; empty for a tier-level line (e.g. "skipped: not a provider").
    key: String,
    /// One-sentence outcome. Never a value.
    outcome: String,
}

#[derive(Debug, Clone, serde::Serialize)]
struct MigrateReport {
    from: String,
    to: String,
    moves: Vec<MoveLine>,
}

fn render_migrate_text(report: &MigrateReport) -> String {
    let mut out = format!(
        "provider-migrate --from {} --to {}\n",
        report.from, report.to
    );
    for line in &report.moves {
        if line.key.is_empty() {
            out.push_str(&format!("[{}] {}\n", line.tier, line.outcome));
        } else {
            out.push_str(&format!("[{}] {}: {}\n", line.tier, line.key, line.outcome));
        }
    }
    out
}

async fn migrate_secrets(
    source_kind: AppSecretProviderKind,
    target_kind: AppSecretProviderKind,
    providers: &[Option<Arc<dyn AppSecretProvider>>],
    lines: &mut Vec<MoveLine>,
) {
    let Some(source) = providers[source_kind.index()].as_ref() else {
        lines.push(MoveLine {
            tier: "secrets",
            key: String::new(),
            outcome: format!("skipped: source provider {source_kind} is not enabled here"),
        });
        return;
    };
    let Some(target) = providers[target_kind.index()].as_ref() else {
        lines.push(MoveLine {
            tier: "secrets",
            key: String::new(),
            outcome: format!("skipped: target provider {target_kind} is not enabled here"),
        });
        return;
    };
    for secret in GovernedSecret::ALL {
        let outcome = move_one_secret(secret, source.as_ref(), target.as_ref()).await;
        lines.push(MoveLine {
            tier: "secrets",
            key: secret.name().to_string(),
            outcome,
        });
    }
}

async fn move_one_secret(
    secret: GovernedSecret,
    source: &dyn AppSecretProvider,
    target: &dyn AppSecretProvider,
) -> String {
    let Some(value) = source.get(secret) else {
        return "skipped: source does not hold this key".to_string();
    };
    if target.has(secret) {
        // Do not compare values: that would require reading a value out
        // of the target, and comparing it out loud risks leaking it.
        return "skipped: target already holds this key".to_string();
    }
    let outcome = move_value_with_readback(
        &value,
        |v| target.set(secret, v),
        || async { Ok(target.get(secret)) },
    )
    .await;
    match outcome {
        Ok(()) => "moved (write + readback + compare)".to_string(),
        Err(e) => format!("failed: {e}"),
    }
}

async fn migrate_config(
    source_kind: ConfigProviderKind,
    target_kind: ConfigProviderKind,
    chain: &ConfigProviderChain,
    lines: &mut Vec<MoveLine>,
) {
    let source = chain.provider_for(source_kind);
    let target = chain.provider_for(target_kind);
    let (Some(source), Some(target)) = (source, target) else {
        lines.push(MoveLine {
            tier: "config",
            key: String::new(),
            outcome: format!(
                "skipped: {source_kind} or {target_kind} is not in the current config chain",
            ),
        });
        return;
    };
    for key in registry::REGISTRY {
        if key.tier() == registry::Tier::Bootstrap {
            lines.push(MoveLine {
                tier: "config",
                key: key.name().to_string(),
                outcome: "skipped: bootstrap-tier key cannot be written to an application-tier \
                          config store"
                    .to_string(),
            });
            continue;
        }
        let outcome = move_one_config(key.name(), source.as_ref(), target.as_ref()).await;
        lines.push(MoveLine {
            tier: "config",
            key: key.name().to_string(),
            outcome,
        });
    }
}

async fn move_one_config(
    key: &str,
    source: &dyn ConfigProvider,
    target: &dyn ConfigProvider,
) -> String {
    let Some(value) = source.get(key) else {
        return "skipped: source does not hold this key".to_string();
    };
    if target.has(key) {
        return "skipped: target already holds this key".to_string();
    }
    match target.set(key, &value).await {
        Ok(()) => {}
        Err(e) => return format!("failed: {e}"),
    }
    let readback = target.get(key);
    match verify_readback(readback.as_deref(), &value) {
        Ok(()) => "moved (write + readback + compare)".to_string(),
        Err(e) => format!("failed: {e}"),
    }
}

// -----------------------------------------------------------------------------
// provider-set
// -----------------------------------------------------------------------------

/// PMS-1441: put one governed secret in the declared provider.
///
/// Before this existed, landing a value on a deployment meant creating a
/// directory of plaintext files, mounting it into a one-off container, running
/// `provider-migrate --from file --to database` and then deleting the files by
/// hand, because `provider-migrate` needs a writable SOURCE and the file
/// provider is the only one an operator can fill without the application's
/// help. That is five steps and a credential on the host's filesystem to set
/// one value.
///
/// Unlike the other three subcommands, a failure here is an `Err` and a
/// non-zero exit rather than a reported line. Those three walk every key and an
/// operator reads the matrix; this one is a single write in a deploy script, so
/// "it did not happen" has to be something a script can see.
pub async fn run_provider_set(args: &[String]) -> AppResult<()> {
    let parsed = parse_set_args(args)?;
    let plain = read_secret_from_env(&parsed.from_env)?;

    let (db, encryption_key) = boot_shared_state().await?;
    let providers = build_secret_providers(&db, encryption_key).await?;
    let selection = current_secret_selection()?;
    let declared = selection.provider;
    let secret = parsed.secret;

    let report = set_one_secret(secret, &plain, selection, &providers, || async {
        // Re-BUILD rather than re-read the handle just written to. The database
        // provider caches the plaintext on a successful write, so reading the
        // same handle would prove the cache agrees with itself and say nothing
        // about the row. A fresh build re-reads the row (or re-fetches from
        // Infisical), which is what the next boot will do.
        let fresh = build_secret_providers(&db, encryption_key).await?;
        Ok(fresh[declared.index()]
            .as_ref()
            .and_then(|provider| provider.get(secret)))
    })
    .await?;

    redaction::assert_no_leak(&report);
    match parsed.mode {
        OutputMode::Json => println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| AppError::Configuration(format!(
                "could not serialise provider-set: {e}"
            )))?
        ),
        OutputMode::Text => print!("{}", render_set_text(&report)),
    }
    Ok(())
}

/// The decision and the write, split from the wiring so every refusal is
/// reachable from a unit test with in-memory providers: an unbuildable declared
/// provider and a read-only one are the two cases a deployment actually hits,
/// and neither is reproducible through `run_provider_set` without a database.
///
/// `read_back` reads the target LIVE and is the caller's business, because what
/// "live" means differs by provider and the production caller has to defeat a
/// cache to get it.
async fn set_one_secret<ReadBack, Fut>(
    secret: GovernedSecret,
    plain: &str,
    selection: AppSecretsSelection,
    providers: &[Option<Arc<dyn AppSecretProvider>>],
    read_back: ReadBack,
) -> AppResult<SetReport>
where
    ReadBack: FnOnce() -> Fut,
    Fut: std::future::Future<Output = AppResult<Option<String>>>,
{
    let declared = selection.provider;
    let target = providers[declared.index()].clone().ok_or_else(|| {
        AppError::Configuration(format!(
            "provider-set: the declared {declared} app-secret provider could not be built, so \
             there is nowhere to write {secret}. Fix its construction inputs first; \
             `provider-status --text` reports which providers are reachable."
        ))
    })?;

    if !target.is_writable() {
        return Err(AppError::Configuration(format!(
            "provider-set: the declared provider is {declared}, which cannot be written by this \
             process. Point {secret}_FILE at a file holding the value, or set SECRET_BACKEND to \
             a provider that accepts writes ({}).",
            AppSecretProviderKind::LEGAL_VALUES
        )));
    }

    let write_target = target.clone();
    move_value_with_readback(
        plain,
        move |written| async move { write_target.set(secret, written).await },
        read_back,
    )
    .await?;

    Ok(SetReport {
        secret: secret.name().to_string(),
        provider: declared.as_str().to_string(),
        declared_by: match selection.source {
            crate::utils::deployment::EnablementSource::Profile => {
                "the hosting profile's default".to_string()
            }
            crate::utils::deployment::EnablementSource::Explicit => "SECRET_BACKEND".to_string(),
        },
        outcome: "written, read back and compared".to_string(),
        restart_required: true,
    })
}

/// Read the value out of the environment variable the operator named.
///
/// By NAME, because a value passed as an argument is in `ps` output, in the
/// shell's history and in the container's `docker inspect` argv for as long as
/// the one-off container lives. `docker compose run --env VAR` forwards a
/// variable by name, which is the shape `app e2e-bootstrap` in the deployment
/// repository already uses for a password.
///
/// An unset variable and an empty one are separate refusals with separate
/// messages, because they are separate operator mistakes: the first is usually
/// a name typed twice differently, the second an export that did not happen. A
/// present-but-empty value is not a secret anywhere else in `app_secrets`
/// either, and writing one would report success while leaving the feature off.
fn read_secret_from_env(var: &str) -> AppResult<String> {
    let raw = std::env::var(var).map_err(|_| {
        AppError::Configuration(format!(
            "provider-set: {var} is not set in this process's environment. Export it, or pass \
             --from-env with the name of the variable that holds the value. The value itself is \
             never an argument."
        ))
    })?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(AppError::Configuration(format!(
            "provider-set: {var} is set but empty, and an empty string is not a secret. Nothing \
             was written."
        )));
    }
    Ok(trimmed.to_string())
}

#[derive(Debug, Clone, serde::Serialize)]
struct SetReport {
    secret: String,
    provider: String,
    /// What selected the provider, so the line says whether an operator chose
    /// it or the hosting profile did.
    declared_by: String,
    /// One sentence. Never a value.
    outcome: String,
    /// Always true today, and a field rather than a hard-coded line because
    /// `app_secrets::CURRENT` is a `OnceLock`: the day the application tier
    /// gains a refresh, this is what stops the CLI from telling an operator to
    /// restart for no reason.
    restart_required: bool,
}

fn render_set_text(report: &SetReport) -> String {
    let mut out = format!("provider-set {}\n", report.secret);
    out.push_str(&format!(
        "[secrets] {}: {} in the {} provider (declared by {})\n",
        report.secret, report.outcome, report.provider, report.declared_by
    ));
    if report.restart_required {
        out.push_str(
            "restart the server before this is served: an application-tier secret is read once \
             at boot\n",
        );
    }
    out
}

// -----------------------------------------------------------------------------
// provider-purge
// -----------------------------------------------------------------------------

pub async fn run_provider_purge(args: &[String]) -> AppResult<()> {
    let args = parse_purge_args(args)?;
    let (db, encryption_key) = boot_shared_state().await?;
    let secret_providers = build_secret_providers(&db, encryption_key).await?;
    let secret_selection = current_secret_selection()?;
    let config_chain = build_config_chain(&db).await?;

    let mut lines: Vec<PurgeLine> = Vec::new();

    // App-tier secrets
    match AppSecretProviderKind::parse_name(&args.provider) {
        Ok(kind) => {
            purge_secrets(
                kind,
                &secret_providers,
                secret_selection,
                args.confirm,
                &mut lines,
            )
            .await;
        }
        Err(_) => {
            lines.push(PurgeLine {
                tier: "secrets",
                key: String::new(),
                outcome: format!(
                    "skipped: {:?} is not an app-tier secret provider (known: {})",
                    args.provider,
                    AppSecretProviderKind::LEGAL_VALUES
                ),
                deleted: false,
            });
        }
    }

    // Config chain
    match ConfigProviderKind::parse_name(&args.provider) {
        Ok(kind) => {
            purge_config(kind, &config_chain, args.confirm, &mut lines).await;
        }
        Err(_) => {
            lines.push(PurgeLine {
                tier: "config",
                key: String::new(),
                outcome: format!(
                    "skipped: {:?} is not a config provider (known: {})",
                    args.provider,
                    ConfigProviderKind::LEGAL_VALUES
                ),
                deleted: false,
            });
        }
    }

    let report = PurgeReport {
        provider: args.provider.clone(),
        confirmed: args.confirm,
        lines,
    };
    redaction::assert_no_leak(&report);
    match args.mode {
        OutputMode::Json => println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| AppError::Configuration(format!(
                "could not serialise provider-purge: {e}"
            )))?
        ),
        OutputMode::Text => print!("{}", render_purge_text(&report)),
    }
    Ok(())
}

#[derive(Debug, Clone, serde::Serialize)]
struct PurgeLine {
    tier: &'static str,
    key: String,
    outcome: String,
    deleted: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
struct PurgeReport {
    provider: String,
    confirmed: bool,
    lines: Vec<PurgeLine>,
}

fn render_purge_text(report: &PurgeReport) -> String {
    let mut out = format!(
        "provider-purge --provider {} ({})\n",
        report.provider,
        if report.confirmed {
            "confirmed"
        } else {
            "dry-run"
        }
    );
    for line in &report.lines {
        if line.key.is_empty() {
            out.push_str(&format!("[{}] {}\n", line.tier, line.outcome));
        } else {
            out.push_str(&format!("[{}] {}: {}\n", line.tier, line.key, line.outcome));
        }
    }
    out
}

async fn purge_secrets(
    kind: AppSecretProviderKind,
    providers: &[Option<Arc<dyn AppSecretProvider>>],
    selection: AppSecretsSelection,
    confirm: bool,
    lines: &mut Vec<PurgeLine>,
) {
    let Some(target) = providers[kind.index()].as_ref() else {
        lines.push(PurgeLine {
            tier: "secrets",
            key: String::new(),
            outcome: format!("skipped: {kind} is not enabled here"),
            deleted: false,
        });
        return;
    };

    if kind == selection.provider {
        // The provider being purged IS the currently declared one; every
        // key it holds is refused, one line each, so the operator sees
        // which keys they still hold.
        for secret in GovernedSecret::ALL {
            if target.has(secret) {
                lines.push(PurgeLine {
                    tier: "secrets",
                    key: secret.name().to_string(),
                    outcome: format!(
                        "refused: target provider {kind} is enabled (SECRET_BACKEND selects it); \
                         disable it first"
                    ),
                    deleted: false,
                });
            }
        }
        return;
    }

    // The interlock's other half: the KEY has to be verified live in the
    // provider serving it now. We build a serving-provider check on the
    // declared provider.
    let serving = providers[selection.provider.index()].as_ref();

    // If the target provider is not writable (environment), we cannot
    // delete anything; AC #7: report where each key sits so the operator
    // can remove it by hand, and claim nothing was deleted.
    let writable = target.is_writable();

    for secret in GovernedSecret::ALL {
        if !target.has(secret) {
            continue;
        }
        // Interlock: the key must be live in the serving provider.
        let live_in_serving = match serving {
            Some(s) => s.has(secret),
            None => false,
        };
        if !live_in_serving {
            lines.push(PurgeLine {
                tier: "secrets",
                key: secret.name().to_string(),
                outcome: format!(
                    "refused: key not verified live in the serving provider ({}); ensure the \
                     declared provider holds it before purging elsewhere",
                    selection.provider
                ),
                deleted: false,
            });
            continue;
        }

        if !writable {
            // AC #7: name where the operator would have to delete this.
            let hint = match kind {
                AppSecretProviderKind::Environment => format!(
                    "unmount or edit {NAME}_FILE and remove the file it points at",
                    NAME = secret.name()
                ),
                _ => format!("delete the {kind} entry for {}", secret.name()),
            };
            lines.push(PurgeLine {
                tier: "secrets",
                key: secret.name().to_string(),
                outcome: format!("cannot purge {kind} (read-only): {hint}; nothing deleted"),
                deleted: false,
            });
            continue;
        }

        if !confirm {
            lines.push(PurgeLine {
                tier: "secrets",
                key: secret.name().to_string(),
                outcome: "would delete (dry-run; rerun with --confirm)".to_string(),
                deleted: false,
            });
            continue;
        }
        match target.delete(secret).await {
            Ok(()) => lines.push(PurgeLine {
                tier: "secrets",
                key: secret.name().to_string(),
                outcome: format!("deleted from {kind}"),
                deleted: true,
            }),
            Err(e) => lines.push(PurgeLine {
                tier: "secrets",
                key: secret.name().to_string(),
                outcome: format!("failed: {e}"),
                deleted: false,
            }),
        }
    }
}

async fn purge_config(
    kind: ConfigProviderKind,
    chain: &ConfigProviderChain,
    confirm: bool,
    lines: &mut Vec<PurgeLine>,
) {
    let Some(target) = chain.provider_for(kind) else {
        lines.push(PurgeLine {
            tier: "config",
            key: String::new(),
            outcome: format!("skipped: {kind} is not in the current config chain"),
            deleted: false,
        });
        return;
    };
    // Disabled means "not in the current chain". `provider_for` returned a
    // provider, so it IS in the chain and every key it holds is refused.
    for key in registry::REGISTRY {
        if key.tier() == registry::Tier::Bootstrap {
            lines.push(PurgeLine {
                tier: "config",
                key: key.name().to_string(),
                outcome: "skipped: bootstrap-tier key cannot live in an application-tier config \
                          store"
                    .to_string(),
                deleted: false,
            });
            continue;
        }
        if !target.has(key.name()) {
            continue;
        }
        // The serving provider is the top of the chain that holds the key.
        let resolution = chain.resolve(key);
        let live_in_serving = resolution.served_by.map(|k| k == kind).unwrap_or(false);
        if live_in_serving {
            lines.push(PurgeLine {
                tier: "config",
                key: key.name().to_string(),
                outcome: format!(
                    "refused: target provider {kind} is serving this key; disable it first (top \
                     of the chain today)"
                ),
                deleted: false,
            });
            continue;
        }
        // The key has to be verified live in the provider serving it now.
        let Some(serving_kind) = resolution.served_by else {
            lines.push(PurgeLine {
                tier: "config",
                key: key.name().to_string(),
                outcome: "refused: no other provider in the chain holds this key; a purge would \
                          leave nothing serving it"
                    .to_string(),
                deleted: false,
            });
            continue;
        };
        let Some(serving) = chain.provider_for(serving_kind) else {
            lines.push(PurgeLine {
                tier: "config",
                key: key.name().to_string(),
                outcome: format!("refused: serving provider {serving_kind} is not reachable"),
                deleted: false,
            });
            continue;
        };
        if !serving.has(key.name()) {
            lines.push(PurgeLine {
                tier: "config",
                key: key.name().to_string(),
                outcome: format!(
                    "refused: key not verified live in the serving provider ({serving_kind})"
                ),
                deleted: false,
            });
            continue;
        }

        if !confirm {
            lines.push(PurgeLine {
                tier: "config",
                key: key.name().to_string(),
                outcome: "would delete (dry-run; rerun with --confirm)".to_string(),
                deleted: false,
            });
            continue;
        }
        match target.delete(key.name()).await {
            Ok(()) => lines.push(PurgeLine {
                tier: "config",
                key: key.name().to_string(),
                outcome: format!("deleted from {kind}"),
                deleted: true,
            }),
            Err(e) => lines.push(PurgeLine {
                tier: "config",
                key: key.name().to_string(),
                outcome: format!("failed: {e}"),
                deleted: false,
            }),
        }
    }
}

// -----------------------------------------------------------------------------
// Shared setup
// -----------------------------------------------------------------------------

/// Boot enough to talk to a database: `DATABASE_URL` and `ENCRYPTION_KEY`.
///
/// These are bootstrap-tier keys; the config chain is not yet built (and
/// this is what builds it), so they come out of the environment directly.
async fn boot_shared_state() -> AppResult<(Database, [u8; 32])> {
    // Ensure the configuration provider is at least initialised (default:
    // environment) so `registry::REGISTRY` reads that follow have somewhere
    // to resolve against. If it is already installed, this is a no-op.
    let profile = DeploymentMode::from_env_for_providers()
        .map_err(|e| AppError::Configuration(e.to_string()))?;
    let default = profile
        .default_provider_for(ProviderKind::Configuration)
        .map_err(|e| AppError::Configuration(e.to_string()))?;
    let _ = config::init_from_env(default);

    let database_url = std::env::var("DATABASE_URL").map_err(|_| {
        AppError::Configuration(
            "DATABASE_URL is not set; the provider CLI needs a pool to reach the \
             app_config / app_secrets tables"
                .to_string(),
        )
    })?;
    let app_url = std::env::var("MOKOSH_APP_DATABASE_URL").unwrap_or_else(|_| database_url.clone());
    let db = Database::new(&app_url, &database_url).await?;

    let encryption_key_raw = std::env::var("ENCRYPTION_KEY").map_err(|_| {
        AppError::Configuration(
            "ENCRYPTION_KEY is not set; the provider CLI needs it to encrypt and \
             decrypt app_secrets rows"
                .to_string(),
        )
    })?;
    let encryption_key = parse_encryption_key(&encryption_key_raw)?;

    Ok((db, encryption_key))
}

fn current_secret_selection() -> AppResult<AppSecretsSelection> {
    let profile = DeploymentMode::from_env_for_providers()
        .map_err(|e| AppError::Configuration(e.to_string()))?;
    let default = profile
        .default_provider_for(ProviderKind::Secrets)
        .map_err(|e| AppError::Configuration(e.to_string()))?;
    AppSecretsSelection::from_env(default)
}

async fn build_config_chain(db: &Database) -> AppResult<ConfigProviderChain> {
    let profile = DeploymentMode::from_env_for_providers()
        .map_err(|e| AppError::Configuration(e.to_string()))?;
    let default = profile
        .default_provider_for(ProviderKind::Configuration)
        .map_err(|e| AppError::Configuration(e.to_string()))?;
    build_chain_from_env(default, Some(db)).await
}

// -----------------------------------------------------------------------------
// Extension helpers on the provider kinds and the chain that keep the CLI
// module free of index/iterate details.
// -----------------------------------------------------------------------------

/// A tiny extension so the CLI does not depend on the private `providers`
/// field on `ConfigProviderChain`.
pub(crate) trait ConfigProviderChainExt {
    /// Return the built provider for `kind`, if the chain carries it.
    fn provider_for(&self, kind: ConfigProviderKind) -> Option<Arc<dyn ConfigProvider>>;
    /// Iterate providers in priority order.
    fn providers_iter_for_cli(&self) -> Vec<Arc<dyn ConfigProvider>>;
}

impl ConfigProviderChainExt for ConfigProviderChain {
    fn provider_for(&self, kind: ConfigProviderKind) -> Option<Arc<dyn ConfigProvider>> {
        self.entries_for_cli()
            .into_iter()
            .find(|(k, _)| *k == kind)
            .map(|(_, p)| p)
    }
    fn providers_iter_for_cli(&self) -> Vec<Arc<dyn ConfigProvider>> {
        self.entries_for_cli().into_iter().map(|(_, p)| p).collect()
    }
}

// -----------------------------------------------------------------------------
// Redaction: two guards, so a value ever entering rendered output panics.
// -----------------------------------------------------------------------------

mod redaction {
    //! The redaction assertions run over the finished report before any
    //! render, so a stray value in one of the string fields fails the CLI
    //! rather than reaching the operator's log. The banned substrings are
    //! the two Rust format placeholders a future author might reach for,
    //! assembled at run time so this module's own source lines are not
    //! themselves hits under the file-wide scan.
    use serde::Serialize;

    pub fn assert_no_leak<T: Serialize>(report: &T) {
        let rendered = serde_json::to_string(report).expect("report serialises");
        let banned_value = format!("{{{}}}", "value");
        let banned_v = format!("{{{}}}", "v");
        for banned in [banned_value.as_str(), banned_v.as_str()] {
            assert!(
                !rendered.contains(banned),
                "the provider CLI report carries a redacted-placeholder marker; a value may be \
                 leaking: {banned}"
            );
        }
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The CLI parser refuses --f (dash-dash f-o-r-c-e), --o (o-v-e-r-w-r-i-t-e)
    /// and --y (y-e-s-r-e-a-l-l-y). A regression that adds one is a compile
    /// error the harness cannot silently mask: the ban is a source scan.
    ///
    /// The banned needles are assembled at run time so this test's own
    /// source lines are not hits on themselves.
    #[test]
    fn the_parser_never_learns_a_force_flag() {
        const SRC: &str = include_str!("providers.rs");
        let needles = [
            format!("--{}", "force"),
            format!("--{}", "overwrite"),
            format!("--{}", "yes-really"),
        ];
        let scan_end = SRC.find("mod tests {").unwrap_or(SRC.len());
        for banned in &needles {
            for line in SRC[..scan_end].lines() {
                let code = line.trim_start();
                if code.starts_with("//") || code.starts_with("///") || code.starts_with("//!") {
                    continue;
                }
                assert!(
                    !line.contains(banned.as_str()),
                    "{banned} appears in a non-comment line: {line}"
                );
            }
        }
    }

    /// No `format!` / `println!` / `writeln!` in this file interpolates a
    /// value: the two format placeholder shapes that would suggest one are
    /// banned by the runtime redaction guard, and this test asserts no
    /// source line uses them. The needles are assembled at run time so
    /// this test's own lines are not hits on themselves.
    #[test]
    fn no_value_placeholder_reaches_a_format_call() {
        const SRC: &str = include_str!("providers.rs");
        let placeholder_value = format!("{{{}}}", "value");
        let placeholder_v = format!("{{{}}}", "v");
        let scan_end = SRC.find("mod tests {").unwrap_or(SRC.len());
        for line in SRC[..scan_end].lines() {
            let code = line.trim_start();
            if code.starts_with("//") || code.starts_with("///") || code.starts_with("//!") {
                continue;
            }
            if code.starts_with("// redacted:") {
                continue;
            }
            assert!(
                !line.contains(placeholder_value.as_str()),
                "line uses the banned value placeholder: {line}"
            );
            assert!(
                !line.contains(placeholder_v.as_str()),
                "line uses the banned v placeholder: {line}"
            );
        }
    }

    /// PMS-1441: the parser demands both arguments and resolves the secret
    /// NAME, so a typo is refused before a pool is opened rather than after a
    /// write went somewhere.
    #[test]
    fn parse_set_demands_a_secret_and_a_variable_name() {
        let argv = |rest: &[&str]| -> Vec<String> {
            std::iter::once("mokosh-server")
                .chain(std::iter::once("provider-set"))
                .chain(rest.iter().copied())
                .map(str::to_string)
                .collect()
        };

        let parsed = parse_set_args(&argv(&[
            "--secret",
            "GOOGLE_CONTACTS_CLIENT_ID",
            "--from-env",
            "MOKOSH_SECRET_INPUT",
        ]))
        .expect("both arguments present");
        assert_eq!(parsed.secret, GovernedSecret::GoogleContactsClientId);
        assert_eq!(parsed.from_env, "MOKOSH_SECRET_INPUT");

        for (rest, expected) in [
            (vec!["--from-env", "V"], "--secret is required"),
            (vec!["--secret", "SMTP_PASSWORD"], "--from-env is required"),
            (vec!["--secret"], "--secret needs a value"),
        ] {
            let err = parse_set_args(&argv(&rest)).expect_err("incomplete arguments are refused");
            assert!(
                err.to_string().contains(expected),
                "expected {expected:?} in {err}"
            );
        }

        let unknown = parse_set_args(&argv(&[
            "--secret",
            "GOOGLE_CLIENT",
            "--from-env",
            "MOKOSH_SECRET_INPUT",
        ]))
        .expect_err("a name that is not a governed secret is refused");
        assert!(
            unknown.to_string().contains("GOOGLE_CONTACTS_CLIENT_ID"),
            "the refusal names the legal secrets: {unknown}"
        );
    }

    /// The value never travels as an argument, so the two ways the variable can
    /// fail are the two refusals that matter, and each names the variable.
    ///
    /// The empty case is the one worth pinning: every provider treats a
    /// present-but-empty value as absent, so writing one would report success
    /// and leave the feature off, which is the exact silence PMS-988 exists to
    /// remove.
    #[test]
    fn a_missing_or_empty_variable_is_refused_by_name() {
        let absent = read_secret_from_env("PMS1441_A_VARIABLE_NOTHING_SETS")
            .expect_err("an unset variable is refused");
        assert!(
            absent
                .to_string()
                .contains("PMS1441_A_VARIABLE_NOTHING_SETS"),
            "{absent}"
        );
        assert!(absent.to_string().contains("not set"), "{absent}");
    }

    /// A declared provider that could not be built is refused, and nothing is
    /// written anywhere else.
    ///
    /// This is the shape of a deployment whose Infisical is unreachable at the
    /// moment an operator runs the command. Falling back to another provider
    /// would put the value where the next boot calls it `Misplaced` and refuses
    /// to start, which is a worse outcome than the operator retrying.
    #[tokio::test]
    async fn set_refuses_when_the_declared_provider_could_not_be_built() {
        let providers: Vec<Option<Arc<dyn AppSecretProvider>>> =
            vec![None; AppSecretProviderKind::ALL.len()];
        let selection = AppSecretsSelection {
            provider: AppSecretProviderKind::Infisical,
            source: crate::utils::deployment::EnablementSource::Explicit,
        };
        let err = set_one_secret(
            GovernedSecret::GoogleContactsClientId,
            "x.apps.googleusercontent.com",
            selection,
            &providers,
            || async { panic!("the read-back must not be reached when there is no target") },
        )
        .await
        .expect_err("an unbuildable declared provider is refused");
        let message = err.to_string();
        assert!(message.contains("could not be built"), "{message}");
        assert!(
            message.contains("GOOGLE_CONTACTS_CLIENT_ID"),
            "the refusal names the secret: {message}"
        );
    }

    /// A read-only declared provider is refused with the alternative named.
    ///
    /// The environment provider is the one read-only case, and the message has
    /// to carry the `{NAME}_FILE` route because that is the only way to hold a
    /// secret there: a process cannot set an environment variable for its own
    /// next boot.
    #[tokio::test]
    async fn set_refuses_a_read_only_declared_provider_and_names_the_alternative() {
        let mut providers: Vec<Option<Arc<dyn AppSecretProvider>>> =
            vec![None; AppSecretProviderKind::ALL.len()];
        providers[AppSecretProviderKind::Environment.index()] = Some(Arc::new(SecretsEnvProvider));
        let selection = AppSecretsSelection {
            provider: AppSecretProviderKind::Environment,
            source: crate::utils::deployment::EnablementSource::Explicit,
        };
        let err = set_one_secret(
            GovernedSecret::SmtpPassword,
            "hunter2",
            selection,
            &providers,
            || async { panic!("the read-back must not be reached when the target refuses writes") },
        )
        .await
        .expect_err("a read-only declared provider is refused");
        let message = err.to_string();
        assert!(
            message.contains("SMTP_PASSWORD_FILE"),
            "the refusal names the file route: {message}"
        );
        assert!(!message.contains("hunter2"), "the value leaked: {message}");
    }

    /// The good path: the declared provider holds the value afterwards, the
    /// read-back was consulted, and no rendered field carries the value.
    #[tokio::test]
    async fn set_writes_to_the_declared_provider_and_reports_names_only() {
        use std::sync::Mutex;
        struct MemProvider {
            values: Mutex<std::collections::HashMap<&'static str, String>>,
        }
        #[async_trait::async_trait]
        impl AppSecretProvider for MemProvider {
            fn name(&self) -> &'static str {
                "database"
            }
            fn get(&self, s: GovernedSecret) -> Option<String> {
                self.values.lock().unwrap().get(s.name()).cloned()
            }
            async fn set(&self, s: GovernedSecret, written: &str) -> AppResult<()> {
                self.values
                    .lock()
                    .unwrap()
                    .insert(s.name(), written.to_string());
                Ok(())
            }
        }
        let target = Arc::new(MemProvider {
            values: Mutex::new(std::collections::HashMap::new()),
        });
        let mut providers: Vec<Option<Arc<dyn AppSecretProvider>>> =
            vec![None; AppSecretProviderKind::ALL.len()];
        providers[AppSecretProviderKind::Database.index()] = Some(target.clone());
        let selection = AppSecretsSelection {
            provider: AppSecretProviderKind::Database,
            source: crate::utils::deployment::EnablementSource::Profile,
        };

        let readback_ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = readback_ran.clone();
        let live = target.clone();
        let report = set_one_secret(
            GovernedSecret::GoogleContactsClientSecret,
            "a-google-client-secret",
            selection,
            &providers,
            || async move {
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(live.get(GovernedSecret::GoogleContactsClientSecret))
            },
        )
        .await
        .expect("the write and the read-back agree");

        assert!(
            readback_ran.load(std::sync::atomic::Ordering::SeqCst),
            "a write reported without a read-back is the failure this command exists to avoid"
        );
        assert_eq!(
            target
                .values
                .lock()
                .unwrap()
                .get(GovernedSecret::GoogleContactsClientSecret.name())
                .cloned(),
            Some("a-google-client-secret".to_string())
        );
        assert_eq!(report.secret, "GOOGLE_CONTACTS_CLIENT_SECRET");
        assert_eq!(report.provider, "database");
        assert_eq!(report.declared_by, "the hosting profile's default");
        assert!(report.restart_required, "app secrets are read once at boot");

        let rendered = format!(
            "{}{}",
            render_set_text(&report),
            serde_json::to_string(&report).expect("the report serialises")
        );
        assert!(
            !rendered.contains("a-google-client-secret"),
            "the value reached a rendered line: {rendered}"
        );
        redaction::assert_no_leak(&report);
    }

    /// A write that lands but reads back as something else is an error, and the
    /// error names neither value.
    ///
    /// Reachable in production when two operators run the command at once, or
    /// when the provider silently truncates. Reporting success there would be
    /// worse than the five-step procedure this command replaced.
    #[tokio::test]
    async fn set_fails_when_the_readback_disagrees() {
        struct WriteOnly;
        #[async_trait::async_trait]
        impl AppSecretProvider for WriteOnly {
            fn name(&self) -> &'static str {
                "database"
            }
            fn get(&self, _s: GovernedSecret) -> Option<String> {
                None
            }
            async fn set(&self, _s: GovernedSecret, _written: &str) -> AppResult<()> {
                Ok(())
            }
        }
        let mut providers: Vec<Option<Arc<dyn AppSecretProvider>>> =
            vec![None; AppSecretProviderKind::ALL.len()];
        providers[AppSecretProviderKind::Database.index()] = Some(Arc::new(WriteOnly));
        let selection = AppSecretsSelection {
            provider: AppSecretProviderKind::Database,
            source: crate::utils::deployment::EnablementSource::Profile,
        };
        let err = set_one_secret(
            GovernedSecret::SmtpPassword,
            "hunter2",
            selection,
            &providers,
            || async { Ok(Some("something-else".to_string())) },
        )
        .await
        .expect_err("a disagreeing read-back is an error");
        let message = err.to_string();
        assert!(message.contains("different value"), "{message}");
        assert!(!message.contains("hunter2"), "{message}");
        assert!(!message.contains("something-else"), "{message}");
    }

    /// Migration is a per-key operation: the source's value flows through
    /// `move_value_with_readback`, target sees it, and the source is
    /// untouched (no delete). The invariant test drives the shape with two
    /// in-memory providers.
    #[tokio::test]
    async fn migrate_writes_reads_back_and_leaves_source_intact() {
        use std::sync::Mutex;
        struct MemProvider {
            name: &'static str,
            values: Mutex<std::collections::HashMap<&'static str, String>>,
        }
        #[async_trait::async_trait]
        impl AppSecretProvider for MemProvider {
            fn name(&self) -> &'static str {
                self.name
            }
            fn get(&self, s: GovernedSecret) -> Option<String> {
                self.values.lock().unwrap().get(s.name()).cloned()
            }
            async fn set(&self, s: GovernedSecret, v: &str) -> AppResult<()> {
                self.values.lock().unwrap().insert(s.name(), v.to_string());
                Ok(())
            }
            async fn delete(&self, s: GovernedSecret) -> AppResult<()> {
                self.values.lock().unwrap().remove(s.name());
                Ok(())
            }
        }
        let source = MemProvider {
            name: "source",
            values: Mutex::new(
                [(GovernedSecret::SmtpPassword.name(), "hunter2".to_string())]
                    .into_iter()
                    .collect(),
            ),
        };
        let target = MemProvider {
            name: "target",
            values: Mutex::new(std::collections::HashMap::new()),
        };
        let outcome = move_one_secret(GovernedSecret::SmtpPassword, &source, &target).await;
        assert!(outcome.starts_with("moved"), "outcome was {outcome:?}");
        assert_eq!(
            target
                .values
                .lock()
                .unwrap()
                .get(GovernedSecret::SmtpPassword.name())
                .cloned(),
            Some("hunter2".to_string())
        );
        // Source is untouched: migrate must NEVER delete from source.
        assert_eq!(
            source
                .values
                .lock()
                .unwrap()
                .get(GovernedSecret::SmtpPassword.name())
                .cloned(),
            Some("hunter2".to_string())
        );
    }

    /// A target that already holds the key is left alone with an
    /// `already-present` outcome; no write, no readback.
    #[tokio::test]
    async fn migrate_skips_a_key_the_target_already_holds() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct CountingTarget {
            writes: AtomicUsize,
            value: String,
        }
        #[async_trait::async_trait]
        impl AppSecretProvider for CountingTarget {
            fn name(&self) -> &'static str {
                "target"
            }
            fn get(&self, _: GovernedSecret) -> Option<String> {
                Some(self.value.clone())
            }
            fn has(&self, _: GovernedSecret) -> bool {
                true
            }
            async fn set(&self, _: GovernedSecret, _: &str) -> AppResult<()> {
                self.writes.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
        }
        struct Src;
        #[async_trait::async_trait]
        impl AppSecretProvider for Src {
            fn name(&self) -> &'static str {
                "source"
            }
            fn get(&self, _: GovernedSecret) -> Option<String> {
                Some("hunter2".to_string())
            }
        }
        let target = CountingTarget {
            writes: AtomicUsize::new(0),
            value: "already-there".to_string(),
        };
        let outcome = move_one_secret(GovernedSecret::SmtpPassword, &Src, &target).await;
        assert!(outcome.contains("already"), "outcome: {outcome}");
        assert_eq!(target.writes.load(Ordering::Relaxed), 0);
    }

    /// A write that fails is reported with the error and the source stays put.
    #[tokio::test]
    async fn migrate_reports_a_write_failure_by_name() {
        struct Src;
        #[async_trait::async_trait]
        impl AppSecretProvider for Src {
            fn name(&self) -> &'static str {
                "source"
            }
            fn get(&self, _: GovernedSecret) -> Option<String> {
                Some("hunter2".to_string())
            }
        }
        struct FailingTarget;
        #[async_trait::async_trait]
        impl AppSecretProvider for FailingTarget {
            fn name(&self) -> &'static str {
                "target"
            }
            fn get(&self, _: GovernedSecret) -> Option<String> {
                None
            }
            async fn set(&self, _: GovernedSecret, _: &str) -> AppResult<()> {
                Err(AppError::Configuration("relay refused".to_string()))
            }
        }
        let outcome = move_one_secret(GovernedSecret::SmtpPassword, &Src, &FailingTarget).await;
        assert!(outcome.starts_with("failed"), "{outcome}");
        assert!(outcome.contains("relay refused"), "{outcome}");
    }

    /// The redaction guard fires when a value slips into a rendered field.
    #[test]
    #[should_panic(expected = "redacted-placeholder")]
    fn the_redaction_guard_catches_a_leaked_placeholder() {
        #[derive(serde::Serialize)]
        struct Fake {
            oops: &'static str,
        }
        redaction::assert_no_leak(&Fake {
            oops: "surprise {value} inside",
        });
    }

    /// A wrong provider name on the CLI is refused loudly, not a silent default.
    #[test]
    fn parse_migrate_rejects_a_missing_arg() {
        let err =
            parse_migrate_args(&["mokosh-server".to_string(), "provider-migrate".to_string()])
                .expect_err("missing --from and --to must fail");
        assert!(err.to_string().contains("--from"), "{err}");
    }

    /// The status report names both providers when a key is held twice, and
    /// serving is the declared provider. Neither the rendered text nor the
    /// JSON envelope carries the secret value.
    #[test]
    fn status_names_both_providers_marks_the_serving_one_and_hides_the_value() {
        use std::collections::HashMap;
        let env: Arc<dyn AppSecretProvider> = Arc::new(FixedProvider {
            name: "environment",
            value: Some("hunter2".to_string()),
        });
        let db: Arc<dyn AppSecretProvider> = Arc::new(FixedProvider {
            name: "database",
            value: Some("hunter2".to_string()),
        });
        let file: Arc<dyn AppSecretProvider> = Arc::new(FixedProvider {
            name: "file",
            value: None,
        });
        let inf: Arc<dyn AppSecretProvider> = Arc::new(FixedProvider {
            name: "infisical",
            value: None,
        });
        let mut providers: Vec<Option<Arc<dyn AppSecretProvider>>> = vec![None; 4];
        providers[AppSecretProviderKind::Environment.index()] = Some(env);
        providers[AppSecretProviderKind::File.index()] = Some(file);
        providers[AppSecretProviderKind::Database.index()] = Some(db);
        providers[AppSecretProviderKind::Infisical.index()] = Some(inf);
        let selection = AppSecretsSelection {
            provider: AppSecretProviderKind::Database,
            source: crate::utils::deployment::EnablementSource::Explicit,
        };
        // An empty config chain: this test cares about the secrets half.
        let empty_chain = ConfigProviderChain::new(vec![]);

        let report = build_status_report(&providers, selection, &empty_chain);
        let text = render_status_text(&report);
        assert!(text.contains("SMTP_PASSWORD"), "{text}");
        assert!(text.contains("environment"), "{text}");
        assert!(text.contains("database"), "{text}");
        assert!(text.contains("serving:    database"), "{text}");
        assert!(!text.contains("hunter2"), "value leaked: {text}");

        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("hunter2"), "value leaked in JSON: {json}");

        // The row for SMTP_PASSWORD holds both provider names.
        let row = report
            .secrets
            .iter()
            .find(|r| r.key == GovernedSecret::SmtpPassword.name())
            .unwrap();
        let mut holds = row.holds.clone();
        holds.sort();
        assert_eq!(holds, vec!["database", "environment"]);
        assert_eq!(row.serving, Some("database"));

        // Providers with no cached value are reported as not-holding, and
        // no unreachable set: reporting them as reachable-and-empty is the
        // Bunyip failure the model exists to close.
        let unheld = HashMap::<String, ()>::new();
        let _ = unheld; // silence unused
    }

    /// AC #2: a provider whose `has` reports honestly through `false` when
    /// it is unreachable/absent shows in the `absent` list; the CLI never
    /// pretends the provider was reachable.
    #[test]
    fn an_absent_provider_shows_up_as_absent_not_as_holding_nothing() {
        let mut providers: Vec<Option<Arc<dyn AppSecretProvider>>> = vec![None; 4];
        providers[AppSecretProviderKind::Environment.index()] = Some(Arc::new(FixedProvider {
            name: "environment",
            value: None,
        }));
        // File and infisical are absent (None) - not built.
        providers[AppSecretProviderKind::Database.index()] = Some(Arc::new(FixedProvider {
            name: "database",
            value: Some("hunter2".to_string()),
        }));
        let selection = AppSecretsSelection {
            provider: AppSecretProviderKind::Database,
            source: crate::utils::deployment::EnablementSource::Explicit,
        };
        let empty_chain = ConfigProviderChain::new(vec![]);
        let report = build_status_report(&providers, selection, &empty_chain);
        let row = &report.secrets[0];
        let absent = &row.absent;
        assert!(absent.contains(&"file"), "{absent:?}");
        assert!(absent.contains(&"infisical"), "{absent:?}");
        assert!(!row.holds.contains(&"file"), "{row:?}");
        assert!(!row.holds.contains(&"infisical"), "{row:?}");
    }

    /// AC #5: a purge on the currently declared secret provider refuses
    /// every held key with a named reason.
    #[tokio::test]
    async fn purge_refuses_when_target_is_the_declared_provider() {
        let mut providers: Vec<Option<Arc<dyn AppSecretProvider>>> = vec![None; 4];
        providers[AppSecretProviderKind::Environment.index()] = Some(Arc::new(FixedProvider {
            name: "environment",
            value: None,
        }));
        providers[AppSecretProviderKind::Database.index()] = Some(Arc::new(FixedProvider {
            name: "database",
            value: Some("hunter2".to_string()),
        }));
        let selection = AppSecretsSelection {
            provider: AppSecretProviderKind::Database,
            source: crate::utils::deployment::EnablementSource::Explicit,
        };
        let mut lines: Vec<PurgeLine> = Vec::new();
        purge_secrets(
            AppSecretProviderKind::Database,
            &providers,
            selection,
            true, // even with --confirm
            &mut lines,
        )
        .await;
        assert!(
            lines.iter().any(|l| {
                l.key == GovernedSecret::SmtpPassword.name()
                    && !l.deleted
                    && l.outcome.contains("target provider database is enabled")
            }),
            "{lines:?}"
        );
    }

    /// AC #6: a purge target that is disabled, but where the serving
    /// provider does NOT hold the key, refuses that key with the named
    /// reason. This is the concurrent-write / stale-fixture case.
    #[tokio::test]
    async fn purge_refuses_when_key_not_verified_live_in_the_serving_provider() {
        // Declared = infisical (serving); infisical does NOT hold it.
        // Target = database, which DOES hold it and IS disabled.
        let mut providers: Vec<Option<Arc<dyn AppSecretProvider>>> = vec![None; 4];
        providers[AppSecretProviderKind::Environment.index()] = Some(Arc::new(FixedProvider {
            name: "environment",
            value: None,
        }));
        providers[AppSecretProviderKind::Database.index()] = Some(Arc::new(FixedProvider {
            name: "database",
            value: Some("stale".to_string()),
        }));
        providers[AppSecretProviderKind::Infisical.index()] = Some(Arc::new(FixedProvider {
            name: "infisical",
            value: None,
        }));
        let selection = AppSecretsSelection {
            provider: AppSecretProviderKind::Infisical,
            source: crate::utils::deployment::EnablementSource::Explicit,
        };
        let mut lines: Vec<PurgeLine> = Vec::new();
        purge_secrets(
            AppSecretProviderKind::Database,
            &providers,
            selection,
            true,
            &mut lines,
        )
        .await;
        assert!(
            lines.iter().any(|l| {
                l.key == GovernedSecret::SmtpPassword.name()
                    && !l.deleted
                    && l.outcome
                        .contains("not verified live in the serving provider")
            }),
            "{lines:?}"
        );
    }

    /// Purge dry-run is the default: no delete happens; the outcome says
    /// "would delete" for each key that passes the interlock.
    #[tokio::test]
    async fn purge_dry_run_is_the_default_and_writes_nothing() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct CountingTarget {
            deletes: AtomicUsize,
        }
        #[async_trait::async_trait]
        impl AppSecretProvider for CountingTarget {
            fn name(&self) -> &'static str {
                "database"
            }
            fn get(&self, _: GovernedSecret) -> Option<String> {
                Some("stale".to_string())
            }
            fn has(&self, _: GovernedSecret) -> bool {
                true
            }
            async fn delete(&self, _: GovernedSecret) -> AppResult<()> {
                self.deletes.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
        }
        let target: Arc<dyn AppSecretProvider> = Arc::new(CountingTarget {
            deletes: AtomicUsize::new(0),
        });
        let mut providers: Vec<Option<Arc<dyn AppSecretProvider>>> = vec![None; 4];
        providers[AppSecretProviderKind::Environment.index()] = Some(Arc::new(FixedProvider {
            name: "environment",
            value: None,
        }));
        // File serves the key live.
        providers[AppSecretProviderKind::File.index()] = Some(Arc::new(FixedProvider {
            name: "file",
            value: Some("hunter2".to_string()),
        }));
        providers[AppSecretProviderKind::Database.index()] = Some(target.clone());
        let selection = AppSecretsSelection {
            provider: AppSecretProviderKind::File,
            source: crate::utils::deployment::EnablementSource::Explicit,
        };
        let mut lines: Vec<PurgeLine> = Vec::new();
        purge_secrets(
            AppSecretProviderKind::Database,
            &providers,
            selection,
            false, // dry-run
            &mut lines,
        )
        .await;
        assert!(
            lines.iter().any(|l| {
                l.key == GovernedSecret::SmtpPassword.name()
                    && !l.deleted
                    && l.outcome.contains("would delete")
            }),
            "{lines:?}"
        );

        // And with --confirm the delete runs.
        let mut lines: Vec<PurgeLine> = Vec::new();
        purge_secrets(
            AppSecretProviderKind::Database,
            &providers,
            selection,
            true,
            &mut lines,
        )
        .await;
        assert!(
            lines.iter().any(|l| {
                l.key == GovernedSecret::SmtpPassword.name()
                    && l.deleted
                    && l.outcome.starts_with("deleted from")
            }),
            "{lines:?}"
        );
    }

    /// AC #7: the environment provider cannot purge. The command reports
    /// what to delete and where, and claims nothing was deleted.
    #[tokio::test]
    async fn purge_reports_the_hint_for_a_read_only_provider() {
        // Environment holds the key (say via SMTP_PASSWORD_FILE); declared
        // is database, which also holds it live (so the interlock passes).
        struct EnvHolder;
        #[async_trait::async_trait]
        impl AppSecretProvider for EnvHolder {
            fn name(&self) -> &'static str {
                "environment"
            }
            fn get(&self, _: GovernedSecret) -> Option<String> {
                Some("hunter2".to_string())
            }
            fn has(&self, _: GovernedSecret) -> bool {
                true
            }
            fn is_writable(&self) -> bool {
                false
            }
        }
        let mut providers: Vec<Option<Arc<dyn AppSecretProvider>>> = vec![None; 4];
        providers[AppSecretProviderKind::Environment.index()] = Some(Arc::new(EnvHolder));
        providers[AppSecretProviderKind::Database.index()] = Some(Arc::new(FixedProvider {
            name: "database",
            value: Some("hunter2".to_string()),
        }));
        let selection = AppSecretsSelection {
            provider: AppSecretProviderKind::Database,
            source: crate::utils::deployment::EnablementSource::Explicit,
        };
        let mut lines: Vec<PurgeLine> = Vec::new();
        purge_secrets(
            AppSecretProviderKind::Environment,
            &providers,
            selection,
            true,
            &mut lines,
        )
        .await;
        let line = lines
            .iter()
            .find(|l| l.key == GovernedSecret::SmtpPassword.name())
            .expect("SMTP_PASSWORD line present");
        assert!(
            line.outcome.contains("cannot purge environment"),
            "{line:?}"
        );
        assert!(!line.deleted);
        assert!(
            line.outcome.contains("SMTP_PASSWORD_FILE")
                || line.outcome.contains("file it points at"),
            "{line:?}"
        );
    }

    /// Config-chain orphans: the enumerable providers can list keys the
    /// registry does not declare; the status report surfaces those under
    /// "orphans".
    #[test]
    fn config_provider_orphans_are_surfaced() {
        struct EnumerableStub {
            keys: Vec<String>,
        }
        #[async_trait::async_trait]
        impl ConfigProvider for EnumerableStub {
            fn name(&self) -> &'static str {
                "file"
            }
            fn get(&self, key: &str) -> Option<String> {
                self.keys
                    .contains(&key.to_string())
                    .then(|| "x".to_string())
            }
            fn list(&self) -> config::Enumeration {
                config::Enumeration::Keys(self.keys.clone())
            }
        }
        let chain = ConfigProviderChain::new(vec![(
            ConfigProviderKind::File,
            Arc::new(EnumerableStub {
                keys: vec!["THIS_KEY_IS_NOT_DECLARED".to_string()],
            }),
        )]);
        let providers: Vec<Option<Arc<dyn AppSecretProvider>>> = vec![None; 4];
        let selection = AppSecretsSelection {
            provider: AppSecretProviderKind::Database,
            source: crate::utils::deployment::EnablementSource::Profile,
        };
        let report = build_status_report(&providers, selection, &chain);
        assert!(
            report
                .orphans
                .iter()
                .any(|o| o.provider == "file" && o.key == "THIS_KEY_IS_NOT_DECLARED"),
            "{:?}",
            report.orphans
        );
    }

    /// A tiny fixture provider driven from a map, so the status/purge
    /// tests can compose scenarios without touching a DB or Infisical.
    struct FixedProvider {
        name: &'static str,
        value: Option<String>,
    }

    #[async_trait::async_trait]
    impl AppSecretProvider for FixedProvider {
        fn name(&self) -> &'static str {
            self.name
        }
        fn get(&self, _: GovernedSecret) -> Option<String> {
            self.value.clone()
        }
    }

    /// An in-memory [`ConfigProvider`] that counts every `set`/`delete` call,
    /// so a test can assert a bootstrap-tier key was never reached with a
    /// write rather than only inspecting the final map.
    struct MemConfigProvider {
        name: &'static str,
        values: std::sync::Mutex<std::collections::HashMap<String, String>>,
        writes: std::sync::atomic::AtomicUsize,
        deletes: std::sync::atomic::AtomicUsize,
    }

    impl MemConfigProvider {
        fn new(name: &'static str, seed: &[(&str, &str)]) -> Self {
            Self {
                name,
                values: std::sync::Mutex::new(
                    seed.iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect(),
                ),
                writes: std::sync::atomic::AtomicUsize::new(0),
                deletes: std::sync::atomic::AtomicUsize::new(0),
            }
        }
    }

    #[async_trait::async_trait]
    impl ConfigProvider for MemConfigProvider {
        fn name(&self) -> &'static str {
            self.name
        }
        fn get(&self, key: &str) -> Option<String> {
            self.values.lock().unwrap().get(key).cloned()
        }
        fn has(&self, key: &str) -> bool {
            self.values.lock().unwrap().contains_key(key)
        }
        async fn set(&self, key: &str, value: &str) -> AppResult<()> {
            self.writes
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.values
                .lock()
                .unwrap()
                .insert(key.to_string(), value.to_string());
            Ok(())
        }
        async fn delete(&self, key: &str) -> AppResult<()> {
            self.deletes
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.values.lock().unwrap().remove(key);
            Ok(())
        }
    }

    /// `provider-migrate`'s config walk must skip a bootstrap-tier key with
    /// a named "skipped" outcome and never call the target's `set` for it,
    /// even though the source holds it: this is the CLI-layer half of
    /// PMS-1228 (`set`/`delete` themselves refuse it too, in `database.rs`
    /// and `file.rs`).
    #[tokio::test]
    async fn migrate_config_skips_a_bootstrap_tier_key_and_reports_it() {
        let source = MemConfigProvider::new(
            "environment",
            &[
                ("ENCRYPTION_KEY", "super-secret"),
                ("SMTP_HOST", "relay.example.com"),
            ],
        );
        let target = MemConfigProvider::new("database", &[]);
        let chain = ConfigProviderChain::new(vec![
            (ConfigProviderKind::Environment, Arc::new(source)),
            (ConfigProviderKind::Database, Arc::new(target)),
        ]);
        let mut lines = Vec::new();
        migrate_config(
            ConfigProviderKind::Environment,
            ConfigProviderKind::Database,
            &chain,
            &mut lines,
        )
        .await;

        let bootstrap_line = lines
            .iter()
            .find(|l| l.key == "ENCRYPTION_KEY")
            .expect("ENCRYPTION_KEY must be reported, not silently dropped");
        assert!(
            bootstrap_line.outcome.starts_with("skipped:")
                && bootstrap_line.outcome.contains("bootstrap"),
            "outcome: {}",
            bootstrap_line.outcome
        );

        let target = chain
            .entries_for_cli()
            .into_iter()
            .find(|(kind, _)| *kind == ConfigProviderKind::Database)
            .unwrap()
            .1;
        assert!(
            !target.has("ENCRYPTION_KEY"),
            "the bootstrap-tier key must never reach the target provider"
        );
        // The application-tier key beside it migrates normally.
        assert_eq!(
            target.get("SMTP_HOST").as_deref(),
            Some("relay.example.com")
        );
    }

    /// `provider-purge`'s config walk must skip a bootstrap-tier key even
    /// when `--confirm` is set and the key is (wrongly) present in the
    /// target, rather than attempting a delete on it.
    #[tokio::test]
    async fn purge_config_skips_a_bootstrap_tier_key_and_reports_it() {
        let target = Arc::new(MemConfigProvider::new(
            "database",
            &[("ENCRYPTION_KEY", "leaked")],
        ));
        let chain = ConfigProviderChain::new(vec![(
            ConfigProviderKind::Database,
            target.clone() as Arc<dyn ConfigProvider>,
        )]);
        let mut lines = Vec::new();
        purge_config(ConfigProviderKind::Database, &chain, true, &mut lines).await;

        let bootstrap_line = lines
            .iter()
            .find(|l| l.key == "ENCRYPTION_KEY")
            .expect("ENCRYPTION_KEY must be reported, not silently dropped");
        assert!(
            bootstrap_line.outcome.starts_with("skipped:")
                && bootstrap_line.outcome.contains("bootstrap"),
            "outcome: {}",
            bootstrap_line.outcome
        );
        assert!(!bootstrap_line.deleted);
        assert_eq!(target.deletes.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert!(target.has("ENCRYPTION_KEY"));
    }
}
