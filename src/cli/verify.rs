//! `verify-providers`: one shot that boots every provider seam and reports
//! whether each capability is live.
//!
//! Runs INSIDE the server process image (`docker compose exec server
//! mokosh-server verify-providers`), so it reproduces `main`'s wiring for
//! every provider - configuration, application-tier secrets, tenant-tier
//! secrets, storage, authentication and email - and then asks each one two
//! questions: did it BUILD, and does it ANSWER. The build half is the
//! provider-status collector's data; the answer half is capability-specific:
//! the email verify NOOP against the relay is the one interactive check that
//! is safe to run at any time, and it is the reason a `MAIL_PROVIDER=smtp`
//! deployment fails loud here instead of on the first outbound at 3am.
//!
//! No fabricated writes, no test messages sent onward: the storage seam
//! reports what `storage::init_from_env` did, the app-tier secret survey
//! reports what `app_secrets::init_from_env` saw, and the mailer verify
//! rides on lettre's `NOOP` request (`SmtpMailer::verify`, PMS-1013), so a
//! `verify-providers` run is safe to schedule and produces no side effects.
//!
//! Output is a table by default and a JSON envelope with `--json` for CI.
//! Any provider that failed to build, that reports an unreachable enabled
//! entry, or whose capability probe returned an error takes the run non-zero.

use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;

use crate::providers::status::{
    self, EnabledProviderReport, HostingProfileDeviation, ProviderKindReport,
};
use crate::utils::deployment::{DeploymentMode, ProviderKind};
use crate::utils::email::{self, EmailConfig, Mailer, MailerConfig};
use crate::utils::error::{AppError, AppResult};

/// The one operator-facing verdict per row, in a fixed vocabulary the JSON
/// consumer can key on. The nuance of "running on the profile default rather
/// than an explicit choice" is not a verdict here: the deployment serves,
/// and the whole hosting-profile-vs-operator overlay already lives in the
/// `deviations` block below. A row is either serving (pass) or it is not
/// (fail).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Verdict {
    /// Built and answered (or the check is trivially green, like the
    /// LogMailer verify).
    Pass,
    /// Something the caller asked for did not answer. A misconfigured relay,
    /// an unreachable Infisical, an S3 endpoint that refuses the credential.
    Fail,
}

impl Verdict {
    fn as_str(self) -> &'static str {
        match self {
            Verdict::Pass => "pass",
            Verdict::Fail => "fail",
        }
    }
}

/// One row of the verify table: what this kind is running, who chose it and
/// whether the capability answered.
#[derive(Clone, Debug, Serialize)]
struct ProviderRow {
    kind: String,
    serving: Option<String>,
    verdict: Verdict,
    /// The `MAIL_PROVIDER=smtp requires SMTP_HOST` shape: one sentence naming
    /// what the operator can act on. Empty on a pass with no comment.
    detail: String,
}

/// The whole verify envelope. Serialised verbatim under `--json`.
#[derive(Clone, Debug, Serialize)]
struct VerifyReport {
    hosting_profile: String,
    /// Every kind the collector answered for, in the same stable order the
    /// status page uses, plus one row for the email verify probe.
    rows: Vec<ProviderRow>,
    /// Every hosting-profile deviation from `providers::status::collect()`,
    /// carried verbatim so the operator sees WHICH default they overrode.
    deviations: Vec<HostingProfileDeviation>,
    /// True when every row is `pass` or `profile_default` and no probe
    /// raised. The process exit code follows this.
    ok: bool,
}

/// `mokosh-server verify-providers [--json | --text]`. Text is the default
/// and prints one row per kind plus a summary; JSON prints a single envelope.
pub async fn run(args: &[String]) -> AppResult<()> {
    let mode = parse_args(args)?;

    // Reproduce main's boot order for every provider, then collect. `main`
    // already tolerates half-configured deployments so long as the caller
    // fails loud on a bad selection; this path does the same, and reports
    // per capability rather than crashing on the first bad one.
    init_bootstrap_config()?;
    let (db, encryption_key) = boot_shared_state().await?;
    init_application_secrets(&db, encryption_key).await?;
    init_storage()?;
    let email_config = init_email()?;

    // The mailer build reads what `resolve_mailer_config` would at boot, so
    // a DB-override that overrides a bad SMTP relay is exercised too. We
    // fall back to env alone when the DB row cannot be read (a schema
    // problem this command is deliberately not the place to diagnose).
    let mailer_config =
        match crate::modules::settings::email::resolve_mailer_config(&db, &encryption_key).await {
            Ok(cfg) => cfg,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "verify-providers: could not read the DB email override; falling back to env"
                );
                MailerConfig::from_env()?
            }
        };

    let report = status::collect();
    let mut rows: Vec<ProviderRow> = report.kinds.iter().map(row_from_kind).collect();

    // Email verify: a NOOP over the built mailer. The transport check has a
    // timeout so a black-holed relay does not stall the CLI.
    let email_row = verify_email(email_config, mailer_config).await;
    if let Some(existing) = rows.iter_mut().find(|r| r.kind == "email") {
        merge_email_row(existing, email_row);
    } else {
        rows.push(email_row);
    }

    let ok = rows.iter().all(|r| r.verdict != Verdict::Fail);
    let envelope = VerifyReport {
        hosting_profile: report.hosting_profile.clone(),
        rows,
        deviations: report.deviations.clone(),
        ok,
    };

    match mode {
        Mode::Json => {
            let json = serde_json::to_string_pretty(&envelope)
                .map_err(|e| AppError::Configuration(format!("verify-providers JSON: {e}")))?;
            println!("{json}");
        }
        Mode::Text => print_text(&envelope),
    }

    if envelope.ok {
        Ok(())
    } else {
        Err(AppError::Configuration(
            "verify-providers: one or more capabilities failed; see the table above".to_string(),
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Text,
    Json,
}

fn parse_args(args: &[String]) -> AppResult<Mode> {
    let mut mode = Mode::Text;
    for arg in &args[2..] {
        match arg.as_str() {
            "--json" => mode = Mode::Json,
            "--text" => mode = Mode::Text,
            "--help" | "-h" => {
                println!("{}", help());
                std::process::exit(0);
            }
            other => {
                return Err(AppError::Configuration(format!(
                    "verify-providers: unrecognised argument {other:?}\n\n{}",
                    help()
                )));
            }
        }
    }
    Ok(mode)
}

fn help() -> String {
    "usage: mokosh-server verify-providers [--json | --text]\n\
     \n\
     Boots every provider seam - configuration, application-tier secrets,\n\
     tenant-tier secrets, storage, authentication, email - and reports\n\
     whether each is serving. The email row runs an SMTP NOOP against the\n\
     relay (LogMailer trivially passes). Exits non-zero on any failure.\n"
        .to_string()
}

fn init_bootstrap_config() -> AppResult<()> {
    let profile = DeploymentMode::from_env_for_providers()
        .map_err(|e| AppError::Configuration(e.to_string()))?;
    let default = profile.default_provider_for(ProviderKind::Configuration)?;
    let _ = crate::config::init_from_env(default);
    Ok(())
}

async fn boot_shared_state() -> AppResult<(crate::db::Database, [u8; 32])> {
    let database_url = std::env::var("DATABASE_URL").map_err(|_| {
        AppError::Configuration(
            "verify-providers: DATABASE_URL is not set; the CLI needs a pool to reach the \
             tenant_settings row that overrides the SMTP configuration"
                .to_string(),
        )
    })?;
    let app_url = std::env::var("MOKOSH_APP_DATABASE_URL").unwrap_or_else(|_| database_url.clone());
    let db = crate::db::Database::new(&app_url, &database_url).await?;

    let raw = std::env::var("ENCRYPTION_KEY").map_err(|_| {
        AppError::Configuration(
            "verify-providers: ENCRYPTION_KEY is not set; the CLI needs it to decrypt the \
             stored SMTP password"
                .to_string(),
        )
    })?;
    let encryption_key = crate::utils::crypto::parse_encryption_key(&raw)?;
    Ok((db, encryption_key))
}

async fn init_application_secrets(
    db: &crate::db::Database,
    encryption_key: [u8; 32],
) -> AppResult<()> {
    let profile = DeploymentMode::from_env_for_providers()
        .map_err(|e| AppError::Configuration(e.to_string()))?;
    let default = profile.default_provider_for(ProviderKind::Secrets)?;
    crate::app_secrets::init_from_env(default, db.clone(), encryption_key).await?;
    Ok(())
}

fn init_storage() -> AppResult<()> {
    let profile = DeploymentMode::from_env_for_providers()
        .map_err(|e| AppError::Configuration(e.to_string()))?;
    let default = profile.default_provider_for(ProviderKind::Storage)?;
    crate::storage::init_from_env(default)?;
    Ok(())
}

fn init_email() -> AppResult<EmailConfig> {
    let profile = DeploymentMode::from_env_for_providers()
        .map_err(|e| AppError::Configuration(e.to_string()))?;
    let default = profile.default_provider_for(ProviderKind::Email)?;
    let cfg = EmailConfig::from_env(default)?;
    email::init_selected_kind(cfg.provider);
    Ok(cfg)
}

/// One row per collected kind. The verdict is `fail` when any enabled
/// provider is unreachable or no provider is serving; otherwise `pass` if
/// there is a serving provider and `profile_default` when only the profile
/// left one on.
fn row_from_kind(kind: &ProviderKindReport) -> ProviderRow {
    let unreachable: Vec<&EnabledProviderReport> =
        kind.enabled.iter().filter(|e| !e.reachable).collect();
    let (verdict, detail) = if !unreachable.is_empty() {
        let names: Vec<String> = unreachable
            .iter()
            .map(|e| match &e.unreachable_reason {
                Some(r) => format!("{} ({r})", e.name),
                None => e.name.clone(),
            })
            .collect();
        (Verdict::Fail, format!("unreachable: {}", names.join(", ")))
    } else if kind.serving.is_none() {
        (
            Verdict::Fail,
            "no provider is serving this capability".to_string(),
        )
    } else if kind.enabled.is_empty() {
        (Verdict::Fail, "no provider was built".to_string())
    } else {
        (Verdict::Pass, String::new())
    };

    ProviderRow {
        kind: kind.kind.clone(),
        serving: kind.serving.clone(),
        verdict,
        detail,
    }
}

/// Overlay the email row's transport verdict on the collector's build
/// verdict. A build-time refusal stays a failure regardless of what verify
/// says (verify would never run because there is no mailer to run it on).
fn merge_email_row(existing: &mut ProviderRow, verify_row: ProviderRow) {
    if existing.verdict == Verdict::Fail {
        // Build already failed; keep the build failure, append the verify
        // note so the operator sees both signals at once.
        if !verify_row.detail.is_empty() {
            existing.detail = format!("{}; {}", existing.detail, verify_row.detail);
        }
        return;
    }
    // Verify has the final say when the build passed: a LogMailer verify is
    // trivially Ok, an SMTP verify surfaces here as pass or fail.
    existing.verdict = verify_row.verdict;
    existing.detail = verify_row.detail;
}

/// Run the mailer's verify with a bound. `LogMailer::verify` is trivially
/// Ok; `SmtpMailer::verify` issues a NOOP against the relay so the NOOP is
/// the whole interactive check. The timeout keeps a black-holed relay from
/// stalling a CI job.
async fn verify_email(cfg: EmailConfig, mailer_config: MailerConfig) -> ProviderRow {
    let kind = "email".to_string();
    let serving = Some(cfg.provider.as_str().to_string());

    let mailer: Arc<dyn Mailer> = match email::build_mailer(cfg.provider, mailer_config) {
        Ok(m) => m,
        Err(e) => {
            return ProviderRow {
                kind,
                serving,
                verdict: Verdict::Fail,
                detail: format!("build refused: {e}"),
            };
        }
    };

    match tokio::time::timeout(Duration::from_secs(10), mailer.verify()).await {
        Ok(Ok(())) => ProviderRow {
            kind,
            serving,
            verdict: Verdict::Pass,
            detail: String::new(),
        },
        Ok(Err(e)) => ProviderRow {
            kind,
            serving,
            verdict: Verdict::Fail,
            detail: format!("verify: {e}"),
        },
        Err(_) => ProviderRow {
            kind,
            serving,
            verdict: Verdict::Fail,
            detail: "verify: timed out after 10s".to_string(),
        },
    }
}

fn print_text(envelope: &VerifyReport) {
    println!("hosting profile: {}", envelope.hosting_profile);
    println!();
    println!(
        "{:<24}  {:<16}  {:<16}  detail",
        "kind", "serving", "verdict"
    );
    println!("{}", "-".repeat(78));
    for row in &envelope.rows {
        println!(
            "{:<24}  {:<16}  {:<16}  {}",
            row.kind,
            row.serving.as_deref().unwrap_or("-"),
            row.verdict.as_str(),
            row.detail
        );
    }
    if !envelope.deviations.is_empty() {
        println!();
        println!("hosting-profile deviations:");
        for d in &envelope.deviations {
            println!(
                "  {}: profile={} explicit={}",
                d.kind,
                d.profile_default.join(","),
                d.explicit.join(",")
            );
        }
    }
    println!();
    println!("overall: {}", if envelope.ok { "OK" } else { "FAIL" });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn row_from_kind_passes_when_a_provider_is_serving_and_all_reachable() {
        let kind = ProviderKindReport {
            kind: "storage".to_string(),
            enabled: vec![EnabledProviderReport {
                name: "local".to_string(),
                priority: 0,
                reachable: true,
                unreachable_reason: None,
            }],
            serving: Some("local".to_string()),
            keys: Vec::new(),
            enumeration: None,
        };
        let row = row_from_kind(&kind);
        assert_eq!(row.verdict, Verdict::Pass);
        assert!(row.detail.is_empty());
    }

    #[test]
    fn row_from_kind_fails_when_a_provider_is_unreachable() {
        let kind = ProviderKindReport {
            kind: "secrets_tenant".to_string(),
            enabled: vec![EnabledProviderReport {
                name: "infisical".to_string(),
                priority: 0,
                reachable: false,
                unreachable_reason: Some("connection refused".to_string()),
            }],
            serving: None,
            keys: Vec::new(),
            enumeration: None,
        };
        let row = row_from_kind(&kind);
        assert_eq!(row.verdict, Verdict::Fail);
        assert!(row.detail.contains("infisical"));
        assert!(row.detail.contains("connection refused"));
    }

    #[test]
    fn row_from_kind_fails_when_nothing_is_serving() {
        let kind = ProviderKindReport {
            kind: "email".to_string(),
            enabled: Vec::new(),
            serving: None,
            keys: Vec::new(),
            enumeration: None,
        };
        let row = row_from_kind(&kind);
        assert_eq!(row.verdict, Verdict::Fail);
    }

    #[test]
    fn merge_email_row_keeps_a_build_failure_over_a_verify_pass() {
        let mut existing = ProviderRow {
            kind: "email".to_string(),
            serving: Some("smtp".to_string()),
            verdict: Verdict::Fail,
            detail: "no provider is serving this capability".to_string(),
        };
        let verify = ProviderRow {
            kind: "email".to_string(),
            serving: Some("smtp".to_string()),
            verdict: Verdict::Pass,
            detail: String::new(),
        };
        merge_email_row(&mut existing, verify);
        assert_eq!(existing.verdict, Verdict::Fail);
    }

    #[test]
    fn merge_email_row_takes_the_verify_verdict_when_the_build_passed() {
        let mut existing = ProviderRow {
            kind: "email".to_string(),
            serving: Some("smtp".to_string()),
            verdict: Verdict::Pass,
            detail: String::new(),
        };
        let verify = ProviderRow {
            kind: "email".to_string(),
            serving: Some("smtp".to_string()),
            verdict: Verdict::Fail,
            detail: "verify: SMTP relay unreachable".to_string(),
        };
        merge_email_row(&mut existing, verify);
        assert_eq!(existing.verdict, Verdict::Fail);
        assert!(existing.detail.contains("SMTP relay unreachable"));
    }
}
