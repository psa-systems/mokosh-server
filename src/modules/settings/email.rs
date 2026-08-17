//! DB-backed SMTP email settings (PMS-638, first slice of PMS-636).
//!
//! Moves the SMTP mailer configuration out of `SMTP_*` env vars into a single
//! DB-backed admin setting, resolved at boot and hot-swapped on change. Scope
//! decision (PMS-636): one SYSTEM config stored on the default tenant
//! (`Uuid::from_u128(1)`), not per-tenant. Env stays the fallback: any field
//! absent from the DB row keeps its [`MailerConfig::from_env`] value, and no DB
//! row at all is identical to today's env-only behaviour.
//!
//! `smtp_password` is stored AES-256-GCM-encrypted (the same [`crypto`] helper +
//! `ENCRYPTION_KEY` that protects `payment_gateway_configs`); it is decrypted
//! only inside [`resolve_mailer_config`] and never returned by the read API.
//!
//! `tenant_settings` is fail-closed RLS (migration 038), so every access goes
//! through `begin_with_tenant(SYSTEM_TENANT)` - a raw pool query would be
//! filtered to nothing.

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::Database;
use crate::utils::crypto;
use crate::utils::email::{MailerConfig, SharedMailer, SmtpTls};
use crate::utils::error::{AppError, AppResult};

/// System tenant that owns the single deployment-wide email config. Matches
/// `auth::bootstrap`'s `default_tenant_id` and `OIDC_DEFAULT_TENANT_ID`.
fn system_tenant() -> Uuid {
    Uuid::from_u128(1)
}

const EMAIL_CATEGORY: &str = "email";
const EMAIL_KEY: &str = "smtp";

/// Shape persisted in `tenant_settings.value` (JSONB). Every field is optional
/// so an operator sets only what differs from the env baseline.
/// `password_encrypted` holds the AES-256-GCM ciphertext, never plaintext.
#[derive(Debug, Default, Serialize, Deserialize)]
struct StoredEmailConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tls: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    password_encrypted: Option<String>,
}

/// Admin write payload for `PUT /settings/email`. A field left `None` keeps its
/// current stored value; an explicit empty string clears that override. The
/// password is write-only (omit to keep the existing one), mirroring the
/// payment-gateway update semantics.
#[derive(Debug, Deserialize)]
pub struct EmailSettingsInput {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub from: Option<String>,
    pub tls: Option<String>,
    pub password: Option<String>,
}

/// Read view for `GET /settings/email`. The password is never returned; only
/// whether one is set.
#[derive(Debug, Serialize)]
pub struct EmailSettingsView {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub from: Option<String>,
    pub tls: Option<String>,
    pub password_set: bool,
}

impl EmailSettingsView {
    fn from_stored(stored: StoredEmailConfig) -> Self {
        Self {
            host: stored.host,
            port: stored.port,
            username: stored.username,
            from: stored.from,
            tls: stored.tls,
            password_set: stored.password_encrypted.is_some(),
        }
    }
}

/// Read the stored config object for the system tenant, if present.
async fn load_stored(db: &Database) -> AppResult<Option<StoredEmailConfig>> {
    let mut tx = db.begin_with_tenant(system_tenant()).await?;
    let value: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT value FROM tenant_settings WHERE tenant_id = $1 AND category = $2 AND key = $3",
    )
    .bind(system_tenant())
    .bind(EMAIL_CATEGORY)
    .bind(EMAIL_KEY)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;

    match value {
        Some(v) => Ok(Some(serde_json::from_value(v).map_err(|e| {
            AppError::Internal(format!("stored email config is not valid JSON: {e}"))
        })?)),
        None => Ok(None),
    }
}

/// Build the effective [`MailerConfig`] from the env baseline overridden by a
/// stored config object. Mirrors `from_env`'s invariant that a username with no
/// password is a hard error (an unauthenticated SMTP send is a misconfiguration,
/// not a silent fallback) - the override path must not weaken it.
fn config_from_stored(stored: &StoredEmailConfig, enc_key: &[u8; 32]) -> AppResult<MailerConfig> {
    let mut cfg = MailerConfig::from_env()?;
    if let Some(host) = stored.host.as_deref().filter(|s| !s.is_empty()) {
        cfg.host = Some(host.to_string());
    }
    if let Some(port) = stored.port {
        cfg.port = port;
    }
    if let Some(username) = stored.username.as_deref().filter(|s| !s.is_empty()) {
        cfg.username = Some(username.to_string());
    }
    if let Some(from) = stored.from.as_deref().filter(|s| !s.is_empty()) {
        cfg.from = from.to_string();
    }
    if let Some(tls) = stored.tls.as_deref().filter(|s| !s.is_empty()) {
        cfg.tls = SmtpTls::parse(tls)?;
    }
    if let Some(enc) = stored
        .password_encrypted
        .as_deref()
        .filter(|s| !s.is_empty())
    {
        cfg.password = Some(SecretString::from(crypto::decrypt(enc, enc_key)?));
    }
    if cfg.username.is_some() && cfg.password.is_none() {
        return Err(AppError::Configuration(
            "email settings set a username but no password; SMTP auth needs both".to_string(),
        ));
    }
    Ok(cfg)
}

/// Resolve the effective mailer config: env baseline ([`MailerConfig::from_env`])
/// overridden by any field present in the DB system row. Called at boot and
/// whenever the settings change. No DB row => identical to `from_env()`.
pub async fn resolve_mailer_config(db: &Database, enc_key: &[u8; 32]) -> AppResult<MailerConfig> {
    let stored = load_stored(db).await?.unwrap_or_default();
    config_from_stored(&stored, enc_key)
}

/// Rebuild the mailer from current settings and swap it into the shared handle,
/// so the change takes effect on every consumer without a restart.
pub async fn rebuild_and_swap(
    db: &Database,
    enc_key: &[u8; 32],
    shared: &SharedMailer,
) -> AppResult<()> {
    let mailer = resolve_mailer_config(db, enc_key).await?.build()?;
    shared.swap(mailer);
    Ok(())
}

/// Current stored email settings (password masked). No row => all-empty view.
pub async fn get_email_settings(db: &Database) -> AppResult<EmailSettingsView> {
    let stored = load_stored(db).await?.unwrap_or_default();
    Ok(EmailSettingsView::from_stored(stored))
}

/// Persist the email settings for the system tenant, encrypting a new password,
/// then return the masked view. Callers rebuild + swap the live mailer after.
pub async fn put_email_settings(
    db: &Database,
    enc_key: &[u8; 32],
    input: EmailSettingsInput,
) -> AppResult<EmailSettingsView> {
    // Validate the fields that must parse before we persist anything.
    if let Some(tls) = input.tls.as_deref().filter(|s| !s.is_empty()) {
        SmtpTls::parse(tls)?;
    }
    if let Some(from) = input.from.as_deref().filter(|s| !s.is_empty()) {
        from.parse::<lettre::message::Mailbox>().map_err(|e| {
            AppError::BadRequest(format!("From {from:?} is not a valid address: {e}"))
        })?;
    }

    let mut stored = load_stored(db).await?.unwrap_or_default();
    // Some(value) overrides; None leaves the field as-is. An empty string on a
    // text field is a deliberate clear (fall back to env for that field).
    if let Some(host) = input.host {
        stored.host = Some(host).filter(|s| !s.is_empty());
    }
    if let Some(port) = input.port {
        stored.port = Some(port);
    }
    if let Some(username) = input.username {
        stored.username = Some(username).filter(|s| !s.is_empty());
    }
    if let Some(from) = input.from {
        stored.from = Some(from).filter(|s| !s.is_empty());
    }
    if let Some(tls) = input.tls {
        stored.tls = Some(tls).filter(|s| !s.is_empty());
    }
    if let Some(password) = input.password {
        stored.password_encrypted = if password.is_empty() {
            None
        } else {
            Some(crypto::encrypt(&password, enc_key)?)
        };
    }

    // Prove the FULL effective config builds a mailer BEFORE persisting it.
    // Otherwise a bad value (an unparseable host, or a username with no
    // password) would be saved and then panic the next boot, where
    // `resolve_mailer_config(..).build()` is `.expect`-ed in main. Building is
    // cheap (no network) and rejects the write with the underlying error.
    config_from_stored(&stored, enc_key)?.build()?;

    let value = serde_json::to_value(&stored)
        .map_err(|e| AppError::Internal(format!("failed to serialise email config: {e}")))?;
    let mut tx = db.begin_with_tenant(system_tenant()).await?;
    sqlx::query(
        "INSERT INTO tenant_settings (tenant_id, category, key, value)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (tenant_id, category, key)
         DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()",
    )
    .bind(system_tenant())
    .bind(EMAIL_CATEGORY)
    .bind(EMAIL_KEY)
    .bind(&value)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok(EmailSettingsView::from_stored(stored))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A new password round-trips through encrypt/store-shape/decrypt so the
    /// resolver recovers the cleartext, and the masked view never leaks it.
    #[test]
    fn password_encrypts_and_masks() {
        let key = [7u8; 32];
        let ciphertext = crypto::encrypt("hunter2", &key).unwrap();
        let stored = StoredEmailConfig {
            password_encrypted: Some(ciphertext.clone()),
            ..Default::default()
        };
        // Never the cleartext at rest.
        assert_ne!(ciphertext, "hunter2");
        // Resolver-side recovery.
        assert_eq!(crypto::decrypt(&ciphertext, &key).unwrap(), "hunter2");
        // Read view masks it.
        let view = EmailSettingsView::from_stored(stored);
        assert!(view.password_set);
    }

    /// The stored JSON shape omits absent fields (so `resolve` treats them as
    /// env fallbacks) and preserves the ones that are set.
    #[test]
    fn stored_shape_omits_absent_fields() {
        let stored = StoredEmailConfig {
            host: Some("smtp.example".to_string()),
            port: Some(465),
            tls: Some("implicit".to_string()),
            ..Default::default()
        };
        let v = serde_json::to_value(&stored).unwrap();
        assert_eq!(v["host"], "smtp.example");
        assert_eq!(v["port"], 465);
        assert_eq!(v["tls"], "implicit");
        assert!(v.get("username").is_none(), "absent fields omitted");
        assert!(v.get("password_encrypted").is_none());
    }
}
