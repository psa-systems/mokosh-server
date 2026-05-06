//! Auth configuration loaded from environment variables (or any other
//! source: `AuthConfig` is just data).
//!
//! All secret-bearing fields use `secrecy::SecretString` so they cannot
//! be accidentally logged via `Debug`.

use chrono::Duration;
use secrecy::SecretString;
use std::path::PathBuf;
use url::Url;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("missing required env var: {0}")]
    MissingEnv(&'static str),
    #[error("invalid env var {0}: {1}")]
    InvalidEnv(&'static str, String),
}

#[derive(Clone)]
pub struct AuthConfig {
    pub issuer: Url,
    pub cookie_domain: Option<String>,
    pub jwt_private_key_path: PathBuf,
    pub jwt_active_kid: String,
    pub jwt_public_keys_dir: PathBuf,
    pub data_encryption_key: SecretString,
    pub data_encryption_key_prev: Option<SecretString>,
    pub data_key_version: u16,
    pub access_token_ttl: Duration,
    pub refresh_token_ttl: Duration,
    pub refresh_idle_ttl: Duration,
    pub authorization_code_ttl: Duration,
    pub op_session_ttl: Duration,
    pub require_email_verification: bool,
    pub allow_signup: bool,
    pub allow_first_run: bool,
    pub federation_enabled: bool,
}

impl AuthConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        fn req(key: &'static str) -> Result<String, ConfigError> {
            std::env::var(key).map_err(|_| ConfigError::MissingEnv(key))
        }
        fn opt(key: &str) -> Option<String> {
            std::env::var(key).ok().filter(|s| !s.is_empty())
        }
        fn parse_u64(key: &'static str, default: u64) -> Result<u64, ConfigError> {
            match std::env::var(key) {
                Ok(s) => s
                    .parse()
                    .map_err(|e: std::num::ParseIntError| ConfigError::InvalidEnv(key, e.to_string())),
                Err(_) => Ok(default),
            }
        }
        fn parse_bool(key: &'static str, default: bool) -> Result<bool, ConfigError> {
            match std::env::var(key) {
                Ok(s) => match s.as_str() {
                    "true" | "1" | "yes" => Ok(true),
                    "false" | "0" | "no" => Ok(false),
                    other => Err(ConfigError::InvalidEnv(key, format!("expected bool, got {other}"))),
                },
                Err(_) => Ok(default),
            }
        }

        let issuer_s = req("MOKOSH_AUTH_ISSUER")?;
        let issuer = Url::parse(&issuer_s)
            .map_err(|e| ConfigError::InvalidEnv("MOKOSH_AUTH_ISSUER", e.to_string()))?;

        Ok(Self {
            issuer,
            cookie_domain: opt("MOKOSH_AUTH_COOKIE_DOMAIN"),
            jwt_private_key_path: PathBuf::from(req("MOKOSH_AUTH_JWT_PRIVATE_KEY_PATH")?),
            jwt_active_kid: req("MOKOSH_AUTH_JWT_ACTIVE_KID")?,
            jwt_public_keys_dir: PathBuf::from(req("MOKOSH_AUTH_JWT_PUBLIC_KEYS_DIR")?),
            data_encryption_key: SecretString::from(req("MOKOSH_AUTH_DATA_ENCRYPTION_KEY")?),
            data_encryption_key_prev: opt("MOKOSH_AUTH_DATA_ENCRYPTION_KEY_PREV").map(SecretString::from),
            data_key_version: parse_u64("MOKOSH_AUTH_DATA_KEY_VERSION", 1)? as u16,
            access_token_ttl: Duration::seconds(parse_u64("MOKOSH_AUTH_ACCESS_TOKEN_TTL", 600)? as i64),
            refresh_token_ttl: Duration::seconds(parse_u64("MOKOSH_AUTH_REFRESH_TOKEN_TTL", 2_592_000)? as i64),
            refresh_idle_ttl: Duration::seconds(parse_u64("MOKOSH_AUTH_REFRESH_IDLE_TTL", 1_209_600)? as i64),
            authorization_code_ttl: Duration::seconds(parse_u64("MOKOSH_AUTH_AUTHORIZATION_CODE_TTL", 60)? as i64),
            op_session_ttl: Duration::seconds(parse_u64("MOKOSH_AUTH_OP_SESSION_TTL", 604_800)? as i64),
            require_email_verification: parse_bool("MOKOSH_AUTH_REQUIRE_EMAIL_VERIFICATION", true)?,
            allow_signup: parse_bool("MOKOSH_AUTH_ALLOW_SIGNUP", false)?,
            allow_first_run: parse_bool("MOKOSH_AUTH_ALLOW_FIRST_RUN", false)?,
            federation_enabled: parse_bool("MOKOSH_AUTH_FEDERATION_ENABLED", false)?,
        })
    }
}

impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthConfig")
            .field("issuer", &self.issuer.as_str())
            .field("cookie_domain", &self.cookie_domain)
            .field("jwt_private_key_path", &self.jwt_private_key_path)
            .field("jwt_active_kid", &self.jwt_active_kid)
            .field("jwt_public_keys_dir", &self.jwt_public_keys_dir)
            .field("data_encryption_key", &"<redacted>")
            .field("data_encryption_key_prev", &self.data_encryption_key_prev.as_ref().map(|_| "<redacted>"))
            .field("data_key_version", &self.data_key_version)
            .field("access_token_ttl", &self.access_token_ttl)
            .field("refresh_token_ttl", &self.refresh_token_ttl)
            .field("refresh_idle_ttl", &self.refresh_idle_ttl)
            .field("authorization_code_ttl", &self.authorization_code_ttl)
            .field("op_session_ttl", &self.op_session_ttl)
            .field("require_email_verification", &self.require_email_verification)
            .field("allow_signup", &self.allow_signup)
            .field("allow_first_run", &self.allow_first_run)
            .field("federation_enabled", &self.federation_enabled)
            .finish()
    }
}
