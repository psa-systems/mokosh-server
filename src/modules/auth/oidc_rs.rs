//! Resource-Server OIDC verifier (scaffold).
//!
//! After the bunyip-as-OP cutover lands (see
//! `docs/new-auth/mokosh/03-mokosh-server-rs-cutover.md` in the docs repo),
//! mokosh-server stops minting tokens and starts validating Bearer `at+jwt`s
//! issued by bunyip-api against bunyip's JWKS. This module is the home of that
//! verifier; it is intentionally NOT wired into `AuthMiddleware` yet so the
//! existing IdP code path keeps working in the transitional dual-issuer state.
//!
//! Ported in shape from `rusty-links/src/auth/oidc_rs.rs`. The implementation
//! lands in a follow-up commit on this branch; this file establishes the
//! module boundary + env-driven config so reviewers can land it incrementally.

#![allow(dead_code)]

use std::sync::Arc;

use serde::Deserialize;
use tokio::sync::RwLock;

/// Subset of the RFC 9068 `at+jwt` claims we read on the RS side.
///
/// Mirrors `bunyip/crates/bunyip-oidc/src/services/oidc_provider.rs:31` with
/// the fields mokosh-server actually consumes (sub for user lookup, scope for
/// gating, exp for expiry). The full set bunyip mints is documented in
/// docs/new-auth/mokosh/01-architecture.md.
#[derive(Debug, Clone, Deserialize)]
pub struct AtClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub client_id: String,
    pub scope: String,
    pub exp: i64,
    pub iat: i64,
}

/// Static config the verifier reads at startup from env.
///
/// `OIDC_ISSUER` and `OIDC_AUDIENCE` must be set before `Verifier::new` is
/// called from `main.rs`. Both fail-loud so a misconfigured RS never silently
/// accepts tokens from the wrong issuer.
#[derive(Debug, Clone)]
pub struct VerifierConfig {
    pub issuer: String,
    pub audience: String,
}

impl VerifierConfig {
    pub fn from_env() -> Result<Self, String> {
        let issuer = std::env::var("OIDC_ISSUER")
            .map_err(|_| "OIDC_ISSUER must be set (e.g. https://api.a8n.systems)".to_string())?;
        let audience = std::env::var("OIDC_AUDIENCE").map_err(|_| {
            "OIDC_AUDIENCE must be set (e.g. https://api.msp.a8n.systems)".to_string()
        })?;
        Ok(Self { issuer, audience })
    }
}

/// JWKS cache. Populated lazily on first verify, refreshed on `kid` miss or
/// every `cache_ttl_secs` (whichever comes first).
#[derive(Debug, Default)]
pub struct JwksCache {
    pub fetched_at: Option<std::time::SystemTime>,
    /// Raw `serde_json::Value` until the implementation lands. The follow-up
    /// commit replaces this with a `HashMap<String, jsonwebtoken::DecodingKey>`.
    pub raw: Option<serde_json::Value>,
}

/// RS verifier handle. Cheap to clone; `Arc`s the shared cache.
#[derive(Clone)]
pub struct Verifier {
    pub config: VerifierConfig,
    pub http: reqwest::Client,
    pub cache: Arc<RwLock<JwksCache>>,
}

impl Verifier {
    pub fn new(config: VerifierConfig) -> Self {
        Self {
            config,
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .expect("reqwest client build"),
            cache: Arc::new(RwLock::new(JwksCache::default())),
        }
    }

    /// Validate an `at+jwt` Bearer. Returns the claims on success.
    ///
    /// Implementation lands in a follow-up commit. Until then this is a hard
    /// 401 so any accidental wiring fails closed, never open.
    pub async fn verify_at_jwt(&self, _token: &str) -> Result<AtClaims, VerifyError> {
        Err(VerifyError::NotImplemented)
    }
}

/// Errors the verifier surfaces. The middleware translates these into 401s.
#[derive(Debug)]
pub enum VerifyError {
    NotImplemented,
    InvalidSignature,
    InvalidIssuer,
    InvalidAudience,
    Expired,
    JwksFetch(String),
    Malformed(String),
}
