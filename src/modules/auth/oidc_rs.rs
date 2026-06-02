//! Resource-Server OIDC verifier.
//!
//! After the bunyip-as-OP cutover lands (see
//! `docs/new-auth/mokosh/03-mokosh-server-rs-cutover.md` in the docs repo),
//! mokosh-server stops minting tokens and starts validating Bearer `at+jwt`s
//! issued by bunyip-api against bunyip's JWKS. This module owns that verifier.
//! It is NOT yet wired into `AuthMiddleware` so the existing IdP code path
//! keeps working through the transitional dual-issuer state; a follow-up
//! commit on the same branch flips the switch.
//!
//! Ported in shape from `rusty-links/src/auth/oidc_rs.rs`.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use tokio::sync::RwLock;

// ── Token claim types ─────────────────────────────────────────────────────────

/// Subset of the RFC 9068 `at+jwt` claims mokosh-server reads on the RS side.
///
/// Mirrors `bunyip/crates/bunyip-oidc/src/services/oidc_provider.rs:31`,
/// narrowed to the fields the middleware actually consumes (sub for user
/// lookup, scope for gating, exp/iat for expiry, iss/aud for pinning).
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

/// Subset of bunyip-api's `/oauth2/userinfo` response. The RS calls this on
/// first sight of a new `sub` to resolve `email` for JIT-provisioning a row in
/// `public.users` (the `at+jwt` itself does NOT carry an email claim).
#[derive(Debug, Clone, Deserialize)]
pub struct UserInfo {
    pub sub: String,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
}

// ── Wire types ────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct DiscoveryDoc {
    issuer: String,
    jwks_uri: String,
    userinfo_endpoint: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JwksResponse {
    keys: Vec<JwkEntry>,
}

#[derive(Debug, Deserialize)]
struct JwkEntry {
    kty: String,
    #[serde(rename = "use")]
    key_use: Option<String>,
    kid: String,
    crv: Option<String>,
    x: Option<String>,
}

// ── Config ────────────────────────────────────────────────────────────────────

/// Static config the verifier reads at startup from env.
#[derive(Debug, Clone)]
pub struct VerifierConfig {
    /// Expected `iss` claim and the host the discovery doc lives on.
    pub issuer: String,
    /// Expected `aud` claim (the RS's own canonical URL, e.g.
    /// `https://api.msp.a8n.systems`). Must match the `audience` column of the
    /// bunyip oauth_clients row that issued the token.
    pub audience: String,
    /// JWKS refresh interval. The cache is also force-refreshed on `kid` miss.
    pub jwks_cache_ttl_secs: u64,
    /// Allowed clock skew (RFC 9068 leeway).
    pub leeway_seconds: u64,
}

impl VerifierConfig {
    /// `OIDC_ISSUER` + `OIDC_AUDIENCE` are required; both fail-loud so a
    /// misconfigured RS never silently accepts tokens from the wrong issuer.
    pub fn from_env() -> Result<Self, String> {
        let issuer = std::env::var("OIDC_ISSUER")
            .map_err(|_| "OIDC_ISSUER must be set (e.g. https://api.a8n.systems)".to_string())?
            .trim_end_matches('/')
            .to_string();
        let audience = std::env::var("OIDC_AUDIENCE").map_err(|_| {
            "OIDC_AUDIENCE must be set (e.g. https://api.msp.a8n.systems)".to_string()
        })?;
        let jwks_cache_ttl_secs = std::env::var("OIDC_JWKS_CACHE_TTL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(600);
        let leeway_seconds = std::env::var("OIDC_LEEWAY_SECONDS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30);
        Ok(Self {
            issuer,
            audience,
            jwks_cache_ttl_secs,
            leeway_seconds,
        })
    }
}

// ── JWKS cache ────────────────────────────────────────────────────────────────

struct JwksCache {
    keys: HashMap<String, DecodingKey>,
    jwks_uri: String,
    userinfo_endpoint: Option<String>,
    refreshed_at: DateTime<Utc>,
}

// ── Verifier ──────────────────────────────────────────────────────────────────

/// RS verifier handle. Cheap to clone; `Arc`s the shared cache.
#[derive(Clone)]
pub struct Verifier {
    pub config: VerifierConfig,
    http: reqwest::Client,
    cache: Arc<RwLock<Option<JwksCache>>>,
}

#[derive(Debug)]
pub enum VerifyError {
    /// JWT header missing/invalid, wrong typ, wrong alg, etc.
    Malformed(String),
    /// Signature does not validate against any cached JWK.
    InvalidSignature,
    /// `iss` claim mismatch.
    InvalidIssuer,
    /// `aud` claim mismatch.
    InvalidAudience,
    /// Token is expired (with leeway).
    Expired,
    /// JWKS could not be fetched or parsed.
    JwksFetch(String),
    /// Discovery doc could not be fetched or parsed.
    DiscoveryFetch(String),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::Malformed(s) => write!(f, "malformed token: {s}"),
            VerifyError::InvalidSignature => write!(f, "invalid signature"),
            VerifyError::InvalidIssuer => write!(f, "invalid issuer"),
            VerifyError::InvalidAudience => write!(f, "invalid audience"),
            VerifyError::Expired => write!(f, "token expired"),
            VerifyError::JwksFetch(s) => write!(f, "JWKS fetch failed: {s}"),
            VerifyError::DiscoveryFetch(s) => write!(f, "discovery fetch failed: {s}"),
        }
    }
}

impl std::error::Error for VerifyError {}

impl Verifier {
    pub fn new(config: VerifierConfig) -> Self {
        Self {
            config,
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .expect("reqwest client build"),
            cache: Arc::new(RwLock::new(None)),
        }
    }

    /// Validate an `at+jwt` Bearer. Returns the claims on success.
    pub async fn verify_at_jwt(&self, token: &str) -> Result<AtClaims, VerifyError> {
        let header = jsonwebtoken::decode_header(token)
            .map_err(|e| VerifyError::Malformed(format!("decode header: {e}")))?;
        if header.typ.as_deref() != Some("at+jwt") {
            return Err(VerifyError::Malformed(format!(
                "expected typ=at+jwt, got {:?}",
                header.typ
            )));
        }
        let kid = header
            .kid
            .ok_or_else(|| VerifyError::Malformed("missing kid".into()))?;

        // First try with the cached JWKS; on unknown-kid, force a refresh and
        // retry once.
        match self.try_validate(token, &kid).await {
            Ok(claims) => Ok(claims),
            Err(VerifyError::InvalidSignature) => {
                self.refresh_jwks().await?;
                self.try_validate(token, &kid).await
            }
            Err(e) => Err(e),
        }
    }

    /// Resolve `email` for a JIT-provisioned user. Called once per new `sub`.
    /// Returns `None` (rather than failing the request) if userinfo is
    /// unreachable: the local users row is still created with email=NULL, and
    /// a subsequent call refreshes it.
    pub async fn userinfo(&self, bearer: &str) -> Option<UserInfo> {
        self.ensure_cache().await.ok()?;
        let guard = self.cache.read().await;
        let endpoint = guard.as_ref()?.userinfo_endpoint.clone()?;
        drop(guard);

        self.http
            .get(endpoint)
            .bearer_auth(bearer)
            .send()
            .await
            .ok()?
            .error_for_status()
            .ok()?
            .json::<UserInfo>()
            .await
            .ok()
    }

    // ── internals ────────────────────────────────────────────────────────────

    async fn try_validate(&self, token: &str, kid: &str) -> Result<AtClaims, VerifyError> {
        self.ensure_cache().await?;
        let guard = self.cache.read().await;
        let cache = guard.as_ref().expect("ensure_cache populated");
        let key = cache
            .keys
            .get(kid)
            .ok_or(VerifyError::InvalidSignature)?
            .clone();
        drop(guard);

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.audience]);
        validation.validate_exp = true;
        validation.leeway = self.config.leeway_seconds;

        match jsonwebtoken::decode::<AtClaims>(token, &key, &validation) {
            Ok(data) => Ok(data.claims),
            Err(e) => Err(match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => VerifyError::Expired,
                jsonwebtoken::errors::ErrorKind::InvalidIssuer => VerifyError::InvalidIssuer,
                jsonwebtoken::errors::ErrorKind::InvalidAudience => VerifyError::InvalidAudience,
                _ => VerifyError::InvalidSignature,
            }),
        }
    }

    async fn ensure_cache(&self) -> Result<(), VerifyError> {
        let needs_refresh = {
            let guard = self.cache.read().await;
            match guard.as_ref() {
                None => true,
                Some(c) => {
                    (Utc::now() - c.refreshed_at).num_seconds()
                        > self.config.jwks_cache_ttl_secs as i64
                }
            }
        };
        if needs_refresh {
            self.refresh_jwks().await?;
        }
        Ok(())
    }

    async fn refresh_jwks(&self) -> Result<(), VerifyError> {
        // 1. Discovery doc.
        let discovery_url =
            format!("{}/.well-known/openid-configuration", self.config.issuer);
        let discovery: DiscoveryDoc = self
            .http
            .get(&discovery_url)
            .send()
            .await
            .map_err(|e| VerifyError::DiscoveryFetch(e.to_string()))?
            .error_for_status()
            .map_err(|e| VerifyError::DiscoveryFetch(e.to_string()))?
            .json()
            .await
            .map_err(|e| VerifyError::DiscoveryFetch(e.to_string()))?;

        if discovery.issuer.trim_end_matches('/') != self.config.issuer {
            return Err(VerifyError::DiscoveryFetch(format!(
                "discovery doc issuer {:?} does not match configured OIDC_ISSUER {:?}",
                discovery.issuer, self.config.issuer
            )));
        }

        // 2. JWKS.
        let resp: JwksResponse = self
            .http
            .get(&discovery.jwks_uri)
            .send()
            .await
            .map_err(|e| VerifyError::JwksFetch(e.to_string()))?
            .error_for_status()
            .map_err(|e| VerifyError::JwksFetch(e.to_string()))?
            .json()
            .await
            .map_err(|e| VerifyError::JwksFetch(e.to_string()))?;

        let mut keys = HashMap::new();
        for entry in &resp.keys {
            if entry.kty != "OKP" || entry.crv.as_deref() != Some("Ed25519") {
                continue;
            }
            if entry.key_use.as_deref().is_some_and(|u| u != "sig") {
                continue;
            }
            let Some(x) = &entry.x else { continue };
            match ed25519_spki_pem_from_x(x) {
                Ok(pem) => match DecodingKey::from_ed_pem(pem.as_bytes()) {
                    Ok(key) => {
                        keys.insert(entry.kid.clone(), key);
                    }
                    Err(e) => tracing::warn!(kid = %entry.kid, error = %e, "JWKS key parse"),
                },
                Err(e) => tracing::warn!(kid = %entry.kid, error = %e, "SPKI rebuild"),
            }
        }
        if keys.is_empty() {
            return Err(VerifyError::JwksFetch(
                "no usable Ed25519 keys in JWKS".into(),
            ));
        }

        let mut guard = self.cache.write().await;
        *guard = Some(JwksCache {
            keys,
            jwks_uri: discovery.jwks_uri,
            userinfo_endpoint: discovery.userinfo_endpoint,
            refreshed_at: Utc::now(),
        });
        Ok(())
    }
}

// ── Ed25519 SPKI PEM reconstruction ──────────────────────────────────────────

/// Build a SubjectPublicKeyInfo PEM string from a base64url-encoded 32-byte
/// Ed25519 key. SPKI DER for Ed25519 has a fixed 12-byte header followed by
/// the 32-byte raw key:
///
/// ```text
/// 30 2A 30 05 06 03 2B 65 70 03 21 00 <32 bytes>
/// ```
fn ed25519_spki_pem_from_x(x_b64url: &str) -> Result<String, String> {
    let key_bytes = URL_SAFE_NO_PAD
        .decode(x_b64url)
        .map_err(|e| format!("base64url decode: {e}"))?;
    if key_bytes.len() != 32 {
        return Err(format!(
            "expected 32-byte Ed25519 key, got {}",
            key_bytes.len()
        ));
    }
    const HEADER: [u8; 12] = [
        0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    let mut der = Vec::with_capacity(44);
    der.extend_from_slice(&HEADER);
    der.extend_from_slice(&key_bytes);
    let b64 = STANDARD.encode(&der);
    Ok(format!(
        "-----BEGIN PUBLIC KEY-----\n{b64}\n-----END PUBLIC KEY-----\n"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_spki_pem_length_check() {
        // 16 raw bytes -> 22 base64url chars without padding -> rejected.
        let bad = URL_SAFE_NO_PAD.encode([0u8; 16]);
        assert!(ed25519_spki_pem_from_x(&bad).is_err());
    }

    #[test]
    fn ed25519_spki_pem_round_trip() {
        let raw = [0u8; 32];
        let x_b64 = URL_SAFE_NO_PAD.encode(raw);
        let pem = ed25519_spki_pem_from_x(&x_b64).unwrap();
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        assert!(pem.trim_end().ends_with("-----END PUBLIC KEY-----"));
    }

    #[test]
    fn config_requires_issuer_and_audience() {
        // Run sequentially via a mutex elsewhere if env tests get flaky; for
        // now this just verifies the error path is wired.
        std::env::remove_var("OIDC_ISSUER");
        std::env::remove_var("OIDC_AUDIENCE");
        assert!(VerifierConfig::from_env().is_err());
    }
}
