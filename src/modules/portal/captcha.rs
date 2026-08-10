//! PMS-729 phase 2 H8: Cloudflare Turnstile challenge on portal login.
//!
//! Per-account (PMS-501) + per-IP-and-account (PMS-501) rate limits
//! catch a targeted brute-force against ONE account. Neither catches a
//! wide-spray attack from a single IP against MANY accounts: each
//! target account stays under its own 5/min ceiling, but the same IP
//! can spend 100+ attempts/hour churning through the tenant.
//!
//! This module adds a third tier: a moving-window failure counter per
//! IP. When the count crosses [`TurnstileConfig::trigger_threshold`],
//! the login handler requires the caller to solve a Turnstile
//! challenge before spending an Argon2 verify. A successful solve
//! clears the counter for that IP.
//!
//! # Feature gate
//!
//! Off by default. Setting BOTH `TURNSTILE_SITE_KEY` (client-facing)
//! and `TURNSTILE_SECRET_KEY` (server-side) enables the module; either
//! one missing keeps the surface exactly as it was pre-H8 (failure
//! counter still ticks, but the challenge is never required).
//!
//! The site key is exposed to the SPA via
//! `window.__MOKOSH_CONFIG__.turnstile_site_key`; the secret key is
//! server-only and never leaves this process.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use moka::future::Cache;
use serde::Deserialize;

/// Default trigger threshold: 100 failed attempts in a rolling 1-hour
/// window per source IP. Under this, no challenge is required. Above
/// this, the login handler rejects with `CAPTCHA_REQUIRED` unless a
/// valid `cf-turnstile-response` accompanies the request. Matches the
/// D6 recommendation in `docs/mokosh-client-login/phase-2-plan.md §5.3`.
pub const DEFAULT_TRIGGER_THRESHOLD: u32 = 100;

/// How long a failure entry persists in the per-IP counter. 1 hour
/// matches the trigger-threshold window: an IP that stops attacking
/// stops needing a challenge after the counter drains.
const FAILURE_WINDOW: Duration = Duration::from_secs(60 * 60);

/// Cloudflare's canonical siteverify endpoint. Documented at
/// <https://developers.cloudflare.com/turnstile/get-started/server-side-validation/>.
const SITEVERIFY_URL: &str = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

/// Boot-time configuration for the Turnstile gate. Empty
/// `secret_key`/`site_key` disables the challenge entirely (failure
/// counter still runs so the future toggle-on has warm state).
#[derive(Clone, Debug)]
pub struct TurnstileConfig {
    pub site_key: String,
    pub secret_key: String,
    pub trigger_threshold: u32,
}

impl TurnstileConfig {
    /// Read config from env. Both env vars empty = feature off; the
    /// portal keeps its pre-H8 behaviour.
    pub fn from_env() -> Self {
        let site_key = std::env::var("TURNSTILE_SITE_KEY").unwrap_or_default();
        let secret_key = std::env::var("TURNSTILE_SECRET_KEY").unwrap_or_default();
        let trigger_threshold = std::env::var("TURNSTILE_TRIGGER_THRESHOLD")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_TRIGGER_THRESHOLD);
        Self {
            site_key,
            secret_key,
            trigger_threshold,
        }
    }

    /// Test-only constructor so tests can wire a custom threshold + a
    /// stubbed secret without touching process env.
    pub fn for_test(site_key: &str, secret_key: &str, trigger_threshold: u32) -> Self {
        Self {
            site_key: site_key.to_string(),
            secret_key: secret_key.to_string(),
            trigger_threshold,
        }
    }

    /// `true` when both keys are set. When false, the login handler
    /// never demands a challenge (but the failure counter still ticks
    /// so operators can inspect it, and a future toggle-on has warm
    /// state).
    pub fn is_enabled(&self) -> bool {
        !self.site_key.is_empty() && !self.secret_key.is_empty()
    }
}

/// Per-IP failure counter + Turnstile verifier. Cheap to clone (Arc'd
/// cache + the config); lives on `PortalRouterState`.
#[derive(Clone)]
pub struct TurnstileGate {
    config: TurnstileConfig,
    failures: Cache<IpAddr, u32>,
    http: reqwest::Client,
}

impl TurnstileGate {
    /// Build the gate with the supplied config. Uses a moka cache
    /// sized for reasonable operator scale (10k distinct IPs in the
    /// window; entries evict on TTL regardless).
    pub fn new(config: TurnstileConfig) -> Arc<Self> {
        let failures = Cache::builder()
            .time_to_live(FAILURE_WINDOW)
            .max_capacity(10_000)
            .build();
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .build()
            .expect("build reqwest client");
        Arc::new(Self {
            config,
            failures,
            http,
        })
    }

    /// Called at the top of `login` BEFORE the credential check.
    /// Returns `Ok(())` when the caller may proceed (either the
    /// threshold is not yet crossed, or a valid Turnstile token was
    /// supplied), and `Err(TurnstileError::Required)` when the caller
    /// must solve a challenge first. On a supplied-but-invalid token
    /// returns `Err(TurnstileError::Invalid)`.
    pub async fn gate(&self, ip: IpAddr, token: Option<&str>) -> Result<(), TurnstileError> {
        // Feature off = allow.
        if !self.config.is_enabled() {
            return Ok(());
        }
        let count = self.failures.get(&ip).await.unwrap_or(0);
        if count < self.config.trigger_threshold {
            return Ok(());
        }
        // Threshold crossed. Require a token.
        let Some(token) = token.filter(|s| !s.is_empty()) else {
            return Err(TurnstileError::Required);
        };
        if self.verify(token, ip).await {
            // Successful solve resets the counter so a legitimate
            // human is not stuck in the "prove it every request" loop.
            self.failures.invalidate(&ip).await;
            Ok(())
        } else {
            Err(TurnstileError::Invalid)
        }
    }

    /// Increment the per-IP failure counter. Called from the login
    /// handler AFTER a credential failure but BEFORE returning the 401
    /// so the next attempt from this IP is more likely to trip the
    /// challenge. Idempotent on a fresh entry (creates it at 1).
    pub async fn record_failure(&self, ip: IpAddr) {
        // moka's atomic upsert: fetch existing value + add 1, or
        // insert 1. `entry().or_insert` returns a handle we don't
        // need, so bind + drop.
        let _ = self
            .failures
            .entry(ip)
            .and_upsert_with(|maybe_entry| async move {
                maybe_entry.map(|e| e.into_value() + 1).unwrap_or(1)
            })
            .await;
    }

    /// The public site key (for the SPA to pass to the Turnstile
    /// widget). Never returns the secret key; callers that need to
    /// verify go through [`gate`].
    pub fn site_key(&self) -> &str {
        &self.config.site_key
    }

    /// Ask Cloudflare's siteverify endpoint to validate the presented
    /// token against the configured secret. Returns `true` iff the
    /// response body is `{ "success": true, ... }`. Any transport
    /// failure or non-success response returns `false` (fail-closed).
    async fn verify(&self, token: &str, remote_ip: IpAddr) -> bool {
        let form = [
            ("secret", self.config.secret_key.as_str()),
            ("response", token),
            ("remoteip", &remote_ip.to_string()),
        ];
        match self.http.post(SITEVERIFY_URL).form(&form).send().await {
            Ok(resp) => match resp.json::<SiteverifyResponse>().await {
                Ok(body) => body.success,
                Err(e) => {
                    tracing::warn!(
                        ?e,
                        "turnstile siteverify: response body did not deserialize"
                    );
                    false
                }
            },
            Err(e) => {
                tracing::warn!(?e, "turnstile siteverify: HTTP call failed");
                false
            }
        }
    }
}

/// Shape of the Cloudflare siteverify response. Only `success` is
/// consumed; `error-codes` etc. are logged from the failure path but
/// not surfaced to the caller.
#[derive(Debug, Deserialize)]
struct SiteverifyResponse {
    success: bool,
}

/// What went wrong when [`TurnstileGate::gate`] rejected a request.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TurnstileError {
    /// Threshold crossed AND no token supplied. The SPA needs to
    /// render the widget and retry with the response token.
    #[error("captcha challenge required")]
    Required,
    /// Threshold crossed AND a token was supplied but failed
    /// verification (expired, forged, or Cloudflare said no).
    #[error("captcha challenge invalid")]
    Invalid,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn feature_off_never_requires_a_challenge() {
        let cfg = TurnstileConfig::for_test("", "", 1);
        let gate = TurnstileGate::new(cfg);
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        // Even after crossing the threshold, gate allows through.
        gate.record_failure(ip).await;
        gate.record_failure(ip).await;
        assert_eq!(gate.gate(ip, None).await, Ok(()));
    }

    #[tokio::test]
    async fn under_threshold_no_challenge_required() {
        let cfg = TurnstileConfig::for_test("site", "secret", 3);
        let gate = TurnstileGate::new(cfg);
        let ip: IpAddr = "203.0.113.8".parse().unwrap();
        gate.record_failure(ip).await;
        gate.record_failure(ip).await;
        assert_eq!(gate.gate(ip, None).await, Ok(()));
    }

    #[tokio::test]
    async fn over_threshold_no_token_returns_required() {
        let cfg = TurnstileConfig::for_test("site", "secret", 2);
        let gate = TurnstileGate::new(cfg);
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        gate.record_failure(ip).await;
        gate.record_failure(ip).await;
        assert_eq!(gate.gate(ip, None).await, Err(TurnstileError::Required));
    }

    #[tokio::test]
    async fn feature_off_still_ticks_the_counter() {
        // So a future toggle-on picks up warm state.
        let cfg = TurnstileConfig::for_test("", "", 2);
        let gate = TurnstileGate::new(cfg);
        let ip: IpAddr = "203.0.113.10".parse().unwrap();
        gate.record_failure(ip).await;
        gate.record_failure(ip).await;
        assert_eq!(gate.failures.get(&ip).await, Some(2));
    }

    #[tokio::test]
    async fn is_enabled_requires_both_keys() {
        assert!(!TurnstileConfig::for_test("", "", 100).is_enabled());
        assert!(!TurnstileConfig::for_test("site", "", 100).is_enabled());
        assert!(!TurnstileConfig::for_test("", "secret", 100).is_enabled());
        assert!(TurnstileConfig::for_test("site", "secret", 100).is_enabled());
    }
}
