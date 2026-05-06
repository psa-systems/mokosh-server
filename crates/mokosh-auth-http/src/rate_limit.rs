//! In-memory rate limiting for authentication endpoints.
//!
//! Three keyed governors guard the most-attacked endpoints. Limits are
//! deliberately generous for legitimate traffic and tight enough to
//! make brute-force impractical.
//!
//! For multi-replica deployments these counters live in each replica
//! separately. That is intentional for phase 1: the failure mode is
//! "an attacker gets N times the limit" where N is the replica count,
//! which is still bounded and small. A future iteration can swap the
//! state store for a Redis-backed one without changing the call sites.

use governor::{
    clock::{Clock, DefaultClock},
    state::keyed::DefaultKeyedStateStore,
    Quota, RateLimiter as Governor,
};
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::time::Duration;

type Keyed<K> = Governor<K, DefaultKeyedStateStore<K>, DefaultClock>;

/// What the caller did that should be rate-limited.
#[derive(Debug, Clone, Copy)]
pub enum LoginScope {
    /// Browser POST to `/login`.
    Form,
    /// JSON POST to `/v1/auth/login`.
    Json,
}

#[derive(Clone)]
pub struct RateLimiter {
    /// Login attempts by source IP. Catches single-IP brute-force.
    login_by_ip: std::sync::Arc<Keyed<IpAddr>>,
    /// Login attempts by (lowercase) email. Catches credential-stuffing
    /// from rotating IPs against a single account.
    login_by_email: std::sync::Arc<Keyed<String>>,
    /// All token-endpoint requests by IP. Generous: legitimate clients
    /// refresh every ~10 minutes per session, so 60/min is far above
    /// the honest steady state but well below any meaningful brute
    /// force.
    token_by_ip: std::sync::Arc<Keyed<IpAddr>>,
}

#[derive(Debug, Clone, Copy)]
pub struct RateLimited {
    /// Suggested seconds to wait before the next attempt. Sent back as
    /// the `Retry-After` HTTP header so well-behaved clients can pace.
    pub retry_after_seconds: u64,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        // 10 attempts per minute per IP. The most heavily loaded form.
        let login_ip_quota = Quota::per_minute(nz(10));
        // 5 attempts per 15 minutes per email. Covers credential
        // stuffing where an attacker rotates IPs but not the username.
        let login_email_quota = Quota::with_period(Duration::from_secs(900))
            .expect("non-zero period")
            .allow_burst(nz(5));
        // 60/min per IP for /oauth2/token. Legitimate clients refresh
        // every ~10 minutes per session.
        let token_quota = Quota::per_minute(nz(60));

        Self {
            login_by_ip: std::sync::Arc::new(Governor::keyed(login_ip_quota)),
            login_by_email: std::sync::Arc::new(Governor::keyed(login_email_quota)),
            token_by_ip: std::sync::Arc::new(Governor::keyed(token_quota)),
        }
    }

    /// Check before processing a login request.
    ///
    /// We check both keys so a single hot key (e.g. one IP) does not
    /// shield credential stuffing from rotating IPs against the same
    /// email, and vice versa.
    pub fn check_login(
        &self,
        _scope: LoginScope,
        ip: Option<IpAddr>,
        email: &str,
    ) -> Result<(), RateLimited> {
        if let Some(ip) = ip {
            self.login_by_ip
                .check_key(&ip)
                .map_err(|n| RateLimited::from_negative(&n))?;
        }
        let normalized = email.trim().to_ascii_lowercase();
        if !normalized.is_empty() {
            self.login_by_email
                .check_key(&normalized)
                .map_err(|n| RateLimited::from_negative(&n))?;
        }
        Ok(())
    }

    /// Check before processing a token-endpoint request.
    pub fn check_token(&self, ip: Option<IpAddr>) -> Result<(), RateLimited> {
        if let Some(ip) = ip {
            self.token_by_ip
                .check_key(&ip)
                .map_err(|n| RateLimited::from_negative(&n))?;
        }
        Ok(())
    }
}

impl RateLimited {
    fn from_negative(
        n: &governor::NotUntil<<DefaultClock as Clock>::Instant>,
    ) -> Self {
        // Round up so we never advise a wait shorter than the actual
        // refill interval.
        let nanos = n
            .wait_time_from(DefaultClock::default().now())
            .as_nanos();
        let secs = (nanos.div_ceil(1_000_000_000)) as u64;
        Self {
            retry_after_seconds: secs.max(1),
        }
    }
}

fn nz(n: u32) -> NonZeroU32 {
    NonZeroU32::new(n).expect("static positive limit")
}

impl axum::response::IntoResponse for RateLimited {
    fn into_response(self) -> axum::response::Response {
        use axum::http::{header, StatusCode};
        let body = serde_json::json!({
            "error": "rate_limited",
            "retry_after_seconds": self.retry_after_seconds,
        });
        (
            StatusCode::TOO_MANY_REQUESTS,
            [
                (header::RETRY_AFTER, self.retry_after_seconds.to_string()),
                (header::CONTENT_TYPE, "application/json".to_string()),
                (header::CACHE_CONTROL, "no-store".to_string()),
            ],
            body.to_string(),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn login_by_ip_allows_burst_then_blocks() {
        let rl = RateLimiter::new();
        let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
        // Quota::per_minute(10) allows a burst of 10 immediately. Each
        // attempt uses a DIFFERENT email so the email-keyed bucket
        // (5/15min) does not trip first; we want this test to exercise
        // the IP-keyed limit in isolation.
        for i in 0..10 {
            rl.check_login(LoginScope::Form, Some(ip), &format!("user{i}@example.com"))
                .expect("first 10 attempts allowed");
        }
        // 11th from the same IP should be limited.
        let result = rl.check_login(LoginScope::Form, Some(ip), "user99@example.com");
        assert!(result.is_err(), "11th attempt should be rate-limited");
    }

    #[test]
    fn login_by_email_caps_credential_stuffing() {
        let rl = RateLimiter::new();
        // Five distinct IPs, same email: the email-keyed limiter must
        // still trigger by attempt 6.
        for i in 1u8..=5 {
            let ip: IpAddr = Ipv4Addr::new(10, 0, 0, i).into();
            rl.check_login(LoginScope::Form, Some(ip), "victim@example.com")
                .unwrap();
        }
        let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 6).into();
        let result = rl.check_login(LoginScope::Form, Some(ip), "victim@example.com");
        assert!(result.is_err(), "email-keyed quota must catch IP rotation");
    }

    #[test]
    fn email_normalization_collapses_case_and_padding() {
        let rl = RateLimiter::new();
        // 5 attempts with various capitalisations and surrounding
        // whitespace must all count toward the same email-keyed bucket.
        for (i, email) in [
            "victim@example.com",
            "VICTIM@example.com",
            "  victim@Example.com  ",
            "Victim@example.com",
            "victim@EXAMPLE.COM",
        ]
        .iter()
        .enumerate()
        {
            let ip: IpAddr = Ipv4Addr::new(10, 0, 1, i as u8).into();
            rl.check_login(LoginScope::Form, Some(ip), email)
                .expect("first 5 allowed");
        }
        let ip: IpAddr = Ipv4Addr::new(10, 0, 1, 99).into();
        let result = rl.check_login(LoginScope::Form, Some(ip), "victim@example.com");
        assert!(result.is_err(), "case-folded email collapses to one bucket");
    }
}
