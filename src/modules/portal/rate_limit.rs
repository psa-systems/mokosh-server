//! Per-(IP, (tenant_slug, email)) rate limiting for the portal
//! `/auth/login` endpoint (PMS-501).
//!
//! Mirrors `crate::modules::auth::rate_limit::LoginLimiter`, but the
//! account bucket is keyed by `(tenant_slug, email)` rather than by email
//! alone: portal `contacts.email` is only unique within a tenant, so two
//! tenants can legitimately host the same customer email and must not
//! share one quota. Two keyed buckets are consulted on every attempt: one
//! keyed by source IP (20/min, covers NAT'd offices), one keyed by the
//! lowercased `(slug, email)` pair (5/min, the account-level cap). Either
//! being over-quota returns 429 with a `Retry-After` header carrying the
//! longer of the two refill times.
//!
//! In-memory state only; it does not survive a restart and does not
//! coordinate across replicas. The persistent half of the PMS-501
//! remediation (the failed-attempt counter + `portal_locked_until`
//! lockout on the `contacts` row) lives in [`super::service`] and IS
//! durable; this limiter is the cheap first line that also throttles
//! guesses against non-existent accounts (which have no row to lock).

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use governor::clock::{Clock, DefaultClock};
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};

type IpLimiter = RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>;
type AccountLimiter = RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>;

/// Bundled portal-login limiters. Stash the resulting `Arc` in
/// `PortalRouterState` and call [`PortalLoginLimiter::check`] at the top
/// of the login handler.
pub struct PortalLoginLimiter {
    by_ip: IpLimiter,
    by_account: AccountLimiter,
    clock: DefaultClock,
}

impl PortalLoginLimiter {
    pub fn new() -> Arc<Self> {
        let ip_quota = Quota::per_minute(NonZeroU32::new(20).expect("20 is non-zero"));
        let account_quota = Quota::per_minute(NonZeroU32::new(5).expect("5 is non-zero"));
        Arc::new(Self {
            by_ip: RateLimiter::keyed(ip_quota),
            by_account: RateLimiter::keyed(account_quota),
            clock: DefaultClock::default(),
        })
    }

    /// Returns `Err(retry_after_seconds)` if either bucket is empty. The
    /// seconds value is the larger of the two refill waits and is always
    /// at least 1, so a client honouring `Retry-After` never retries too
    /// soon.
    pub fn check(&self, ip: IpAddr, tenant_slug: &str, email_raw: &str) -> Result<(), u64> {
        let mut wait: Option<u64> = None;
        if let Err(neg) = self.by_ip.check_key(&ip) {
            wait = Some(seconds_until(&neg, &self.clock));
        }
        let key = account_key(tenant_slug, email_raw);
        if !key.is_empty() {
            if let Err(neg) = self.by_account.check_key(&key) {
                let secs = seconds_until(&neg, &self.clock);
                wait = Some(wait.map(|w| w.max(secs)).unwrap_or(secs));
            }
        }
        match wait {
            Some(w) => Err(w),
            None => Ok(()),
        }
    }
}

/// Normalised `(tenant_slug, email)` bucket key. Both halves are trimmed
/// and lowercased so casing/whitespace cannot dodge the quota; a NUL byte
/// separates them so `("ab", "c")` and `("a", "bc")` never collide.
/// Returns an empty string when both halves are blank (nothing to key on).
fn account_key(tenant_slug: &str, email_raw: &str) -> String {
    let slug = tenant_slug.trim().to_ascii_lowercase();
    let email = email_raw.trim().to_ascii_lowercase();
    if slug.is_empty() && email.is_empty() {
        return String::new();
    }
    format!("{slug}\u{0}{email}")
}

fn seconds_until(
    n: &governor::NotUntil<<DefaultClock as Clock>::Instant>,
    clock: &DefaultClock,
) -> u64 {
    let d: Duration = n.wait_time_from(clock.now());
    let nanos = d.as_nanos();
    let secs = (nanos.div_ceil(1_000_000_000)) as u64;
    secs.max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_key_distinguishes_tenant() {
        // Same email, different tenant slug -> different bucket.
        assert_ne!(
            account_key("acme", "bob@example.com"),
            account_key("globex", "bob@example.com")
        );
    }

    #[test]
    fn account_key_is_case_and_space_insensitive() {
        assert_eq!(
            account_key("Acme", " Bob@Example.com "),
            account_key("acme", "bob@example.com")
        );
    }

    #[test]
    fn account_key_no_split_collision() {
        // The NUL separator prevents ("ab","c") colliding with ("a","bc").
        assert_ne!(account_key("ab", "c"), account_key("a", "bc"));
    }

    #[test]
    fn account_bucket_blocks_sixth_attempt() {
        let limiter = PortalLoginLimiter::new();
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        // 5/min account quota: first five pass, the sixth is throttled.
        for _ in 0..5 {
            assert!(limiter.check(ip, "acme", "bob@example.com").is_ok());
        }
        assert!(limiter.check(ip, "acme", "bob@example.com").is_err());
        // A different account on the same IP is unaffected by the account
        // bucket (the per-IP quota is 20/min, so still has headroom).
        assert!(limiter.check(ip, "acme", "alice@example.com").is_ok());
    }
}
