//! Per-(IP, (tenant_slug, email)) rate limiting for the portal
//! `/auth/login` endpoint (PMS-501).
//!
//! Mirrors `crate::modules::auth::rate_limit::AuthRateLimiter`, but the
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

/// Per-(IP, contact) limiter for the PMS-673 quote decision routes.
///
/// Accepting or declining a quote is a commercial commitment and is not
/// reversible from the client side, so the routes are throttled to blunt
/// both a runaway client retrying a submit and an attacker who has a
/// session and is spraying quote ids. It is a separate limiter from
/// [`PortalLoginLimiter`] rather than a reused one because the buckets
/// mean different things: login throttles credential guessing against an
/// unauthenticated caller, this throttles actions by an already
/// authenticated contact, and sharing quota would let a burst of
/// decisions lock the contact out of logging back in.
///
/// Same in-memory, per-replica caveat as the login limiter: it does not
/// survive a restart and does not coordinate across replicas. The durable
/// guarantee is the state machine, which only accepts a decision from
/// `sent` and 409s every repeat.
pub struct PortalDecisionLimiter {
    by_ip: IpLimiter,
    by_contact: AccountLimiter,
    clock: DefaultClock,
}

impl PortalDecisionLimiter {
    pub fn new() -> Arc<Self> {
        // Deliberately roomier than login: a legitimate contact clicking
        // through several quotes in one sitting must not be throttled,
        // while a script hammering the route still is.
        let ip_quota = Quota::per_minute(NonZeroU32::new(30).expect("30 is non-zero"));
        let contact_quota = Quota::per_minute(NonZeroU32::new(10).expect("10 is non-zero"));
        Arc::new(Self {
            by_ip: RateLimiter::keyed(ip_quota),
            by_contact: RateLimiter::keyed(contact_quota),
            clock: DefaultClock::default(),
        })
    }

    /// Returns `Err(retry_after_seconds)` if either bucket is empty, with
    /// the larger of the two refill waits.
    pub fn check(&self, ip: IpAddr, contact_id: uuid::Uuid) -> Result<(), u64> {
        let mut wait: Option<u64> = None;
        if let Err(neg) = self.by_ip.check_key(&ip) {
            wait = Some(seconds_until(&neg, &self.clock));
        }
        if let Err(neg) = self.by_contact.check_key(&contact_id.to_string()) {
            let secs = seconds_until(&neg, &self.clock);
            wait = Some(wait.map(|w| w.max(secs)).unwrap_or(secs));
        }
        match wait {
            Some(w) => Err(w),
            None => Ok(()),
        }
    }
}

/// Per-IP limiter for the pre-auth `GET /portal/host` branding endpoint.
///
/// PMS-729 nice-to-have: the endpoint is unauthenticated and DB-hitting
/// (one `SELECT ... WHERE slug = $1 AND status = 'active'` per call). A
/// scanner probing many Host headers against the same IP could otherwise
/// walk the tenant list at unlimited RPS; a per-IP bucket keeps that
/// cheap without penalising a legitimate browser (the SPA calls this
/// once per page load).
///
/// Roomier than login (60/min per IP) because a real user's SPA can
/// legitimately re-fetch the hint on every route change; the intent
/// here is to blunt a script, not gate a human. In-memory / per-replica
/// like the other portal limiters.
pub struct PortalHostLimiter {
    by_ip: IpLimiter,
    clock: DefaultClock,
}

impl PortalHostLimiter {
    pub fn new() -> Arc<Self> {
        let ip_quota = Quota::per_minute(NonZeroU32::new(60).expect("60 is non-zero"));
        Arc::new(Self {
            by_ip: RateLimiter::keyed(ip_quota),
            clock: DefaultClock::default(),
        })
    }

    /// Returns `Err(retry_after_seconds)` when the IP bucket is empty,
    /// always at least 1 so a client honouring `Retry-After` never
    /// retries too soon.
    pub fn check(&self, ip: IpAddr) -> Result<(), u64> {
        match self.by_ip.check_key(&ip) {
            Ok(()) => Ok(()),
            Err(neg) => Err(seconds_until(&neg, &self.clock)),
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
    fn host_limiter_blocks_after_quota() {
        let limiter = PortalHostLimiter::new();
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        // 60/min per IP quota: first 60 pass, 61st is throttled.
        for _ in 0..60 {
            assert!(limiter.check(ip).is_ok());
        }
        assert!(limiter.check(ip).is_err());
        // A different IP is unaffected.
        let other: IpAddr = "198.51.100.3".parse().unwrap();
        assert!(limiter.check(other).is_ok());
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
