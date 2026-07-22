//! Per-(IP, email-lowercased) rate limiting for the unauthenticated auth
//! endpoints (`/auth/login`, `/auth/forgot-password`).
//!
//! Audit F2 (P0) closeout / PMS-4 AC2 (login) and PMS-680 (forgot-password).
//! Two keyed buckets are consulted on every attempt: one keyed by source IP
//! (covers NAT'd offices where several users legitimately act inside the same
//! minute), one keyed by lowercased email (the account-level cap). Either being
//! over-quota returns 429 with a `Retry-After` header carrying the longer of
//! the two refill times. Quotas are per-endpoint (login is more frequent than a
//! password-reset request), so each endpoint constructs its own limiter with
//! its own numbers and its own buckets - one endpoint's traffic never consumes
//! another's quota.
//!
//! In-memory state only; will not survive a server restart and does
//! not coordinate across replicas. Acceptable for the single-process
//! deployment; horizontal scale needs a Redis-backed store.

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use governor::clock::{Clock, DefaultClock};
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};

pub type IpLimiter = RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>;
pub type EmailLimiter = RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>;

/// Bundled per-(IP, email) limiters for an unauthenticated auth endpoint.
/// Stash the resulting `Arc` in `AuthRouterState` and call `check` at the top
/// of the handler. Construct one per endpoint with [`AuthRateLimiter::new`] so
/// login and forgot-password keep independent quotas and buckets.
pub struct AuthRateLimiter {
    by_ip: IpLimiter,
    by_email: EmailLimiter,
    clock: DefaultClock,
}

impl AuthRateLimiter {
    /// Build a limiter that allows `ip_per_min` attempts per source IP and
    /// `email_per_min` attempts per lowercased email each minute. Both must be
    /// non-zero (callers pass compile-time literals).
    pub fn new(ip_per_min: u32, email_per_min: u32) -> Arc<Self> {
        let ip_quota =
            Quota::per_minute(NonZeroU32::new(ip_per_min).expect("ip quota must be non-zero"));
        let email_quota = Quota::per_minute(
            NonZeroU32::new(email_per_min).expect("email quota must be non-zero"),
        );
        Arc::new(Self {
            by_ip: RateLimiter::keyed(ip_quota),
            by_email: RateLimiter::keyed(email_quota),
            clock: DefaultClock::default(),
        })
    }

    /// Returns `Err(retry_after_seconds)` if either bucket is empty.
    /// The seconds value is the larger of the two refill waits and is
    /// always at least 1, so a client honouring `Retry-After` never
    /// retries too soon.
    pub fn check(&self, ip: IpAddr, email_raw: &str) -> Result<(), u64> {
        let mut wait: Option<u64> = None;
        if let Err(neg) = self.by_ip.check_key(&ip) {
            wait = Some(seconds_until(&neg, &self.clock));
        }
        let normalized = email_raw.trim().to_ascii_lowercase();
        if !normalized.is_empty() {
            if let Err(neg) = self.by_email.check_key(&normalized) {
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

fn seconds_until(
    n: &governor::NotUntil<<DefaultClock as Clock>::Instant>,
    clock: &DefaultClock,
) -> u64 {
    let d: Duration = n.wait_time_from(clock.now());
    let nanos = d.as_nanos();
    let secs = (nanos.div_ceil(1_000_000_000)) as u64;
    secs.max(1)
}
