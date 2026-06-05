//! Per-(IP, email-lowercased) rate limiting for `/auth/login`.
//!
//! Audit F2 (P0) closeout / PMS-4 AC2. Two keyed buckets are consulted
//! on every login attempt: one keyed by source IP (20/min, covers
//! NAT'd offices where several users legitimately log in inside the
//! same minute), one keyed by lowercased email (5/min, the
//! account-level cap the audit asked for). Either being over-quota
//! returns 429 with a `Retry-After` header carrying the longer of the
//! two refill times.
//!
//! In-memory state only; will not survive a server restart and does
//! not coordinate across replicas. Acceptable for the single-process
//! deployment; horizontal scale needs a Redis-backed store.
//!
//! Modelled on `crates/mokosh-auth-http/src/rate_limit.rs:270-310`.

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use governor::clock::{Clock, DefaultClock};
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};

pub type IpLimiter = RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>;
pub type EmailLimiter = RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>;

/// Bundled limiters. Stash the resulting `Arc` in `AuthRouterState` and
/// call `check` at the top of the login handler.
pub struct LoginLimiter {
    by_ip: IpLimiter,
    by_email: EmailLimiter,
    clock: DefaultClock,
}

impl LoginLimiter {
    pub fn new() -> Arc<Self> {
        let ip_quota = Quota::per_minute(NonZeroU32::new(20).expect("20 is non-zero"));
        let email_quota = Quota::per_minute(NonZeroU32::new(5).expect("5 is non-zero"));
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
