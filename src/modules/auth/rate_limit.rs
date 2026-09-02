//! Rate limiting for the auth endpoints: per-(IP, email-lowercased) for the
//! unauthenticated ones (`/auth/login`, `/auth/forgot-password`), and
//! per-(IP, user id) for the authenticated password re-auth
//! ([`ReauthRateLimiter`], PMS-881).
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

use std::collections::HashMap;
use std::hash::Hash;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use governor::clock::{Clock, DefaultClock};
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};
use uuid::Uuid;

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

/// Fixed one-minute window for [`ReauthRateLimiter`], the unit its quotas are
/// stated in.
const REAUTH_WINDOW: Duration = Duration::from_secs(60);

/// Failure-counted limiter for the authenticated password re-auth on
/// `PUT /auth/me/password` and `POST /auth/me/mfa/disable` (PMS-881, audit F6).
///
/// Two things it does that [`AuthRateLimiter`] cannot, both required here.
/// Budget is spent by a FAILED re-auth only, so a user who types their password
/// correctly never spends any and cannot lock themselves out of their own
/// settings screen; and the quota is consulted BEFORE the credential check, so
/// an exhausted budget stops the password comparison happening at all rather
/// than merely reporting it differently. `governor`'s `check_key` is
/// check-and-spend in one call and offers no peek, so it gives neither: hence
/// the plain windowed counter below rather than a third `AuthRateLimiter`.
///
/// The account bucket is keyed by `users.id`, not by a submitted email: both
/// routes run behind `RequireAuth`, so the account is the caller's own and
/// there is nothing to spoof. One instance is shared by both routes on purpose
/// (they re-check the same credential), so grinding the password through
/// `disable_mfa` after exhausting `change_password` does not reset the budget.
///
/// Same in-memory, per-replica caveat as the limiters above: the counters do
/// not survive a restart and do not coordinate across replicas.
pub struct ReauthRateLimiter {
    ip_per_min: u32,
    account_per_min: u32,
    window: Duration,
    state: Mutex<Buckets>,
}

#[derive(Default)]
struct Buckets {
    by_ip: HashMap<IpAddr, Window>,
    by_account: HashMap<Uuid, Window>,
}

/// Failures recorded for one key since `started`.
#[derive(Clone, Copy)]
struct Window {
    started: Instant,
    failures: u32,
}

impl ReauthRateLimiter {
    /// Build a limiter allowing `ip_per_min` failed re-auths per source IP and
    /// `account_per_min` per user id each minute. Both must be non-zero
    /// (callers pass compile-time literals).
    pub fn new(ip_per_min: u32, account_per_min: u32) -> Arc<Self> {
        Self::with_window(ip_per_min, account_per_min, REAUTH_WINDOW)
    }

    fn with_window(ip_per_min: u32, account_per_min: u32, window: Duration) -> Arc<Self> {
        assert!(
            ip_per_min > 0 && account_per_min > 0,
            "re-auth quotas must be non-zero"
        );
        Arc::new(Self {
            ip_per_min,
            account_per_min,
            window,
            state: Mutex::new(Buckets::default()),
        })
    }

    /// Returns `Err(retry_after_seconds)` when either bucket has already spent
    /// its quota of failures in the current window, with the larger of the two
    /// remaining waits and always at least 1. Records nothing: call
    /// [`Self::record_failure`] once the re-auth is known to have failed.
    pub fn check(&self, ip: IpAddr, account: Uuid) -> Result<(), u64> {
        let now = Instant::now();
        let buckets = self.buckets();
        let ip_wait = buckets
            .by_ip
            .get(&ip)
            .and_then(|w| self.retry_after(w, self.ip_per_min, now));
        let account_wait = buckets
            .by_account
            .get(&account)
            .and_then(|w| self.retry_after(w, self.account_per_min, now));
        match ip_wait.into_iter().chain(account_wait).max() {
            Some(w) => Err(w),
            None => Ok(()),
        }
    }

    /// Charge one failed re-auth to both buckets.
    pub fn record_failure(&self, ip: IpAddr, account: Uuid) {
        let now = Instant::now();
        let window = self.window;
        let mut buckets = self.buckets();
        // Expired entries go on the way in. An entry only ever exists because
        // of a failure, so the sweep is bounded by the failures in one window
        // and the maps cannot grow with ordinary traffic.
        buckets
            .by_ip
            .retain(|_, w| now.saturating_duration_since(w.started) < window);
        buckets
            .by_account
            .retain(|_, w| now.saturating_duration_since(w.started) < window);
        bump(&mut buckets.by_ip, ip, now);
        bump(&mut buckets.by_account, account, now);
    }

    /// Seconds left in `w`'s window once `quota` failures have been spent, or
    /// `None` while the key is still under quota or its window has passed.
    fn retry_after(&self, w: &Window, quota: u32, now: Instant) -> Option<u64> {
        let elapsed = now.saturating_duration_since(w.started);
        if elapsed >= self.window || w.failures < quota {
            return None;
        }
        let left = self.window - elapsed;
        Some((left.as_nanos().div_ceil(1_000_000_000) as u64).max(1))
    }

    fn buckets(&self) -> MutexGuard<'_, Buckets> {
        // A panic while this lock is held can only leave failure counters
        // behind, and failing open on the path this guards is worse than
        // reusing them, so recover the state - loudly, since a poisoned lock
        // means something else already panicked.
        self.state.lock().unwrap_or_else(|poisoned| {
            tracing::warn!("re-auth rate-limit state was poisoned by an earlier panic; recovering");
            poisoned.into_inner()
        })
    }
}

fn bump<K: Eq + Hash>(map: &mut HashMap<K, Window>, key: K, now: Instant) {
    map.entry(key)
        .and_modify(|w| w.failures = w.failures.saturating_add(1))
        .or_insert(Window {
            started: now,
            failures: 1,
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test IP parses")
    }

    #[test]
    fn success_never_spends_budget() {
        // 10/min per IP, 5/min per account: a thousand calls that never report
        // a failure stay under both, because nothing charged them.
        let limiter = ReauthRateLimiter::new(10, 5);
        let user = Uuid::new_v4();
        for _ in 0..1000 {
            assert!(limiter.check(ip("203.0.113.9"), user).is_ok());
        }
    }

    #[test]
    fn account_bucket_blocks_after_its_quota_of_failures() {
        let limiter = ReauthRateLimiter::new(100, 5);
        let user = Uuid::new_v4();
        let peer = ip("203.0.113.9");
        for _ in 0..5 {
            assert!(limiter.check(peer, user).is_ok());
            limiter.record_failure(peer, user);
        }
        let retry_after = limiter
            .check(peer, user)
            .expect_err("the sixth attempt is over the 5/min account quota");
        assert!(retry_after >= 1, "Retry-After is at least one second");
        // Another user from the same IP still has the IP quota's headroom.
        assert!(limiter.check(peer, Uuid::new_v4()).is_ok());
    }

    #[test]
    fn ip_bucket_blocks_after_its_quota_of_failures() {
        // Account quota high enough that only the IP bucket can trip.
        let limiter = ReauthRateLimiter::new(3, 100);
        let peer = ip("203.0.113.9");
        for _ in 0..3 {
            let user = Uuid::new_v4();
            assert!(limiter.check(peer, user).is_ok());
            limiter.record_failure(peer, user);
        }
        assert!(
            limiter.check(peer, Uuid::new_v4()).is_err(),
            "a fourth failing account from the same IP is over the 3/min IP quota"
        );
        // A different IP is unaffected.
        assert!(limiter.check(ip("198.51.100.4"), Uuid::new_v4()).is_ok());
    }

    #[test]
    fn window_refills() {
        let limiter = ReauthRateLimiter::with_window(10, 1, Duration::from_millis(30));
        let user = Uuid::new_v4();
        let peer = ip("203.0.113.9");
        limiter.record_failure(peer, user);
        assert!(limiter.check(peer, user).is_err(), "quota of 1 is spent");
        std::thread::sleep(Duration::from_millis(40));
        assert!(
            limiter.check(peer, user).is_ok(),
            "the window has passed, so the budget is back"
        );
    }
}
