//! Per-IP attempt budget for the two unauthenticated contact credential
//! routes: `POST /auth/login` and `POST /auth/login-link/redeem`.
//!
//! The per-contact lockout only sees an email that resolves to a contact, so
//! an enumerating or spraying caller was never limited at the IP level. This
//! budget is consulted BEFORE any lookup, so a refusal reveals nothing about
//! whether an email exists. Every attempt spends it, success included: a
//! success does not reset the window.
//!
//! In memory and per process, like the other IP limiters: a restart empties
//! it and replicas do not share it, which the per-contact lockout covers.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Hard cap on tracked IPs. Past it, expired windows are swept so a spray from
/// many addresses cannot grow the map without bound.
const MAX_TRACKED_IPS: usize = 100_000;

struct Window {
    started: Instant,
    count: u32,
}

/// Fixed-window counter keyed by client IP.
pub struct ContactLoginLimiter {
    max: u32,
    window: Duration,
    by_ip: Mutex<HashMap<IpAddr, Window>>,
}

impl ContactLoginLimiter {
    pub fn new(max: u32, window_secs: u64) -> Arc<Self> {
        Arc::new(Self {
            max,
            window: Duration::from_secs(window_secs),
            by_ip: Mutex::new(HashMap::new()),
        })
    }

    /// Build from `CONTACT_LOGIN_IP_RATE_MAX` / `CONTACT_LOGIN_IP_RATE_WINDOW_SECS`,
    /// defaulting to 10 attempts per 60 seconds. A malformed, zero or negative
    /// value is an `Err` naming the key, for the caller to refuse boot on.
    // SPEC-6.104
    pub fn from_config() -> Result<Arc<Self>, String> {
        use crate::config::{self, parse::parse_positive, registry as keys};
        let max = parse_positive::<u32>(
            &keys::CONTACT_LOGIN_IP_RATE_MAX,
            config::get(&keys::CONTACT_LOGIN_IP_RATE_MAX),
        )?
        .unwrap_or(10);
        let window = parse_positive::<u64>(
            &keys::CONTACT_LOGIN_IP_RATE_WINDOW_SECS,
            config::get(&keys::CONTACT_LOGIN_IP_RATE_WINDOW_SECS),
        )?
        .unwrap_or(60);
        Ok(Self::new(max, window))
    }

    /// Spend one attempt for `ip`. `Err(retry_after_seconds)` when the budget
    /// for the current window is already spent.
    pub fn check(&self, ip: IpAddr) -> Result<(), u64> {
        self.check_at(ip, Instant::now())
    }

    fn check_at(&self, ip: IpAddr, now: Instant) -> Result<(), u64> {
        let mut map = self.by_ip.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() >= MAX_TRACKED_IPS && !map.contains_key(&ip) {
            map.retain(|_, w| now.saturating_duration_since(w.started) < self.window);
        }
        let entry = map.entry(ip).or_insert(Window {
            started: now,
            count: 0,
        });
        if now.saturating_duration_since(entry.started) >= self.window {
            entry.started = now;
            entry.count = 0;
        }
        if entry.count >= self.max {
            let remaining = self
                .window
                .saturating_sub(now.saturating_duration_since(entry.started));
            // SPEC-5.103: the wait rounds up, never under-reports, minimum 1.
            let secs = remaining.as_secs() + u64::from(remaining.subsec_nanos() > 0);
            return Err(secs.max(1));
        }
        entry.count += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test IP parses")
    }

    #[test]
    fn first_ten_pass_and_the_eleventh_is_refused() {
        let limiter = ContactLoginLimiter::new(10, 60);
        let now = Instant::now();
        for _ in 0..10 {
            assert!(limiter.check_at(ip("203.0.113.7"), now).is_ok());
        }
        assert_eq!(limiter.check_at(ip("203.0.113.7"), now), Err(60));
    }

    #[test]
    fn the_window_expiring_resets_the_budget() {
        let limiter = ContactLoginLimiter::new(2, 60);
        let start = Instant::now();
        assert!(limiter.check_at(ip("203.0.113.7"), start).is_ok());
        assert!(limiter.check_at(ip("203.0.113.7"), start).is_ok());
        assert!(limiter.check_at(ip("203.0.113.7"), start).is_err());
        let later = start + Duration::from_secs(60);
        assert!(limiter.check_at(ip("203.0.113.7"), later).is_ok());
    }

    #[test]
    fn two_ips_do_not_share_a_budget() {
        let limiter = ContactLoginLimiter::new(1, 60);
        let now = Instant::now();
        assert!(limiter.check_at(ip("203.0.113.7"), now).is_ok());
        assert!(limiter.check_at(ip("203.0.113.7"), now).is_err());
        assert!(limiter.check_at(ip("198.51.100.9"), now).is_ok());
    }

    #[test]
    fn the_wait_rounds_up_and_is_never_zero() {
        let limiter = ContactLoginLimiter::new(1, 60);
        let start = Instant::now();
        assert!(limiter.check_at(ip("203.0.113.7"), start).is_ok());
        // 58.6s elapsed leaves 1.4s: reports 2, not 1.
        let t = start + Duration::from_millis(58_600);
        assert_eq!(limiter.check_at(ip("203.0.113.7"), t), Err(2));
        // 59.9s elapsed leaves 0.1s: reports 1, not 0.
        let t = start + Duration::from_millis(59_900);
        assert_eq!(limiter.check_at(ip("203.0.113.7"), t), Err(1));
    }

    #[test]
    fn a_full_map_sheds_expired_windows() {
        let limiter = ContactLoginLimiter::new(1, 60);
        let start = Instant::now();
        {
            let mut map = limiter.by_ip.lock().expect("lock");
            for i in 0..MAX_TRACKED_IPS as u32 {
                map.insert(
                    IpAddr::from(std::net::Ipv4Addr::from(i)),
                    Window {
                        started: start,
                        count: 1,
                    },
                );
            }
        }
        let later = start + Duration::from_secs(61);
        assert!(limiter.check_at(ip("203.0.113.7"), later).is_ok());
        assert_eq!(limiter.by_ip.lock().expect("lock").len(), 1);
    }
}
