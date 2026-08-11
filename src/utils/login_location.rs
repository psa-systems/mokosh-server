//! Post-code-review finding #10: shared login-location predicate + decision.
//!
//! The agent side (`src/modules/auth/service.rs`) and the portal side
//! (`src/modules/portal/service.rs`) each carried a byte-for-byte
//! duplicate of `is_non_public_ip` + `login_location_decision` +
//! `LoginLocationDecision`. Any change to the private-range set (see
//! finding #9's IPv4-mapped-v6 fix) or the alert threshold had to land
//! in both places or one path stayed vulnerable. This module owns the
//! single source of truth.

use std::net::IpAddr;

/// What the login handler should do about a login-location observation.
///
/// - `Record` on a first login (`previous == None`): stamp the country
///   on the row without emailing.
/// - `Unchanged` when the caller is signing in from the same country
///   we last observed: no-op.
/// - `Alert` when the country changed: fire the new-sign-in email.
///
/// `NotApplicable` was deliberately kept as a separate return from
/// `is_non_public_ip` so the caller can short-circuit before even
/// running the GeoIP lookup; this enum only covers the "we have a
/// country" branches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginLocationDecision {
    Record,
    Unchanged,
    Alert,
}

pub fn login_location_decision(previous: Option<&str>, current: &str) -> LoginLocationDecision {
    match previous {
        None => LoginLocationDecision::Record,
        Some(prev) if prev == current => LoginLocationDecision::Unchanged,
        Some(_) => LoginLocationDecision::Alert,
    }
}

/// Private / loopback / link-local / unspecified / broadcast addresses
/// can never map to a public country. Skip them so a request behind a
/// misconfigured proxy (or in dev) does not register as a country
/// change.
///
/// Handles the IPv4-mapped-IPv6 case (`::ffff:a.b.c.d`) that the v6
/// predicates alone miss - see post-code-review finding #9.
pub fn is_non_public_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_non_public_ip(&IpAddr::V4(v4));
            }
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_first_login_records() {
        assert_eq!(
            login_location_decision(None, "US"),
            LoginLocationDecision::Record
        );
    }

    #[test]
    fn decision_same_country_is_unchanged() {
        assert_eq!(
            login_location_decision(Some("GB"), "GB"),
            LoginLocationDecision::Unchanged
        );
    }

    #[test]
    fn decision_country_change_alerts() {
        assert_eq!(
            login_location_decision(Some("US"), "FR"),
            LoginLocationDecision::Alert
        );
    }

    #[test]
    fn public_ipv4_is_geolocatable() {
        assert!(!is_non_public_ip(&"203.0.113.7".parse().unwrap()));
    }

    #[test]
    fn private_ipv4_ranges_are_non_public() {
        for ip in [
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.0.1",
            "0.0.0.0",
        ] {
            assert!(is_non_public_ip(&ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn ipv6_loopback_and_link_local_are_non_public() {
        for ip in ["::1", "fe80::1", "fc00::1", "::"] {
            assert!(is_non_public_ip(&ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn ipv4_mapped_ipv6_private_ranges_are_non_public() {
        for ip in [
            "::ffff:10.0.0.1",
            "::ffff:172.16.0.1",
            "::ffff:192.168.1.1",
            "::ffff:127.0.0.1",
        ] {
            assert!(is_non_public_ip(&ip.parse().unwrap()), "{ip}");
        }
        // A mapped PUBLIC v4 must remain public.
        assert!(!is_non_public_ip(&"::ffff:203.0.113.7".parse().unwrap()));
    }
}
