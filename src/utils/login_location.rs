//! Post-code-review finding #10: shared login-location predicate + decision.
//!
//! The agent side (`src/modules/auth/service.rs`) and the portal side
//! (`src/modules/portal/service.rs`) each carried a byte-for-byte
//! duplicate of `is_non_public_ip` + `login_location_decision` +
//! `LoginLocationDecision`. Any change to the private-range set (see
//! finding #9's IPv4-mapped-v6 fix) or the alert threshold had to land
//! in both places or one path stayed vulnerable. This module owns the
//! single source of truth.

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

// PMS-805 makes `crate::utils::net::is_non_public_ip` the sole definition
// (its `exactly_one_definition_in_the_crate` test enforces this). Callers on
// the contact-login branch that used this module's copy should import from
// `crate::utils::net` directly.

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

    // is_non_public_ip tests moved to `crate::utils::net` alongside its
    // sole definition (PMS-805).
}
