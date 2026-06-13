//! Non-cryptographic invariants enforced across the auth stack.
//!
//! Every function here is pure: deterministic, side-effect-free, no I/O.
//! That makes them trivial to property-test.

use crate::error::AuthError;
use std::collections::BTreeSet;
use url::Url;

/// Minimum password length (chars). OWASP 2024 recommends >= 12.
pub const MIN_PASSWORD_LEN: usize = 12;
/// Hard cap on password length to prevent Argon2id DoS via huge inputs.
pub const MAX_PASSWORD_LEN: usize = 128;

/// Validate a redirect URI against the client's registered list.
///
/// Policy:
/// - Exact match against any registered URI, OR
/// - Loopback exception: if the registered URI is exactly
///   `http://127.0.0.1` or `http://localhost`, the presented URI may
///   include any port. This matches RFC 8252 (OAuth 2.0 for Native Apps).
pub fn validate_redirect_uri(presented: &Url, allowed: &[Url]) -> bool {
    let p = presented.as_str();
    allowed.iter().any(|u| {
        if is_loopback_root(u) {
            same_loopback(presented, u)
        } else {
            u.as_str() == p
        }
    })
}

/// True if the URL is exactly `http://127.0.0.1[/]` or `http://localhost[/]`
/// with no port and no real path. The `url` crate normalizes empty paths to
/// "/", so we accept either form.
fn is_loopback_root(u: &Url) -> bool {
    if u.scheme() != "http" || u.port().is_some() {
        return false;
    }
    matches!(u.host_str(), Some("127.0.0.1") | Some("localhost"))
        && (u.path() == "" || u.path() == "/")
        && u.query().is_none()
        && u.fragment().is_none()
}

fn same_loopback(presented: &Url, registered: &Url) -> bool {
    presented.scheme() == "http" && presented.host_str() == registered.host_str()
    // Loopback exception ignores port and path (per RFC 8252 native-app
    // redirect URIs typically vary by port and may carry a callback path).
}

/// Narrow a requested scope set to those granted by the client.
///
/// Returns the intersection. The caller is responsible for emitting
/// `invalid_scope` if narrowing dropped any requested scope.
pub fn narrow_scopes(requested: &BTreeSet<String>, allowed: &BTreeSet<String>) -> BTreeSet<String> {
    requested.intersection(allowed).cloned().collect()
}

/// Parse a space-separated `scope` string into an ordered set.
pub fn parse_scope(s: &str) -> BTreeSet<String> {
    s.split_whitespace().map(String::from).collect()
}

/// Password strength policy.
///
/// Required: 12..=128 chars, at least one upper, one lower, one digit, one
/// symbol. Must not equal the email local-part.
pub fn validate_password_strength(plain: &str, email: &str) -> Result<(), AuthError> {
    // Count Unicode scalar values, not bytes: a password of multi-byte
    // characters must not be miscounted against the char-based policy.
    let char_len = plain.chars().count();
    if char_len < MIN_PASSWORD_LEN {
        return Err(AuthError::Policy(format!(
            "password must be at least {MIN_PASSWORD_LEN} characters"
        )));
    }
    if char_len > MAX_PASSWORD_LEN {
        return Err(AuthError::Policy(format!(
            "password must be at most {MAX_PASSWORD_LEN} characters"
        )));
    }
    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_digit = false;
    let mut has_symbol = false;
    for ch in plain.chars() {
        if ch.is_ascii_uppercase() {
            has_upper = true;
        } else if ch.is_ascii_lowercase() {
            has_lower = true;
        } else if ch.is_ascii_digit() {
            has_digit = true;
        } else if !ch.is_alphanumeric() {
            has_symbol = true;
        }
    }
    if !(has_upper && has_lower && has_digit && has_symbol) {
        return Err(AuthError::Policy(
            "password must include upper, lower, digit, and symbol".into(),
        ));
    }
    if let Some(local) = email.split('@').next() {
        if !local.is_empty() && plain.eq_ignore_ascii_case(local) {
            return Err(AuthError::Policy(
                "password must not equal the email local part".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_exact_match() {
        let allowed = vec![Url::parse("https://app.example.com/cb").unwrap()];
        assert!(validate_redirect_uri(
            &Url::parse("https://app.example.com/cb").unwrap(),
            &allowed
        ));
        assert!(!validate_redirect_uri(
            &Url::parse("https://app.example.com/cb/extra").unwrap(),
            &allowed
        ));
        assert!(!validate_redirect_uri(
            &Url::parse("https://attacker.com/cb").unwrap(),
            &allowed
        ));
    }

    #[test]
    fn redirect_loopback_any_port() {
        let allowed = vec![Url::parse("http://127.0.0.1").unwrap()];
        assert!(validate_redirect_uri(
            &Url::parse("http://127.0.0.1:34567").unwrap(),
            &allowed
        ));
    }

    #[test]
    fn password_policy_basics() {
        assert!(validate_password_strength("Sup3rL0ngPass!", "alice@x.com").is_ok());
        assert!(validate_password_strength("short1!A", "alice@x.com").is_err());
        assert!(validate_password_strength("aaaaaaaaaaaa", "alice@x.com").is_err()); // no upper/digit/symbol
        assert!(validate_password_strength("alice", "alice@x.com").is_err());
    }
}
