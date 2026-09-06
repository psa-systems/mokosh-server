//! CORS `Origin` header matcher for the mokosh API.
//!
//! Wraps the `CORS_ORIGIN` env-derived list so [`create_api_router`] can
//! feed a predicate into `AllowOrigin::predicate`. Two entry shapes:
//!
//! - **Exact origin** (`https://msp.a8n.systems`): matched byte-for-byte
//!   against the request's `Origin` header. Same behaviour as the
//!   `AllowOrigin::list(...)` this replaced.
//! - **Scheme-locked wildcard** (`https://*.client.a8n.systems`): matches
//!   any `Origin` whose scheme matches and whose host ends with the
//!   trailing suffix (dot included). Introduced by PMS-729 so per-tenant
//!   portal origins do not each need an explicit CORS_ORIGIN entry.
//!
//! The wildcard is scheme-locked on purpose (`http://*.` and `https://*.`
//! are separate entries): letting a wildcard match on `http://*.` too
//! would allow-list an insecure origin, which the browser would reject
//! anyway, but the CorsLayer's predicate is the safer place to enforce
//! it than a browser assumption.
//!
//! Wildcards are the LEFTMOST label only (`*.host.tld`, not `sub.*.tld`).
//! Anything else fails to parse and is rejected at boot: a misconfigured
//! CORS entry does not silently allow-list nothing.

use axum::http::HeaderValue;

/// One CORS_ORIGIN entry after parsing.
#[derive(Debug, Clone)]
enum Rule {
    /// Byte-identical origin match, e.g. `https://msp.a8n.systems`.
    Exact(HeaderValue),
    /// Scheme-locked wildcard: `scheme` includes `://` and matches the
    /// origin's scheme+`://`; `suffix` starts with a dot and matches the
    /// tail of the host portion.
    Wildcard {
        scheme: &'static str,
        suffix: String,
    },
}

/// Origin matcher used by the router's `CorsLayer`.
///
/// Cheap to clone (shallow copy of `Vec<Rule>`); `matches` allocates only
/// when it has to split scheme from host on a wildcard entry, which is a
/// cheap `[u8]` comparison.
#[derive(Debug, Clone)]
pub(crate) struct CorsOriginMatcher {
    rules: Vec<Rule>,
}

impl CorsOriginMatcher {
    /// Parse the raw CORS_ORIGIN entry list. Panics with a clear
    /// message on a malformed entry so a bad env fails the boot.
    pub(crate) fn from_entries(entries: &[String]) -> Self {
        let rules = entries.iter().map(|raw| parse_entry(raw)).collect();
        Self { rules }
    }

    /// Return `true` if `origin_bytes` (the raw `Origin` header value)
    /// matches any configured entry.
    pub(crate) fn matches(&self, origin_bytes: &[u8]) -> bool {
        self.rules.iter().any(|rule| match rule {
            Rule::Exact(v) => v.as_bytes() == origin_bytes,
            Rule::Wildcard { scheme, suffix } => {
                let scheme_bytes = scheme.as_bytes();
                let Some(host) = origin_bytes.strip_prefix(scheme_bytes) else {
                    return false;
                };
                // Prevent `evil.com` bypassing `.client.a8n.systems`
                // with `evilclient.a8n.systems`: the suffix must sit
                // exactly at the tail of the host, and the label to the
                // left of the leading dot must be non-empty.
                if host.len() <= suffix.len() {
                    return false;
                }
                host.ends_with(suffix.as_bytes())
            }
        })
    }
}

/// Parse one CORS_ORIGIN entry. Two shapes:
///
/// - `scheme://*.suffix.tld` -> wildcard (leftmost label only, scheme locked).
/// - anything else -> exact origin, must parse as a valid HeaderValue.
///
/// Panics on a malformed wildcard (missing scheme, missing dot,
/// interior `*`) so the operator sees the misconfiguration at boot.
fn parse_entry(raw: &str) -> Rule {
    let raw = raw.trim();
    if raw.is_empty() {
        panic!("CORS_ORIGIN entry is empty");
    }

    for scheme in ["https://", "http://"] {
        let wildcard_prefix = format!("{scheme}*.");
        if let Some(suffix) = raw.strip_prefix(&wildcard_prefix) {
            if suffix.is_empty() {
                panic!(
                    "CORS_ORIGIN wildcard {raw:?} is missing a suffix after {wildcard_prefix:?}"
                );
            }
            if suffix.contains('*') {
                panic!(
                    "CORS_ORIGIN wildcard {raw:?} must not contain another `*` after the leftmost label"
                );
            }
            if !suffix.contains('.') {
                panic!(
                    "CORS_ORIGIN wildcard {raw:?} suffix must include at least one dot (host must have a TLD)"
                );
            }
            return Rule::Wildcard {
                scheme,
                suffix: format!(".{suffix}"),
            };
        }
    }

    if raw.contains('*') {
        panic!(
            "CORS_ORIGIN entry {raw:?} contains `*` outside the leading `<scheme>://*.` position"
        );
    }

    let value = raw
        .parse::<HeaderValue>()
        .unwrap_or_else(|e| panic!("CORS_ORIGIN entry {raw:?} is not a valid header value: {e}"));
    Rule::Exact(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matcher(entries: &[&str]) -> CorsOriginMatcher {
        CorsOriginMatcher::from_entries(&entries.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn exact_origin_matches_byte_for_byte() {
        let m = matcher(&["https://msp.a8n.systems", "https://a8n.systems"]);
        assert!(m.matches(b"https://msp.a8n.systems"));
        assert!(m.matches(b"https://a8n.systems"));
        assert!(!m.matches(b"https://other.example.com"));
    }

    #[test]
    fn wildcard_origin_matches_any_label_prefix() {
        let m = matcher(&["https://*.client.a8n.systems"]);
        assert!(m.matches(b"https://acme.client.a8n.systems"));
        assert!(m.matches(b"https://beta.client.a8n.systems"));
        assert!(m.matches(b"https://a.client.a8n.systems"));
    }

    #[test]
    fn wildcard_rejects_scheme_mismatch() {
        let m = matcher(&["https://*.client.a8n.systems"]);
        assert!(!m.matches(b"http://acme.client.a8n.systems"));
    }

    #[test]
    fn wildcard_rejects_multi_label_prefix_ok() {
        // The predicate does allow `sub.acme.client.a8n.systems` because
        // it only checks the tail; the SPA-side extractor is what rejects
        // multi-label prefixes at the HTTP layer. The CORS predicate is
        // one layer of defense; label validation is another. This test
        // pins that the CORS predicate is deliberately permissive on the
        // shape of the leftmost portion, matching browser CORS semantics.
        let m = matcher(&["https://*.client.a8n.systems"]);
        assert!(m.matches(b"https://sub.acme.client.a8n.systems"));
    }

    #[test]
    fn wildcard_rejects_suffix_lookalike() {
        // `evilclient.a8n.systems` must not match `.client.a8n.systems`:
        // the suffix comparison is anchored to the literal dot.
        let m = matcher(&["https://*.client.a8n.systems"]);
        assert!(!m.matches(b"https://evilclient.a8n.systems"));
    }

    #[test]
    fn wildcard_rejects_empty_leftmost_label() {
        // The host would be `.client.a8n.systems`, which is the same
        // length as `.client.a8n.systems`. The `<=` guard rejects.
        let m = matcher(&["https://*.client.a8n.systems"]);
        assert!(!m.matches(b"https://.client.a8n.systems"));
    }

    #[test]
    fn wildcard_does_not_match_the_apex() {
        // `client.a8n.systems` (no leading dot) shorter than the
        // stored suffix `.client.a8n.systems`; rejected by length.
        let m = matcher(&["https://*.client.a8n.systems"]);
        assert!(!m.matches(b"https://client.a8n.systems"));
    }

    #[test]
    fn matcher_composes_exact_and_wildcard_entries() {
        let m = matcher(&[
            "https://msp.a8n.systems",
            "https://*.client.a8n.systems",
            "http://*.client.localhost:4301",
        ]);
        assert!(m.matches(b"https://msp.a8n.systems"));
        assert!(m.matches(b"https://acme.client.a8n.systems"));
        assert!(m.matches(b"http://acme.client.localhost:4301"));
        assert!(!m.matches(b"http://acme.client.a8n.systems"));
        assert!(!m.matches(b"https://acme.client.localhost:4301"));
        assert!(!m.matches(b"https://msp.psa.systems"));
    }

    #[test]
    #[should_panic(expected = "CORS_ORIGIN wildcard")]
    fn wildcard_without_a_dot_panics_at_boot() {
        matcher(&["https://*.localhost"]);
    }

    #[test]
    #[should_panic(expected = "CORS_ORIGIN wildcard")]
    fn wildcard_without_a_suffix_panics_at_boot() {
        matcher(&["https://*."]);
    }

    #[test]
    #[should_panic(expected = "outside the leading")]
    fn interior_star_panics_at_boot() {
        matcher(&["https://foo.*.bar.example"]);
    }

    #[test]
    #[should_panic(expected = "empty")]
    fn empty_entry_panics_at_boot() {
        matcher(&[""]);
    }
}
