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
    // called exactly once, at router construction (boot), not
    // per request; a parse failure here panics the boot instead of being deferred to request time.
    // SPEC-12.14: entries are trimmed and parsed here, once.
    pub(crate) fn from_entries(entries: &[String]) -> Self {
        // SPEC-2.103
        let rules = entries.iter().map(|raw| parse_entry(raw)).collect();
        Self { rules }
    }

    /// Return `true` if `origin_bytes` (the raw `Origin` header value)
    /// matches any configured entry.
    // runs on every CORS-checked request; does no parsing, only
    // byte comparisons against the rules parsed once at boot.
    // SPEC-2.104
    pub(crate) fn matches(&self, origin_bytes: &[u8]) -> bool {
        self.rules.iter().any(|rule| match rule {
            // byte-for-byte, case-sensitive; no
            // normalization of the incoming Origin header.
            // SPEC-12.15
            // SPEC-2.111
            Rule::Exact(v) => v.as_bytes() == origin_bytes,
            // SPEC-12.16: scheme prefix, strictly longer host, tail match on `.suffix`.
            Rule::Wildcard { scheme, suffix } => {
                // scheme is matched as a literal prefix, so a
                // wildcard entry never matches the other scheme.
                let scheme_bytes = scheme.as_bytes();
                // SPEC-2.112
                let Some(host) = origin_bytes.strip_prefix(scheme_bytes) else {
                    return false;
                };
                // Prevent `evil.com` bypassing `.client.a8n.systems`
                // with `evilclient.a8n.systems`: the suffix must sit
                // exactly at the tail of the host, and the label to the
                // left of the leading dot must be non-empty.
                // rejects the bare apex and the empty-label host.
                // SPEC-2.114
                if host.len() <= suffix.len() {
                    return false;
                }
                // a tail (suffix) comparison, not leftmost-label-only, so any number of leading
                // host labels match; suffix is the literal config text and includes a port if one was written into the entry.
                // SPEC-2.113
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
    // SPEC-12.17: every malformed shape below panics with a CORS_ORIGIN message.
    if raw.is_empty() {
        // panics at boot rather than being skipped or allow-listing nothing.
        // SPEC-2.105
        panic!("CORS_ORIGIN entry is empty");
    }

    for scheme in ["https://", "http://"] {
        let wildcard_prefix = format!("{scheme}*.");
        if let Some(suffix) = raw.strip_prefix(&wildcard_prefix) {
            // SPEC-2.106
            if suffix.is_empty() {
                // panics at boot on a wildcard with no suffix.
                panic!(
                    "CORS_ORIGIN wildcard {raw:?} is missing a suffix after {wildcard_prefix:?}"
                );
            }
            // SPEC-2.107
            if suffix.contains('*') {
                // panics at boot; only the leftmost label may be a wildcard.
                panic!(
                    "CORS_ORIGIN wildcard {raw:?} must not contain another `*` after the leftmost label"
                );
            }
            // SPEC-2.108
            if !suffix.contains('.') {
                // panics at boot; a wildcard suffix must have a TLD.
                panic!(
                    "CORS_ORIGIN wildcard {raw:?} suffix must include at least one dot (host must have a TLD)"
                );
            }
            return Rule::Wildcard {
                scheme,
                // SPEC-2.115 SPEC-2.116
                suffix: format!(".{suffix}"),
            };
        }
    }

    // SPEC-2.109
    if raw.contains('*') {
        // panics at boot; `*` is only legal in the `<scheme>://*.` position.
        panic!(
            "CORS_ORIGIN entry {raw:?} contains `*` outside the leading `<scheme>://*.` position"
        );
    }

    // panics at boot if an exact entry is not a valid header value.
    let value = raw
        .parse::<HeaderValue>()
        // SPEC-2.110
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
