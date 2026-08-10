//! Host-to-tenant resolution for the client portal (PMS-729).
//!
//! Two pure functions and one config struct. Together they let the portal
//! login handler accept a request without a `tenant_slug` in the body when
//! the request host resolves to a live tenant. The DB lookup itself lives
//! on [`super::service::PortalAuthService::resolve_host_tenant`] so this
//! module stays synchronous and unit-testable without a Postgres fixture.
//!
//! ## Configuration
//!
//! [`PortalHostConfig::from_env`] reads `PORTAL_HOST_SUFFIX`:
//! - Empty (unset) -> `is_enabled()` returns `false` and every extraction
//!   returns `None`. The kill switch for the phased rollout: the code can
//!   ship to production behind an empty env and change nothing at runtime.
//! - `.client.a8n.systems` -> extracts the leftmost label off a request
//!   Host that ends with the suffix; any other host returns `None`.
//!
//! ## Fail-closed shape
//!
//! Every negative outcome (config disabled, host miss, malformed label,
//! label collides with another host component) collapses to `None`. The
//! login handler treats a `None`+`None` body slug pair as "wrong password"
//! so the response is byte-identical to a credential rejection and does
//! not enumerate MSPs (PMS-729 AC).

use super::models::ResolvedTenant;

/// Boot-time configuration for host-based tenant resolution.
///
/// Lives on [`super::routes::PortalRouterState`]. Cheap to clone (owns a
/// single `String`), so passing it into handlers via `State` is fine.
#[derive(Clone, Debug)]
pub struct PortalHostConfig {
    /// Trailing suffix like `.client.a8n.systems`. Includes the leading
    /// dot. Lowercased at construction so the extractor does not have to
    /// re-normalize on every request. Empty when the feature is off.
    suffix: String,
}

impl PortalHostConfig {
    /// Read `PORTAL_HOST_SUFFIX` from the process env, lowercase, trim
    /// whitespace. An unset or empty value disables the feature.
    pub fn from_env() -> Self {
        let raw = std::env::var("PORTAL_HOST_SUFFIX").unwrap_or_default();
        let suffix = raw.trim().to_ascii_lowercase();
        Self { suffix }
    }

    /// Build a config from an explicit suffix. Used by integration tests
    /// (which build the router without going through the process env) and
    /// by callers that want to override the env for a specific instance.
    /// The empty string keeps the feature disabled, exactly like unset env.
    pub fn from_suffix(suffix: impl Into<String>) -> Self {
        Self {
            suffix: suffix.into().to_ascii_lowercase(),
        }
    }

    /// `true` when the extractor is active (i.e. `PORTAL_HOST_SUFFIX` was
    /// set). Callers can shortcut before touching the request headers.
    pub fn is_enabled(&self) -> bool {
        !self.suffix.is_empty()
    }

    /// Extract the candidate slug label from a Host header value. Returns
    /// `None` on any failure mode, so the caller only has to check for
    /// `Some`. Kept pure (no DB, no async) so unit tests cover every case
    /// without a fixture.
    ///
    /// Rules:
    /// - Feature off (empty suffix) -> `None`.
    /// - Strip any `:port` suffix; browsers include it on non-443 hosts.
    /// - Lowercase the whole thing; matching is case-insensitive.
    /// - Host must end with the configured suffix. Anything else returns
    ///   `None` (agent hosts like `msp.a8n.systems` land here).
    /// - The label preceding the suffix must be non-empty, at most 100
    ///   characters (`tenants.slug` column cap), and match
    ///   `[a-z0-9](?:[a-z0-9-]*[a-z0-9])?` (RFC 1123 subset). No leading
    ///   or trailing hyphen; no interior dots (a nested label would be a
    ///   different host shape entirely).
    pub fn extract_slug(&self, host_header: &str) -> Option<String> {
        if !self.is_enabled() {
            return None;
        }
        // Trim `:port`. `split_once` handles the "no port" case too.
        let host = host_header
            .split_once(':')
            .map(|(h, _)| h)
            .unwrap_or(host_header)
            .to_ascii_lowercase();
        let label = host.strip_suffix(&self.suffix)?;
        if label.is_empty() || label.len() > 100 {
            return None;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return None;
        }
        if label.contains('.') {
            return None;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return None;
        }
        Some(label.to_string())
    }
}

/// Marker error returned by [`resolve_slug`] when neither the host nor
/// the body supplied a usable slug, or when they supplied disagreeing
/// values. The login handler collapses this into
/// [`crate::utils::error::AppError::Unauthorized`] so the response
/// envelope is byte-identical to a wrong-password rejection - the caller
/// cannot tell "slug missing" from "bad password".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlugResolveError;

/// Decide which slug the login handler feeds into the credential check,
/// given the host-resolved tenant (if any) and the body's optional
/// `tenant_slug` field. Pure function.
///
/// Policy (PMS-729 §5.3):
///
/// | host_tenant | body_slug | Outcome |
/// |-------------|-----------|---------|
/// | Some(t)     | Some(s)   | Ok if `t.slug == s.trim().to_lowercase()`, else Err |
/// | Some(t)     | None      | Ok, use `t.slug` |
/// | None        | Some(s)   | Ok, use `s.trim().to_lowercase()` (legacy path) |
/// | None        | None      | Err (fail-closed) |
pub fn resolve_slug(
    host_tenant: Option<&ResolvedTenant>,
    body_slug: Option<&str>,
) -> Result<String, SlugResolveError> {
    let body_norm = body_slug.map(|s| s.trim().to_ascii_lowercase());
    match (host_tenant, body_norm) {
        (Some(t), Some(s)) if t.slug == s => Ok(t.slug.clone()),
        (Some(_), Some(_)) => Err(SlugResolveError), // cross-tenant credential replay
        (Some(t), None) => Ok(t.slug.clone()),
        (None, Some(s)) if !s.is_empty() => Ok(s),
        _ => Err(SlugResolveError),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn resolved(slug: &str) -> ResolvedTenant {
        ResolvedTenant {
            tenant_id: Uuid::nil(),
            slug: slug.to_string(),
            display_name: "Test MSP".to_string(),
            branding: super::super::models::PortalBranding::default(),
        }
    }

    #[test]
    fn extractor_returns_none_when_feature_disabled() {
        let cfg = PortalHostConfig::from_suffix("");
        assert!(!cfg.is_enabled());
        assert_eq!(cfg.extract_slug("acme.client.a8n.systems"), None);
        assert_eq!(cfg.extract_slug("anything"), None);
    }

    #[test]
    fn extractor_hits_leftmost_label_off_a_matching_host() {
        let cfg = PortalHostConfig::from_suffix(".client.a8n.systems");
        assert_eq!(
            cfg.extract_slug("acme.client.a8n.systems"),
            Some("acme".to_string())
        );
    }

    #[test]
    fn extractor_strips_port_before_matching() {
        let cfg = PortalHostConfig::from_suffix(".client.localhost");
        assert_eq!(
            cfg.extract_slug("acme.client.localhost:4300"),
            Some("acme".to_string())
        );
    }

    #[test]
    fn extractor_is_case_insensitive_on_the_host() {
        let cfg = PortalHostConfig::from_suffix(".client.a8n.systems");
        assert_eq!(
            cfg.extract_slug("ACME.Client.A8N.Systems"),
            Some("acme".to_string())
        );
    }

    #[test]
    fn extractor_rejects_hosts_that_dont_match_the_suffix() {
        let cfg = PortalHostConfig::from_suffix(".client.a8n.systems");
        // Agent host - not portal.
        assert_eq!(cfg.extract_slug("msp.a8n.systems"), None);
        // Different apex.
        assert_eq!(cfg.extract_slug("acme.client.psa.systems"), None);
        // Missing the "client" layer.
        assert_eq!(cfg.extract_slug("acme.a8n.systems"), None);
        // Empty.
        assert_eq!(cfg.extract_slug(""), None);
    }

    #[test]
    fn extractor_rejects_malformed_labels() {
        let cfg = PortalHostConfig::from_suffix(".client.a8n.systems");
        // Empty label.
        assert_eq!(cfg.extract_slug(".client.a8n.systems"), None);
        // Leading hyphen.
        assert_eq!(cfg.extract_slug("-bad.client.a8n.systems"), None);
        // Trailing hyphen.
        assert_eq!(cfg.extract_slug("bad-.client.a8n.systems"), None);
        // Invalid character.
        assert_eq!(cfg.extract_slug("bad_slug.client.a8n.systems"), None);
        // Space.
        assert_eq!(cfg.extract_slug("bad slug.client.a8n.systems"), None);
        // Overlong label (101 chars).
        let long = "a".repeat(101);
        let host = format!("{long}.client.a8n.systems");
        assert_eq!(cfg.extract_slug(&host), None);
    }

    #[test]
    fn extractor_rejects_multi_label_prefix() {
        // The suffix strip would return "sub.acme" which contains a dot;
        // an interior dot means the host is not `{slug}.client.<apex>`
        // but some other shape. Fail-closed.
        let cfg = PortalHostConfig::from_suffix(".client.a8n.systems");
        assert_eq!(cfg.extract_slug("sub.acme.client.a8n.systems"), None);
    }

    #[test]
    fn extractor_accepts_hyphens_in_the_middle() {
        let cfg = PortalHostConfig::from_suffix(".client.a8n.systems");
        assert_eq!(
            cfg.extract_slug("acme-msp.client.a8n.systems"),
            Some("acme-msp".to_string())
        );
        assert_eq!(
            cfg.extract_slug("a.client.a8n.systems"),
            Some("a".to_string())
        );
    }

    #[test]
    fn resolve_slug_host_only_ok() {
        let t = resolved("acme");
        assert_eq!(resolve_slug(Some(&t), None), Ok("acme".to_string()));
    }

    #[test]
    fn resolve_slug_body_only_ok_legacy_path() {
        assert_eq!(resolve_slug(None, Some("acme")), Ok("acme".to_string()));
        // Normalization: whitespace + case.
        assert_eq!(resolve_slug(None, Some("  ACME  ")), Ok("acme".to_string()));
    }

    #[test]
    fn resolve_slug_host_matches_body_ok() {
        let t = resolved("acme");
        assert_eq!(resolve_slug(Some(&t), Some("acme")), Ok("acme".to_string()));
        // Body normalization applies before compare.
        assert_eq!(resolve_slug(Some(&t), Some("ACME")), Ok("acme".to_string()));
    }

    #[test]
    fn resolve_slug_host_mismatches_body_fails_closed() {
        let t = resolved("acme");
        assert_eq!(resolve_slug(Some(&t), Some("beta")), Err(SlugResolveError));
    }

    #[test]
    fn resolve_slug_both_none_fails_closed() {
        assert_eq!(resolve_slug(None, None), Err(SlugResolveError));
    }

    #[test]
    fn resolve_slug_empty_body_treated_as_none() {
        assert_eq!(resolve_slug(None, Some("")), Err(SlugResolveError));
        assert_eq!(resolve_slug(None, Some("   ")), Err(SlugResolveError));
    }
}
