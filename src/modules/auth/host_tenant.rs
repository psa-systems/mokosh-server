//! Host-based agent-tenant derivation (MAPPS-473).
//!
//! Parallels the portal-side [`crate::modules::portal::PortalHostConfig`]:
//! deploy the agent SPA at `{slug}.msp.<apex>` and the login handler
//! pulls the tenant slug straight from the browser Host header, so an
//! MSP admin never types their account slug. Set via `AGENT_HOST_SUFFIX`
//! (e.g. `.msp.a8n.systems`); unset disables the feature and the
//! existing standalone slug-input form is the fallback.
//!
//! Newtype over `PortalHostConfig` so the extraction shape (RFC 1123
//! label validation, port stripping, case-insensitive suffix match,
//! 100-char cap) stays in one place. Only the env var and the type name
//! differ.

use crate::modules::portal::PortalHostConfig;

/// Boot-time configuration for host-based agent-tenant resolution.
///
/// Cheap to clone (owns a single `String`), so passing it into the
/// login handler via `AuthRouterState` is fine. Wraps
/// [`PortalHostConfig`] so all extraction logic lives in one place.
#[derive(Clone, Debug)]
pub struct AgentHostConfig(PortalHostConfig);

impl AgentHostConfig {
    /// Read `AGENT_HOST_SUFFIX` from the process env. Empty (unset) or
    /// whitespace-only disables the feature and every extraction call
    /// returns `None`.
    pub fn from_env() -> Self {
        let raw = std::env::var("AGENT_HOST_SUFFIX").unwrap_or_default();
        Self(PortalHostConfig::from_suffix(raw))
    }

    /// Build from an explicit suffix. Used by integration tests that
    /// build the router without going through the process env.
    pub fn from_suffix(suffix: impl Into<String>) -> Self {
        Self(PortalHostConfig::from_suffix(suffix))
    }

    /// `true` when the feature is on (i.e. `AGENT_HOST_SUFFIX` was
    /// non-empty). Callers can shortcut before touching request headers.
    pub fn is_enabled(&self) -> bool {
        self.0.is_enabled()
    }

    /// Configured suffix (with leading dot) or the empty string when
    /// off. Exposed so callers that need to build an agent URL for a
    /// specific slug can reuse the same value the router configured.
    pub fn suffix(&self) -> &str {
        self.0.suffix()
    }

    /// Extract the candidate slug label from a Host header value. See
    /// [`PortalHostConfig::extract_slug`] for the full ruleset. Returns
    /// `None` on any failure mode (feature off, host does not end with
    /// the configured suffix, label empty, label too long, label
    /// contains invalid characters).
    pub fn extract_slug(&self, host_header: &str) -> Option<String> {
        self.0.extract_slug(host_header)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_when_suffix_empty() {
        let cfg = AgentHostConfig::from_suffix("");
        assert!(!cfg.is_enabled());
        assert_eq!(cfg.extract_slug("acme.msp.a8n.systems"), None);
    }

    #[test]
    fn extracts_agent_slug_from_host() {
        let cfg = AgentHostConfig::from_suffix(".msp.a8n.systems");
        assert_eq!(
            cfg.extract_slug("acme.msp.a8n.systems"),
            Some("acme".to_string())
        );
    }

    #[test]
    fn extracts_default_slug_for_super_admin() {
        let cfg = AgentHostConfig::from_suffix(".msp.a8n.systems");
        assert_eq!(
            cfg.extract_slug("default.msp.a8n.systems"),
            Some("default".to_string())
        );
    }

    #[test]
    fn bare_apex_returns_none() {
        // `msp.a8n.systems` has no leftmost label preceding the suffix.
        let cfg = AgentHostConfig::from_suffix(".msp.a8n.systems");
        assert_eq!(cfg.extract_slug("msp.a8n.systems"), None);
    }

    #[test]
    fn non_matching_host_returns_none() {
        // A portal host must not be treated as an agent host.
        let cfg = AgentHostConfig::from_suffix(".msp.a8n.systems");
        assert_eq!(cfg.extract_slug("acme.client.a8n.systems"), None);
    }

    #[test]
    fn strips_port_before_matching() {
        let cfg = AgentHostConfig::from_suffix(".msp.localhost");
        assert_eq!(
            cfg.extract_slug("acme.msp.localhost:4301"),
            Some("acme".to_string())
        );
    }
}
