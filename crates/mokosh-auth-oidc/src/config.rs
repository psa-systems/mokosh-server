//! Engine-level configuration. Smaller than `mokosh_auth::AuthConfig`:
//! only what the protocol logic needs.

use chrono::Duration;
use url::Url;

#[derive(Clone, Debug)]
pub struct EngineConfig {
    pub issuer: Url,
    pub authorization_code_ttl: Duration,
    pub op_session_ttl: Duration,
    /// Default access-token TTL applied when a client does not specify one.
    /// Per-client TTLs in `oauth_clients` override this.
    pub default_access_token_ttl: Duration,
    pub default_refresh_token_ttl: Duration,
    pub default_refresh_idle_ttl: Duration,
    /// Clock-skew tolerance when verifying inbound JWTs.
    pub leeway: Duration,
}

impl EngineConfig {
    pub fn issuer_str(&self) -> &str {
        self.issuer.as_str().trim_end_matches('/')
    }
}
