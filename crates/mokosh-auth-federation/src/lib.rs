//! Mokosh auth: BYO-SSO federation.
//!
//! Phase-2 surface. The trait and registry are defined here so that
//! upstream IdP brokers (OIDC RP, SAML SP) can be plugged in without
//! touching other crates. Phase-1 ships with an empty registry.

use async_trait::async_trait;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    OidcRp,
    SamlSp,
}

#[derive(Debug, thiserror::Error)]
pub enum FederationError {
    #[error("provider not found: {0}")]
    NotFound(String),
    #[error("provider error: {0}")]
    Provider(String),
}

pub struct BeginLoginCtx {
    pub tenant_id: uuid::Uuid,
    pub return_to: String,
}

pub struct CompleteLoginCtx {
    pub tenant_id: uuid::Uuid,
    pub raw_query: String,
}

pub struct UpstreamAssertion {
    pub external_subject: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub display_name: Option<String>,
    pub raw_claims: serde_json::Value,
}

pub struct RedirectTarget {
    pub url: url::Url,
}

#[async_trait]
pub trait UpstreamIdentityProvider: Send + Sync {
    fn id(&self) -> &str;
    fn kind(&self) -> ProviderKind;
    async fn begin_login(&self, ctx: BeginLoginCtx) -> Result<RedirectTarget, FederationError>;
    async fn complete_login(
        &self,
        ctx: CompleteLoginCtx,
    ) -> Result<UpstreamAssertion, FederationError>;
}

/// Phase-1: empty registry. Phase-2 will populate this from
/// `mokosh_auth.tenant_identity_providers`.
#[derive(Default)]
pub struct ProviderRegistry {
    providers: Vec<std::sync::Arc<dyn UpstreamIdentityProvider>>,
}

impl ProviderRegistry {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn register(&mut self, p: std::sync::Arc<dyn UpstreamIdentityProvider>) {
        self.providers.push(p);
    }
    pub fn find(&self, id: &str) -> Option<std::sync::Arc<dyn UpstreamIdentityProvider>> {
        self.providers.iter().find(|p| p.id() == id).cloned()
    }
    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }
}
