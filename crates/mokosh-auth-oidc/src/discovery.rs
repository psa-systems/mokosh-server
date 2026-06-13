//! `/.well-known/openid-configuration` document.

use serde::Serialize;
use url::Url;

#[derive(Serialize)]
pub struct OpenIdConfiguration {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
    pub revocation_endpoint: String,
    pub end_session_endpoint: String,
    pub scopes_supported: Vec<&'static str>,
    pub response_types_supported: Vec<&'static str>,
    pub grant_types_supported: Vec<&'static str>,
    pub subject_types_supported: Vec<&'static str>,
    pub id_token_signing_alg_values_supported: Vec<&'static str>,
    pub token_endpoint_auth_methods_supported: Vec<&'static str>,
    pub code_challenge_methods_supported: Vec<&'static str>,
    pub claims_supported: Vec<&'static str>,
    pub backchannel_logout_supported: bool,
    pub backchannel_logout_session_supported: bool,
    pub require_request_uri_registration: bool,
}

/// Build the discovery document for a given issuer.
pub fn openid_configuration(issuer: &Url) -> OpenIdConfiguration {
    let base = issuer.as_str().trim_end_matches('/').to_string();
    OpenIdConfiguration {
        issuer: base.clone(),
        authorization_endpoint: format!("{base}/oauth2/authorize"),
        token_endpoint: format!("{base}/oauth2/token"),
        userinfo_endpoint: format!("{base}/oauth2/userinfo"),
        jwks_uri: format!("{base}/.well-known/jwks.json"),
        revocation_endpoint: format!("{base}/oauth2/revoke"),
        end_session_endpoint: format!("{base}/oauth2/logout"),
        scopes_supported: vec![
            "openid",
            "email",
            "offline_access",
            "mokosh:full",
            "mokosh:read",
        ],
        response_types_supported: vec!["code"],
        grant_types_supported: vec!["authorization_code", "refresh_token"],
        subject_types_supported: vec!["public"],
        id_token_signing_alg_values_supported: vec!["EdDSA"],
        token_endpoint_auth_methods_supported: vec![
            "client_secret_basic",
            "client_secret_post",
            "none",
        ],
        code_challenge_methods_supported: vec!["S256"],
        claims_supported: vec![
            "sub",
            "iss",
            "aud",
            "exp",
            "iat",
            "auth_time",
            "nonce",
            "email",
            "email_verified",
            "mokosh_tenant_id",
            "mokosh_active_tenant",
            "mokosh_role",
            "acr",
            "amr",
        ],
        backchannel_logout_supported: true,
        backchannel_logout_session_supported: true,
        require_request_uri_registration: false,
    }
}
