//! Client authentication at the token endpoint.
//!
//! Three modes are accepted (per the client's `token_endpoint_auth_method`):
//!
//!  - `client_secret_basic`: HTTP `Authorization: Basic <b64(id:secret)>`.
//!  - `client_secret_post`:  `client_id` + `client_secret` in the form body.
//!  - `none`:                public client; no secret. The client is
//!                           authenticated by the binding to a redirect_uri
//!                           plus PKCE verifier.
//!
//! Secret comparison goes through Argon2id verification (constant-time at
//! the hash layer). We never log the secret.

// The module-doc list above is intentionally column-aligned for readability.
#![allow(clippy::doc_overindented_list_items)]

use mokosh_auth_core::{AuthError, ClientAuthMethod, OAuthClient};
use mokosh_auth_crypto::password::verify_password;

/// Inputs lifted from the HTTP request by the HTTP layer.
#[derive(Debug, Clone, Default)]
pub struct PresentedClientCredentials {
    /// The `client_id` claimed by the request: from the Basic header
    /// username, falling back to the form body.
    pub client_id: Option<String>,
    /// `client_secret` from Basic password OR from form body.
    pub client_secret: Option<String>,
    /// True if the credential pair came from the Authorization header.
    pub from_basic_header: bool,
}

/// Verify the presented credentials against the registered client. Returns
/// the client on success.
///
/// On failure we emit `invalid_client` rather than surfacing the actual
/// reason: distinguishing between "unknown client", "wrong secret", and
/// "wrong auth method" leaks information.
pub fn authenticate_client(
    client: &OAuthClient,
    presented: &PresentedClientCredentials,
) -> Result<(), AuthError> {
    if !client.is_enabled() {
        return Err(AuthError::InvalidClient);
    }

    match client.token_endpoint_auth_method {
        ClientAuthMethod::None => {
            // Public client: must NOT present a secret.
            if presented.client_secret.is_some() {
                return Err(AuthError::InvalidClient);
            }
            Ok(())
        }
        ClientAuthMethod::ClientSecretBasic => {
            if !presented.from_basic_header {
                return Err(AuthError::InvalidClient);
            }
            verify_secret(client, presented.client_secret.as_deref())
        }
        ClientAuthMethod::ClientSecretPost => {
            if presented.from_basic_header {
                return Err(AuthError::InvalidClient);
            }
            verify_secret(client, presented.client_secret.as_deref())
        }
        ClientAuthMethod::PrivateKeyJwt => {
            // Phase 2: client signs an assertion with its registered key.
            // For now we reject so a misconfigured client cannot silently
            // skip authentication.
            Err(AuthError::InvalidClient)
        }
    }
}

fn verify_secret(client: &OAuthClient, presented: Option<&str>) -> Result<(), AuthError> {
    let presented = presented.ok_or(AuthError::InvalidClient)?;
    let stored = client
        .client_secret_hash
        .as_deref()
        .ok_or(AuthError::InvalidClient)?;
    if verify_password(presented, stored) {
        Ok(())
    } else {
        Err(AuthError::InvalidClient)
    }
}
