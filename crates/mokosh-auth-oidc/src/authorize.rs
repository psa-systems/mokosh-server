//! `/oauth2/authorize`: the OIDC code flow entry point.
//!
//! Returns an [`AuthorizeOutcome`] that the HTTP layer interprets:
//!  - [`AuthorizeOutcome::Redirect`]   redirect with `code` + `state`.
//!  - [`AuthorizeOutcome::NeedsLogin`] no valid OP session: render or
//!    redirect to the login UI, preserving the request to resume after.
//!  - [`AuthorizeOutcome::ErrorRedirect`] OAuth-spec error returned as a
//!    redirect to the registered URI.
//!  - [`AuthorizeOutcome::ErrorPage`] errors that MUST NOT redirect:
//!    invalid `client_id`, invalid `redirect_uri`. Returning these to a
//!    redirect would be unsafe (they could leak to an attacker).
//!
//! Order of validation matters: the redirect URI MUST be validated
//! *before* any error is reflected back to the client, otherwise an
//! attacker who controls a malicious redirect_uri can harvest authorize
//! errors. See OAuth 2.0 Security BCP section 4.1.

use mokosh_auth_core::{policy, AuthError, ClientId, NewAuthCode, OAuthClient, OpSession};
use mokosh_auth_crypto::{generate_opaque_token, hash_opaque_token};
use std::collections::BTreeSet;
use url::Url;

use crate::provider::OidcProvider;

/// Parsed query parameters from `GET /oauth2/authorize`.
#[derive(Debug, Clone)]
pub struct AuthorizeRequest {
    pub response_type: String,
    pub client_id: String, // pre-parse: stays a string so a bad UUID is "invalid_request"
    pub redirect_uri: String,
    pub scope: String,
    pub state: String,
    pub nonce: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub prompt: Option<String>,
}

#[derive(Debug)]
pub enum AuthorizeOutcome {
    /// Redirect the browser to `to`. Used both for success (carrying
    /// `code` + `state`) and for spec-compliant error responses.
    Redirect { to: Url },
    /// Render the login UI. The HTTP layer should re-invoke
    /// `handle_authorize` with the same request once the user signs in.
    NeedsLogin { request: AuthorizeRequest },
    /// Error that must NOT be returned via the redirect_uri.
    ErrorPage { error: AuthError },
}

/// Run the authorize logic.
///
/// `current_session` is `Some` only when a valid (unrevoked, unexpired)
/// OP session is present in the browser cookie. The HTTP layer is
/// responsible for that lookup so this function is independent of cookie
/// mechanics.
pub async fn handle_authorize(
    p: &OidcProvider,
    req: AuthorizeRequest,
    current_session: Option<&OpSession>,
) -> AuthorizeOutcome {
    // 1. Resolve client. A bad client_id stays an error PAGE: we cannot
    //    redirect (where would we send it?).
    let client_id = match req.client_id.parse::<uuid::Uuid>() {
        Ok(u) => ClientId(u),
        Err(_) => {
            return AuthorizeOutcome::ErrorPage {
                error: AuthError::InvalidClient,
            }
        }
    };
    let client = match p.clients.find_by_client_id(client_id).await {
        Ok(Some(c)) if c.is_enabled() => c,
        Ok(_) => {
            return AuthorizeOutcome::ErrorPage {
                error: AuthError::InvalidClient,
            }
        }
        Err(e) => return AuthorizeOutcome::ErrorPage { error: e },
    };

    // 2. Validate redirect_uri BEFORE any other reflected error.
    let redirect_uri = match Url::parse(&req.redirect_uri) {
        Ok(u) => u,
        Err(_) => {
            return AuthorizeOutcome::ErrorPage {
                error: AuthError::InvalidRedirect,
            }
        }
    };
    if !policy::validate_redirect_uri(&redirect_uri, &client.redirect_uris) {
        return AuthorizeOutcome::ErrorPage {
            error: AuthError::InvalidRedirect,
        };
    }

    // 3. From here on, errors can be redirected back as RFC 6749 / OIDC
    //    Core error responses with `error`, `error_description`, `state`.
    //    Wrap remaining checks in a closure so we can centrally redirect.
    let result = (|| -> Result<(NewAuthCode, String, String), AuthError> {
        if req.response_type != "code" {
            return Err(AuthError::UnsupportedResponseType);
        }
        if req.code_challenge_method != "S256" || req.code_challenge.is_empty() {
            return Err(AuthError::PkceRequired);
        }
        if req.state.is_empty() {
            return Err(AuthError::InvalidRequest("state is required".into()));
        }

        let requested = policy::parse_scope(&req.scope);
        if !requested.contains("openid") {
            return Err(AuthError::InvalidScope);
        }
        let granted: BTreeSet<String> = requested
            .intersection(&client.allowed_scopes)
            .cloned()
            .collect();
        if granted.len() != requested.len() {
            return Err(AuthError::InvalidScope);
        }

        // 4. Authentication. If unauthenticated or `prompt=login`, we
        //    bail out to NeedsLogin via the outer match, not here.
        let session = current_session.ok_or(AuthError::LoginRequired)?;
        if req.prompt.as_deref() == Some("none") && current_session.is_none() {
            // prompt=none: never interact. We can only succeed if the
            // user is already authenticated; otherwise spec error.
            return Err(AuthError::LoginRequired);
        }

        let raw_code = generate_opaque_token();
        let code_hash = hash_opaque_token(&raw_code);
        let now = p.clock.now();
        let new_code = NewAuthCode {
            code_hash,
            client_id: client.client_id,
            user_id: session.user_id,
            tenant_id: session.tenant_id,
            op_session_id: session.id,
            redirect_uri: redirect_uri.to_string(),
            scope: granted.into_iter().collect(),
            code_challenge: req.code_challenge.clone(),
            nonce: req.nonce.clone(),
            auth_time: session.created_at,
            acr: session.acr.clone(),
            amr: session.amr.clone(),
            expires_at: now + p.cfg.authorization_code_ttl,
        };
        Ok((new_code, raw_code, req.state.clone()))
    })();

    let (new_code, raw_code, state) = match result {
        Ok(v) => v,
        Err(AuthError::LoginRequired) if req.prompt.as_deref() != Some("none") => {
            return AuthorizeOutcome::NeedsLogin { request: req };
        }
        Err(e) => {
            return AuthorizeOutcome::Redirect {
                to: error_redirect(&redirect_uri, &e, req.state.as_str()),
            };
        }
    };

    // 5. Persist code, JIT-grant entitlement, audit.
    if let Err(e) = ensure_entitlement(p, &client, &new_code).await {
        return AuthorizeOutcome::Redirect {
            to: error_redirect(&redirect_uri, &e, &state),
        };
    }
    if let Err(e) = p.codes.insert(new_code.clone()).await {
        return AuthorizeOutcome::Redirect {
            to: error_redirect(&redirect_uri, &e, &state),
        };
    }

    let mut to = redirect_uri.clone();
    to.query_pairs_mut()
        .append_pair("code", &raw_code)
        .append_pair("state", &state);
    AuthorizeOutcome::Redirect { to }
}

async fn ensure_entitlement(
    p: &OidcProvider,
    client: &OAuthClient,
    code: &NewAuthCode,
) -> Result<(), AuthError> {
    if !p.entitlements.has(code.user_id, client.client_id).await? {
        let scope_set: BTreeSet<String> = code.scope.iter().cloned().collect();
        p.entitlements
            .grant(code.user_id, client.client_id, code.tenant_id, &scope_set)
            .await?;
    }
    Ok(())
}

fn error_redirect(redirect_uri: &Url, err: &AuthError, state: &str) -> Url {
    let mut out = redirect_uri.clone();
    out.query_pairs_mut()
        .append_pair("error", err.oauth_code())
        .append_pair("state", state);
    out
}
