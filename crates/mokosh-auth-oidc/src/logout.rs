//! `/oauth2/logout`: RP-Initiated Logout (OIDC Front-Channel/RP-Initiated
//! Logout 1.0).
//!
//! The HTTP layer is responsible for clearing OP cookies after this
//! function returns. We:
//!  1. Validate `id_token_hint` (signature only; the issuer is the OP
//!     itself so signing key is in our own JWKS).
//!  2. Validate `post_logout_redirect_uri` against the client's allow list.
//!  3. Revoke the OP session matching the token's `sid` claim (if any).
//!  4. Return an outcome the HTTP layer can act on.

use mokosh_auth_core::{AuditEvent, AuthError, ClientId, TenantId, UserId};
use serde::Deserialize;
use url::Url;

use crate::provider::OidcProvider;

#[derive(Debug, Clone)]
pub struct LogoutRequest {
    pub id_token_hint: Option<String>,
    pub client_id: Option<String>,
    pub post_logout_redirect_uri: Option<String>,
    pub state: Option<String>,
}

/// Identifies the OP session that this logout invocation revoked, so the
/// HTTP layer can fan a Back-Channel Logout 1.0 token out to every other
/// RP registered with a `backchannel_logout_uri`. None when no session
/// matched the id_token_hint's `sid` (already logged out, or hint
/// carried no sid).
#[derive(Debug, Clone)]
pub struct RevokedSession {
    pub user_id: UserId,
    pub tenant_id: TenantId,
    pub sid: String,
}

#[derive(Debug)]
pub enum LogoutOutcome {
    /// Browser was logged in; we revoked the session. If `redirect_to`
    /// is set, the HTTP layer should send a 302 there with `state` in
    /// the query. `revoked` carries the session identifiers when a
    /// session was actually killed, so the HTTP layer can emit
    /// Back-Channel Logout tokens to other RPs.
    LoggedOut {
        redirect_to: Option<Url>,
        revoked: Option<RevokedSession>,
    },
    /// No usable id_token_hint; we cannot validate redirect, so we
    /// surface a confirmation page (or simply clear the cookie and end).
    NeedsConfirmation,
    /// Validation failed.
    Error(AuthError),
}

#[derive(Debug, Deserialize)]
struct IdTokenSubsetClaims {
    aud: serde_json::Value,
    sid: Option<String>,
}

pub async fn handle_logout(p: &OidcProvider, req: LogoutRequest) -> LogoutOutcome {
    // 1. id_token_hint is optional but strongly recommended. Without it
    //    we cannot safely honor `post_logout_redirect_uri`.
    let hint = match req.id_token_hint {
        Some(ref h) if !h.is_empty() => h.clone(),
        _ => return LogoutOutcome::NeedsConfirmation,
    };

    let header = match jsonwebtoken::decode_header(&hint) {
        Ok(h) => h,
        Err(_) => {
            return LogoutOutcome::Error(AuthError::InvalidRequest(
                "malformed id_token_hint".into(),
            ))
        }
    };
    let kid = match header.kid {
        Some(k) => k,
        None => return LogoutOutcome::Error(AuthError::InvalidRequest("missing kid".into())),
    };
    let dk = match p.keys.decoding_key(&kid) {
        Some(d) => d,
        None => return LogoutOutcome::Error(AuthError::InvalidRequest("unknown kid".into())),
    };

    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
    validation.set_issuer(&[p.cfg.issuer_str()]);
    validation.leeway = p.cfg.leeway.num_seconds().max(0) as u64;
    validation.validate_aud = false;
    // Allow expired hints: per spec a logout request is meaningful even
    // after the id_token has expired.
    validation.validate_exp = false;

    let claims = match jsonwebtoken::decode::<IdTokenSubsetClaims>(&hint, dk, &validation) {
        Ok(d) => d.claims,
        Err(_) => {
            return LogoutOutcome::Error(AuthError::InvalidRequest("invalid id_token_hint".into()))
        }
    };

    // 2. Resolve client (from claims.aud or from `client_id` form field).
    let aud_str: Option<String> = match claims.aud {
        serde_json::Value::String(s) => Some(s),
        serde_json::Value::Array(ref a) => a.first().and_then(|v| v.as_str()).map(str::to_string),
        _ => None,
    };
    let client_id_str = req.client_id.clone().or(aud_str).unwrap_or_default();
    let client_uuid = match client_id_str.parse::<uuid::Uuid>() {
        Ok(u) => u,
        Err(_) => return LogoutOutcome::Error(AuthError::InvalidClient),
    };
    let client = match p.clients.find_by_client_id(ClientId(client_uuid)).await {
        Ok(Some(c)) => c,
        _ => return LogoutOutcome::Error(AuthError::InvalidClient),
    };

    // 3. Validate post_logout_redirect_uri against the client's allow list.
    let redirect_to = match req.post_logout_redirect_uri.as_deref() {
        Some(s) => match Url::parse(s) {
            Ok(u)
                if client
                    .post_logout_redirect_uris
                    .iter()
                    .any(|allowed| allowed == &u) =>
            {
                Some(u)
            }
            _ => return LogoutOutcome::Error(AuthError::InvalidRedirect),
        },
        None => None,
    };

    // 4. Revoke the OP session by sid. Also revoke every refresh-token
    //    family issued from it - otherwise an RP that holds a refresh
    //    token can mint a fresh access token after we just told the
    //    user "you're signed out", which is the exact scenario
    //    Back-Channel Logout is supposed to close.
    let mut revoked: Option<RevokedSession> = None;
    if let Some(sid) = claims.sid.as_deref() {
        if let Ok(Some(session)) = p.sessions.find_by_sid(sid).await {
            let now = p.clock.now();
            let _ = p.sessions.revoke(session.id, now).await;
            let _ = p
                .refresh
                .revoke_families_for_session(session.id, "rp_initiated_logout", now)
                .await;
            let _ = p
                .audit
                .record(
                    Some(session.tenant_id),
                    Some(session.user_id),
                    None,
                    AuditEvent::SessionRevoked {
                        user_id: session.user_id,
                        sid: sid.to_string(),
                        reason: "rp_initiated_logout".into(),
                    },
                )
                .await;
            revoked = Some(RevokedSession {
                user_id: session.user_id,
                tenant_id: session.tenant_id,
                sid: sid.to_string(),
            });
        }
    }

    // 5. Return redirect target (with state) to the HTTP layer.
    let to = redirect_to.map(|mut u| {
        if let Some(state) = req.state.as_deref() {
            u.query_pairs_mut().append_pair("state", state);
        }
        u
    });

    LogoutOutcome::LoggedOut {
        redirect_to: to,
        revoked,
    }
}
