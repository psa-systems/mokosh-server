//! `/oauth2/userinfo`. Bearer access-token auth, returns claims gated by
//! the token's `scope` claim.

use jsonwebtoken::{decode, DecodingKey, Validation};
use mokosh_auth_core::{AuthError, UserId};
use serde::Serialize;

use crate::provider::OidcProvider;
use crate::tokens::AccessTokenClaims;

#[derive(Debug, Serialize)]
pub struct UserInfoResponse {
    pub sub: String,
    pub mokosh_tenant_id: String,
    /// The tenant the bearer token authorizes the caller to act under.
    /// This is the authorization-gating claim: RPs MUST gate on it, not
    /// on `mokosh_tenant_id` (the user's home tenant). Mirrored from the
    /// access token so /userinfo callers see the same value the token
    /// carried.
    pub mokosh_active_tenant: String,
    pub mokosh_role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
}

pub async fn handle_userinfo(
    p: &OidcProvider,
    bearer: &str,
) -> Result<UserInfoResponse, AuthError> {
    let header = jsonwebtoken::decode_header(bearer)
        .map_err(|_| AuthError::AccessDenied("malformed token".into()))?;
    if header.typ.as_deref() != Some("at+jwt") {
        return Err(AuthError::AccessDenied("wrong token type".into()));
    }
    let kid = header
        .kid
        .ok_or_else(|| AuthError::AccessDenied("missing kid".into()))?;
    let dk: &DecodingKey = p
        .keys
        .decoding_key(&kid)
        .ok_or_else(|| AuthError::AccessDenied("unknown kid".into()))?;

    let mut validation = Validation::new(jsonwebtoken::Algorithm::EdDSA);
    validation.set_issuer(&[p.cfg.issuer_str()]);
    validation.leeway = p.cfg.leeway.num_seconds().max(0) as u64;
    // Audience is per-client; the engine doesn't know which audience to
    // require here, so we don't constrain it. Verifying caller relies on
    // signature + iss + exp + nbf.
    validation.validate_aud = false;

    let data = decode::<AccessTokenClaims>(bearer, dk, &validation)
        .map_err(|e| AuthError::AccessDenied(format!("token verify failed: {e}")))?;
    let claims = data.claims;

    let user_uuid = claims
        .sub
        .parse::<uuid::Uuid>()
        .map_err(|_| AuthError::AccessDenied("malformed sub".into()))?;
    let user = p
        .users
        .find_by_id(UserId(user_uuid))
        .await?
        .ok_or(AuthError::AccessDenied("user not found".into()))?;
    if !matches!(user.status, mokosh_auth_core::UserStatus::Active) {
        return Err(AuthError::AccessDenied("user not active".into()));
    }

    let scopes: std::collections::BTreeSet<&str> = claims.scope.split_whitespace().collect();
    let include_email = scopes.contains("email");
    Ok(UserInfoResponse {
        sub: user.id.0.to_string(),
        mokosh_tenant_id: user.tenant_id.0.to_string(),
        mokosh_active_tenant: claims.mokosh_active_tenant.clone(),
        mokosh_role: user.role.as_str().to_string(),
        email: include_email.then(|| user.email.clone()),
        email_verified: include_email.then(|| user.email_verified_at.is_some()),
    })
}
