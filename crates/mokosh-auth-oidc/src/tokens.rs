//! JWT minting: RFC 9068 `at+jwt` access tokens, OIDC ID tokens, and
//! back-channel logout tokens. All signed with EdDSA via the active
//! Ed25519 key from [`OidcKeySet`](mokosh_auth_crypto::OidcKeySet).
//!
//! Refresh tokens are NOT JWTs (they are opaque base64url-encoded random
//! 32-byte values, hashed for storage); see `mokosh_auth_crypto::token`.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use jsonwebtoken::{encode, Algorithm, Header};
use mokosh_auth_core::{AuthError, ClientId, OAuthClient, User, UserId};
use mokosh_auth_crypto::OidcKeySet;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use uuid::Uuid;

use crate::config::EngineConfig;

/// RFC 9068 access token claims. Serialized into a JWT with `typ=at+jwt`.
#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub iss: String,
    pub sub: String,           // user UUID as string
    pub aud: String,           // client.audience
    pub client_id: String,
    /// Mokosh-specific. Namespaced (`mokosh_tenant_id`) so it cannot be
    /// confused with anyone else's `tenant_id` claim. Historically the
    /// "home tenant"; with memberships it equals `mokosh_active_tenant`
    /// for now and is kept for backcompat with relying parties that
    /// have not learned the active-tenant claim yet.
    pub mokosh_tenant_id: String,
    /// The tenant the user is *currently acting under*. With the
    /// memberships model a user can have many; this claim pins the
    /// one this token is good for. RPs MUST gate authorization on
    /// this claim, not on `mokosh_tenant_id`.
    pub mokosh_active_tenant: String,
    /// OP session id this token was minted under, when known.
    /// Lets handlers identify the "current session" without
    /// relying on the cookie. Refresh-grant tokens may omit it
    /// (the refresh path doesn't carry session_id end-to-end yet).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mokosh_op_session_id: Option<String>,
    pub scope: String,         // space-separated
    pub jti: String,
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
    pub auth_time: i64,
    pub acr: String,
    pub amr: Vec<String>,
}

/// OIDC Core ID token claims.
#[derive(Debug, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub azp: String,           // authorized party = client_id
    pub exp: i64,
    pub iat: i64,
    pub auth_time: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    pub at_hash: String,       // base64url(left-half(SHA-256(access_token)))
    pub acr: String,
    pub amr: Vec<String>,
    pub mokosh_tenant_id: String,
    pub mokosh_active_tenant: String,
    pub mokosh_role: String,
    // OIDC Core "email" scope claims, populated only when the scope is granted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
}

/// RFC 8417 SET (Security Event Token) for OIDC Back-Channel Logout 1.0.
#[derive(Debug, Serialize, Deserialize)]
pub struct LogoutTokenClaims {
    pub iss: String,
    pub aud: String,
    pub iat: i64,
    pub jti: String,
    pub sub: String,
    pub sid: String,
    /// Single-element map: `"http://schemas.openid.net/event/backchannel-logout"`
    /// to an empty object. Required by the spec.
    pub events: BTreeMap<String, serde_json::Value>,
}

/// Result of minting an access token: the encoded JWT plus its absolute
/// expiry, used by the token endpoint to populate `expires_in`.
pub struct MintedAccessToken {
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub jti: String,
}

/// Mint an RFC 9068 access token.
///
/// `active_tenant` is the tenant context this token authorizes. For
/// pre-memberships call sites pass `user.tenant_id` (the home tenant)
/// and the result matches the historical behaviour. With memberships,
/// the caller resolves the active tenant from the request (explicit
/// `tenant_id` body field at login, `users.last_active_tenant`, or
/// home tenant) and passes it here; the claim flows to RPs as
/// `mokosh_active_tenant`.
pub fn mint_access_token(
    keys: &OidcKeySet,
    cfg: &EngineConfig,
    user: &User,
    client: &OAuthClient,
    scope: &[String],
    auth_time: DateTime<Utc>,
    acr: &str,
    amr: &[String],
    active_tenant: mokosh_auth_core::TenantId,
    op_session_id: Option<mokosh_auth_core::OpSessionId>,
    now: DateTime<Utc>,
) -> Result<MintedAccessToken, AuthError> {
    let exp = now + client.access_token_ttl;
    let jti = Uuid::new_v4().to_string();
    let claims = AccessTokenClaims {
        iss: cfg.issuer_str().to_string(),
        sub: user.id.0.to_string(),
        aud: client.audience.clone(),
        client_id: client.client_id.0.to_string(),
        mokosh_tenant_id: user.tenant_id.0.to_string(),
        mokosh_active_tenant: active_tenant.0.to_string(),
        mokosh_op_session_id: op_session_id.map(|s| s.0.to_string()),
        scope: scope.join(" "),
        jti: jti.clone(),
        iat: now.timestamp(),
        nbf: now.timestamp(),
        exp: exp.timestamp(),
        auth_time: auth_time.timestamp(),
        acr: acr.to_string(),
        amr: amr.to_vec(),
    };

    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(keys.active_kid().to_string());
    header.typ = Some("at+jwt".into());
    let token = encode(&header, &claims, keys.encoding_key())
        .map_err(|e| AuthError::Crypto(format!("at+jwt encode: {e}")))?;

    Ok(MintedAccessToken {
        token,
        expires_at: exp,
        jti,
    })
}

/// Mint an OIDC ID token. Must be called *after* the access token so its
/// `at_hash` claim can be computed.
pub fn mint_id_token(
    keys: &OidcKeySet,
    cfg: &EngineConfig,
    user: &User,
    client: &OAuthClient,
    scope: &[String],
    auth_time: DateTime<Utc>,
    acr: &str,
    amr: &[String],
    nonce: Option<&str>,
    access_token: &str,
    active_tenant: mokosh_auth_core::TenantId,
    now: DateTime<Utc>,
) -> Result<String, AuthError> {
    let exp = now + client.access_token_ttl;
    let at_hash = compute_at_hash(access_token);
    let include_email = scope.iter().any(|s| s == "email");

    let claims = IdTokenClaims {
        iss: cfg.issuer_str().to_string(),
        sub: user.id.0.to_string(),
        aud: client.client_id.0.to_string(),
        azp: client.client_id.0.to_string(),
        exp: exp.timestamp(),
        iat: now.timestamp(),
        auth_time: auth_time.timestamp(),
        nonce: nonce.map(str::to_string),
        at_hash,
        acr: acr.to_string(),
        amr: amr.to_vec(),
        mokosh_tenant_id: user.tenant_id.0.to_string(),
        mokosh_active_tenant: active_tenant.0.to_string(),
        mokosh_role: user.role.as_str().to_string(),
        email: include_email.then(|| user.email.clone()),
        email_verified: include_email.then(|| user.email_verified_at.is_some()),
    };

    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(keys.active_kid().to_string());
    encode(&header, &claims, keys.encoding_key())
        .map_err(|e| AuthError::Crypto(format!("id_token encode: {e}")))
}

/// Mint a back-channel logout token.
pub fn mint_logout_token(
    keys: &OidcKeySet,
    cfg: &EngineConfig,
    user_id: UserId,
    sid: &str,
    audience_client_id: ClientId,
    now: DateTime<Utc>,
) -> Result<String, AuthError> {
    let mut events = BTreeMap::new();
    events.insert(
        "http://schemas.openid.net/event/backchannel-logout".to_string(),
        serde_json::json!({}),
    );
    let claims = LogoutTokenClaims {
        iss: cfg.issuer_str().to_string(),
        aud: audience_client_id.0.to_string(),
        iat: now.timestamp(),
        jti: Uuid::new_v4().to_string(),
        sub: user_id.0.to_string(),
        sid: sid.to_string(),
        events,
    };
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(keys.active_kid().to_string());
    encode(&header, &claims, keys.encoding_key())
        .map_err(|e| AuthError::Crypto(format!("logout_token encode: {e}")))
}

/// `at_hash`: base64url(no-pad) of the left half of SHA-256(access_token).
/// Defined in OIDC Core 3.1.3.6.
fn compute_at_hash(access_token: &str) -> String {
    let digest = Sha256::digest(access_token.as_bytes());
    URL_SAFE_NO_PAD.encode(&digest[..16])
}

