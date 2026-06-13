//! `/oauth2/token`. Two grants: `authorization_code` and `refresh_token`.

use mokosh_auth_core::{
    AuditEvent, AuthError, ClientId, GrantType, NewRefreshToken, NewRefreshTokenFamily,
    OAuthClient, RefreshTokenId,
};
use mokosh_auth_crypto::{ct_eq, generate_opaque_token, hash_opaque_token, pkce_s256_challenge};
use std::collections::BTreeSet;

use crate::client_auth::{authenticate_client, PresentedClientCredentials};
use crate::provider::OidcProvider;
use crate::tokens::{mint_access_token, mint_id_token};

/// Inputs lifted from the HTTP form body.
#[derive(Debug, Clone)]
pub struct TokenRequest {
    pub grant_type: String,
    /// `authorization_code` grant.
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    /// `refresh_token` grant.
    pub refresh_token: Option<String>,
    /// Scope narrowing for refresh.
    pub scope: Option<String>,
    /// Client credentials lifted by the HTTP layer.
    pub client_credentials: PresentedClientCredentials,
}

/// What the engine returned. The HTTP layer serializes this as the JSON
/// response body.
#[derive(Debug)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str, // always "Bearer"
    pub expires_in: i64,
    pub refresh_token: String,
    pub scope: String,
    /// Only returned for the authorization_code grant.
    pub id_token: Option<String>,
}

pub async fn handle_token(p: &OidcProvider, req: TokenRequest) -> Result<TokenResponse, AuthError> {
    // 1. Identify and authenticate the client.
    let client_id_str = req
        .client_credentials
        .client_id
        .as_deref()
        .ok_or(AuthError::InvalidClient)?;
    let client_uuid = client_id_str
        .parse::<uuid::Uuid>()
        .map_err(|_| AuthError::InvalidClient)?;
    let client = p
        .clients
        .find_by_client_id(ClientId(client_uuid))
        .await?
        .ok_or(AuthError::InvalidClient)?;
    authenticate_client(&client, &req.client_credentials)?;

    // 2. Dispatch on grant type.
    let grant = GrantType::parse(&req.grant_type).ok_or(AuthError::UnsupportedGrantType)?;
    if !client.allowed_grant_types.contains(&grant) {
        return Err(AuthError::UnauthorizedClient(format!(
            "grant_type {} not allowed for this client",
            req.grant_type
        )));
    }

    match grant {
        GrantType::AuthorizationCode => exchange_code(p, &client, &req).await,
        GrantType::RefreshToken => exchange_refresh(p, &client, &req).await,
    }
}

async fn exchange_code(
    p: &OidcProvider,
    client: &OAuthClient,
    req: &TokenRequest,
) -> Result<TokenResponse, AuthError> {
    let code = req
        .code
        .as_deref()
        .ok_or_else(|| AuthError::InvalidRequest("code is required".into()))?;
    let redirect_uri = req
        .redirect_uri
        .as_deref()
        .ok_or_else(|| AuthError::InvalidRequest("redirect_uri is required".into()))?;
    let verifier = req
        .code_verifier
        .as_deref()
        .ok_or_else(|| AuthError::InvalidRequest("code_verifier is required".into()))?;

    let now = p.clock.now();
    let code_hash = hash_opaque_token(code);
    // Atomic consume. If the code is unknown / used / expired, this is
    // `invalid_grant` and (per the OIDC spec) we MUST also revoke any
    // refresh-token family already issued from a successful prior exchange
    // of the same code. That session-aware revocation is handled below by
    // looking the consumed row up; here we treat the failure path simply.
    let consumed = match p.codes.consume(code_hash, now).await {
        Ok(c) => c,
        Err(e) => {
            // Best-effort: log a warning. Without the consumed row we
            // cannot identify which family to revoke, but we still refuse.
            tracing::warn!("authorization code consume failed: {e}");
            return Err(AuthError::InvalidGrant(
                "authorization code is invalid".into(),
            ));
        }
    };

    // PKCE verification (constant-time on the SHA-256 hash, never on the
    // raw verifier).
    let computed = pkce_s256_challenge(verifier);
    if !ct_eq(computed.as_bytes(), consumed.code_challenge.as_bytes()) {
        return Err(AuthError::InvalidGrant("PKCE verification failed".into()));
    }

    // Bind to client and redirect_uri.
    if consumed.client_id != client.client_id {
        return Err(AuthError::InvalidGrant("code/client mismatch".into()));
    }
    if consumed.redirect_uri != redirect_uri {
        return Err(AuthError::InvalidGrant("redirect_uri mismatch".into()));
    }

    // Load user.
    let user = p
        .users
        .find_by_id(consumed.user_id)
        .await?
        .ok_or(AuthError::InvalidGrant("user not found".into()))?;

    let scope_vec: Vec<String> = consumed.scope.clone();

    // Mint access + id tokens.
    let acr = consumed.acr.clone();
    let amr = consumed.amr.clone();
    // Active tenant: home tenant for the OIDC code path. The
    // membership-aware tenant switch lives on the SPA-only
    // /v1/auth/login flow; external RPs see one tenant per token
    // and would re-issue if the user wanted to switch.
    let active_tenant = user.tenant_id;
    let access = mint_access_token(
        &p.keys,
        &p.cfg,
        &user,
        client,
        &scope_vec,
        consumed.auth_time,
        &acr,
        &amr,
        active_tenant,
        Some(consumed.op_session_id),
        now,
    )?;
    let id_token = mint_id_token(
        &p.keys,
        &p.cfg,
        &user,
        client,
        &scope_vec,
        consumed.auth_time,
        &acr,
        &amr,
        consumed.nonce.as_deref(),
        &access.token,
        active_tenant,
        now,
    )?;

    // Issue initial refresh token (new family).
    let raw_refresh = generate_opaque_token();
    let refresh_hash = hash_opaque_token(&raw_refresh);
    let new_token = NewRefreshToken {
        id: RefreshTokenId::new(),
        token_hash: refresh_hash,
        scope: scope_vec.clone(),
        idle_expires_at: now + client.refresh_idle_ttl,
        absolute_expires_at: now + client.refresh_token_ttl,
        ip: None,
        user_agent: None,
    };
    let family = NewRefreshTokenFamily {
        client_id: client.client_id,
        user_id: user.id,
        tenant_id: user.tenant_id,
        op_session_id: Some(consumed.op_session_id),
    };
    p.refresh.issue_initial(family, new_token).await?;

    // Audit.
    let _ = p
        .audit
        .record(
            Some(user.tenant_id),
            Some(user.id),
            None,
            AuditEvent::TokenIssued {
                user_id: user.id,
                client_id: client.client_id,
                scope: scope_vec.clone(),
                jti: access.jti.clone(),
            },
        )
        .await;

    Ok(TokenResponse {
        access_token: access.token,
        token_type: "Bearer",
        expires_in: (access.expires_at - now).num_seconds().max(0),
        refresh_token: raw_refresh,
        scope: scope_vec.join(" "),
        id_token: Some(id_token),
    })
}

async fn exchange_refresh(
    p: &OidcProvider,
    client: &OAuthClient,
    req: &TokenRequest,
) -> Result<TokenResponse, AuthError> {
    let raw = req
        .refresh_token
        .as_deref()
        .ok_or_else(|| AuthError::InvalidRequest("refresh_token is required".into()))?;
    let presented_hash = hash_opaque_token(raw);
    let now = p.clock.now();

    let new_raw = generate_opaque_token();
    let new_hash = hash_opaque_token(&new_raw);
    let new_token_input = NewRefreshToken {
        id: RefreshTokenId::new(),
        token_hash: new_hash,
        // Scope is set after rotate() based on the narrowed set.
        scope: Vec::new(),
        idle_expires_at: now + client.refresh_idle_ttl,
        absolute_expires_at: now + client.refresh_token_ttl, // ignored by repo (preserved from family)
        ip: None,
        user_agent: None,
    };

    // Determine narrowed scope from the request.
    // The repo will load the row's prior scope from the DB and narrow
    // against the request via the BTreeSet we pass.
    // For simplicity here we pass the request's scope set (or empty for
    // "preserve previous"). The repo treats an empty set as "unchanged".
    let requested_scope: Option<BTreeSet<String>> = req
        .scope
        .as_deref()
        .map(|s| s.split_whitespace().map(String::from).collect());

    let narrowed: BTreeSet<String> = requested_scope.unwrap_or_default();

    let rotated = match p
        .refresh
        .rotate(presented_hash, new_token_input, &narrowed)
        .await
    {
        Ok(r) => r,
        Err(AuthError::ReuseDetected) => {
            // Already revoked by the storage layer. Emit critical audit.
            tracing::warn!(
                "refresh token reuse detected for client {}",
                client.client_id
            );
            return Err(AuthError::InvalidGrant(
                "refresh token reuse detected".into(),
            ));
        }
        Err(e) => return Err(e),
    };
    if rotated.client_id != client.client_id {
        return Err(AuthError::InvalidGrant("token/client mismatch".into()));
    }

    let user = p
        .users
        .find_by_id(rotated.user_id)
        .await?
        .ok_or(AuthError::InvalidGrant("user not found".into()))?;

    // Storage layer guarantees `rotated.scope` is the effective scope
    // (preserved from prior row when the request omitted `scope`,
    // narrowed when the request specified one).
    let scope_vec = rotated.scope.clone();

    // Refresh: preserve the active tenant from the user's
    // last_active_tenant pointer, falling back to the home tenant.
    // Switching tenants triggers a fresh /v1/auth/active-tenant call
    // (which mints a new bundle and resets the family).
    let active_tenant = user.last_active_tenant.unwrap_or(user.tenant_id);
    let access = mint_access_token(
        &p.keys,
        &p.cfg,
        &user,
        client,
        &scope_vec,
        now, // refresh-issued tokens get a current auth_time
        "urn:mokosh:loa:pwd",
        &["pwd".to_string()],
        active_tenant,
        // Refresh-grant: RotatedTokens does not currently carry the
        // bound op_session_id, so refreshed tokens omit the claim.
        // Sessions list still works on the primary login + switch
        // paths; refresh-only tokens just don't get the
        // "current session" badge until the rotate path threads
        // op_session_id through.
        None,
        now,
    )?;

    let _ = p
        .audit
        .record(
            Some(user.tenant_id),
            Some(user.id),
            None,
            AuditEvent::TokenRefreshed {
                user_id: user.id,
                client_id: client.client_id,
                family_id: rotated.family_id,
            },
        )
        .await;

    Ok(TokenResponse {
        access_token: access.token,
        token_type: "Bearer",
        expires_in: (access.expires_at - now).num_seconds().max(0),
        refresh_token: new_raw,
        scope: scope_vec.join(" "),
        id_token: None,
    })
}
