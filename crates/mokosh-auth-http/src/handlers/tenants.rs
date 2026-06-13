//! `/v1/auth/memberships` (list) and `/v1/auth/active-tenant` (switch).
//!
//! The memberships endpoint powers the SPA tenant switcher: shows
//! every tenant the user can act under, with name + kind.
//!
//! The active-tenant endpoint validates that the requested tenant is
//! one the user actually has an active membership in, persists the
//! choice on `users.last_active_tenant`, and reissues a fresh token
//! bundle with the new `mokosh_active_tenant` claim. The SPA replaces
//! its in-memory + sessionStorage tokens with the new bundle and
//! reloads.
//!
//! Phase 4 of docs/mokosh-auth/10-memberships-and-self-signup.md.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use mokosh_auth_core::{
    AuthError, ClientId, MembershipStatus, NewRefreshToken, NewRefreshTokenFamily, RefreshTokenId,
    TenantId,
};
use mokosh_auth_crypto::{generate_opaque_token, hash_opaque_token};
use mokosh_auth_oidc::tokens::{mint_access_token, mint_id_token};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::errors::HttpError;
use crate::extractors::BearerUser;
use crate::handlers::shared::{TokenBundle, DEFAULT_FIRST_PARTY_SCOPE};
use crate::router::AuthHttpState;

#[derive(Debug, Serialize)]
pub struct MembershipView {
    pub tenant_id: String,
    pub tenant_name: String,
    pub tenant_kind: String, // "personal" | "org"
    pub role: String,
    pub status: String,
    pub joined_at: chrono::DateTime<chrono::Utc>,
    pub is_active: bool, // === active_tenant_id from current token
}

#[derive(Debug, Serialize)]
pub struct MembershipListResponse {
    pub memberships: Vec<MembershipView>,
    pub active_tenant_id: String,
}

pub async fn list_my_memberships(
    State(st): State<Arc<AuthHttpState>>,
    BearerUser(user): BearerUser,
) -> Result<Json<MembershipListResponse>, HttpError> {
    let memberships = st
        .memberships
        .list_for_user(user.id)
        .await
        .map_err(HttpError)?;

    let active_tenant = user.last_active_tenant.unwrap_or(user.tenant_id);

    let mut views = Vec::with_capacity(memberships.len());
    for m in memberships {
        let (name, kind) = (st.tenant_info)(m.tenant_id)
            .await
            .unwrap_or_else(|| ("Unknown".to_string(), "org".to_string()));
        views.push(MembershipView {
            tenant_id: m.tenant_id.0.to_string(),
            tenant_name: name,
            tenant_kind: kind,
            role: m.role.as_str().to_string(),
            status: m.status.as_str().to_string(),
            joined_at: m.joined_at,
            is_active: m.tenant_id == active_tenant,
        });
    }

    Ok(Json(MembershipListResponse {
        memberships: views,
        active_tenant_id: active_tenant.0.to_string(),
    }))
}

#[derive(Debug, Deserialize)]
pub struct SwitchBody {
    pub tenant_id: uuid::Uuid,
    /// Required: the SPA must say which client the new tokens are
    /// minted for (mirrors the `/v1/auth/login` first-party-tokens
    /// shape). The client must allow the authorization_code grant.
    pub client_id: uuid::Uuid,
    /// Optional space-separated scope. Defaults to the same set the
    /// SPA uses on initial login.
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SwitchResponse {
    pub active_tenant_id: String,
    pub tokens: TokenBundle,
}

/// `POST /v1/auth/active-tenant`
///
/// Validates that the user has an active membership in the requested
/// tenant, updates `users.last_active_tenant`, and mints a new
/// access+id+refresh bundle with the new `mokosh_active_tenant` claim.
/// The previous bundle is NOT auto-revoked: it stays good until its
/// own expiry. The SPA discards it on receipt of this response.
pub async fn switch_active_tenant(
    State(st): State<Arc<AuthHttpState>>,
    BearerUser(user): BearerUser,
    crate::extractors::BearerSessionId(current_sid): crate::extractors::BearerSessionId,
    Json(body): Json<SwitchBody>,
) -> Result<Response, HttpError> {
    let tenant_id = TenantId(body.tenant_id);

    // 1. Validate membership.
    let m = st
        .memberships
        .find(user.id, tenant_id)
        .await
        .map_err(HttpError)?
        .ok_or(HttpError(AuthError::NotFound))?;
    if !matches!(m.status, MembershipStatus::Active) {
        return Err(HttpError(AuthError::Forbidden(
            "membership is not active".into(),
        )));
    }

    // 2. Persist for next login.
    st.provider
        .users
        .set_last_active_tenant(user.id, Some(tenant_id))
        .await
        .map_err(HttpError)?;

    // 3. Mint new tokens for the new active tenant.
    let provider = &st.provider;
    let client = provider
        .clients
        .find_by_client_id(ClientId(body.client_id))
        .await
        .map_err(HttpError)?
        .ok_or(HttpError(AuthError::InvalidClient))?;
    if !client
        .allowed_grant_types
        .contains(&mokosh_auth_core::GrantType::AuthorizationCode)
    {
        return Err(HttpError(AuthError::UnauthorizedClient(
            "client cannot receive first-party tokens".into(),
        )));
    }
    let scope_vec: Vec<String> = body
        .scope
        .as_deref()
        .map(|s| s.split_whitespace().map(String::from).collect::<Vec<_>>())
        .filter(|v: &Vec<_>| !v.is_empty())
        .unwrap_or_else(|| {
            DEFAULT_FIRST_PARTY_SCOPE
                .iter()
                .map(|&s| s.to_string())
                .collect()
        });

    let now = provider.clock.now();
    let acr = "urn:mokosh:loa:pwd";
    let amr: Vec<String> = vec!["pwd".to_string()];

    let access = mint_access_token(
        &provider.keys,
        &provider.cfg,
        &user,
        &client,
        &scope_vec,
        now,
        acr,
        &amr,
        tenant_id,
        // Re-bind the new access token to the caller's existing OP
        // session so the SPA's "Current session" badge survives a
        // tenant switch. The OP cookie is the same browser device; the
        // tenant scope changes but the device identity doesn't. None
        // when the caller's token had no sid claim (e.g. nested
        // tenant-switched grant); in that case the badge silently
        // disappears, same as the pre-rebind behavior.
        current_sid,
        now,
    )
    .map_err(HttpError)?;
    let id_token = mint_id_token(
        &provider.keys,
        &provider.cfg,
        &user,
        &client,
        &scope_vec,
        now,
        acr,
        &amr,
        None,
        &access.token,
        tenant_id,
        now,
    )
    .map_err(HttpError)?;

    // Issue a fresh refresh family for the new tenant context. The
    // old family stays alive (the SPA discards its tokens; the
    // family will rotate or expire on its own absolute TTL).
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
        op_session_id: current_sid,
    };
    provider
        .refresh
        .issue_initial(family, new_token)
        .await
        .map_err(HttpError)?;

    Ok((
        StatusCode::OK,
        Json(SwitchResponse {
            active_tenant_id: tenant_id.0.to_string(),
            tokens: TokenBundle {
                access_token: access.token,
                token_type: "Bearer",
                expires_in: (access.expires_at - now).num_seconds().max(0),
                id_token,
                refresh_token: raw_refresh,
                scope: scope_vec.join(" "),
            },
        }),
    )
        .into_response())
}
