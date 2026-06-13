//! Conversions between database rows and `mokosh-auth-core` model types.
//!
//! These keep the repository implementations focused on queries: every
//! row maps through one well-typed `From<Row> for Model` conversion.

use chrono::{DateTime, Utc};
use mokosh_auth_core::{
    AuthError, ClientAuthMethod, ClientId, ClientType, GrantType, OAuthClient, OpSession,
    OpSessionId, RefreshFamilyId, RefreshToken, RefreshTokenFamily, RefreshTokenId, TenantId, User,
    UserId, UserRole, UserStatus,
};
use std::collections::BTreeSet;
use url::Url;
use uuid::Uuid;

// --- Users --------------------------------------------------------------

#[derive(sqlx::FromRow)]
pub(crate) struct UserRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub email: String,
    pub email_verified_at: Option<DateTime<Utc>>,
    pub password_hash: Option<String>,
    pub role: String,
    pub status: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub timezone: String,
    pub locale: String,
    pub avatar_url: Option<String>,
    pub mfa_enrolled: bool,
    pub last_login_at: Option<DateTime<Utc>>,
    pub last_active_tenant: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl TryFrom<UserRow> for User {
    type Error = AuthError;
    fn try_from(r: UserRow) -> Result<Self, Self::Error> {
        Ok(User {
            id: UserId(r.id),
            tenant_id: TenantId(r.tenant_id),
            email: r.email,
            email_verified_at: r.email_verified_at,
            password_hash: r.password_hash,
            role: UserRole::parse(&r.role)
                .ok_or_else(|| AuthError::Storage(format!("invalid role: {}", r.role)))?,
            status: UserStatus::parse(&r.status)
                .ok_or_else(|| AuthError::Storage(format!("invalid status: {}", r.status)))?,
            first_name: r.first_name,
            last_name: r.last_name,
            timezone: r.timezone,
            locale: r.locale,
            avatar_url: r.avatar_url,
            mfa_enrolled: r.mfa_enrolled,
            last_login_at: r.last_login_at,
            last_active_tenant: r.last_active_tenant.map(TenantId),
            created_at: r.created_at,
            updated_at: r.updated_at,
        })
    }
}

// --- OAuth clients ------------------------------------------------------

#[derive(sqlx::FromRow)]
pub(crate) struct OAuthClientRow {
    pub client_id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub client_secret_hash: Option<String>,
    pub client_type: String,
    pub name: String,
    pub description: Option<String>,
    pub icon_url: Option<String>,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    pub backchannel_logout_uri: Option<String>,
    pub lifecycle_event_uri: Option<String>,
    pub allowed_scopes: Vec<String>,
    pub allowed_grant_types: Vec<String>,
    pub token_endpoint_auth_method: String,
    pub require_pkce: bool,
    pub access_token_ttl_seconds: i32,
    pub refresh_token_ttl_seconds: i32,
    pub refresh_idle_ttl_seconds: i32,
    pub audience: String,
    pub disabled_at: Option<DateTime<Utc>>,
}

fn parse_urls(raw: Vec<String>, label: &str) -> Result<Vec<Url>, AuthError> {
    raw.into_iter()
        .map(|s| {
            Url::parse(&s)
                .map_err(|e| AuthError::Storage(format!("invalid {label} URL `{s}`: {e}")))
        })
        .collect()
}

impl TryFrom<OAuthClientRow> for OAuthClient {
    type Error = AuthError;
    fn try_from(r: OAuthClientRow) -> Result<Self, Self::Error> {
        let allowed_grant_types: Result<BTreeSet<GrantType>, _> = r
            .allowed_grant_types
            .iter()
            .map(|s| {
                GrantType::parse(s)
                    .ok_or_else(|| AuthError::Storage(format!("invalid grant_type: {s}")))
            })
            .collect();

        Ok(OAuthClient {
            client_id: ClientId(r.client_id),
            tenant_id: r.tenant_id.map(TenantId),
            name: r.name,
            description: r.description,
            icon_url: r.icon_url,
            client_type: ClientType::parse(&r.client_type).ok_or_else(|| {
                AuthError::Storage(format!("invalid client_type: {}", r.client_type))
            })?,
            client_secret_hash: r.client_secret_hash,
            redirect_uris: parse_urls(r.redirect_uris, "redirect_uri")?,
            post_logout_redirect_uris: parse_urls(
                r.post_logout_redirect_uris,
                "post_logout_redirect_uri",
            )?,
            backchannel_logout_uri: r
                .backchannel_logout_uri
                .map(|s| {
                    Url::parse(&s)
                        .map_err(|e| AuthError::Storage(format!("backchannel_logout_uri: {e}")))
                })
                .transpose()?,
            lifecycle_event_uri: r
                .lifecycle_event_uri
                .map(|s| {
                    Url::parse(&s)
                        .map_err(|e| AuthError::Storage(format!("lifecycle_event_uri: {e}")))
                })
                .transpose()?,
            allowed_scopes: r.allowed_scopes.into_iter().collect(),
            allowed_grant_types: allowed_grant_types?,
            token_endpoint_auth_method: ClientAuthMethod::parse(&r.token_endpoint_auth_method)
                .ok_or_else(|| {
                    AuthError::Storage(format!(
                        "invalid token_endpoint_auth_method: {}",
                        r.token_endpoint_auth_method
                    ))
                })?,
            require_pkce: r.require_pkce,
            access_token_ttl: chrono::Duration::seconds(r.access_token_ttl_seconds as i64),
            refresh_token_ttl: chrono::Duration::seconds(r.refresh_token_ttl_seconds as i64),
            refresh_idle_ttl: chrono::Duration::seconds(r.refresh_idle_ttl_seconds as i64),
            audience: r.audience,
            disabled_at: r.disabled_at,
        })
    }
}

// --- OP sessions --------------------------------------------------------

#[derive(sqlx::FromRow)]
pub(crate) struct OpSessionRow {
    pub id: Uuid,
    pub sid: String,
    pub user_id: Uuid,
    pub tenant_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub last_active_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub user_agent: Option<String>,
    pub ip: Option<ipnetwork::IpNetwork>,
    pub acr: String,
    pub amr: Vec<String>,
    pub display_name: Option<String>,
}

impl From<OpSessionRow> for OpSession {
    fn from(r: OpSessionRow) -> Self {
        OpSession {
            id: OpSessionId(r.id),
            sid: r.sid,
            user_id: UserId(r.user_id),
            tenant_id: TenantId(r.tenant_id),
            created_at: r.created_at,
            last_active_at: r.last_active_at,
            expires_at: r.expires_at,
            revoked_at: r.revoked_at,
            user_agent: r.user_agent,
            ip: r.ip.map(|n| n.ip()),
            acr: r.acr,
            amr: r.amr,
            display_name: r.display_name,
        }
    }
}

// --- Refresh tokens -----------------------------------------------------

#[derive(sqlx::FromRow)]
pub(crate) struct RefreshTokenRow {
    pub id: Uuid,
    pub family_id: Uuid,
    pub parent_id: Option<Uuid>,
    pub client_id: Uuid,
    pub user_id: Uuid,
    pub tenant_id: Uuid,
    pub scope: Vec<String>,
    pub issued_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub idle_expires_at: DateTime<Utc>,
    pub absolute_expires_at: DateTime<Utc>,
    pub ip: Option<ipnetwork::IpNetwork>,
    pub user_agent: Option<String>,
}

impl From<RefreshTokenRow> for RefreshToken {
    fn from(r: RefreshTokenRow) -> Self {
        RefreshToken {
            id: RefreshTokenId(r.id),
            family_id: RefreshFamilyId(r.family_id),
            parent_id: r.parent_id.map(RefreshTokenId),
            client_id: ClientId(r.client_id),
            user_id: UserId(r.user_id),
            tenant_id: TenantId(r.tenant_id),
            scope: r.scope,
            issued_at: r.issued_at,
            used_at: r.used_at,
            revoked_at: r.revoked_at,
            idle_expires_at: r.idle_expires_at,
            absolute_expires_at: r.absolute_expires_at,
            ip: r.ip.map(|n| n.ip()),
            user_agent: r.user_agent,
        }
    }
}

#[derive(sqlx::FromRow)]
pub(crate) struct RefreshFamilyRow {
    pub id: Uuid,
    pub client_id: Uuid,
    pub user_id: Uuid,
    pub tenant_id: Uuid,
    pub op_session_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoke_reason: Option<String>,
}

impl From<RefreshFamilyRow> for RefreshTokenFamily {
    fn from(r: RefreshFamilyRow) -> Self {
        RefreshTokenFamily {
            id: RefreshFamilyId(r.id),
            client_id: ClientId(r.client_id),
            user_id: UserId(r.user_id),
            tenant_id: TenantId(r.tenant_id),
            op_session_id: r.op_session_id.map(OpSessionId),
            created_at: r.created_at,
            revoked_at: r.revoked_at,
            revoke_reason: r.revoke_reason,
        }
    }
}

/// Helper for callers that want to pass `Option<IpAddr>` to a query that
/// expects `Option<ipnetwork::IpNetwork>`.
pub fn ip_to_inet(ip: Option<std::net::IpAddr>) -> Option<ipnetwork::IpNetwork> {
    ip.map(ipnetwork::IpNetwork::from)
}

/// Map any sqlx::Error into AuthError::Storage with a stable shape.
pub fn db_err(e: sqlx::Error) -> AuthError {
    AuthError::Storage(e.to_string())
}

/// Run a SERIALIZABLE operation with retry-on-serialization-failure.
///
/// Postgres returns SQLSTATE `40001` ("could not serialize access") when
/// two concurrent SERIALIZABLE transactions conflict; the loser must
/// retry or fail. This retries `op` up to a small budget before
/// surfacing the error, and is shared by every repository that runs a
/// SERIALIZABLE transaction. `label` names the operation in the
/// retry debug log.
pub async fn retry_serializable<T, F, Fut>(label: &str, mut op: F) -> Result<T, AuthError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, AuthError>>,
{
    const MAX_ATTEMPTS: u32 = 3;
    for attempt in 0..MAX_ATTEMPTS {
        match op().await {
            Err(AuthError::Storage(msg)) if msg.contains("40001") && attempt + 1 < MAX_ATTEMPTS => {
                tracing::debug!(
                    attempt,
                    operation = label,
                    "serialization conflict; retrying"
                );
                continue;
            }
            other => return other,
        }
    }
    unreachable!("loop returns or continues at most MAX_ATTEMPTS times")
}
