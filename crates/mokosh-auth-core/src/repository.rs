//! Repository traits. Implemented by `mokosh-auth-storage` for Postgres,
//! and by in-memory fakes in tests.
//!
//! Every method takes a `TenantId` (or carries it in the input struct) so
//! that cross-tenant data leakage is structurally impossible at this layer.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::BTreeSet;

use crate::error::AuthError;
use crate::ids::*;
use crate::model::*;

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn find_by_id(&self, id: UserId) -> Result<Option<User>, AuthError>;
    async fn find_by_email(
        &self,
        tenant_id: TenantId,
        email: &str,
    ) -> Result<Option<User>, AuthError>;
    /// Look up an active user by email across every tenant.
    ///
    /// Used by the OP login UI so a user only has to type their email
    /// (the tenant is resolved from their row). Returns up to two
    /// matches: the caller treats `len() >= 2` as ambiguous, since
    /// `(tenant_id, email)` is unique but `email` alone is not. The
    /// caller MUST treat ambiguity as a soft failure (do not reveal
    /// which tenants own the email).
    async fn find_by_email_globally(&self, email: &str) -> Result<Vec<User>, AuthError>;
    async fn create(&self, new: NewUser) -> Result<User, AuthError>;
    async fn update_last_login(&self, id: UserId, at: DateTime<Utc>) -> Result<(), AuthError>;
    async fn set_password_hash(&self, id: UserId, hash: &str) -> Result<(), AuthError>;
    async fn set_status(&self, id: UserId, status: UserStatus) -> Result<(), AuthError>;
    async fn mark_email_verified(&self, id: UserId, at: DateTime<Utc>) -> Result<(), AuthError>;
}

#[async_trait]
pub trait OAuthClientRepository: Send + Sync {
    async fn find_by_client_id(&self, client_id: ClientId)
        -> Result<Option<OAuthClient>, AuthError>;
}

#[async_trait]
pub trait OpSessionRepository: Send + Sync {
    async fn create(
        &self,
        user_id: UserId,
        tenant_id: TenantId,
        ttl: chrono::Duration,
        user_agent: Option<&str>,
        ip: Option<std::net::IpAddr>,
        acr: &str,
        amr: &[String],
    ) -> Result<OpSession, AuthError>;
    async fn find_by_sid(&self, sid: &str) -> Result<Option<OpSession>, AuthError>;
    async fn touch(&self, id: OpSessionId, at: DateTime<Utc>) -> Result<(), AuthError>;
    async fn revoke(&self, id: OpSessionId, at: DateTime<Utc>) -> Result<(), AuthError>;
    async fn revoke_all_for_user(&self, user_id: UserId) -> Result<Vec<OpSessionId>, AuthError>;
}

#[async_trait]
pub trait AuthCodeRepository: Send + Sync {
    async fn insert(&self, new: NewAuthCode) -> Result<(), AuthError>;
    /// Atomically consume a code by hash.
    ///
    /// Returns the `AuthorizationCode` row only on the first successful
    /// consumption. If the code is unknown, expired, revoked, or already
    /// consumed, returns `Err(AuthError::InvalidGrant(_))`.
    ///
    /// On replay (a second call with the same hash after the first
    /// succeeded), implementations MUST also revoke any refresh-token
    /// family already issued from the same op_session_id (handled at the
    /// engine level via the audit signal).
    async fn consume(
        &self,
        code_hash: [u8; 32],
        at: DateTime<Utc>,
    ) -> Result<AuthorizationCode, AuthError>;
}

#[async_trait]
pub trait RefreshTokenRepository: Send + Sync {
    /// Insert a brand-new family + first token. Returns the family id.
    async fn issue_initial(
        &self,
        family: NewRefreshTokenFamily,
        new_token: NewRefreshToken,
    ) -> Result<RefreshFamilyId, AuthError>;

    /// Atomic rotation: SERIALIZABLE isolation, reuse detection.
    ///
    /// If the presented token row has `used_at IS NOT NULL`, the entire
    /// family MUST be revoked and `AuthError::ReuseDetected` returned.
    async fn rotate(
        &self,
        presented_hash: [u8; 32],
        new_token: NewRefreshToken,
        narrowed_scope: &BTreeSet<String>,
    ) -> Result<RotatedTokens, AuthError>;

    async fn revoke_family(
        &self,
        family: RefreshFamilyId,
        reason: &str,
        at: DateTime<Utc>,
    ) -> Result<(), AuthError>;

    /// Revoke the family that owns the refresh token whose hash matches.
    ///
    /// Returns `Ok(())` whether or not a row matched: per RFC 7009 the
    /// revocation endpoint MUST NOT differentiate, to prevent token
    /// enumeration. The caller (the `/oauth2/revoke` handler) collapses
    /// errors and unknown tokens into a single 200 response.
    async fn revoke_by_token_hash(
        &self,
        token_hash: [u8; 32],
        reason: &str,
        at: DateTime<Utc>,
    ) -> Result<(), AuthError>;
}

#[async_trait]
pub trait EntitlementRepository: Send + Sync {
    async fn has(&self, user_id: UserId, client_id: ClientId) -> Result<bool, AuthError>;
    async fn grant(
        &self,
        user_id: UserId,
        client_id: ClientId,
        tenant_id: TenantId,
        scopes: &BTreeSet<String>,
    ) -> Result<(), AuthError>;
}

#[async_trait]
pub trait AuditLogger: Send + Sync {
    async fn record(
        &self,
        tenant_id: Option<TenantId>,
        actor: Option<UserId>,
        ip: Option<std::net::IpAddr>,
        event: AuditEvent,
    ) -> Result<(), AuthError>;
}

/// Cryptographic primitives the OIDC engine needs at runtime, abstracted so
/// tests can swap them out.
pub trait RandomSource: Send + Sync {
    fn fill(&self, buf: &mut [u8]);
}
