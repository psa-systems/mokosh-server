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
    /// All non-deleted users in a tenant, newest first. Powers the
    /// admin "User management" page; not used in any auth-critical
    /// path.
    async fn list_by_tenant(&self, tenant_id: TenantId) -> Result<Vec<User>, AuthError>;
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
    async fn find_by_id(&self, id: OpSessionId) -> Result<Option<OpSession>, AuthError>;
    /// All active (unrevoked, unexpired) sessions for a user. Used to
    /// power the "active sessions" UI and the "revoke other devices"
    /// administrative action.
    async fn list_active_for_user(
        &self,
        user_id: UserId,
        now: DateTime<Utc>,
    ) -> Result<Vec<OpSession>, AuthError>;
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
    /// Returns the bound `op_session_id` (if any) so the caller can
    /// also revoke the OP-side SSO session - logging out of the
    /// refresh family without killing the session would leave the
    /// HttpOnly OP cookie alive and silently re-authorize a future
    /// `/oauth2/authorize` request. `Ok(None)` covers both "unknown
    /// token" (per RFC 7009 callers MUST NOT differentiate hits from
    /// misses) and "family had no bound session"; the `/oauth2/revoke`
    /// handler collapses every outcome into a single 200 response.
    async fn revoke_by_token_hash(
        &self,
        token_hash: [u8; 32],
        reason: &str,
        at: DateTime<Utc>,
    ) -> Result<Option<OpSessionId>, AuthError>;

    /// Revoke every refresh family that was issued from a given OP
    /// session. Mirror of the above: revoking an OP session kills
    /// the refresh families bound to it, otherwise a stolen refresh
    /// token would survive a "log out everywhere" action.
    async fn revoke_families_for_session(
        &self,
        op_session_id: OpSessionId,
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

// ---------------------------------------------------------------------------
// Admin invites
// ---------------------------------------------------------------------------

/// Domain payload for the admin-issued invite system. Storage layer
/// owns the `id`, `issued_at`, and the `token_hash` (it hashes the raw
/// token internally on insert).
#[derive(Clone, Debug)]
pub struct NewInvite {
    pub tenant_id: TenantId,
    pub email: String,
    pub role: UserRole,
    pub token: String,
    pub invited_by: UserId,
    pub expires_at: DateTime<Utc>,
    pub note: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Invite {
    pub id: uuid::Uuid,
    pub tenant_id: TenantId,
    pub email: String,
    pub role: UserRole,
    pub invited_by: UserId,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub used_by: Option<UserId>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoked_by: Option<UserId>,
    pub revoke_reason: Option<String>,
    pub note: Option<String>,
}

/// Repository for the admin-invite flow. See
/// `docs/mokosh-auth/01-schema.md` for the contract.
#[async_trait]
pub trait InviteRepository: Send + Sync {
    /// Insert a new invite. The implementation hashes `new.token`
    /// (SHA-256) before storage; the raw value never persists.
    /// Errors with `Conflict("...")` if an open invite already exists
    /// for `(tenant_id, email)` (the partial-unique-index will reject
    /// the insert; the impl translates that into a clean Conflict).
    async fn issue(&self, new: NewInvite) -> Result<Invite, AuthError>;

    /// Find an invite by raw token. Returns `None` for any
    /// non-acceptable state (unknown, used, revoked, expired) so the
    /// caller treats them uniformly.
    async fn find_open_by_token(&self, token: &str) -> Result<Option<Invite>, AuthError>;

    /// Find an invite by id, tenant-scoped. Returns `None` if no row
    /// matches the (id, tenant) pair, which is also the right answer
    /// for cross-tenant lookups (defence-in-depth on top of the
    /// handler's tenant check).
    async fn find_by_id(
        &self,
        invite_id: uuid::Uuid,
        tenant_id: TenantId,
    ) -> Result<Option<Invite>, AuthError>;

    /// Find the open invite (if any) for `(tenant_id, email)`. Used by
    /// the issuance handler to populate `existing_invite_id` in the
    /// 409 response.
    async fn find_open_by_email(
        &self,
        tenant_id: TenantId,
        email: &str,
    ) -> Result<Option<Invite>, AuthError>;

    /// List all OPEN invites for a tenant, newest first.
    async fn list_open(&self, tenant_id: TenantId) -> Result<Vec<Invite>, AuthError>;

    /// Revoke an open invite. Idempotent: revoking a revoked or used
    /// invite returns Ok(()) so the admin UI can retry safely.
    async fn revoke(
        &self,
        invite_id: uuid::Uuid,
        tenant_id: TenantId,
        revoked_by: UserId,
        reason: &str,
    ) -> Result<(), AuthError>;

    /// Replace the token on an open invite (resend flow). Pushes
    /// `expires_at` forward by `ttl_days`. Returns the new raw token
    /// so the caller can email it.
    async fn replace_token(
        &self,
        invite_id: uuid::Uuid,
        tenant_id: TenantId,
        ttl_days: i64,
    ) -> Result<(Invite, String), AuthError>;

    /// Atomic accept under SERIALIZABLE isolation. Marks the invite
    /// used AND inserts the new user in one transaction. Returns the
    /// created user.
    async fn accept(
        &self,
        token: &str,
        password_hash: &str,
        first_name: Option<&str>,
        last_name: Option<&str>,
    ) -> Result<User, AuthError>;
}
