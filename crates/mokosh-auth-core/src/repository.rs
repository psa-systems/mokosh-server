//! Repository traits. Implemented by `mokosh-auth-storage` for Postgres,
//! and by in-memory fakes in tests.
//!
//! Every method takes a `TenantId` (or carries it in the input struct) so
//! that cross-tenant data leakage is structurally impossible at this layer.

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
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
    /// Atomically increment `failed_login_count`, set `last_failed_login_at = NOW()`,
    /// and (if the new count crosses the threshold) set `locked_until = NOW() + lock_for`.
    /// Returns the post-increment counter so the caller can audit the lock.
    async fn record_failed_login(
        &self,
        id: UserId,
        threshold: i32,
        lock_for: Duration,
    ) -> Result<FailedLoginOutcome, AuthError>;
    /// Reset the counter + clear `locked_until` after a successful login.
    async fn clear_failed_logins(&self, id: UserId) -> Result<(), AuthError>;
    /// Read `locked_until` for the user; if `> now()` the account is locked.
    async fn lockout_status(&self, id: UserId) -> Result<Option<DateTime<Utc>>, AuthError>;
    async fn set_password_hash(&self, id: UserId, hash: &str) -> Result<(), AuthError>;
    /// Update the self-editable profile fields. Empty strings on
    /// `first_name` / `last_name` / `avatar_url` collapse to NULL; the
    /// `timezone` is set as-is (validation lives in the handler).
    async fn update_profile(
        &self,
        id: UserId,
        first_name: Option<&str>,
        last_name: Option<&str>,
        timezone: &str,
        avatar_url: Option<&str>,
    ) -> Result<(), AuthError>;
    async fn set_status(&self, id: UserId, status: UserStatus) -> Result<(), AuthError>;
    /// Mutate the global role on a single user row. The handler is
    /// responsible for the last-admin guard + the step-up gate when
    /// promoting to Admin; this is the bare write.
    async fn set_role(&self, id: UserId, role: UserRole) -> Result<(), AuthError>;
    /// Count active Admins in the tenant, EXCLUDING `excluded`. Used
    /// by the last-admin guard on suspend / demote / delete. Callers
    /// run this in the same transaction as the mutation they are
    /// guarding so the count is race-safe at SERIALIZABLE.
    async fn count_active_admins_excluding(
        &self,
        tenant_id: TenantId,
        excluded: UserId,
    ) -> Result<u64, AuthError>;
    /// Update the email column. Used by `user.delete` so the original
    /// address can be reused by a fresh signup. Returns `Conflict` if
    /// the new email already exists for the tenant.
    async fn update_email(&self, id: UserId, new_email: &str) -> Result<(), AuthError>;
    /// Filtered + paginated listing. Powers the enhanced admin
    /// user-management page. Returns `(rows, total_matching)` so the
    /// SPA can render "Showing N of M".
    async fn list_filtered(
        &self,
        tenant_id: TenantId,
        filter: UserListFilter,
    ) -> Result<(Vec<User>, u64), AuthError>;
    async fn mark_email_verified(&self, id: UserId, at: DateTime<Utc>) -> Result<(), AuthError>;
    /// Update the user's `last_active_tenant` pointer. Called by
    /// `/v1/auth/active-tenant` when the user switches tenants and
    /// implicitly by login when an explicit tenant_id is supplied.
    /// Pass `None` to clear (falls back to the home tenant).
    async fn set_last_active_tenant(
        &self,
        id: UserId,
        tenant_id: Option<TenantId>,
    ) -> Result<(), AuthError>;
}

#[async_trait]
pub trait OAuthClientRepository: Send + Sync {
    async fn find_by_client_id(
        &self,
        client_id: ClientId,
    ) -> Result<Option<OAuthClient>, AuthError>;
    /// All enabled OAuth clients launchable by the given (user, tenant)
    /// pair. Visibility today is simple: every non-disabled row whose
    /// `tenant_id` is NULL (platform-wide) OR matches the supplied
    /// tenant, AND that has at least one redirect_uri. Powers the
    /// Bunyip app launcher; the `user_id` is accepted today for future
    /// per-user ACLs but is currently unused by every implementation.
    async fn list_for_user(
        &self,
        user_id: UserId,
        tenant_id: TenantId,
    ) -> Result<Vec<OAuthClient>, AuthError>;
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
    /// Revoke every active session for the user whose user_agent matches
    /// the supplied string EXCEPT `keep_id`. Used by the login handler
    /// to dedupe the "same browser = same logical session" case: the
    /// SPA's fetch does not carry the OP-session cookie back, so the
    /// cookie-based revoke does not fire and stale rows pile up. Match
    /// is exact on the UA string; NULL UAs match other NULL UAs.
    async fn revoke_others_same_user_agent(
        &self,
        user_id: UserId,
        user_agent: Option<&str>,
        keep_id: OpSessionId,
        at: DateTime<Utc>,
    ) -> Result<u64, AuthError>;
    /// Update the user-friendly display name on a session row. NULL or
    /// empty clears the name. Tenant-scoped: the caller must own the
    /// session.
    async fn rename(
        &self,
        id: OpSessionId,
        user_id: UserId,
        display_name: Option<&str>,
    ) -> Result<(), AuthError>;
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

    /// List the most recent rows for a tenant. Pagination is offset-based
    /// because the admin UI is the only consumer today and the volumes
    /// are modest; if this grows we switch to a `(created_at, id)` cursor.
    /// `kind` is an optional `event_kind` filter; `actor_id` filters to
    /// rows where the actor matches (used for "show me everything user X
    /// did").
    async fn list_recent(
        &self,
        tenant_id: TenantId,
        kind: Option<&str>,
        actor_id: Option<UserId>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AuditEntry>, AuthError>;
}

#[derive(Clone, Debug)]
pub struct AuditEntry {
    pub id: uuid::Uuid,
    pub tenant_id: Option<TenantId>,
    pub actor_id: Option<UserId>,
    pub event_kind: String,
    pub severity: String,
    pub ip: Option<std::net::IpAddr>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
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
/// (user, tenant, role, status) joins. A user can have many.
///
/// Powers the "active sessions" tenant-switcher UI, the membership-
/// aware invite-accept (existing user gets a fresh membership instead
/// of a duplicate `User` row), and self-signup (new personal-tenant
/// owner membership). See docs/mokosh-auth/10-memberships-and-self-signup.md.
///
/// All methods are tenant-scoped at the SQL level: callers MUST also
/// re-check authorization at the HTTP handler.
#[async_trait]
pub trait MembershipRepository: Send + Sync {
    /// All memberships for a user (active and suspended). Caller filters.
    async fn list_for_user(&self, user_id: UserId) -> Result<Vec<Membership>, AuthError>;

    /// All memberships in a tenant. Used to count active admins for the
    /// "cannot suspend the last admin" guard, and (later) to render the
    /// admin user-management page now that `users.tenant_id` is no longer
    /// authoritative.
    async fn list_for_tenant(&self, tenant_id: TenantId) -> Result<Vec<Membership>, AuthError>;

    /// Resolve a single membership for active-tenant authorization.
    /// Returns `None` if the user is not a member of that tenant.
    async fn find(
        &self,
        user_id: UserId,
        tenant_id: TenantId,
    ) -> Result<Option<Membership>, AuthError>;

    /// Insert a new membership. Called from self-signup (new personal
    /// tenant) and invite-accept (existing user joins an org tenant).
    /// Returns `AuthError::Conflict` if the (user_id, tenant_id) pair
    /// already exists; the caller decides whether that is a soft
    /// "already a member" 409 or a hard error.
    async fn create(&self, m: NewMembership) -> Result<Membership, AuthError>;

    /// Mutate the status of an existing membership (active <-> suspended).
    /// Mirrors `set_status` on User but tenant-scoped: suspending the
    /// admin's membership in tenant A does not affect their access to
    /// tenant B.
    async fn set_status(
        &self,
        user_id: UserId,
        tenant_id: TenantId,
        status: MembershipStatus,
    ) -> Result<(), AuthError>;
}

/// Persistent storage for one-shot self-signup tokens.
///
/// Used by POST /v1/auth/signup (issue) and the
/// /v1/auth/signup/by-token/{token}/{,complete} endpoints (consume).
/// Lifetime mirrors admin invites: SHA-256 hash for storage, raw
/// token never persisted; rows are immutable except for `used_at` /
/// `user_id` which are set once on completion.
#[async_trait]
pub trait SignupTokenRepository: Send + Sync {
    /// Insert a new open signup token. Implementations MUST persist
    /// the hash byte-for-byte; the caller has already SHA-256-hashed
    /// the raw token.
    async fn issue(&self, new: NewSignupToken) -> Result<SignupToken, AuthError>;

    /// Look up by token hash. Returns `None` for unknown hashes; the
    /// caller cannot tell unknown / used / expired apart in its
    /// 404 response.
    async fn find_by_token_hash(
        &self,
        token_hash: [u8; 32],
    ) -> Result<Option<SignupToken>, AuthError>;

    /// Find an open (unused, unexpired) token for an email, if any.
    /// Used to coalesce repeat /v1/auth/signup requests so the
    /// recipient does not get spammed.
    async fn find_open_by_email(
        &self,
        email: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<SignupToken>, AuthError>;

    /// Mark a token as used and bind it to the new user. Called from
    /// inside the SERIALIZABLE accept transaction; if the row is
    /// already used the implementation MUST return
    /// `AuthError::NotFound` so the handler collapses to the same
    /// generic 404 as unknown-token.
    async fn mark_used(
        &self,
        token_hash: [u8; 32],
        user_id: UserId,
        at: DateTime<Utc>,
    ) -> Result<(), AuthError>;
}

/// Persistent storage for password-reset tokens.
///
/// Same shape as `SignupTokenRepository` but for the
/// `/v1/auth/password-reset` flow. The `complete` handler runs its
/// own SERIALIZABLE transaction at the storage layer (see
/// `PgPasswordResetTokenRepository::complete`); this trait only
/// covers the simple lifecycle methods.
#[async_trait]
pub trait PasswordResetTokenRepository: Send + Sync {
    async fn issue(&self, new: NewPasswordResetToken) -> Result<PasswordResetToken, AuthError>;

    async fn find_by_token_hash(
        &self,
        token_hash: [u8; 32],
    ) -> Result<Option<PasswordResetToken>, AuthError>;

    async fn find_open_by_email(
        &self,
        email: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<PasswordResetToken>, AuthError>;

    /// Atomic complete under SERIALIZABLE isolation. Locks the
    /// password-reset row by token_hash, looks up the user by the
    /// row's email, updates `users.password_hash`, marks the token
    /// used, and revokes every active op_session + refresh-token
    /// family for the user. Returns the affected `UserId`.
    ///
    /// Returns `AuthError::NotFound` for unknown / used / expired
    /// tokens, and for the rare case where the email no longer
    /// resolves to a user (deleted between request and complete).
    async fn complete(
        &self,
        token_hash: [u8; 32],
        new_password_hash: &str,
    ) -> Result<UserId, AuthError>;
}

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

    /// Membership-aware accept for an invitee whose email already
    /// belongs to a `mokosh_auth.users` row. Marks the invite used
    /// AND inserts a membership in `(user_id, invite.tenant_id)` in
    /// one transaction. The User row is NOT touched. Returns the
    /// existing user so the handler can echo it back to the SPA.
    ///
    /// `AuthError::Conflict` if the user is already a member of the
    /// inviter's tenant; the handler can surface that as a soft "you
    /// are already a member" notice or as a redirect to /login.
    async fn accept_existing(&self, token: &str, user_id: UserId) -> Result<User, AuthError>;
}

#[async_trait]
pub trait TotpRepository: Send + Sync {
    /// Idempotent "start enrollment". If a row exists with
    /// `confirmed_at IS NULL`, leaves the existing `user_totp` row in
    /// place and returns it (so a page-reload during enrollment does
    /// not generate a new secret). If a row exists with
    /// `confirmed_at IS NOT NULL`, returns
    /// `Conflict("already_enrolled")`. Otherwise inserts a fresh
    /// unconfirmed row.
    ///
    /// The caller passes the encrypted blob + the key version it was
    /// produced under. The handler is responsible for the encryption.
    async fn start_enrollment(
        &self,
        user_id: UserId,
        tenant_id: TenantId,
        encrypted_secret: serde_json::Value,
        key_version: u16,
    ) -> Result<TotpEnrollment, AuthError>;

    async fn find_for_user(&self, user_id: UserId) -> Result<Option<TotpEnrollment>, AuthError>;

    /// SERIALIZABLE: locks the user_totp row, marks `confirmed_at`,
    /// flips `users.mfa_enrolled = TRUE`, and clears
    /// `users.mfa_disenrolled_at`. Recovery codes are NOT touched here;
    /// `RecoveryCodeRepository::replace_all` is called by the handler
    /// at `setup` time so the user sees the cleartext codes alongside
    /// the QR. Confirm-only path is just the flag flip.
    async fn confirm(&self, user_id: UserId) -> Result<(), AuthError>;

    /// Anti-replay: succeeds only if `step` is strictly greater than the
    /// stored `last_used_step` (or it is NULL). Single-statement UPDATE;
    /// no transaction required.
    async fn consume_step(&self, user_id: UserId, step: i64) -> Result<(), AuthError>;

    /// SERIALIZABLE: removes the user_totp row + every recovery_codes
    /// row + flips `users.mfa_enrolled = FALSE` + writes
    /// `users.mfa_disenrolled_at = NOW()`. Idempotent.
    async fn disenroll(&self, user_id: UserId) -> Result<(), AuthError>;
}

#[async_trait]
pub trait RecoveryCodeRepository: Send + Sync {
    /// SERIALIZABLE: looks up an unused row whose hash matches and marks
    /// it used. Returns `NotFound` for unknown/used. Same shape as the
    /// "wrong TOTP code" response in the verify handler so callers can
    /// keep them indistinguishable.
    async fn consume_unused(&self, user_id: UserId, code_hash: [u8; 32]) -> Result<(), AuthError>;

    async fn count_unused(&self, user_id: UserId) -> Result<usize, AuthError>;

    /// SERIALIZABLE: wipes every existing row for the user and inserts
    /// the fresh set in one tx. Used by enrollment (initial issue) and
    /// by `/v1/auth/mfa/recovery-codes/regenerate`.
    async fn replace_all(
        &self,
        user_id: UserId,
        tenant_id: TenantId,
        user_totp_id: uuid::Uuid,
        new_hashes: &[[u8; 32]],
    ) -> Result<(), AuthError>;
}

#[async_trait]
pub trait TrustedDeviceRepository: Send + Sync {
    async fn issue(&self, new: NewTrustedDevice) -> Result<TrustedDevice, AuthError>;
    /// Look up a non-revoked, non-expired device whose hash matches.
    /// Side effects: bumps `last_used_at` to `NOW()` on a successful
    /// lookup so the SPA's "trusted devices" list shows the freshness.
    async fn find_active_and_touch(
        &self,
        token_hash: [u8; 32],
    ) -> Result<Option<TrustedDevice>, AuthError>;
    async fn list_active_for_user(&self, user_id: UserId) -> Result<Vec<TrustedDevice>, AuthError>;
    async fn revoke(&self, id: uuid::Uuid, user_id: UserId) -> Result<(), AuthError>;
}

#[async_trait]
pub trait MfaChallengeRepository: Send + Sync {
    async fn issue(&self, new: NewMfaChallenge) -> Result<MfaChallenge, AuthError>;

    async fn find_by_token_hash(
        &self,
        token_hash: [u8; 32],
    ) -> Result<Option<MfaChallenge>, AuthError>;

    /// SERIALIZABLE: locks the row, returns `NotFound` if it is
    /// missing/used/expired/wrong-purpose, otherwise marks it consumed
    /// and returns the row.
    async fn consume(
        &self,
        token_hash: [u8; 32],
        expected_purpose: MfaChallengePurpose,
    ) -> Result<MfaChallenge, AuthError>;
}
