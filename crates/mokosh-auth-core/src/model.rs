//! Domain model: shapes that flow through the auth stack.
//!
//! These types are deliberately small and free of I/O. They are owned by
//! the protocol/HTTP layers and converted at the storage boundary.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use url::Url;

use crate::ids::*;

// --- User ---------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    Admin,
    Manager,
    Finance,
    Member,
    ReadOnly,
}

impl UserRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Manager => "manager",
            Self::Finance => "finance",
            Self::Member => "member",
            Self::ReadOnly => "readonly",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "admin" => Self::Admin,
            "manager" => Self::Manager,
            "finance" => Self::Finance,
            "member" => Self::Member,
            "readonly" => Self::ReadOnly,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserStatus {
    Pending,
    Active,
    Suspended,
    Deleted,
}

impl UserStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Deleted => "deleted",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "pending" => Self::Pending,
            "active" => Self::Active,
            "suspended" => Self::Suspended,
            "deleted" => Self::Deleted,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug)]
pub struct User {
    pub id: UserId,
    pub tenant_id: TenantId,
    pub email: String,
    pub email_verified_at: Option<DateTime<Utc>>,
    /// Argon2id PHC string. None => passwordless (federated only).
    pub password_hash: Option<String>,
    pub role: UserRole,
    pub status: UserStatus,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub timezone: String,
    pub locale: String,
    pub mfa_enrolled: bool,
    pub last_login_at: Option<DateTime<Utc>>,
    /// Tenant the user was most recently acting under. `None` means
    /// "use the home tenant" (`tenant_id` field above). Read at login
    /// time to resolve the active-tenant token claim; updated by the
    /// /v1/auth/active-tenant switcher endpoint.
    pub last_active_tenant: Option<TenantId>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct NewUser {
    pub tenant_id: TenantId,
    pub email: String,
    pub password_hash: Option<String>,
    pub role: UserRole,
    pub status: UserStatus,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

// --- OAuth client -------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientType {
    Public,
    Confidential,
}

impl ClientType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Confidential => "confidential",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "public" => Self::Public,
            "confidential" => Self::Confidential,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum GrantType {
    AuthorizationCode,
    RefreshToken,
}

impl GrantType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AuthorizationCode => "authorization_code",
            Self::RefreshToken => "refresh_token",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "authorization_code" => Self::AuthorizationCode,
            "refresh_token" => Self::RefreshToken,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuthMethod {
    None,
    ClientSecretBasic,
    ClientSecretPost,
    PrivateKeyJwt,
}

impl ClientAuthMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ClientSecretBasic => "client_secret_basic",
            Self::ClientSecretPost => "client_secret_post",
            Self::PrivateKeyJwt => "private_key_jwt",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "none" => Self::None,
            "client_secret_basic" => Self::ClientSecretBasic,
            "client_secret_post" => Self::ClientSecretPost,
            "private_key_jwt" => Self::PrivateKeyJwt,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug)]
pub struct OAuthClient {
    pub client_id: ClientId,
    /// `None` means platform-wide; `Some(t)` scopes the client to tenant `t`.
    pub tenant_id: Option<TenantId>,
    pub name: String,
    pub client_type: ClientType,
    /// Argon2id PHC string. `None` for public clients.
    pub client_secret_hash: Option<String>,
    pub redirect_uris: Vec<Url>,
    pub post_logout_redirect_uris: Vec<Url>,
    pub backchannel_logout_uri: Option<Url>,
    pub lifecycle_event_uri: Option<Url>,
    pub allowed_scopes: BTreeSet<String>,
    pub allowed_grant_types: BTreeSet<GrantType>,
    pub token_endpoint_auth_method: ClientAuthMethod,
    pub require_pkce: bool,
    pub access_token_ttl: Duration,
    pub refresh_token_ttl: Duration,
    pub refresh_idle_ttl: Duration,
    pub audience: String,
    pub disabled_at: Option<DateTime<Utc>>,
}

impl OAuthClient {
    pub fn is_enabled(&self) -> bool {
        self.disabled_at.is_none()
    }
}

// --- OP session ---------------------------------------------------------

#[derive(Clone, Debug)]
pub struct OpSession {
    pub id: OpSessionId,
    /// Opaque value placed in the OP cookie.
    pub sid: String,
    pub user_id: UserId,
    pub tenant_id: TenantId,
    pub created_at: DateTime<Utc>,
    pub last_active_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub user_agent: Option<String>,
    pub ip: Option<std::net::IpAddr>,
    pub acr: String,
    pub amr: Vec<String>,
}

impl OpSession {
    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_none() && self.expires_at > now
    }
}

// --- Memberships --------------------------------------------------------
//
// One row per (user, tenant) pair. A user can be a member of N tenants;
// `mokosh_auth.users.tenant_id` is the user's "home" tenant pointer but
// the source of truth for access is the memberships table. Status and
// role are tenant-scoped: a user may be `admin` in their personal
// tenant and `member` in an org tenant they were invited to.
//
// See docs/mokosh-auth/10-memberships-and-self-signup.md.

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MembershipStatus {
    Active,
    Suspended,
}

impl MembershipStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "active" => Self::Active,
            "suspended" => Self::Suspended,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug)]
pub struct Membership {
    pub user_id: UserId,
    pub tenant_id: TenantId,
    pub role: UserRole,
    pub status: MembershipStatus,
    pub joined_at: DateTime<Utc>,
}

impl Membership {
    pub fn is_active(&self) -> bool {
        matches!(self.status, MembershipStatus::Active)
    }
}

#[derive(Clone, Debug)]
pub struct NewMembership {
    pub user_id: UserId,
    pub tenant_id: TenantId,
    pub role: UserRole,
    pub status: MembershipStatus,
}

/// A membership joined with the resolved tenant display name. The auth
/// crates do not own `public.tenants`, so the storage layer takes the
/// name as a closure-resolved value. Used by the (forthcoming)
/// `/v1/auth/memberships` endpoint and the SPA tenant switcher.
#[derive(Clone, Debug)]
pub struct MembershipWithTenant {
    pub membership: Membership,
    pub tenant_name: String,
}

// --- Self-signup --------------------------------------------------------
//
// One-shot tokens issued by POST /v1/auth/signup. The bearer of the
// raw token (delivered via email) is allowed to complete an account
// creation by POSTing to /v1/auth/signup/by-token/{token}/complete.
// The accept transaction creates a personal tenant, a user, and an
// owner membership atomically under SERIALIZABLE isolation.
//
// See docs/mokosh-auth/10-memberships-and-self-signup.md.

#[derive(Clone, Debug)]
pub struct NewSignupToken {
    pub email: String,
    /// SHA-256 of the URL-safe random token. The raw token is delivered
    /// via email and never persisted.
    pub token_hash: [u8; 32],
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct SignupToken {
    pub id: uuid::Uuid,
    pub email: String,
    pub token_hash: [u8; 32],
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub user_id: Option<UserId>,
}

impl SignupToken {
    /// `true` if the row is still consumable: not yet used and within
    /// the expiry window.
    pub fn is_open(&self, now: DateTime<Utc>) -> bool {
        self.used_at.is_none() && self.expires_at > now
    }
}

// --- Password reset -----------------------------------------------------
//
// One-shot tokens issued by POST /v1/auth/password-reset. Bearer of
// the raw token (delivered via email) sets a new password by POSTing
// to /v1/auth/password-reset/by-token/{token}/complete. The complete
// transaction runs under SERIALIZABLE and revokes every active OP
// session for the user (boot-everywhere is the point of a reset).
//
// See docs/mokosh-smtp/05-password-reset.md.

#[derive(Clone, Debug)]
pub struct NewPasswordResetToken {
    pub email: String,
    pub token_hash: [u8; 32],
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct PasswordResetToken {
    pub id: uuid::Uuid,
    pub email: String,
    pub token_hash: [u8; 32],
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub user_id: Option<UserId>,
}

impl PasswordResetToken {
    pub fn is_open(&self, now: DateTime<Utc>) -> bool {
        self.used_at.is_none() && self.expires_at > now
    }
}

// --- Authorization code -------------------------------------------------

#[derive(Clone, Debug)]
pub struct NewAuthCode {
    pub code_hash: [u8; 32],
    pub client_id: ClientId,
    pub user_id: UserId,
    pub tenant_id: TenantId,
    pub op_session_id: OpSessionId,
    pub redirect_uri: String,
    pub scope: Vec<String>,
    pub code_challenge: String,
    pub nonce: Option<String>,
    pub auth_time: DateTime<Utc>,
    pub acr: String,
    pub amr: Vec<String>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct AuthorizationCode {
    pub code_hash: [u8; 32],
    pub client_id: ClientId,
    pub user_id: UserId,
    pub tenant_id: TenantId,
    pub op_session_id: OpSessionId,
    pub redirect_uri: String,
    pub scope: Vec<String>,
    pub code_challenge: String,
    pub nonce: Option<String>,
    pub auth_time: DateTime<Utc>,
    pub acr: String,
    pub amr: Vec<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

// --- Refresh tokens -----------------------------------------------------

#[derive(Clone, Debug)]
pub struct NewRefreshTokenFamily {
    pub client_id: ClientId,
    pub user_id: UserId,
    pub tenant_id: TenantId,
    pub op_session_id: Option<OpSessionId>,
}

#[derive(Clone, Debug)]
pub struct RefreshTokenFamily {
    pub id: RefreshFamilyId,
    pub client_id: ClientId,
    pub user_id: UserId,
    pub tenant_id: TenantId,
    pub op_session_id: Option<OpSessionId>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoke_reason: Option<String>,
}

#[derive(Clone, Debug)]
pub struct NewRefreshToken {
    pub id: RefreshTokenId,
    pub token_hash: [u8; 32],
    pub scope: Vec<String>,
    pub idle_expires_at: DateTime<Utc>,
    pub absolute_expires_at: DateTime<Utc>,
    pub ip: Option<std::net::IpAddr>,
    pub user_agent: Option<String>,
}

#[derive(Clone, Debug)]
pub struct RefreshToken {
    pub id: RefreshTokenId,
    pub family_id: RefreshFamilyId,
    pub parent_id: Option<RefreshTokenId>,
    pub client_id: ClientId,
    pub user_id: UserId,
    pub tenant_id: TenantId,
    pub scope: Vec<String>,
    pub issued_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub idle_expires_at: DateTime<Utc>,
    pub absolute_expires_at: DateTime<Utc>,
    pub ip: Option<std::net::IpAddr>,
    pub user_agent: Option<String>,
}

#[derive(Clone, Debug)]
pub struct RotatedTokens {
    pub new_token_id: RefreshTokenId,
    pub family_id: RefreshFamilyId,
    pub client_id: ClientId,
    pub user_id: UserId,
    pub tenant_id: TenantId,
    pub scope: Vec<String>,
}

// --- TOTP / MFA ---------------------------------------------------------
//
// One `user_totp` row per user. `secret_encrypted` is the AES-GCM blob
// the encryption-key set produced; `key_version` selects which key to
// use for decryption. `confirmed_at` flips when the user completes
// /v1/auth/mfa/confirm. `last_used_step` is the most recent verified
// step, used to defeat in-window replay.

#[derive(Clone, Debug)]
pub struct TotpEnrollment {
    pub id: uuid::Uuid,
    pub user_id: UserId,
    pub tenant_id: TenantId,
    /// Raw JSONB form of `mokosh_auth_crypto::EncryptedBlob`. Kept as a
    /// `serde_json::Value` here so the core crate stays free of the
    /// crypto dep; the handler layer (which has crypto) deserializes
    /// into the typed blob and calls `EncryptionKeySet::decrypt`.
    pub secret_encrypted: serde_json::Value,
    pub key_version: u16,
    pub confirmed_at: Option<DateTime<Utc>>,
    pub last_used_step: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl TotpEnrollment {
    pub fn is_confirmed(&self) -> bool {
        self.confirmed_at.is_some()
    }
}

#[derive(Clone, Debug)]
pub struct RecoveryCode {
    pub id: uuid::Uuid,
    pub user_totp_id: uuid::Uuid,
    pub user_id: UserId,
    pub tenant_id: TenantId,
    pub code_hash: [u8; 32],
    pub used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

// --- MFA challenge ------------------------------------------------------
//
// Issued by `/v1/auth/login` when the user has MFA on, or by the step-up
// flow for destructive operations. Single-use, short-lived, raw token is
// returned to the caller exactly once.

#[derive(Clone, Debug)]
pub struct NewMfaChallenge {
    pub user_id: UserId,
    pub tenant_id: TenantId,
    pub token_hash: [u8; 32],
    pub client_id: Option<ClientId>,
    pub scope: Vec<String>,
    pub active_tenant_id: TenantId,
    pub purpose: MfaChallengePurpose,
    pub expires_at: DateTime<Utc>,
    pub ip: Option<std::net::IpAddr>,
    pub user_agent: Option<String>,
}

#[derive(Clone, Debug)]
pub struct MfaChallenge {
    pub id: uuid::Uuid,
    pub user_id: UserId,
    pub tenant_id: TenantId,
    pub token_hash: [u8; 32],
    pub client_id: Option<ClientId>,
    pub scope: Vec<String>,
    pub active_tenant_id: TenantId,
    pub purpose: MfaChallengePurpose,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl MfaChallenge {
    pub fn is_open(&self, now: DateTime<Utc>) -> bool {
        self.consumed_at.is_none() && self.expires_at > now
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MfaChallengePurpose {
    /// Issued by `/v1/auth/login` when the user has MFA on; consumed by
    /// `/v1/auth/mfa/verify` which returns the OIDC token bundle.
    Login,
    /// Issued by `/v1/auth/mfa/step-up/start`; consumed by
    /// `/v1/auth/mfa/step-up/verify` which returns a `step_up_token`
    /// (itself another challenge row of `purpose = StepUp`). The
    /// step-up token gates destructive operations (regenerate recovery
    /// codes, disable MFA).
    StepUp,
}

impl MfaChallengePurpose {
    pub fn as_str(&self) -> &'static str {
        match self {
            MfaChallengePurpose::Login => "login",
            MfaChallengePurpose::StepUp => "step_up",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "login" => Some(Self::Login),
            "step_up" => Some(Self::StepUp),
            _ => None,
        }
    }
}

// --- Audit events -------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditSeverity {
    Info,
    Warning,
    Critical,
}

impl AuditSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuditEvent {
    LoginSuccess { user_id: UserId, ip: Option<String>, user_agent: Option<String> },
    LoginFailed { email: String, ip: Option<String>, reason: String },
    LogoutSuccess { user_id: UserId },
    PasswordChanged { user_id: UserId },
    PasswordResetRequested { email: String, ip: Option<String> },
    PasswordResetCompleted { user_id: UserId, ip: Option<String> },
    MagicLinkRequested { email: String, ip: Option<String> },
    MagicLinkUsed { user_id: UserId, ip: Option<String> },
    TokenIssued { user_id: UserId, client_id: ClientId, scope: Vec<String>, jti: String },
    TokenRefreshed { user_id: UserId, client_id: ClientId, family_id: RefreshFamilyId },
    RefreshReuseDetected { family_id: RefreshFamilyId, client_id: ClientId, user_id: UserId },
    SessionRevoked { user_id: UserId, sid: String, reason: String },
    ClientCreated { client_id: ClientId, by: Option<UserId> },
    ClientDisabled { client_id: ClientId, by: Option<UserId> },
    KeyRotated { kid_old: String, kid_new: String },
    SuspiciousActivity { description: String, ip: Option<String> },
    AdminAction { admin_id: UserId, action: String, target: String },
    InviteIssued {
        invite_id: uuid::Uuid,
        tenant_id: TenantId,
        email: String,
        role: UserRole,
        invited_by: UserId,
    },
    InviteRevoked {
        invite_id: uuid::Uuid,
        revoked_by: UserId,
        reason: String,
    },
    InviteAccepted {
        invite_id: uuid::Uuid,
        new_user_id: UserId,
        tenant_id: TenantId,
        email: String,
        role: UserRole,
    },
    /// Used for failed lookups + failed accepts. We log only the first
    /// 8 hex chars of the SHA-256 hash so the raw token never touches
    /// the audit table even on replay attempts.
    InviteAttemptFailed {
        token_hash_prefix: String,
        ip: Option<String>,
        reason: String,
    },
    /// Self-signup requested. Always recorded - even when the email is
    /// already in use and the request is a no-op - so brute-force
    /// attempts are visible in the audit trail. The email is recorded;
    /// the token is not.
    SignupRequested {
        email: String,
        ip: Option<String>,
    },
    /// Self-signup token successfully redeemed. The new user, personal
    /// tenant, and owner membership all exist by the time this is
    /// written.
    SignupCompleted {
        user_id: UserId,
        tenant_id: TenantId,
        email: String,
    },
    /// Failed signup-token redemption (unknown / used / expired token,
    /// password policy rejection, etc). Same enumeration-resistance
    /// shape as InviteAttemptFailed.
    /// Failed password-reset attempt: unknown / used / expired token
    /// at preview or complete time, or a complete request that
    /// failed policy / confirmation. We log only the first 8 hex
    /// chars of the SHA-256 hash so the raw token never reaches the
    /// audit table.
    PasswordResetAttemptFailed {
        token_hash_prefix: String,
        ip: Option<String>,
        reason: String,
    },
    SignupAttemptFailed {
        token_hash_prefix: String,
        ip: Option<String>,
        reason: String,
    },
    // --- TOTP / MFA ---
    /// User started MFA enrollment: `/v1/auth/mfa/setup` returned a fresh
    /// (or in-progress) secret. Not yet confirmed; `mfa_enrolled` is still
    /// false.
    TotpEnrollmentStarted {
        user_id: UserId,
    },
    /// Confirmation succeeded; `users.mfa_enrolled` is now true.
    TotpEnrolled {
        user_id: UserId,
    },
    /// MFA was turned off. `by = "self"` for the user-initiated path,
    /// `by = "admin"` for force-disenroll (with `admin_user_id` set).
    TotpDisenrolled {
        user_id: UserId,
        by: String,
        admin_user_id: Option<UserId>,
        reason: Option<String>,
        ip: Option<String>,
    },
    /// `/v1/auth/login` returned a challenge (the user has MFA on); the
    /// SPA must now POST to `/v1/auth/mfa/verify`.
    MfaChallengeIssued {
        user_id: UserId,
        ip: Option<String>,
    },
    /// Challenge was successfully consumed. `method` is `"totp"` or
    /// `"recovery"`.
    MfaChallengeConsumed {
        user_id: UserId,
        method: String,
    },
    /// Verify-time failure: wrong code, expired/used challenge, replayed
    /// step, used recovery code. `reason` is one of "wrong_totp",
    /// "wrong_recovery", "unknown_or_used_or_expired", "code_replayed".
    MfaVerifyFailed {
        user_id: Option<UserId>,
        reason: String,
        ip: Option<String>,
    },
    /// Step-up challenge was issued for a destructive operation
    /// (regenerate recovery codes, disable MFA).
    StepUpIssued {
        user_id: UserId,
        purpose: String,
    },
    StepUpConsumed {
        user_id: UserId,
        purpose: String,
    },
    RecoveryCodesIssued {
        user_id: UserId,
        count: usize,
    },
    RecoveryCodesRegenerated {
        user_id: UserId,
        count: usize,
        ip: Option<String>,
    },
    RecoveryCodeUsed {
        user_id: UserId,
        ip: Option<String>,
    },
}

impl AuditEvent {
    pub fn severity(&self) -> AuditSeverity {
        use AuditEvent::*;
        match self {
            LoginFailed { .. } | PasswordResetRequested { .. } => AuditSeverity::Info,
            RefreshReuseDetected { .. } | SuspiciousActivity { .. } => AuditSeverity::Critical,
            ClientDisabled { .. } | SessionRevoked { .. } | InviteRevoked { .. } => {
                AuditSeverity::Warning
            }
            TotpDisenrolled { by, .. } if by == "admin" => AuditSeverity::Warning,
            _ => AuditSeverity::Info,
        }
    }
}
