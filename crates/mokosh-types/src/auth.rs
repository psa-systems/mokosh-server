//! Authentication models and types

// These model enums expose `from_str(&str) -> Option<Self>` as a deliberate
// infallible-style parser API; they intentionally do not implement
// `std::str::FromStr` (which requires a `Result`).
#![allow(clippy::should_implement_trait)]
// A couple of doc-comment lists below use column-aligned continuations.
#![allow(clippy::doc_lazy_continuation)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

/// User role types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum UserRole {
    /// Platform-level administrator (SaaS only)
    SuperAdmin,
    /// MSP organization administrator
    Admin,
    /// Team/department manager
    Manager,
    /// Service delivery staff
    #[default]
    Technician,
    /// Resource scheduling
    Dispatcher,
    /// Account management
    Sales,
    /// Billing and invoicing
    Finance,
}

impl UserRole {
    /// Check if this role has admin privileges
    pub fn is_admin(&self) -> bool {
        matches!(self, Self::SuperAdmin | Self::Admin)
    }

    /// Check if this role can manage users
    pub fn can_manage_users(&self) -> bool {
        matches!(self, Self::SuperAdmin | Self::Admin | Self::Manager)
    }

    /// Privilege rank used to enforce a role ceiling when one user grants a
    /// role to another (PMS-503). A caller may only grant roles whose rank is
    /// `<=` their own, so `super_admin` (the only rank-3 role) can only be
    /// granted by an existing `super_admin`.
    pub fn privilege_rank(&self) -> u8 {
        match self {
            Self::SuperAdmin => 3,
            Self::Admin => 2,
            Self::Manager => 1,
            Self::Technician | Self::Dispatcher | Self::Sales | Self::Finance => 0,
        }
    }

    /// Whether a caller holding `self` may grant `target` to another user.
    /// Enforces the role ceiling from PMS-503: a role may only be granted by
    /// a caller of equal or higher privilege.
    pub fn can_grant(&self, target: Self) -> bool {
        self.privilege_rank() >= target.privilege_rank()
    }

    /// Check if this role can view financial data
    pub fn can_view_financials(&self) -> bool {
        matches!(
            self,
            Self::SuperAdmin | Self::Admin | Self::Manager | Self::Finance
        )
    }

    /// Check if this role can manage billing
    pub fn can_manage_billing(&self) -> bool {
        matches!(self, Self::SuperAdmin | Self::Admin | Self::Finance)
    }

    /// Parse from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "super_admin" => Some(Self::SuperAdmin),
            "admin" => Some(Self::Admin),
            "manager" => Some(Self::Manager),
            "technician" => Some(Self::Technician),
            "dispatcher" => Some(Self::Dispatcher),
            "sales" => Some(Self::Sales),
            "finance" => Some(Self::Finance),
            _ => None,
        }
    }

    /// Convert to string
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SuperAdmin => "super_admin",
            Self::Admin => "admin",
            Self::Manager => "manager",
            Self::Technician => "technician",
            Self::Dispatcher => "dispatcher",
            Self::Sales => "sales",
            Self::Finance => "finance",
        }
    }
}

impl std::fmt::Display for UserRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// User account status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum UserStatus {
    #[default]
    Active,
    Inactive,
    Pending,
}

impl UserStatus {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "active" => Some(Self::Active),
            "inactive" => Some(Self::Inactive),
            "pending" => Some(Self::Pending),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Inactive => "inactive",
            Self::Pending => "pending",
        }
    }
}

/// Marker error returned by [`AuthState::require_user`] /
/// [`AuthState::require_tenant`] when there is no authenticated
/// principal. The shared crate cannot reach the server-side
/// `AppError`, so callers map this to whatever they use locally
/// (server side: `AppError::Unauthorized`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthRequired;

impl std::fmt::Display for AuthRequired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("authentication required")
    }
}

impl std::error::Error for AuthRequired {}

/// Current authenticated user state
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthState {
    /// Whether the user is authenticated
    pub is_authenticated: bool,
    /// The current user (if authenticated)
    pub user: Option<CurrentUser>,
    /// The current tenant ID
    pub tenant_id: Option<Uuid>,
    /// MAPPS-348: JWT verified successfully but the user's row was
    /// found to be soft-deleted (Bunyip account_deleted webhook
    /// tombstoned them). Extractors surface this as a 410 Gone
    /// (`ACCOUNT_DELETED`) instead of the generic 401. `#[serde(default)]`
    /// keeps the wire shape backward-compatible for any consumer that
    /// still deserializes a pre-348 payload.
    #[serde(default)]
    pub deleted: bool,
}

impl AuthState {
    /// Create an authenticated state
    pub fn authenticated(user: CurrentUser, tenant_id: Uuid) -> Self {
        Self {
            is_authenticated: true,
            user: Some(user),
            tenant_id: Some(tenant_id),
            deleted: false,
        }
    }

    /// MAPPS-348: JWT verified but the target user's row is tombstoned.
    /// The middleware sets this on the request extensions so the
    /// `RequireAuth` extractor can return 410 Gone (`ACCOUNT_DELETED`)
    /// instead of a plain 401, letting the SPA distinguish "your account
    /// has been deleted" from "your session expired / please refresh".
    pub fn deleted() -> Self {
        Self {
            is_authenticated: false,
            user: None,
            tenant_id: None,
            deleted: true,
        }
    }

    /// Get the current user or return an [`AuthRequired`] marker.
    /// Callers map `AuthRequired` to their own error type
    /// (e.g. the server maps it to `AppError::Unauthorized`).
    pub fn require_user(&self) -> Result<&CurrentUser, AuthRequired> {
        self.user.as_ref().ok_or(AuthRequired)
    }

    /// Get the current tenant ID or return an [`AuthRequired`] marker.
    pub fn require_tenant(&self) -> Result<Uuid, AuthRequired> {
        self.tenant_id.ok_or(AuthRequired)
    }

    /// Check if the user has a specific role
    pub fn has_role(&self, role: UserRole) -> bool {
        self.user.as_ref().is_some_and(|u| u.role == role)
    }

    /// Check if the user has admin privileges
    pub fn is_admin(&self) -> bool {
        self.user.as_ref().is_some_and(|u| u.role.is_admin())
    }
}

/// Current authenticated user information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrentUser {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub role: UserRole,
    pub timezone: String,
    pub avatar_url: Option<String>,
    /// `true` once the user has confirmed first + last name through the
    /// onboarding screen. `false` for freshly JIT-created Bunyip users
    /// whose names are still placeholder values derived from email.
    /// Default `true` so deserialising an old response (or test fixtures
    /// that omit the field) does not unexpectedly trap users in
    /// onboarding.
    #[serde(default = "crate::default_true")]
    pub profile_completed: bool,
    /// PMS-253: per-user date/time format string (mokosh-apps token
    /// grammar). `None` means "use browser locale" - the legacy
    /// rendering behaviour. Capped server-side at 64 chars.
    #[serde(default)]
    pub date_format_string: Option<String>,
    /// PMS-410: per-user theme base mode. One of `light`, `dark`,
    /// `system`. `None` = unset; the client treats it as `system`.
    #[serde(default)]
    pub theme_base_mode: Option<String>,
    /// PMS-410: per-user accent id (opaque; the accent catalog lives in
    /// the SPA). `None` = unset; the client falls back to its default
    /// accent. Capped server-side at 32 chars.
    #[serde(default)]
    pub theme_accent_id: Option<String>,
    /// PMS-413: the tenant's own-company id, used by the SPA to attribute
    /// general / overhead time entries (no customer to bill). Tenant-scoped
    /// (same for every user in the tenant). `None` only on a tenant that
    /// predates the backfill and has not yet been provisioned; the default
    /// `None` keeps old responses / fixtures deserialising cleanly.
    #[serde(default)]
    pub own_company_id: Option<Uuid>,
}

impl CurrentUser {
    /// Get the full name
    pub fn full_name(&self) -> String {
        format!("{} {}", self.first_name, self.last_name)
    }

    /// Get initials
    pub fn initials(&self) -> String {
        let first = self.first_name.chars().next().unwrap_or(' ');
        let last = self.last_name.chars().next().unwrap_or(' ');
        format!("{}{}", first, last).to_uppercase()
    }
}

/// User database model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: Option<String>,
    pub first_name: String,
    pub last_name: String,
    pub phone: Option<String>,
    pub mobile: Option<String>,
    pub title: Option<String>,
    pub avatar_url: Option<String>,
    pub timezone: String,
    pub locale: String,
    /// PMS-253: per-user date/time format string. See [`CurrentUser::date_format_string`].
    #[serde(default)]
    pub date_format_string: Option<String>,
    /// PMS-410: per-user theme base mode. See [`CurrentUser::theme_base_mode`].
    #[serde(default)]
    pub theme_base_mode: Option<String>,
    /// PMS-410: per-user accent id. See [`CurrentUser::theme_accent_id`].
    #[serde(default)]
    pub theme_accent_id: Option<String>,
    pub role: UserRole,
    pub status: UserStatus,
    pub email_verified_at: Option<DateTime<Utc>>,
    pub last_login_at: Option<DateTime<Utc>>,
    /// PMS-657: ISO 3166-1 alpha-2 country of the user's last geolocatable
    /// login, or `None` until the first one. Compared against the current
    /// login's country to detect a significant location change.
    #[serde(default)]
    pub last_login_country: Option<String>,
    /// PMS-657: per-user opt-out for the new-login-location alert (default true).
    #[serde(default = "crate::default_true")]
    pub login_location_alerts: bool,
    pub mfa_enabled: bool,
    #[serde(skip_serializing)]
    pub mfa_secret: Option<String>,
    pub notification_preferences: serde_json::Value,
    pub settings: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// PMS-681: wall-clock time of the last password change (reset or
    /// self-service). The auth middleware rejects any access token whose `iat`
    /// predates it, so a stolen token dies the moment the password changes.
    /// NULL = never changed since the column existed (no cutoff). Never
    /// serialized to clients (internal auth state).
    #[serde(skip_serializing)]
    pub password_changed_at: Option<DateTime<Utc>>,
    /// Timestamp at which the user confirmed first + last name via the
    /// onboarding screen. NULL = needs onboarding; set on first
    /// successful `PUT /api/v1/auth/me` whose body includes non-empty
    /// `first_name` and `last_name`. See migration
    /// `046_users_profile_completed_at.sql`.
    pub profile_completed_at: Option<DateTime<Utc>>,
    /// PMS-413: the owning tenant's own-company id (a tenant-level attribute
    /// surfaced on the user payload so the SPA reads it without an extra
    /// round-trip). Populated by a correlated subquery against `tenants` in the
    /// user-load queries. See [`CurrentUser::own_company_id`].
    #[serde(default)]
    pub own_company_id: Option<Uuid>,
}

impl User {
    /// Convert to CurrentUser for auth context
    pub fn to_current_user(&self) -> CurrentUser {
        CurrentUser {
            id: self.id,
            tenant_id: self.tenant_id,
            email: self.email.clone(),
            first_name: self.first_name.clone(),
            last_name: self.last_name.clone(),
            role: self.role,
            timezone: self.timezone.clone(),
            avatar_url: self.avatar_url.clone(),
            profile_completed: self.profile_completed_at.is_some(),
            date_format_string: self.date_format_string.clone(),
            theme_base_mode: self.theme_base_mode.clone(),
            theme_accent_id: self.theme_accent_id.clone(),
            own_company_id: self.own_company_id,
        }
    }
}

/// Login request
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(email(message = "Invalid email address"))]
    pub email: String,
    #[validate(length(min = 1, message = "Password is required"))]
    pub password: String,
    /// Remember me for longer session
    #[serde(default)]
    pub remember_me: bool,
    /// 6-8 digit TOTP code if MFA is enabled.
    pub mfa_code: Option<String>,
    /// MFA recovery code (single-use). When supplied alongside a
    /// valid password this bypasses `mfa_code`; on success the
    /// matched hash is removed from
    /// `users.mfa_recovery_codes_hashes`.
    pub recovery_code: Option<String>,
    /// PMS-658: single-use 6-digit code from the "approve this sign-in"
    /// email, supplied on the re-POST after a suspicious-login challenge
    /// (`LoginResponse::approval_required`). Mirrors `mfa_code`.
    pub approval_code: Option<String>,
    /// PMS-658: stable per-browser device identifier generated and
    /// persisted by the SPA. Hashed server-side into the known-device
    /// set; a login from an unseen device is a suspicious-login signal.
    /// Absent (older clients) means the device signal is inactive for
    /// this request, so gating falls back to country only.
    #[serde(default)]
    pub device_id: Option<String>,
    /// Optional tenant hint sourced by the SPA from the request
    /// hostname (e.g. `acme.mokosh.example` -> tenant slug lookup
    /// -> tenant_id). Required to disambiguate multi-tenant
    /// deployments where the same email exists under multiple
    /// tenants; omitted clients fall back to
    /// `00000000-0000-0000-0000-000000000001`. PMS-138.
    #[serde(default)]
    pub tenant_id: Option<Uuid>,
}

/// Login response
#[derive(Debug, Clone, Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: DateTime<Utc>,
    /// The authenticated user. Omitted (None) while `mfa_required` is
    /// true so no user profile data leaks before the second factor is
    /// satisfied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<CurrentUser>,
    /// Whether MFA is required to complete login
    pub mfa_required: bool,
    /// PMS-658: whether an "approve this sign-in" email challenge must be
    /// cleared to finish login. Like `mfa_required`, the tokens are empty
    /// and `user` is None while this is true; the client re-POSTs the same
    /// login with `approval_code` to complete it.
    #[serde(default)]
    pub approval_required: bool,
}

/// Refresh token request
#[derive(Debug, Clone, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

/// Refresh token response
#[derive(Debug, Clone, Serialize)]
pub struct RefreshTokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: DateTime<Utc>,
}

/// Password reset request
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct ForgotPasswordRequest {
    #[validate(email(message = "Invalid email address"))]
    pub email: String,
    /// Same shape + semantics as `LoginRequest::tenant_id`. PMS-138.
    #[serde(default)]
    pub tenant_id: Option<Uuid>,
}

/// Password reset completion
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct ResetPasswordRequest {
    pub token: String,
    #[validate(
        length(min = 8, message = "Password must be at least 8 characters"),
        must_match(other = "confirm_password", message = "Passwords do not match")
    )]
    pub new_password: String,
    pub confirm_password: String,
}

/// MFA enrollment start. The server generates a fresh TOTP secret,
/// persists it on `users.mfa_secret` (base32), and returns the secret
/// + provisioning URI for the client to display as a QR code. The
/// `mfa_enabled` flag stays false until the user confirms ownership
/// of the secret via [`MfaEnableRequest`].
#[derive(Debug, Clone, Serialize)]
pub struct MfaSetupResponse {
    /// Base32-encoded secret, displayed for manual entry.
    pub secret: String,
    /// `otpauth://` URI suitable for QR-code encoding.
    pub provisioning_uri: String,
}

/// MFA enrollment confirmation. The user types a 6-digit TOTP code
/// from their authenticator; on success the server flips
/// `users.mfa_enabled = true`.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct MfaEnableRequest {
    #[validate(
        length(min = 6, max = 8, message = "Code must be 6-8 digits"),
        custom(function = "validate_digits", message = "Code must be digits only")
    )]
    pub code: String,
}

/// Validate that a TOTP code contains only ASCII digits. A length-only
/// check would accept `"abc123"`; the second factor must be numeric.
fn validate_digits(code: &str) -> Result<(), validator::ValidationError> {
    if !code.is_empty() && code.bytes().all(|b| b.is_ascii_digit()) {
        Ok(())
    } else {
        Err(validator::ValidationError::new("not_digits"))
    }
}

/// PMS-410: validate that a theme base mode is one of the allowed values.
/// The `users.theme_base_mode` check constraint also enforces this set, but
/// catching it here turns a bad value into a clean 422 instead of a 500
/// from the database CHECK violation.
fn validate_theme_base_mode(value: &str) -> Result<(), validator::ValidationError> {
    if matches!(value, "light" | "dark" | "system") {
        Ok(())
    } else {
        Err(validator::ValidationError::new("invalid_theme_base_mode"))
    }
}

/// MFA enable response. Includes the freshly minted recovery codes,
/// shown ONCE and never retrievable afterwards. The client is
/// responsible for displaying them somewhere the user can save them.
#[derive(Debug, Clone, Serialize)]
pub struct MfaEnableResponse {
    /// 10 single-use codes in `XXXXX-XXXXX` format. Each may be
    /// submitted as `LoginRequest::recovery_code` exactly once.
    pub recovery_codes: Vec<String>,
}

/// MFA disable. Requires the current password (re-auth) so a stolen
/// session cannot disable MFA silently.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct MfaDisableRequest {
    #[validate(length(min = 1, message = "Password is required"))]
    pub password: String,
}

/// Change password request (when logged in)
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    #[validate(
        length(min = 8, message = "Password must be at least 8 characters"),
        must_match(other = "confirm_password", message = "Passwords do not match")
    )]
    pub new_password: String,
    pub confirm_password: String,
}

/// Create user request
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateUserRequest {
    #[validate(email(message = "Invalid email address"))]
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub phone: Option<String>,
    pub mobile: Option<String>,
    pub title: Option<String>,
    pub role: UserRole,
    pub timezone: Option<String>,
    /// PMS-253: optional date/time format pref. Capped at 64 chars to
    /// match the users.date_format_string check constraint.
    #[validate(length(
        max = 64,
        message = "Date format string must be 64 characters or fewer"
    ))]
    pub date_format_string: Option<String>,
    /// PMS-410: optional theme base mode (`light` | `dark` | `system`).
    /// Validated against the allowed set (mirrors the
    /// users.theme_base_mode check constraint) so a bad value returns a
    /// 422 rather than a 500 from the database CHECK.
    #[validate(custom(
        function = "validate_theme_base_mode",
        message = "Theme base mode must be one of light, dark, system"
    ))]
    pub theme_base_mode: Option<String>,
    /// PMS-410: optional opaque accent id. Capped at 32 chars to match
    /// the users.theme_accent_id check constraint.
    #[validate(length(max = 32, message = "Accent id must be 32 characters or fewer"))]
    pub theme_accent_id: Option<String>,
    /// If true, send welcome email with password setup link
    #[serde(default = "crate::default_true")]
    pub send_welcome_email: bool,
}

/// Update user request.
///
/// PMS-512: `first_name`, `last_name`, and `phone` are deliberately absent.
/// Bunyip is the identity source of truth for the names (mokosh keeps them as
/// a read-only cache refreshed on every login, see
/// `AuthService::upsert_user_from_oidc`), and `phone` is an inert cache with
/// no local edit path. Sending any of the three is ignored, not applied.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpdateUserRequest {
    #[validate(email(message = "Invalid email address"))]
    pub email: Option<String>,
    pub mobile: Option<String>,
    pub title: Option<String>,
    pub role: Option<UserRole>,
    pub status: Option<UserStatus>,
    pub timezone: Option<String>,
    /// PMS-253: optional date/time format pref. Capped at 64 chars to
    /// match the users.date_format_string check constraint.
    #[validate(length(
        max = 64,
        message = "Date format string must be 64 characters or fewer"
    ))]
    pub date_format_string: Option<String>,
    /// PMS-410: optional theme base mode (`light` | `dark` | `system`).
    /// Validated against the allowed set (mirrors the
    /// users.theme_base_mode check constraint) so a bad value returns a
    /// 422 rather than a 500 from the database CHECK.
    #[validate(custom(
        function = "validate_theme_base_mode",
        message = "Theme base mode must be one of light, dark, system"
    ))]
    pub theme_base_mode: Option<String>,
    /// PMS-410: optional opaque accent id. Capped at 32 chars to match
    /// the users.theme_accent_id check constraint.
    #[validate(length(max = 32, message = "Accent id must be 32 characters or fewer"))]
    pub theme_accent_id: Option<String>,
    /// PMS-657: per-user opt-out for the new-login-location email alert.
    /// Absent leaves it unchanged; `true`/`false` sets it.
    pub login_location_alerts: Option<bool>,
}

/// User list filter parameters. Parsed from the query string on
/// `GET /api/v1/auth/users`. `q` matches `email`, `first_name`,
/// and `last_name` via case-insensitive substring; capped at 200
/// chars to keep the ILIKE plan bounded (F9 parity with
/// `CompanyFilter::q` / `ContactFilter::q`).
#[derive(Debug, Clone, Deserialize, Default, Validate)]
pub struct ListUsersFilter {
    #[validate(length(max = 200))]
    pub q: Option<String>,
    pub role: Option<UserRole>,
    pub status: Option<UserStatus>,
}

/// PMS-921: the minimum needed to name a colleague, readable by any
/// authenticated user of the tenant.
///
/// Deliberately NOT a subset of [`UserResponse`] built by trimming fields.
/// This is its own type so that adding a field to `UserResponse`, which serves
/// user management and carries role, status, MFA state and login history,
/// cannot widen what an unprivileged caller sees. The two have different
/// audiences and must be able to evolve apart.
///
/// `handle` rather than `email`: it is the local part of the address, which is
/// what an author types to mention somebody and what mention resolution
/// matches on. A technician can already see every colleague's display name
/// (`assigned_to_name`, `created_by_name` and article authorship are on
/// surfaces they read all day), so the name is not a new disclosure. A
/// contactable address would be.
#[derive(Debug, Clone, Serialize)]
pub struct DirectoryEntry {
    pub id: Uuid,
    /// The person's display name.
    pub name: String,
    /// The local part of their email address, lowercased.
    pub handle: String,
}

/// User list response (for API)
#[derive(Debug, Clone, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub full_name: String,
    pub phone: Option<String>,
    pub mobile: Option<String>,
    pub title: Option<String>,
    pub avatar_url: Option<String>,
    pub timezone: String,
    /// PMS-253: per-user date/time format. See [`CurrentUser::date_format_string`].
    #[serde(default)]
    pub date_format_string: Option<String>,
    /// PMS-410: per-user theme base mode. See [`CurrentUser::theme_base_mode`].
    #[serde(default)]
    pub theme_base_mode: Option<String>,
    /// PMS-410: per-user accent id. See [`CurrentUser::theme_accent_id`].
    #[serde(default)]
    pub theme_accent_id: Option<String>,
    pub role: UserRole,
    pub status: UserStatus,
    pub mfa_enabled: bool,
    pub last_login_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    /// `true` once first + last name were confirmed via onboarding.
    /// SPAs gate their non-onboarding routes on this.
    pub profile_completed: bool,
    /// PMS-413: the owning tenant's own-company id. Returned on
    /// `GET /api/v1/auth/me` (which serialises this type) so the SPA can
    /// attribute general / overhead time entries without an extra round-trip.
    /// See [`CurrentUser::own_company_id`].
    #[serde(default)]
    pub own_company_id: Option<Uuid>,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            email: user.email,
            first_name: user.first_name.clone(),
            last_name: user.last_name.clone(),
            full_name: format!("{} {}", user.first_name, user.last_name),
            phone: user.phone,
            mobile: user.mobile,
            title: user.title,
            avatar_url: user.avatar_url,
            timezone: user.timezone,
            date_format_string: user.date_format_string,
            theme_base_mode: user.theme_base_mode,
            theme_accent_id: user.theme_accent_id,
            role: user.role,
            status: user.status,
            mfa_enabled: user.mfa_enabled,
            last_login_at: user.last_login_at,
            created_at: user.created_at,
            profile_completed: user.profile_completed_at.is_some(),
            own_company_id: user.own_company_id,
        }
    }
}

/// Create a new personal API key. The raw key is returned ONCE in
/// [`CreateApiKeyResponse::key`]; the database only ever stores the
/// `key_prefix` (search index) and an argon2 hash of the rest. The
/// scope list defaults to `["*"]` (full account access) to match the
/// `api_keys.scopes` column default, but callers should pin a tighter
/// list when the key only needs read access.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateApiKeyRequest {
    #[validate(length(min = 1, max = 100, message = "Name must be 1-100 chars"))]
    pub name: String,
    /// Optional ISO-8601 expiry. `None` means the key never expires.
    pub expires_at: Option<DateTime<Utc>>,
    /// Optional scope list. `None` -> the existing schema default `["*"]`.
    pub scopes: Option<Vec<String>>,
}

/// One-time create response. The raw `key` is shown once and never
/// stored or returned again.
#[derive(Debug, Clone, Serialize)]
pub struct CreateApiKeyResponse {
    pub id: Uuid,
    pub name: String,
    /// The raw bearer token. Surface this to the user immediately and
    /// never echo it from any other endpoint.
    pub key: String,
    pub key_prefix: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Sanitised representation of an `api_keys` row. Used by list and
/// get. Never carries the secret material.
#[derive(Debug, Clone, Serialize)]
pub struct ApiKeyResponse {
    pub id: Uuid,
    pub name: String,
    pub key_prefix: String,
    pub scopes: Vec<String>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

/// Session information
#[derive(Debug, Clone, Serialize)]
pub struct SessionInfo {
    pub id: Uuid,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub last_activity_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub is_current: bool,
}

/// JWT claims structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    /// Subject (user ID)
    pub sub: Uuid,
    /// Tenant ID
    pub tid: Uuid,
    /// User email
    pub email: String,
    /// User role. Serializes to/from the same snake_case string the
    /// wire format already used (e.g. `"super_admin"`), so this is
    /// drop-in compatible with previously-issued tokens.
    pub role: UserRole,
    /// Issued at
    pub iat: i64,
    /// MAPPS-334: not before. Mirrors `iat` at mint time so the token's
    /// intended start of validity is explicit. `#[serde(default)]` keeps
    /// the deserializer compatible with tokens minted before this field
    /// was added (no rolling-deploy 401 storm).
    #[serde(default)]
    pub nbf: i64,
    /// Expiration
    pub exp: i64,
    /// MAPPS-334: token issuer. Set to the mokosh-server self-identifier
    /// on mint so a future strict-validation flip can pin issuer +
    /// audience and prevent cross-protocol token confusion against other
    /// services that share `JWT_SECRET`. `#[serde(default)]` keeps
    /// already-issued tokens deserializing during the rolling refresh
    /// window. Strict-validation flip is a follow-up ticket once every
    /// minted refresh token has rotated through (~30 days).
    #[serde(default)]
    pub iss: String,
    /// MAPPS-334: token audience. Same shape as `iss`; future strict
    /// validation will pin both. `#[serde(default)]` for back-compat.
    #[serde(default)]
    pub aud: String,
    /// Token type (access/refresh)
    pub typ: String,
    /// Session ID
    pub sid: Uuid,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_role_is_admin() {
        assert!(UserRole::SuperAdmin.is_admin());
        assert!(UserRole::Admin.is_admin());
        assert!(!UserRole::Manager.is_admin());
        assert!(!UserRole::Technician.is_admin());
    }

    #[test]
    fn test_user_role_can_manage_users() {
        assert!(UserRole::SuperAdmin.can_manage_users());
        assert!(UserRole::Admin.can_manage_users());
        assert!(UserRole::Manager.can_manage_users());
        assert!(!UserRole::Technician.can_manage_users());
        assert!(!UserRole::Sales.can_manage_users());
    }

    #[test]
    fn test_user_role_can_grant_ceiling() {
        // super_admin may only be granted by an existing super_admin (PMS-503).
        assert!(UserRole::SuperAdmin.can_grant(UserRole::SuperAdmin));
        assert!(!UserRole::Admin.can_grant(UserRole::SuperAdmin));
        assert!(!UserRole::Manager.can_grant(UserRole::SuperAdmin));

        // A caller may grant roles at or below their own rank.
        assert!(UserRole::Admin.can_grant(UserRole::Admin));
        assert!(UserRole::Admin.can_grant(UserRole::Manager));
        assert!(UserRole::Admin.can_grant(UserRole::Technician));
        assert!(UserRole::SuperAdmin.can_grant(UserRole::Finance));

        // A caller may not grant a role above their own rank.
        assert!(!UserRole::Manager.can_grant(UserRole::Admin));
        assert!(!UserRole::Technician.can_grant(UserRole::Manager));
    }

    #[test]
    fn test_user_role_can_view_financials() {
        assert!(UserRole::SuperAdmin.can_view_financials());
        assert!(UserRole::Admin.can_view_financials());
        assert!(UserRole::Manager.can_view_financials());
        assert!(UserRole::Finance.can_view_financials());
        assert!(!UserRole::Technician.can_view_financials());
        assert!(!UserRole::Dispatcher.can_view_financials());
    }

    #[test]
    fn test_user_role_can_manage_billing() {
        assert!(UserRole::SuperAdmin.can_manage_billing());
        assert!(UserRole::Admin.can_manage_billing());
        assert!(UserRole::Finance.can_manage_billing());
        assert!(!UserRole::Manager.can_manage_billing());
        assert!(!UserRole::Technician.can_manage_billing());
    }

    #[test]
    fn test_user_role_from_str() {
        assert_eq!(UserRole::from_str("admin"), Some(UserRole::Admin));
        assert_eq!(
            UserRole::from_str("super_admin"),
            Some(UserRole::SuperAdmin)
        );
        assert_eq!(UserRole::from_str("technician"), Some(UserRole::Technician));
        assert_eq!(UserRole::from_str("invalid"), None);
    }

    #[test]
    fn test_user_role_as_str() {
        assert_eq!(UserRole::Admin.as_str(), "admin");
        assert_eq!(UserRole::SuperAdmin.as_str(), "super_admin");
        assert_eq!(UserRole::Technician.as_str(), "technician");
    }

    #[test]
    fn test_user_role_display() {
        assert_eq!(format!("{}", UserRole::Admin), "admin");
        assert_eq!(format!("{}", UserRole::Manager), "manager");
    }

    #[test]
    fn test_user_status_from_str() {
        assert_eq!(UserStatus::from_str("active"), Some(UserStatus::Active));
        assert_eq!(UserStatus::from_str("inactive"), Some(UserStatus::Inactive));
        assert_eq!(UserStatus::from_str("pending"), Some(UserStatus::Pending));
        assert_eq!(UserStatus::from_str("unknown"), None);
    }

    #[test]
    fn test_auth_state_default() {
        let state = AuthState::default();
        assert!(!state.is_authenticated);
        assert!(state.user.is_none());
        assert!(state.tenant_id.is_none());
    }

    #[test]
    fn test_auth_state_authenticated() {
        let user = CurrentUser {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            email: "test@example.com".to_string(),
            first_name: "Test".to_string(),
            last_name: "User".to_string(),
            role: UserRole::Admin,
            timezone: "UTC".to_string(),
            avatar_url: None,
            profile_completed: true,
            date_format_string: None,
            theme_base_mode: None,
            theme_accent_id: None,
            own_company_id: None,
        };
        let tenant_id = user.tenant_id;

        let state = AuthState::authenticated(user, tenant_id);
        assert!(state.is_authenticated);
        assert!(state.user.is_some());
        assert_eq!(state.tenant_id, Some(tenant_id));
    }

    #[test]
    fn test_auth_state_has_role() {
        let user = CurrentUser {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            email: "admin@example.com".to_string(),
            first_name: "Admin".to_string(),
            last_name: "User".to_string(),
            role: UserRole::Admin,
            timezone: "UTC".to_string(),
            avatar_url: None,
            profile_completed: true,
            date_format_string: None,
            theme_base_mode: None,
            theme_accent_id: None,
            own_company_id: None,
        };
        let tenant_id = user.tenant_id;
        let state = AuthState::authenticated(user, tenant_id);

        assert!(state.has_role(UserRole::Admin));
        assert!(!state.has_role(UserRole::Technician));
        assert!(state.is_admin());
    }

    #[test]
    fn test_current_user_full_name() {
        let user = CurrentUser {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            email: "john.doe@example.com".to_string(),
            first_name: "John".to_string(),
            last_name: "Doe".to_string(),
            role: UserRole::Technician,
            timezone: "America/New_York".to_string(),
            avatar_url: None,
            profile_completed: true,
            date_format_string: None,
            theme_base_mode: None,
            theme_accent_id: None,
            own_company_id: None,
        };

        assert_eq!(user.full_name(), "John Doe");
    }

    #[test]
    fn test_current_user_initials() {
        let user = CurrentUser {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            email: "john.doe@example.com".to_string(),
            first_name: "John".to_string(),
            last_name: "Doe".to_string(),
            role: UserRole::Technician,
            timezone: "UTC".to_string(),
            avatar_url: None,
            profile_completed: true,
            date_format_string: None,
            theme_base_mode: None,
            theme_accent_id: None,
            own_company_id: None,
        };

        assert_eq!(user.initials(), "JD");
    }

    #[test]
    fn test_auth_state_require_user() {
        let empty_state = AuthState::default();
        assert!(empty_state.require_user().is_err());

        let user = CurrentUser {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            email: "test@example.com".to_string(),
            first_name: "Test".to_string(),
            last_name: "User".to_string(),
            role: UserRole::Admin,
            timezone: "UTC".to_string(),
            avatar_url: None,
            profile_completed: true,
            date_format_string: None,
            theme_base_mode: None,
            theme_accent_id: None,
            own_company_id: None,
        };
        let tenant_id = user.tenant_id;
        let auth_state = AuthState::authenticated(user, tenant_id);
        assert!(auth_state.require_user().is_ok());
    }

    #[test]
    fn test_auth_state_require_tenant() {
        let empty_state = AuthState::default();
        assert!(empty_state.require_tenant().is_err());

        let user = CurrentUser {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            email: "test@example.com".to_string(),
            first_name: "Test".to_string(),
            last_name: "User".to_string(),
            role: UserRole::Admin,
            timezone: "UTC".to_string(),
            avatar_url: None,
            profile_completed: true,
            date_format_string: None,
            theme_base_mode: None,
            theme_accent_id: None,
            own_company_id: None,
        };
        let tenant_id = user.tenant_id;
        let auth_state = AuthState::authenticated(user, tenant_id);
        assert!(auth_state.require_tenant().is_ok());
        assert_eq!(auth_state.require_tenant().unwrap(), tenant_id);
    }
}
