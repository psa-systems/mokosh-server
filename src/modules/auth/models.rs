//! Authentication models and types

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

/// Current authenticated user state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthState {
    /// Whether the user is authenticated
    pub is_authenticated: bool,
    /// The current user (if authenticated)
    pub user: Option<CurrentUser>,
    /// The current tenant ID
    pub tenant_id: Option<Uuid>,
}

impl Default for AuthState {
    fn default() -> Self {
        Self {
            is_authenticated: false,
            user: None,
            tenant_id: None,
        }
    }
}

impl AuthState {
    /// Create an authenticated state
    pub fn authenticated(user: CurrentUser, tenant_id: Uuid) -> Self {
        Self {
            is_authenticated: true,
            user: Some(user),
            tenant_id: Some(tenant_id),
        }
    }

    /// Get the current user or return an error
    pub fn require_user(&self) -> Result<&CurrentUser, crate::utils::error::AppError> {
        self.user
            .as_ref()
            .ok_or(crate::utils::error::AppError::Unauthorized)
    }

    /// Get the current tenant ID or return an error
    pub fn require_tenant(&self) -> Result<Uuid, crate::utils::error::AppError> {
        self.tenant_id
            .ok_or(crate::utils::error::AppError::Unauthorized)
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
    pub role: UserRole,
    pub status: UserStatus,
    pub email_verified_at: Option<DateTime<Utc>>,
    pub last_login_at: Option<DateTime<Utc>>,
    pub mfa_enabled: bool,
    #[serde(skip_serializing)]
    pub mfa_secret: Option<String>,
    pub notification_preferences: serde_json::Value,
    pub settings: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
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
    /// MFA code if required
    pub mfa_code: Option<String>,
}

/// Login response
#[derive(Debug, Clone, Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: DateTime<Utc>,
    pub user: CurrentUser,
    /// Whether MFA is required to complete login
    pub mfa_required: bool,
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
}

/// Password reset completion
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct ResetPasswordRequest {
    pub token: String,
    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    pub new_password: String,
    pub confirm_password: String,
}

/// Change password request (when logged in)
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
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
    /// If true, send welcome email with password setup link
    #[serde(default = "default_true")]
    pub send_welcome_email: bool,
}

fn default_true() -> bool {
    true
}

/// Update user request
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpdateUserRequest {
    #[validate(email(message = "Invalid email address"))]
    pub email: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub phone: Option<String>,
    pub mobile: Option<String>,
    pub title: Option<String>,
    pub role: Option<UserRole>,
    pub status: Option<UserStatus>,
    pub timezone: Option<String>,
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
    pub role: UserRole,
    pub status: UserStatus,
    pub mfa_enabled: bool,
    pub last_login_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
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
            role: user.role,
            status: user.status,
            mfa_enabled: user.mfa_enabled,
            last_login_at: user.last_login_at,
            created_at: user.created_at,
        }
    }
}

/// MFA setup request
#[derive(Debug, Clone, Deserialize)]
pub struct MfaSetupRequest {
    /// The TOTP code to verify setup
    pub code: String,
}

/// MFA setup response
#[derive(Debug, Clone, Serialize)]
pub struct MfaSetupResponse {
    /// The secret to add to authenticator app
    pub secret: String,
    /// QR code data URL
    pub qr_code: String,
    /// Recovery codes
    pub recovery_codes: Vec<String>,
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
    /// User role
    pub role: String,
    /// Issued at
    pub iat: i64,
    /// Expiration
    pub exp: i64,
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
        };
        let tenant_id = user.tenant_id;
        let auth_state = AuthState::authenticated(user, tenant_id);
        assert!(auth_state.require_tenant().is_ok());
        assert_eq!(auth_state.require_tenant().unwrap(), tenant_id);
    }
}
