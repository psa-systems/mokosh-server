//! Authentication service implementation

#[cfg(feature = "server")]
use chrono::{Duration, Utc};
#[cfg(feature = "server")]
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
#[cfg(feature = "server")]
use sqlx::PgPool;
#[cfg(feature = "server")]
use uuid::Uuid;

#[cfg(feature = "server")]
use crate::db::Database;
#[cfg(feature = "server")]
use crate::utils::crypto::{generate_token, hash_password, verify_password};
#[cfg(feature = "server")]
use crate::utils::error::{AppError, AppResult};

#[cfg(feature = "server")]
use super::models::*;

/// Authentication service
#[cfg(feature = "server")]
#[derive(Clone)]
pub struct AuthService {
    db: Database,
    jwt_secret: String,
    access_token_ttl: Duration,
    refresh_token_ttl: Duration,
}

#[cfg(feature = "server")]
impl AuthService {
    /// Create a new auth service
    pub fn new(db: Database, jwt_secret: String) -> Self {
        Self {
            db,
            jwt_secret,
            access_token_ttl: Duration::hours(1),
            refresh_token_ttl: Duration::days(7),
        }
    }

    /// Authenticate user with email and password
    pub async fn login(
        &self,
        request: &LoginRequest,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> AppResult<LoginResponse> {
        // Find user by email
        let user = self.find_user_by_email(&request.email).await?;

        // Check if user is active
        if user.status != UserStatus::Active {
            return Err(AppError::Forbidden("Account is not active".to_string()));
        }

        // Verify password
        let password_hash = user
            .password_hash
            .as_ref()
            .ok_or_else(|| AppError::Unauthorized)?;

        if !verify_password(&request.password, password_hash)? {
            return Err(AppError::Unauthorized);
        }

        // Check MFA if enabled
        if user.mfa_enabled {
            if request.mfa_code.is_none() {
                return Ok(LoginResponse {
                    access_token: String::new(),
                    refresh_token: String::new(),
                    expires_at: Utc::now(),
                    user: user.to_current_user(),
                    mfa_required: true,
                });
            }

            // TODO: Verify MFA code
            let _mfa_code = request.mfa_code.as_ref().unwrap();
            // Verify TOTP code against user.mfa_secret
        }

        // Create session
        let session_id = self
            .create_session(
                user.tenant_id,
                user.id,
                ip_address,
                user_agent,
                request.remember_me,
            )
            .await?;

        // Generate tokens
        let (access_token, refresh_token, expires_at) = self.generate_tokens(&user, session_id)?;

        // Update last login
        self.update_last_login(user.id).await?;

        Ok(LoginResponse {
            access_token,
            refresh_token,
            expires_at,
            user: user.to_current_user(),
            mfa_required: false,
        })
    }

    /// Refresh access token
    pub async fn refresh_token(&self, refresh_token: &str) -> AppResult<RefreshTokenResponse> {
        // Decode and validate refresh token
        let claims = self.decode_token(refresh_token)?;

        if claims.typ != "refresh" {
            return Err(AppError::Unauthorized);
        }

        // Verify session exists and is valid
        let session = self.get_session(claims.sid).await?;

        if session.is_none() {
            return Err(AppError::Unauthorized);
        }

        // Get user
        let user = self.get_user_by_id(claims.sub).await?;

        if user.status != UserStatus::Active {
            return Err(AppError::Forbidden("Account is not active".to_string()));
        }

        // Generate new tokens
        let (access_token, new_refresh_token, expires_at) =
            self.generate_tokens(&user, claims.sid)?;

        // Update session activity
        self.update_session_activity(claims.sid).await?;

        Ok(RefreshTokenResponse {
            access_token,
            refresh_token: new_refresh_token,
            expires_at,
        })
    }

    /// Logout - invalidate session
    pub async fn logout(&self, session_id: Uuid) -> AppResult<()> {
        sqlx::query("DELETE FROM user_sessions WHERE id = $1")
            .bind(session_id)
            .execute(self.db.pool())
            .await?;

        Ok(())
    }

    /// Logout all sessions for a user
    pub async fn logout_all(&self, user_id: Uuid) -> AppResult<()> {
        sqlx::query("DELETE FROM user_sessions WHERE user_id = $1")
            .bind(user_id)
            .execute(self.db.pool())
            .await?;

        Ok(())
    }

    /// Request password reset
    pub async fn request_password_reset(&self, email: &str) -> AppResult<()> {
        // Find user - don't reveal if user exists
        let user = match self.find_user_by_email(email).await {
            Ok(user) => user,
            Err(_) => return Ok(()), // Silently succeed to not reveal user existence
        };

        // Generate reset token
        let token = generate_token(64);
        let token_hash = hash_password(&token)?;
        let expires_at = Utc::now() + Duration::hours(24);

        // Store token
        sqlx::query(
            r#"
            INSERT INTO password_reset_tokens (tenant_id, user_id, token_hash, expires_at)
            VALUES ($1, $2, $3, $4)
            "#,
        )
        .bind(user.tenant_id)
        .bind(user.id)
        .bind(&token_hash)
        .bind(expires_at)
        .execute(self.db.pool())
        .await?;

        // TODO: Send password reset email with token
        tracing::info!("Password reset requested for user {}", user.id);

        Ok(())
    }

    /// Reset password with token
    pub async fn reset_password(&self, request: &ResetPasswordRequest) -> AppResult<()> {
        if request.new_password != request.confirm_password {
            return Err(AppError::validation_field(
                "confirm_password",
                "Passwords do not match",
            ));
        }

        // Find valid token
        let token_record = sqlx::query_as::<_, (Uuid, Uuid, String)>(
            r#"
            SELECT user_id, tenant_id, token_hash
            FROM password_reset_tokens
            WHERE used_at IS NULL AND expires_at > NOW()
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .fetch_optional(self.db.pool())
        .await?;

        let (user_id, _tenant_id, token_hash) = token_record
            .ok_or_else(|| AppError::BadRequest("Invalid or expired reset token".to_string()))?;

        // Verify token
        if !verify_password(&request.token, &token_hash)? {
            return Err(AppError::BadRequest("Invalid reset token".to_string()));
        }

        // Hash new password
        let new_hash = hash_password(&request.new_password)?;

        // Update password
        sqlx::query("UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2")
            .bind(&new_hash)
            .bind(user_id)
            .execute(self.db.pool())
            .await?;

        // Mark token as used
        sqlx::query(
            "UPDATE password_reset_tokens SET used_at = NOW() WHERE user_id = $1 AND used_at IS NULL",
        )
        .bind(user_id)
        .execute(self.db.pool())
        .await?;

        // Invalidate all sessions
        self.logout_all(user_id).await?;

        Ok(())
    }

    /// Change password (when logged in)
    pub async fn change_password(
        &self,
        user_id: Uuid,
        request: &ChangePasswordRequest,
    ) -> AppResult<()> {
        if request.new_password != request.confirm_password {
            return Err(AppError::validation_field(
                "confirm_password",
                "Passwords do not match",
            ));
        }

        // Get current password hash
        let current_hash: String =
            sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1")
                .bind(user_id)
                .fetch_optional(self.db.pool())
                .await?
                .ok_or_else(|| AppError::NotFound("User".to_string()))?;

        // Verify current password
        if !verify_password(&request.current_password, &current_hash)? {
            return Err(AppError::validation_field(
                "current_password",
                "Current password is incorrect",
            ));
        }

        // Hash and update new password
        let new_hash = hash_password(&request.new_password)?;

        sqlx::query("UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2")
            .bind(&new_hash)
            .bind(user_id)
            .execute(self.db.pool())
            .await?;

        Ok(())
    }

    /// Create a new user
    pub async fn create_user(
        &self,
        tenant_id: Uuid,
        request: &CreateUserRequest,
    ) -> AppResult<User> {
        // Check if email already exists
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM users WHERE tenant_id = $1 AND email = $2)",
        )
        .bind(tenant_id)
        .bind(&request.email)
        .fetch_one(self.db.pool())
        .await?;

        if exists {
            return Err(AppError::conflict("A user with this email already exists"));
        }

        let user_id = Uuid::new_v4();
        let timezone = request
            .timezone
            .clone()
            .unwrap_or_else(|| "UTC".to_string());

        sqlx::query(
            r#"
            INSERT INTO users (
                id, tenant_id, email, first_name, last_name, phone, mobile,
                title, role, timezone, status
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'pending')
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .bind(&request.email)
        .bind(&request.first_name)
        .bind(&request.last_name)
        .bind(&request.phone)
        .bind(&request.mobile)
        .bind(&request.title)
        .bind(request.role.as_str())
        .bind(&timezone)
        .execute(self.db.pool())
        .await?;

        if request.send_welcome_email {
            // TODO: Send welcome email with password setup link
            tracing::info!("Welcome email would be sent to {}", request.email);
        }

        self.get_user_by_id(user_id).await
    }

    /// Update user
    pub async fn update_user(&self, user_id: Uuid, request: &UpdateUserRequest) -> AppResult<User> {
        // Build dynamic update query
        let mut updates = Vec::new();
        let mut param_idx = 2;

        if request.email.is_some() {
            updates.push(format!("email = ${}", param_idx));
            param_idx += 1;
        }
        if request.first_name.is_some() {
            updates.push(format!("first_name = ${}", param_idx));
            param_idx += 1;
        }
        if request.last_name.is_some() {
            updates.push(format!("last_name = ${}", param_idx));
            param_idx += 1;
        }
        if request.phone.is_some() {
            updates.push(format!("phone = ${}", param_idx));
            param_idx += 1;
        }
        if request.mobile.is_some() {
            updates.push(format!("mobile = ${}", param_idx));
            param_idx += 1;
        }
        if request.title.is_some() {
            updates.push(format!("title = ${}", param_idx));
            param_idx += 1;
        }
        if request.role.is_some() {
            updates.push(format!("role = ${}", param_idx));
            param_idx += 1;
        }
        if request.status.is_some() {
            updates.push(format!("status = ${}", param_idx));
            param_idx += 1;
        }
        if request.timezone.is_some() {
            updates.push(format!("timezone = ${}", param_idx));
            // param_idx += 1;
        }

        if updates.is_empty() {
            return self.get_user_by_id(user_id).await;
        }

        updates.push("updated_at = NOW()".to_string());

        let query = format!("UPDATE users SET {} WHERE id = $1", updates.join(", "));

        let mut query_builder = sqlx::query(&query).bind(user_id);

        if let Some(ref email) = request.email {
            query_builder = query_builder.bind(email);
        }
        if let Some(ref first_name) = request.first_name {
            query_builder = query_builder.bind(first_name);
        }
        if let Some(ref last_name) = request.last_name {
            query_builder = query_builder.bind(last_name);
        }
        if let Some(ref phone) = request.phone {
            query_builder = query_builder.bind(phone);
        }
        if let Some(ref mobile) = request.mobile {
            query_builder = query_builder.bind(mobile);
        }
        if let Some(ref title) = request.title {
            query_builder = query_builder.bind(title);
        }
        if let Some(ref role) = request.role {
            query_builder = query_builder.bind(role.as_str());
        }
        if let Some(ref status) = request.status {
            query_builder = query_builder.bind(status.as_str());
        }
        if let Some(ref timezone) = request.timezone {
            query_builder = query_builder.bind(timezone);
        }

        query_builder.execute(self.db.pool()).await?;

        self.get_user_by_id(user_id).await
    }

    /// Get user by ID
    pub async fn get_user_by_id(&self, user_id: Uuid) -> AppResult<User> {
        let row = sqlx::query_as::<_, UserRow>(
            r#"
            SELECT id, tenant_id, email, password_hash, first_name, last_name,
                   phone, mobile, title, avatar_url, timezone, locale, role,
                   status, email_verified_at, last_login_at, mfa_enabled,
                   mfa_secret, notification_preferences, settings,
                   created_at, updated_at
            FROM users
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .fetch_optional(self.db.pool())
        .await?
        .ok_or_else(|| AppError::NotFound("User".to_string()))?;

        Ok(row.into())
    }

    /// Find user by email
    async fn find_user_by_email(&self, email: &str) -> AppResult<User> {
        let row = sqlx::query_as::<_, UserRow>(
            r#"
            SELECT id, tenant_id, email, password_hash, first_name, last_name,
                   phone, mobile, title, avatar_url, timezone, locale, role,
                   status, email_verified_at, last_login_at, mfa_enabled,
                   mfa_secret, notification_preferences, settings,
                   created_at, updated_at
            FROM users
            WHERE email = $1
            "#,
        )
        .bind(email)
        .fetch_optional(self.db.pool())
        .await?
        .ok_or(AppError::Unauthorized)?;

        Ok(row.into())
    }

    /// Validate token and return claims
    pub fn decode_token(&self, token: &str) -> AppResult<JwtClaims> {
        let decoding_key = DecodingKey::from_secret(self.jwt_secret.as_bytes());
        let validation = Validation::default();

        let token_data = decode::<JwtClaims>(token, &decoding_key, &validation)?;

        Ok(token_data.claims)
    }

    /// Create a new session
    async fn create_session(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        ip_address: Option<String>,
        user_agent: Option<String>,
        remember_me: bool,
    ) -> AppResult<Uuid> {
        let session_id = Uuid::new_v4();
        let token_hash = generate_token(32);
        let expires_at = if remember_me {
            Utc::now() + Duration::days(30)
        } else {
            Utc::now() + Duration::days(7)
        };

        sqlx::query(
            r#"
            INSERT INTO user_sessions (id, tenant_id, user_id, token_hash, ip_address, user_agent, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
        )
        .bind(session_id)
        .bind(tenant_id)
        .bind(user_id)
        .bind(&token_hash)
        .bind(&ip_address)
        .bind(&user_agent)
        .bind(expires_at)
        .execute(self.db.pool())
        .await?;

        Ok(session_id)
    }

    /// Get session by ID
    async fn get_session(&self, session_id: Uuid) -> AppResult<Option<Uuid>> {
        let result: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM user_sessions WHERE id = $1 AND expires_at > NOW()")
                .bind(session_id)
                .fetch_optional(self.db.pool())
                .await?;

        Ok(result)
    }

    /// Update session last activity
    async fn update_session_activity(&self, session_id: Uuid) -> AppResult<()> {
        sqlx::query("UPDATE user_sessions SET last_activity_at = NOW() WHERE id = $1")
            .bind(session_id)
            .execute(self.db.pool())
            .await?;

        Ok(())
    }

    /// Update user's last login timestamp
    async fn update_last_login(&self, user_id: Uuid) -> AppResult<()> {
        sqlx::query("UPDATE users SET last_login_at = NOW() WHERE id = $1")
            .bind(user_id)
            .execute(self.db.pool())
            .await?;

        Ok(())
    }

    /// Generate access and refresh tokens
    fn generate_tokens(
        &self,
        user: &User,
        session_id: Uuid,
    ) -> AppResult<(String, String, chrono::DateTime<Utc>)> {
        let now = Utc::now();
        let access_expires = now + self.access_token_ttl;
        let refresh_expires = now + self.refresh_token_ttl;

        let access_claims = JwtClaims {
            sub: user.id,
            tid: user.tenant_id,
            email: user.email.clone(),
            role: user.role.as_str().to_string(),
            iat: now.timestamp(),
            exp: access_expires.timestamp(),
            typ: "access".to_string(),
            sid: session_id,
        };

        let refresh_claims = JwtClaims {
            sub: user.id,
            tid: user.tenant_id,
            email: user.email.clone(),
            role: user.role.as_str().to_string(),
            iat: now.timestamp(),
            exp: refresh_expires.timestamp(),
            typ: "refresh".to_string(),
            sid: session_id,
        };

        let encoding_key = EncodingKey::from_secret(self.jwt_secret.as_bytes());

        let access_token = encode(&Header::default(), &access_claims, &encoding_key)?;
        let refresh_token = encode(&Header::default(), &refresh_claims, &encoding_key)?;

        Ok((access_token, refresh_token, access_expires))
    }

    /// Get all active sessions for a user
    pub async fn get_user_sessions(
        &self,
        user_id: Uuid,
        current_session_id: Uuid,
    ) -> AppResult<Vec<SessionInfo>> {
        let rows = sqlx::query_as::<_, SessionRow>(
            r#"
            SELECT id, ip_address, user_agent, last_activity_at, created_at
            FROM user_sessions
            WHERE user_id = $1 AND expires_at > NOW()
            ORDER BY last_activity_at DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(self.db.pool())
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| SessionInfo {
                id: r.id,
                ip_address: r.ip_address,
                user_agent: r.user_agent,
                last_activity_at: r.last_activity_at,
                created_at: r.created_at,
                is_current: r.id == current_session_id,
            })
            .collect())
    }

    /// Delete a specific session
    pub async fn delete_session(&self, user_id: Uuid, session_id: Uuid) -> AppResult<()> {
        sqlx::query("DELETE FROM user_sessions WHERE id = $1 AND user_id = $2")
            .bind(session_id)
            .bind(user_id)
            .execute(self.db.pool())
            .await?;

        Ok(())
    }
}

// Database row types for sqlx
#[cfg(feature = "server")]
#[derive(sqlx::FromRow)]
struct UserRow {
    id: Uuid,
    tenant_id: Uuid,
    email: String,
    password_hash: Option<String>,
    first_name: String,
    last_name: String,
    phone: Option<String>,
    mobile: Option<String>,
    title: Option<String>,
    avatar_url: Option<String>,
    timezone: String,
    locale: String,
    role: String,
    status: String,
    email_verified_at: Option<chrono::DateTime<Utc>>,
    last_login_at: Option<chrono::DateTime<Utc>>,
    mfa_enabled: bool,
    mfa_secret: Option<String>,
    notification_preferences: serde_json::Value,
    settings: serde_json::Value,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
}

#[cfg(feature = "server")]
impl From<UserRow> for User {
    fn from(row: UserRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            email: row.email,
            password_hash: row.password_hash,
            first_name: row.first_name,
            last_name: row.last_name,
            phone: row.phone,
            mobile: row.mobile,
            title: row.title,
            avatar_url: row.avatar_url,
            timezone: row.timezone,
            locale: row.locale,
            role: UserRole::from_str(&row.role).unwrap_or_default(),
            status: UserStatus::from_str(&row.status).unwrap_or_default(),
            email_verified_at: row.email_verified_at,
            last_login_at: row.last_login_at,
            mfa_enabled: row.mfa_enabled,
            mfa_secret: row.mfa_secret,
            notification_preferences: row.notification_preferences,
            settings: row.settings,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[cfg(feature = "server")]
#[derive(sqlx::FromRow)]
struct SessionRow {
    id: Uuid,
    ip_address: Option<String>,
    user_agent: Option<String>,
    last_activity_at: chrono::DateTime<Utc>,
    created_at: chrono::DateTime<Utc>,
}
