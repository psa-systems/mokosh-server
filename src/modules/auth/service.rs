//! Authentication service implementation

#[cfg(feature = "server")]
use chrono::{Duration, Utc};
#[cfg(feature = "server")]
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
#[cfg(feature = "server")]
use std::sync::Arc;
#[cfg(feature = "server")]
use uuid::Uuid;

#[cfg(feature = "server")]
use crate::db::Database;
#[cfg(feature = "server")]
use crate::modules::notifications::NotificationsService;
#[cfg(feature = "server")]
use crate::utils::crypto::{generate_token, hash_password, verify_password};
#[cfg(feature = "server")]
use crate::utils::email::{LogMailer, Mailer};
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
    /// Lowercased exact email addresses allowed to auto-provision a
    /// super_admin account on first Google sign-in. Any other unrecognized
    /// Google identity is rejected (fail-closed) rather than auto-created in
    /// the default tenant. Existing users are never re-roled.
    super_admin_emails: Vec<String>,
    /// Outbound transactional email. Defaults to `LogMailer` so unit
    /// constructions that do not need real SMTP keep working. Kept as
    /// a fallback for builds that do not wire a `NotificationsService`
    /// (e.g. older test fixtures); see [`Self::with_dispatcher`].
    mailer: Arc<dyn Mailer>,
    /// When `Some`, password-reset and welcome emails are enqueued via
    /// the notifications dispatcher (templates from
    /// `notification_templates`, delivery driven by `DispatcherWorker`).
    /// When `None`, the service falls back to calling `mailer`
    /// directly for backwards-compatible test fixtures.
    notifications: Option<NotificationsService>,
    /// Public-facing SPA origin used as the prefix for password-reset
    /// and welcome links sent in transactional email. Equal to
    /// `AppConfig::client_origin`.
    frontend_base_url: String,
}

#[cfg(feature = "server")]
impl AuthService {
    /// Create a new auth service.
    pub fn new(db: Database, jwt_secret: String, super_admin_emails: Vec<String>) -> Self {
        Self::with_mailer(
            db,
            jwt_secret,
            super_admin_emails,
            Arc::new(LogMailer),
            "http://localhost:4301".to_string(),
        )
    }

    /// Create a new auth service with an explicit mailer + frontend
    /// origin. `frontend_base_url` is used as the prefix for any link
    /// the service emails to a user (password reset, welcome).
    pub fn with_mailer(
        db: Database,
        jwt_secret: String,
        super_admin_emails: Vec<String>,
        mailer: Arc<dyn Mailer>,
        frontend_base_url: String,
    ) -> Self {
        Self {
            db,
            jwt_secret,
            access_token_ttl: Duration::hours(1),
            refresh_token_ttl: Duration::days(7),
            super_admin_emails,
            mailer,
            notifications: None,
            frontend_base_url: frontend_base_url.trim_end_matches('/').to_string(),
        }
    }

    /// Like [`Self::with_mailer`] but additionally wires the
    /// notifications dispatcher. The server uses this constructor in
    /// `create_api_router` so password-reset and welcome emails flow
    /// through the queue (templates from `notification_templates`,
    /// retries handled by `DispatcherWorker`) instead of calling SMTP
    /// inline. The `mailer` argument is retained so any future
    /// short-circuit path (or operator that disables the worker) keeps
    /// the direct send available.
    pub fn with_dispatcher(
        db: Database,
        jwt_secret: String,
        super_admin_emails: Vec<String>,
        mailer: Arc<dyn Mailer>,
        frontend_base_url: String,
        notifications: NotificationsService,
    ) -> Self {
        Self {
            db,
            jwt_secret,
            access_token_ttl: Duration::hours(1),
            refresh_token_ttl: Duration::days(7),
            super_admin_emails,
            mailer,
            notifications: Some(notifications),
            frontend_base_url: frontend_base_url.trim_end_matches('/').to_string(),
        }
    }

    /// Authenticate user with email and password
    #[tracing::instrument(skip_all)]
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

        // Reject sign-in when the owning tenant is suspended/cancelled, so a
        // tenant-level suspension takes effect immediately.
        self.ensure_tenant_active(user.tenant_id).await?;

        // Verify password
        let password_hash = user.password_hash.as_ref().ok_or(AppError::Unauthorized)?;

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

            let code = request.mfa_code.as_ref().unwrap();
            let secret_b32 = user
                .mfa_secret
                .as_ref()
                .ok_or_else(|| AppError::Internal("MFA enabled without secret".to_string()))?;
            let secret = mokosh_auth_crypto::totp::base32_decode(secret_b32)
                .map_err(|_| AppError::Internal("stored MFA secret is corrupt".to_string()))?;
            // +-1 step (30s) tolerance handles modest clock skew.
            if mokosh_auth_crypto::totp::verify(&secret, code, Utc::now(), 1).is_none() {
                return Err(AppError::Unauthorized);
            }
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

    /// Reject access when the owning tenant is not active (suspended or
    /// cancelled). Threaded into every session-minting path (password login,
    /// Google login, refresh) so a tenant suspension takes effect immediately
    /// instead of lingering until token expiry.
    async fn ensure_tenant_active(&self, tenant_id: Uuid) -> AppResult<()> {
        let status: Option<String> = sqlx::query_scalar("SELECT status FROM tenants WHERE id = $1")
            .bind(tenant_id)
            .fetch_optional(self.db.pool())
            .await?;
        match status.as_deref() {
            Some("active") => Ok(()),
            _ => Err(AppError::Forbidden(
                "This organization is not active".to_string(),
            )),
        }
    }

    /// Authenticate (or auto-provision) a user from a Google OAuth
    /// userinfo response. The caller is responsible for verifying the
    /// CSRF state and exchanging the authorization code via the
    /// `google-oauth-flow` crate before calling this.
    #[tracing::instrument(skip_all)]
    pub async fn login_with_google(
        &self,
        google: google_oauth_flow::GoogleUserInfo,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> AppResult<LoginResponse> {
        // Reject if Google did not confirm the email is verified.
        if google.email_verified != Some(true) {
            return Err(AppError::Forbidden(
                "Google did not report this email as verified".to_string(),
            ));
        }

        // 1. Look up an existing identity by (provider, subject).
        let linked_user_id: Option<Uuid> = sqlx::query_scalar(
            "SELECT user_id FROM user_oauth_identities \
             WHERE provider = 'google' AND subject = $1",
        )
        .bind(&google.sub)
        .fetch_optional(self.db.pool())
        .await?;

        let user = if let Some(user_id) = linked_user_id {
            sqlx::query(
                "UPDATE user_oauth_identities SET last_used_at = NOW() \
                 WHERE provider = 'google' AND subject = $1",
            )
            .bind(&google.sub)
            .execute(self.db.pool())
            .await?;
            self.get_user_by_id(user_id).await?
        } else {
            // 2. No identity row yet - find or create the user by email.
            match self.find_user_by_email_optional(&google.email).await? {
                Some(existing) => {
                    // Only auto-link to an existing local account whose own
                    // email is verified. Otherwise someone who registered a
                    // password account under another person's email could
                    // capture that person's Google sign-in.
                    if existing.email_verified_at.is_none() {
                        return Err(AppError::Forbidden(
                            "An account with this email exists but is not verified. Sign in with your password first to link Google.".to_string(),
                        ));
                    }
                    // Link new identity to existing user; do NOT change role.
                    sqlx::query(
                        "INSERT INTO user_oauth_identities \
                         (user_id, provider, subject, email) \
                         VALUES ($1, 'google', $2, $3)",
                    )
                    .bind(existing.id)
                    .bind(&google.sub)
                    .bind(&google.email)
                    .execute(self.db.pool())
                    .await?;
                    existing
                }
                None => self.provision_user_from_google(&google).await?,
            }
        };

        // 3. Reject inactive users and suspended/cancelled tenants.
        if user.status != UserStatus::Active {
            return Err(AppError::Forbidden("Account is not active".to_string()));
        }
        self.ensure_tenant_active(user.tenant_id).await?;

        // 4. Issue session + tokens identically to the password flow.
        let session_id = self
            .create_session(user.tenant_id, user.id, ip_address, user_agent, false)
            .await?;
        let (access_token, refresh_token, expires_at) = self.generate_tokens(&user, session_id)?;
        self.update_last_login(user.id).await?;

        Ok(LoginResponse {
            access_token,
            refresh_token,
            expires_at,
            user: user.to_current_user(),
            mfa_required: false,
        })
    }

    /// Auto-provision a user from a verified Google identity. FAIL-CLOSED:
    /// only exact emails in `self.super_admin_emails` may auto-provision (as
    /// super_admin, to bootstrap administrators). Any other unrecognized
    /// Google identity is rejected - real users must be invited rather than
    /// silently dropped into the default tenant.
    async fn provision_user_from_google(
        &self,
        google: &google_oauth_flow::GoogleUserInfo,
    ) -> AppResult<User> {
        if !is_allowlisted_email(&self.super_admin_emails, &google.email) {
            return Err(AppError::Forbidden(
                "No account is provisioned for this Google identity. Ask an administrator for an invite.".to_string(),
            ));
        }
        let role = "super_admin";

        let user_id = Uuid::new_v4();
        // Bootstrap super-admins land in the default tenant seeded by
        // migrations/002_seed_data.sql. Everyone else is invited into a
        // specific tenant via the invite flow, not this path.
        let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001")
            .expect("default tenant UUID is valid");

        sqlx::query(
            r#"
            INSERT INTO users (
                id, tenant_id, email, password_hash, first_name, last_name,
                role, status, email_verified_at
            )
            VALUES ($1, $2, $3, NULL, $4, $5, $6, 'active', NOW())
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .bind(&google.email)
        .bind(google.given_name.clone().unwrap_or_default())
        .bind(google.family_name.clone().unwrap_or_default())
        .bind(role)
        .execute(self.db.pool())
        .await?;

        sqlx::query(
            "INSERT INTO user_oauth_identities \
             (user_id, provider, subject, email) \
             VALUES ($1, 'google', $2, $3)",
        )
        .bind(user_id)
        .bind(&google.sub)
        .bind(&google.email)
        .execute(self.db.pool())
        .await?;

        self.get_user_by_id(user_id).await
    }

    /// Look up a user by email; returns `Ok(None)` instead of
    /// `Err(Unauthorized)` when no user exists.
    async fn find_user_by_email_optional(&self, email: &str) -> AppResult<Option<User>> {
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
        .await?;
        Ok(row.map(Into::into))
    }

    /// Refresh access token
    #[tracing::instrument(skip_all)]
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
        // A tenant suspended after the session was minted is rejected here, so
        // refreshing can't outlive the suspension.
        self.ensure_tenant_active(user.tenant_id).await?;

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
    #[tracing::instrument(skip_all)]
    pub async fn logout(&self, session_id: Uuid) -> AppResult<()> {
        sqlx::query("DELETE FROM user_sessions WHERE id = $1")
            .bind(session_id)
            .execute(self.db.pool())
            .await?;

        Ok(())
    }

    /// Logout all sessions for a user
    #[tracing::instrument(skip_all)]
    pub async fn logout_all(&self, user_id: Uuid) -> AppResult<()> {
        sqlx::query("DELETE FROM user_sessions WHERE user_id = $1")
            .bind(user_id)
            .execute(self.db.pool())
            .await?;

        Ok(())
    }

    /// Request password reset
    #[tracing::instrument(skip_all)]
    pub async fn request_password_reset(&self, email: &str) -> AppResult<()> {
        // Find user - don't reveal if user exists
        let user = match self.find_user_by_email(email).await {
            Ok(user) => user,
            Err(_) => return Ok(()), // Silently succeed to not reveal user existence
        };

        // Generate a reset token bound to the user. The emailed token is
        // `{user_id}.{secret}`; only the secret is hashed and stored so
        // reset_password can scope its lookup to this user.
        let secret = generate_token(64);
        let token_hash = hash_password(&secret)?;
        let token = format!("{}.{}", user.id, secret);
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

        let reset_link = format!("{}/reset-password/{}", self.frontend_base_url, token);
        match &self.notifications {
            Some(notify) => {
                let context = serde_json::json!({
                    "recipient_user_id": user.id.to_string(),
                    "recipient_email": user.email,
                    "reset_link": reset_link,
                });
                if let Err(e) = notify
                    .dispatch(user.tenant_id, "auth.password_reset", &context)
                    .await
                {
                    tracing::warn!(
                        user_id = %user.id,
                        error = ?e,
                        "password reset notify dispatch failed; token persisted but no message queued",
                    );
                } else {
                    tracing::info!(user_id = %user.id, "password reset queued via notifications dispatcher");
                }
            }
            None => {
                if let Err(e) = self
                    .mailer
                    .send_password_reset(&user.email, &reset_link)
                    .await
                {
                    tracing::warn!(
                        user_id = %user.id,
                        error = ?e,
                        "password reset email send failed; token is persisted but unreachable",
                    );
                } else {
                    tracing::info!(user_id = %user.id, "password reset email sent (legacy mailer path)");
                }
            }
        }

        Ok(())
    }

    /// Reset password with token
    #[tracing::instrument(skip_all)]
    pub async fn reset_password(&self, request: &ResetPasswordRequest) -> AppResult<()> {
        if request.new_password != request.confirm_password {
            return Err(AppError::validation_field(
                "confirm_password",
                "Passwords do not match",
            ));
        }

        // The emailed token is `{user_id}.{secret}`; only the secret half is
        // hashed and stored. Bind the lookup to that user so a leaked or
        // guessed token can only reset its own account. (Tokens are salted
        // Argon2 hashes and cannot be looked up by value, which is why the old
        // code grabbed the most-recent token across ALL users - the bug.)
        let (user_id, secret) = parse_user_bound_token(&request.token)
            .ok_or_else(|| AppError::BadRequest("Invalid or expired reset token".to_string()))?;

        let candidates = sqlx::query_as::<_, (String,)>(
            r#"
            SELECT token_hash
            FROM password_reset_tokens
            WHERE user_id = $1 AND used_at IS NULL AND expires_at > NOW()
            ORDER BY created_at DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(self.db.pool())
        .await?;

        let token_valid = candidates.iter().try_fold(false, |found, (token_hash,)| {
            if found {
                Ok(true)
            } else {
                verify_password(secret, token_hash)
            }
        })?;
        if !token_valid {
            return Err(AppError::BadRequest(
                "Invalid or expired reset token".to_string(),
            ));
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
    #[tracing::instrument(skip_all)]
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
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
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
            // Reuse the password_reset_tokens machinery so the recipient
            // can pick a password without going through "Forgot password"
            // first. 7-day window: long enough for admins who batch-create
            // accounts ahead of an onboarding day, short enough that a
            // leaked link is bounded.
            // Same user-bound `{user_id}.{secret}` token shape as
            // request_password_reset so reset_password can scope the lookup.
            let secret = generate_token(64);
            let token_hash = hash_password(&secret)?;
            let token = format!("{}.{}", user_id, secret);
            let expires_at = Utc::now() + Duration::days(7);
            sqlx::query(
                r#"
                INSERT INTO password_reset_tokens (tenant_id, user_id, token_hash, expires_at)
                VALUES ($1, $2, $3, $4)
                "#,
            )
            .bind(tenant_id)
            .bind(user_id)
            .bind(&token_hash)
            .bind(expires_at)
            .execute(self.db.pool())
            .await?;

            let setup_link = format!("{}/reset-password/{}", self.frontend_base_url, token);
            let display_name = match (request.first_name.trim(), request.last_name.trim()) {
                ("", "") => String::new(),
                (f, "") => f.to_string(),
                ("", l) => l.to_string(),
                (f, l) => format!("{f} {l}"),
            };
            match &self.notifications {
                Some(notify) => {
                    let context = serde_json::json!({
                        "recipient_user_id": user_id.to_string(),
                        "recipient_email": request.email,
                        "display_name": display_name,
                        "setup_link": setup_link,
                    });
                    if let Err(e) = notify.dispatch(tenant_id, "auth.welcome", &context).await {
                        tracing::warn!(
                            user_id = %user_id,
                            error = ?e,
                            "welcome notify dispatch failed; setup token persisted but no message queued",
                        );
                    } else {
                        tracing::info!(user_id = %user_id, "welcome email queued via notifications dispatcher");
                    }
                }
                None => {
                    if let Err(e) = self
                        .mailer
                        .send_welcome(&request.email, &display_name, &setup_link)
                        .await
                    {
                        tracing::warn!(
                            user_id = %user_id,
                            error = ?e,
                            "welcome email send failed; setup token persisted but unreachable",
                        );
                    } else {
                        tracing::info!(user_id = %user_id, "welcome email sent (legacy mailer path)");
                    }
                }
            }
        }

        self.get_user_by_id(user_id).await
    }

    /// Update user
    #[tracing::instrument(skip_all)]
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

    /// Begin MFA enrollment. Generates a fresh TOTP secret, persists it
    /// on `users.mfa_secret`, and returns the base32 secret plus the
    /// `otpauth://` provisioning URI. `mfa_enabled` is NOT flipped here
    /// — the caller must complete enrollment by submitting a valid code
    /// via [`AuthService::enable_mfa`]. Refusing partial enrollment
    /// guarantees that an authenticator that was misconfigured (wrong
    /// time, wrong algorithm) cannot lock the user out.
    #[tracing::instrument(skip_all)]
    pub async fn start_mfa_enrollment(
        &self,
        user_id: Uuid,
    ) -> AppResult<crate::modules::auth::models::MfaSetupResponse> {
        let user = self.get_user_by_id(user_id).await?;
        if user.mfa_enabled {
            return Err(AppError::Conflict("MFA is already enabled".to_string()));
        }

        let secret = mokosh_auth_crypto::totp::generate_secret();
        let secret_b32 = mokosh_auth_crypto::totp::base32_encode(&secret);

        sqlx::query("UPDATE users SET mfa_secret = $1, updated_at = NOW() WHERE id = $2")
            .bind(&secret_b32)
            .bind(user_id)
            .execute(self.db.pool())
            .await?;

        let label = format!("Mokosh:{}", user.email);
        let provisioning_uri =
            mokosh_auth_crypto::totp::provisioning_uri(&secret_b32, &label, "Mokosh");

        Ok(crate::modules::auth::models::MfaSetupResponse {
            secret: secret_b32,
            provisioning_uri,
        })
    }

    /// Finish MFA enrollment. Verifies one TOTP code against the secret
    /// staged by [`AuthService::start_mfa_enrollment`]; on success flips
    /// `mfa_enabled = true`.
    #[tracing::instrument(skip_all)]
    pub async fn enable_mfa(&self, user_id: Uuid, code: &str) -> AppResult<()> {
        let user = self.get_user_by_id(user_id).await?;
        let secret_b32 = user.mfa_secret.as_ref().ok_or_else(|| {
            AppError::BadRequest("MFA enrollment has not been started".to_string())
        })?;
        let secret = mokosh_auth_crypto::totp::base32_decode(secret_b32)
            .map_err(|_| AppError::Internal("stored MFA secret is corrupt".to_string()))?;
        if mokosh_auth_crypto::totp::verify(&secret, code, Utc::now(), 1).is_none() {
            return Err(AppError::BadRequest("Invalid MFA code".to_string()));
        }

        sqlx::query("UPDATE users SET mfa_enabled = TRUE, updated_at = NOW() WHERE id = $1")
            .bind(user_id)
            .execute(self.db.pool())
            .await?;

        Ok(())
    }

    /// Disable MFA. Requires the user's current password (re-auth) so a
    /// stolen session cannot quietly weaken the account.
    #[tracing::instrument(skip_all)]
    pub async fn disable_mfa(&self, user_id: Uuid, password: &str) -> AppResult<()> {
        let user = self.get_user_by_id(user_id).await?;
        let hash = user
            .password_hash
            .as_ref()
            .ok_or_else(|| AppError::BadRequest("This account has no password".to_string()))?;
        if !verify_password(password, hash)? {
            return Err(AppError::Unauthorized);
        }

        sqlx::query(
            "UPDATE users SET mfa_enabled = FALSE, mfa_secret = NULL, updated_at = NOW() WHERE id = $1",
        )
        .bind(user_id)
        .execute(self.db.pool())
        .await?;

        Ok(())
    }

    /// Issue a personal API key. Returns the raw key once; thereafter
    /// only the `key_prefix` and an argon2 hash of the full key are
    /// persisted. The first 10 chars of `psa_xxxx...` become the
    /// `key_prefix` lookup column so future bearer auth can find the
    /// row in O(log n) before doing the expensive hash compare.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_api_key(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        request: &crate::modules::auth::models::CreateApiKeyRequest,
    ) -> AppResult<crate::modules::auth::models::CreateApiKeyResponse> {
        use crate::utils::crypto::generate_api_key;

        let raw_key = generate_api_key();
        // `psa_` + 40 alnum = 44 chars; prefix is 10 chars.
        let key_prefix: String = raw_key.chars().take(10).collect();
        let key_hash = hash_password(&raw_key)?;

        let id = Uuid::new_v4();
        let scopes = request
            .scopes
            .clone()
            .unwrap_or_else(|| vec!["*".to_string()]);
        let scopes_json = serde_json::to_value(&scopes)
            .map_err(|e| AppError::Internal(format!("api key scopes serialise: {e}")))?;

        let created_at: chrono::DateTime<Utc> = sqlx::query_scalar(
            r#"
            INSERT INTO api_keys (
                id, tenant_id, user_id, name, key_prefix, key_hash, scopes,
                expires_at, is_active
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, TRUE)
            RETURNING created_at
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(user_id)
        .bind(&request.name)
        .bind(&key_prefix)
        .bind(&key_hash)
        .bind(scopes_json)
        .bind(request.expires_at)
        .fetch_one(self.db.pool())
        .await?;

        Ok(crate::modules::auth::models::CreateApiKeyResponse {
            id,
            name: request.name.clone(),
            key: raw_key,
            key_prefix,
            scopes,
            expires_at: request.expires_at,
            created_at,
        })
    }

    /// List API keys owned by `user_id`. Never returns secret material.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_api_keys(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        pagination: &crate::utils::pagination::PaginationParams,
    ) -> AppResult<(Vec<crate::modules::auth::models::ApiKeyResponse>, u64)> {
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM api_keys WHERE tenant_id = $1 AND user_id = $2",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_one(self.db.pool())
        .await?;

        let rows = sqlx::query_as::<_, ApiKeyRow>(
            r#"
            SELECT id, name, key_prefix, scopes, last_used_at, expires_at,
                   is_active, created_at
            FROM api_keys
            WHERE tenant_id = $1 AND user_id = $2
            ORDER BY created_at DESC
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(self.db.pool())
        .await?;

        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    /// Revoke (hard-delete) an API key. Scoped to the calling user +
    /// tenant so a stolen session for user A cannot kill user B's keys.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn revoke_api_key(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        key_id: Uuid,
    ) -> AppResult<()> {
        let affected =
            sqlx::query("DELETE FROM api_keys WHERE id = $1 AND tenant_id = $2 AND user_id = $3")
                .bind(key_id)
                .bind(tenant_id)
                .bind(user_id)
                .execute(self.db.pool())
                .await?
                .rows_affected();

        if affected == 0 {
            return Err(AppError::NotFound("API key".to_string()));
        }
        Ok(())
    }

    /// List users in a tenant, paginated. Audit F1.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_users(
        &self,
        tenant_id: Uuid,
        pagination: &crate::utils::pagination::PaginationParams,
    ) -> AppResult<(Vec<User>, u64)> {
        let offset = pagination.offset() as i64;
        let limit = pagination.limit() as i64;

        let order_by = pagination.order_by(
            "created_at",
            &[
                "email",
                "first_name",
                "last_name",
                "role",
                "status",
                "created_at",
            ],
        );

        let query = format!(
            r#"
            SELECT id, tenant_id, email, password_hash, first_name, last_name,
                   phone, mobile, title, avatar_url, timezone, locale, role,
                   status, email_verified_at, last_login_at, mfa_enabled,
                   mfa_secret, notification_preferences, settings,
                   created_at, updated_at
            FROM users
            WHERE tenant_id = $1
            ORDER BY {order_by}
            LIMIT $2 OFFSET $3
            "#
        );

        let rows = sqlx::query_as::<_, UserRow>(&query)
            .bind(tenant_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(self.db.pool())
            .await?;

        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_one(self.db.pool())
            .await?;

        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    /// Get user by ID
    #[tracing::instrument(skip_all)]
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

    /// JIT-mirror an OIDC subject into the local `users` table.
    ///
    /// Called from `AuthMiddleware` on first sight of a bunyip-issued `at+jwt`
    /// whose `sub` doesn't yet match a local row. The local `users.id` is set
    /// to `sub` so subsequent requests resolve via `get_user_by_id` without
    /// another userinfo round-trip. See docs/new-auth/mokosh/03-mokosh-server-rs-cutover.md §3.3.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn upsert_user_from_oidc(
        &self,
        sub: Uuid,
        tenant_id: Uuid,
        email: &str,
        role: UserRole,
    ) -> AppResult<User> {
        // `users.first_name` and `users.last_name` are NOT NULL. Bunyip's
        // at+jwt deliberately doesn't carry name claims (RFC 9068), and
        // /oauth2/userinfo only resolves `email`, so on first JIT insert
        // we have nothing better to seed with. Derive a placeholder from
        // the email local-part so the row satisfies the schema; the user
        // can edit their real name from Settings whenever they like, and
        // a later refresh of userinfo (or an explicit profile sync) can
        // overwrite this default.
        let (default_first, default_last) = synthetic_name_from_email(email);
        sqlx::query(
            r#"
            INSERT INTO users (
                id, tenant_id, email, role, status, email_verified_at, timezone,
                first_name, last_name
            )
            VALUES ($1, $2, $3, $4, 'active', NOW(), 'UTC', $5, $6)
            ON CONFLICT (id) DO UPDATE SET
                email = EXCLUDED.email,
                updated_at = NOW()
            "#,
        )
        .bind(sub)
        .bind(tenant_id)
        .bind(email)
        .bind(role.as_str())
        .bind(&default_first)
        .bind(&default_last)
        .execute(self.db.pool())
        .await?;
        self.get_user_by_id(sub).await
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
    #[tracing::instrument(skip_all)]
    pub async fn get_user_sessions(
        &self,
        user_id: Uuid,
        current_session_id: Uuid,
        pagination: &crate::utils::pagination::PaginationParams,
    ) -> AppResult<(Vec<SessionInfo>, u64)> {
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM user_sessions WHERE user_id = $1 AND expires_at > NOW()",
        )
        .bind(user_id)
        .fetch_one(self.db.pool())
        .await?;

        let rows = sqlx::query_as::<_, SessionRow>(
            r#"
            SELECT id, ip_address, user_agent, last_activity_at, created_at
            FROM user_sessions
            WHERE user_id = $1 AND expires_at > NOW()
            ORDER BY last_activity_at DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(user_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(self.db.pool())
        .await?;

        let items = rows
            .into_iter()
            .map(|r| SessionInfo {
                id: r.id,
                ip_address: r.ip_address,
                user_agent: r.user_agent,
                last_activity_at: r.last_activity_at,
                created_at: r.created_at,
                is_current: r.id == current_session_id,
            })
            .collect();
        Ok((items, total as u64))
    }

    /// Delete a specific session
    #[tracing::instrument(skip_all)]
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
struct ApiKeyRow {
    id: Uuid,
    name: String,
    key_prefix: String,
    scopes: serde_json::Value,
    last_used_at: Option<chrono::DateTime<Utc>>,
    expires_at: Option<chrono::DateTime<Utc>>,
    is_active: bool,
    created_at: chrono::DateTime<Utc>,
}

#[cfg(feature = "server")]
impl From<ApiKeyRow> for crate::modules::auth::models::ApiKeyResponse {
    fn from(row: ApiKeyRow) -> Self {
        // Stored as JSONB; tolerate either ["scope1", ...] or other
        // shapes by falling back to `["*"]` rather than 500ing on a
        // hand-edited DB.
        let scopes = match row.scopes {
            serde_json::Value::Array(arr) => arr
                .into_iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect(),
            _ => vec!["*".to_string()],
        };
        Self {
            id: row.id,
            name: row.name,
            key_prefix: row.key_prefix,
            scopes,
            last_used_at: row.last_used_at,
            expires_at: row.expires_at,
            is_active: row.is_active,
            created_at: row.created_at,
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

/// Split a user-bound credential token of the form `{user_id}.{secret}` into
/// its parts. Returns None if the shape is wrong or either half is empty. Lets
/// password-reset / welcome-setup verification scope its lookup to the user the
/// token was minted for instead of grabbing any user's token.
#[cfg(feature = "server")]
fn parse_user_bound_token(token: &str) -> Option<(Uuid, &str)> {
    let (id, secret) = token.split_once('.')?;
    if secret.is_empty() {
        return None;
    }
    let user_id = Uuid::parse_str(id).ok()?;
    Some((user_id, secret))
}

/// Case-insensitive exact-match against an email allowlist. Allowlist entries
/// are expected already lowercased (config parsing lowercases them); the
/// candidate is lowercased here for safety.
#[cfg(feature = "server")]
fn is_allowlisted_email(allowlist: &[String], email: &str) -> bool {
    let email = email.to_ascii_lowercase();
    allowlist.iter().any(|e| e == &email)
}

/// Build a placeholder `(first_name, last_name)` from an email for JIT
/// inserts. The OIDC at+jwt has no name claims so the local row needs a
/// default for the NOT NULL schema columns. Splits the local-part on
/// `.`, `_`, or `-` and title-cases the first two segments; the user is
/// expected to overwrite this later from Settings.
///
/// `(first, last)` falls back to `("User", "")` when the email is
/// shaped like `…@unresolved.invalid` or otherwise has no usable local
/// part. Empty strings are still valid VARCHAR values for NOT NULL
/// columns, so the insert always succeeds.
#[cfg(feature = "server")]
fn synthetic_name_from_email(email: &str) -> (String, String) {
    let local = email.split_once('@').map(|(l, _)| l).unwrap_or(email);
    let parts: Vec<&str> = local
        .split(['.', '_', '-'])
        .filter(|p| !p.is_empty())
        .collect();
    let titlecase = |s: &str| {
        let mut chars = s.chars();
        match chars.next() {
            Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
            None => String::new(),
        }
    };
    match parts.as_slice() {
        [] => ("User".to_string(), String::new()),
        [one] => (titlecase(one), String::new()),
        [one, two, ..] => (titlecase(one), titlecase(two)),
    }
}

#[cfg(all(test, feature = "server"))]
mod tests {
    use super::*;

    #[test]
    fn parse_user_bound_token_splits_valid() {
        let uid = Uuid::new_v4();
        let token = format!("{uid}.secretpart");
        let (got, secret) = parse_user_bound_token(&token).expect("valid token parses");
        assert_eq!(got, uid);
        assert_eq!(secret, "secretpart");
    }

    #[test]
    fn parse_user_bound_token_rejects_bad_shapes() {
        assert!(parse_user_bound_token("no-dot-here").is_none());
        assert!(parse_user_bound_token("not-a-uuid.secret").is_none());
        let uid = Uuid::new_v4();
        assert!(
            parse_user_bound_token(&format!("{uid}.")).is_none(),
            "empty secret rejected"
        );
    }

    #[test]
    fn parse_user_bound_token_keeps_dots_in_secret() {
        // split_once stops at the first '.', so a dotted secret stays intact.
        let uid = Uuid::new_v4();
        let token = format!("{uid}.a.b.c");
        let (_, secret) = parse_user_bound_token(&token).unwrap();
        assert_eq!(secret, "a.b.c");
    }

    #[test]
    fn allowlist_matches_case_insensitively() {
        let allow = vec!["admin@niceguyit.biz".to_string()];
        assert!(is_allowlisted_email(&allow, "Admin@NiceGuyIT.biz"));
        assert!(!is_allowlisted_email(&allow, "other@niceguyit.biz"));
        assert!(
            !is_allowlisted_email(&[], "admin@niceguyit.biz"),
            "empty allowlist matches nothing"
        );
    }
}
