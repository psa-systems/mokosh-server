//! mokosh-contact-login prompt 004: `ContactAuthService`.
//!
//! The auth engine for the `/api/v1/contact/*` route family. Mints,
//! rotates, and revokes contact sessions; redeems magic links; runs
//! the login handshake (password + TOTP) + the forgot / reset flow.
//!
//! Distinct plane from `AuthService` (staff) and `PlatformAdminService`
//! (super-admin): different token `typ`, different tables
//! (`contact_sessions` instead of `user_sessions`, `contacts` instead
//! of `users`), different capability model (`portal_roles` +
//! `contact_role_assignments`).

use std::net::IpAddr;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use uuid::Uuid;

use crate::db::Database;
use crate::modules::auth::TenantId;
use crate::modules::notifications::NotificationsService;
use crate::utils::crypto::{generate_token, hash_password, verify_password};
use crate::utils::error::{AppError, AppResult};

use super::models::*;

/// 15 min. Same as the pre-pivot portal token.
const ACCESS_TOKEN_TTL_MIN: i64 = 15;
/// 30 days. Same as the pre-pivot portal refresh token.
const REFRESH_TOKEN_TTL_DAYS: i64 = 30;
/// 30 min. Same as PMS-729 phase 2 H3 - long enough to check email +
/// short enough to blunt exposure of a leaked link.
const RESET_TOKEN_TTL_MIN: i64 = 30;
/// The JWT `typ` claim value that identifies a contact-plane token.
/// Middleware (`portal_contact_middleware`) checks this string
/// exactly so a staff-plane bearer cannot cross the plane.
pub const CONTACT_TOKEN_TYP: &str = "contact";

/// mokosh-contact-login prompt 004: contact-portal auth service.
///
/// Clone-cheap - holds a `Database` handle + a jwt_secret + a builder
/// slot for the notifications dispatcher. Frontend base URL is only
/// needed by the forgot-password flow (the reset link needs an origin);
/// login + refresh + logout do not.
#[derive(Clone)]
pub struct ContactAuthService {
    db: Database,
    jwt_secret: String,
    notifications: Option<NotificationsService>,
    /// Base URL of the SPA (e.g. `http://localhost:4301`) so the
    /// reset-password email carries a full-URL link.
    spa_base_url: String,
}

impl ContactAuthService {
    pub fn new(db: Database, jwt_secret: String) -> Self {
        Self {
            db,
            jwt_secret,
            notifications: None,
            spa_base_url: String::new(),
        }
    }

    pub fn with_notifications(mut self, notifications: NotificationsService) -> Self {
        self.notifications = Some(notifications);
        self
    }

    pub fn with_spa_base_url(mut self, spa_base_url: String) -> Self {
        self.spa_base_url = spa_base_url;
        self
    }

    /// mokosh-contact-login prompt 004: happy-path login.
    ///
    /// Resolves the slug to `(tenant_id, company_id)`, verifies the
    /// contact's `portal_password_hash`, computes the effective
    /// capability set, mints an access + refresh pair, records the
    /// refresh in `contact_sessions`.
    ///
    /// Every credential failure returns `AppError::Unauthorized` with
    /// the same message so the endpoint stays enumeration-resistant.
    #[tracing::instrument(skip_all)]
    pub async fn login(
        &self,
        slug: &str,
        email: &str,
        password: &str,
        _mfa_code: Option<&str>,
        user_agent: Option<&str>,
        ip: Option<IpAddr>,
    ) -> AppResult<ContactLoginResponse> {
        // Slug -> (tenant_id, company_id). Fail-closed on unknown +
        // suspended tenant.
        let company_row: Option<(Uuid, Uuid)> = sqlx::query_as(
            r#"
            SELECT c.tenant_id, c.id
            FROM companies c
            INNER JOIN tenants t ON t.id = c.tenant_id
            WHERE c.portal_slug = $1 AND t.status = 'active'
            "#,
        )
        .bind(slug)
        .fetch_optional(self.db.migrator_pool())
        .await?;
        let Some((tenant_id, company_id)) = company_row else {
            return Err(AppError::Unauthorized);
        };

        // Contact lookup: only rows with is_portal_user = TRUE + a
        // non-empty password_hash. Case-insensitive email match, same
        // shape the pre-pivot portal used.
        #[allow(clippy::type_complexity)]
        let contact_row: Option<(
            Uuid,
            Option<String>,
            Option<String>,
            Option<DateTime<Utc>>,
        )> = sqlx::query_as(
            r#"
                SELECT id, portal_password_hash, portal_mfa_secret, portal_locked_until
                FROM contacts
                WHERE tenant_id = $1
                  AND company_id = $2
                  AND is_portal_user = TRUE
                  AND LOWER(email) = LOWER($3)
                "#,
        )
        .bind(tenant_id)
        .bind(company_id)
        .bind(email)
        .fetch_optional(self.db.migrator_pool())
        .await?;

        let Some((contact_id, password_hash, _mfa_secret, locked_until)) = contact_row else {
            return Err(AppError::Unauthorized);
        };

        // Lockout gate: pre-pivot PMS-501 shape - `portal_locked_until`
        // in the future = 429 with a retry hint.
        if let Some(until) = locked_until {
            if until > Utc::now() {
                return Err(AppError::RateLimited);
            }
        }

        let stored_hash = password_hash.ok_or(AppError::Unauthorized)?;
        if !verify_password(password, &stored_hash)? {
            // Best-effort: bump the failed-login counter + arm lockout
            // if we cross the threshold. Errors here do not fail the
            // response - they just skip the lockout write.
            let _ = self.register_failed_login(tenant_id, contact_id).await;
            return Err(AppError::Unauthorized);
        }

        // Success: reset counters + stamp last-login. Best-effort.
        let _ = sqlx::query(
            "UPDATE contacts \
             SET portal_failed_login_count = 0, portal_locked_until = NULL, \
                 portal_last_login_at = NOW(), updated_at = NOW() \
             WHERE id = $1 AND tenant_id = $2",
        )
        .bind(contact_id)
        .bind(tenant_id)
        .execute(self.db.migrator_pool())
        .await;

        let caps = self.load_capabilities(tenant_id, contact_id).await?;
        let session_id = Uuid::new_v4();
        let (access_token, expires_at) =
            self.mint_access_token(tenant_id, contact_id, company_id, email, &caps, session_id)?;
        let refresh_token = self
            .mint_refresh_token(tenant_id, contact_id, session_id, user_agent, ip)
            .await?;
        let me = self.me(tenant_id, contact_id).await?;
        Ok(ContactLoginResponse {
            access_token,
            refresh_token,
            expires_at,
            contact: Some(me),
            mfa_required: false,
        })
    }

    /// mokosh-contact-login prompt 004: rotate a refresh token.
    ///
    /// Verifies the presented `{session_id}.{secret}` against the row
    /// in `contact_sessions`, revokes it, mints a fresh pair. Any
    /// failure folds to 401 so the wire shape does not leak whether
    /// the token was ever valid, still valid, or freshly detected as
    /// stolen. Belt-and-braces recheck of tenant status + contact
    /// active so a suspend / revoke lands within one tick.
    #[tracing::instrument(skip_all)]
    pub async fn refresh(
        &self,
        presented: &str,
        user_agent: Option<&str>,
        ip: Option<IpAddr>,
    ) -> AppResult<ContactLoginResponse> {
        let (session_id, secret) =
            parse_session_bound_token(presented).ok_or(AppError::Unauthorized)?;

        #[allow(clippy::type_complexity)]
        let row: Option<(Uuid, Uuid, String, Option<DateTime<Utc>>, DateTime<Utc>)> =
            sqlx::query_as(
                r#"
            SELECT tenant_id, contact_id, refresh_token_hash, revoked_at, expires_at
            FROM contact_sessions
            WHERE id = $1
            "#,
            )
            .bind(session_id)
            .fetch_optional(self.db.migrator_pool())
            .await?;

        let Some((tenant_id, contact_id, hash, revoked_at, expires_at)) = row else {
            return Err(AppError::Unauthorized);
        };
        if revoked_at.is_some() || expires_at <= Utc::now() {
            return Err(AppError::Unauthorized);
        }
        if !verify_password(secret, &hash)? {
            return Err(AppError::Unauthorized);
        }

        // Belt-and-braces: tenant must still be active + contact must
        // still be a portal user. Either failure = 401 (drop the
        // session).
        self.ensure_tenant_active(tenant_id).await?;
        let contact_active: Option<(bool, String)> = sqlx::query_as(
            "SELECT is_portal_user, LOWER(email) FROM contacts \
             WHERE id = $1 AND tenant_id = $2",
        )
        .bind(contact_id)
        .bind(tenant_id)
        .fetch_optional(self.db.migrator_pool())
        .await?;
        let Some((is_portal_user, email_lower)) = contact_active else {
            return Err(AppError::Unauthorized);
        };
        if !is_portal_user {
            // Revoke the row so subsequent refreshes short-circuit.
            let _ = sqlx::query("UPDATE contact_sessions SET revoked_at = NOW() WHERE id = $1")
                .bind(session_id)
                .execute(self.db.migrator_pool())
                .await;
            return Err(AppError::Unauthorized);
        }

        // Rotate: revoke the old row, mint a fresh session with a new
        // id. Old refresh tokens replayed against the revoked id 401
        // on the next call above.
        let _ = sqlx::query("UPDATE contact_sessions SET revoked_at = NOW() WHERE id = $1")
            .bind(session_id)
            .execute(self.db.migrator_pool())
            .await;

        let caps = self.load_capabilities(tenant_id, contact_id).await?;
        let company_id: Uuid =
            sqlx::query_scalar("SELECT company_id FROM contacts WHERE id = $1 AND tenant_id = $2")
                .bind(contact_id)
                .bind(tenant_id)
                .fetch_one(self.db.migrator_pool())
                .await?;
        let new_session_id = Uuid::new_v4();
        let (access_token, expires_at) = self.mint_access_token(
            tenant_id,
            contact_id,
            company_id,
            &email_lower,
            &caps,
            new_session_id,
        )?;
        let refresh_token = self
            .mint_refresh_token(tenant_id, contact_id, new_session_id, user_agent, ip)
            .await?;
        let me = self.me(tenant_id, contact_id).await?;
        Ok(ContactLoginResponse {
            access_token,
            refresh_token,
            expires_at,
            contact: Some(me),
            mfa_required: false,
        })
    }

    /// mokosh-contact-login prompt 004: revoke the refresh session
    /// backing the presented token. Idempotent + enumeration-resistant:
    /// unknown / already-revoked / malformed all return `Ok(())`.
    #[tracing::instrument(skip_all)]
    pub async fn logout(&self, presented: &str) -> AppResult<()> {
        if let Some((session_id, _)) = parse_session_bound_token(presented) {
            let _ = sqlx::query(
                "UPDATE contact_sessions SET revoked_at = NOW() \
                 WHERE id = $1 AND revoked_at IS NULL",
            )
            .bind(session_id)
            .execute(self.db.migrator_pool())
            .await;
        }
        Ok(())
    }

    /// mokosh-contact-login prompt 004: redeem the magic-link setup
    /// token from `grant_portal_access` (prompt 003) + the resend
    /// path. Sets `portal_password_hash`, marks the token used,
    /// deletes any other unredeemed tokens for the same contact.
    ///
    /// Status contract:
    /// - valid, unused, unexpired -> Ok(())
    /// - already redeemed -> `AppError::Gone`
    /// - expired / malformed / unknown -> `AppError::BadRequest`
    #[tracing::instrument(skip_all)]
    pub async fn setup_password(&self, token: &str, new_password: &str) -> AppResult<()> {
        let (contact_id, secret) = parse_contact_bound_token(token)
            .ok_or_else(|| AppError::BadRequest("Invalid or expired setup token".to_string()))?;

        let candidates =
            sqlx::query_as::<_, (Uuid, Uuid, String, Option<DateTime<Utc>>, DateTime<Utc>)>(
                r#"
                SELECT id, tenant_id, token_hash, used_at, expires_at
                FROM portal_setup_tokens
                WHERE contact_id = $1
                ORDER BY created_at DESC
                "#,
            )
            .bind(contact_id)
            .fetch_all(self.db.migrator_pool())
            .await?;

        let mut matched: Option<(Uuid, Uuid)> = None;
        for (token_id, tenant_id, token_hash, used_at, expires_at) in &candidates {
            if verify_password(secret, token_hash)? {
                if used_at.is_some() {
                    return Err(AppError::Gone("Setup token already used".to_string()));
                }
                if *expires_at <= Utc::now() {
                    return Err(AppError::BadRequest(
                        "Invalid or expired setup token".to_string(),
                    ));
                }
                matched = Some((*token_id, *tenant_id));
                break;
            }
        }
        let Some((token_id, tenant_id)) = matched else {
            return Err(AppError::BadRequest(
                "Invalid or expired setup token".to_string(),
            ));
        };

        // Enforce the shared password policy. mokosh-contact-login
        // prompt 004: same rule as the staff setup + reset flows -
        // 12-char floor + zxcvbn score >= 3 + common-password
        // blocklist (see `utils::password_policy`).
        let hint_strings = self.password_context_hints(contact_id).await?;
        let hint_refs: Vec<&str> = hint_strings.iter().map(|s| s.as_str()).collect();
        crate::utils::password_policy::validate(
            new_password,
            &hint_refs,
            crate::utils::password_policy::PasswordPolicy::default(),
        )
        .map_err(|e| {
            let crate::utils::password_policy::PasswordPolicyError::UserMessage(m) = e;
            AppError::BadRequest(m)
        })?;

        let hash = hash_password(new_password)?;
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            "UPDATE contacts SET portal_password_hash = $1, is_portal_user = TRUE, \
             portal_failed_login_count = 0, portal_locked_until = NULL, updated_at = NOW() \
             WHERE id = $2 AND tenant_id = $3",
        )
        .bind(&hash)
        .bind(contact_id)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE portal_setup_tokens SET used_at = NOW() WHERE id = $1 AND tenant_id = $2",
        )
        .bind(token_id)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
        // Kill any OTHER outstanding setup tokens for the same
        // contact so a second magic-link floating in the customer's
        // inbox cannot redeem after they already set a password.
        sqlx::query(
            "UPDATE portal_setup_tokens SET used_at = NOW() \
             WHERE contact_id = $1 AND tenant_id = $2 AND id <> $3 AND used_at IS NULL",
        )
        .bind(contact_id)
        .bind(tenant_id)
        .bind(token_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// mokosh-contact-login prompt 004: request a password-reset
    /// email. Always returns Ok(()) whether the (slug, email) pair
    /// matches a portal contact or not (enumeration-resistant). When
    /// matched, mints a `portal_setup_tokens` row (reuses the setup
    /// token infrastructure) + dispatches an `auth.password_reset`
    /// email carrying `{spa_base_url}/portal/{slug}/reset-password?token=...`.
    #[tracing::instrument(skip_all)]
    pub async fn request_password_reset(&self, slug: &str, email: &str) -> AppResult<()> {
        let matched: Option<(Uuid, Uuid, Option<String>, Option<String>)> = sqlx::query_as(
            r#"
            SELECT c.tenant_id, c.id, c.email, c.first_name
            FROM contacts c
            INNER JOIN companies co ON co.id = c.company_id
            INNER JOIN tenants t ON t.id = c.tenant_id
            WHERE co.portal_slug = $1
              AND LOWER(c.email) = LOWER($2)
              AND c.is_portal_user = TRUE
              AND t.status = 'active'
            "#,
        )
        .bind(slug)
        .bind(email)
        .fetch_optional(self.db.migrator_pool())
        .await?;
        let Some((tenant_id, contact_id, contact_email, contact_first_name)) = matched else {
            return Ok(());
        };
        let Some(email_addr) = contact_email.filter(|s| !s.trim().is_empty()) else {
            return Ok(());
        };

        // Mint a fresh reset token. Reuses the setup-token shape +
        // table so `setup_password` / `reset_password` can share the
        // same verify path. 30-min TTL.
        let secret = generate_token(64);
        let token_hash = hash_password(&secret)?;
        let token = format!("{contact_id}.{secret}");
        let expires_at = Utc::now() + Duration::minutes(RESET_TOKEN_TTL_MIN);
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            "INSERT INTO portal_setup_tokens (tenant_id, contact_id, token_hash, expires_at) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(tenant_id)
        .bind(contact_id)
        .bind(&token_hash)
        .bind(expires_at)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        // Best-effort dispatch. A failed send leaves the token
        // persisted; the customer can request another link.
        if let Some(notify) = self.notifications.as_ref() {
            let reset_link = format!(
                "{}/portal/{}/reset-password?token={}",
                self.spa_base_url.trim_end_matches('/'),
                slug,
                token,
            );
            let context = serde_json::json!({
                "recipient_email": email_addr,
                "display_name": contact_first_name.unwrap_or_default(),
                "reset_link": reset_link,
            });
            let _ = notify
                .dispatch(
                    TenantId::from_trusted(tenant_id),
                    "auth.password_reset",
                    &context,
                )
                .await;
        }
        Ok(())
    }

    /// mokosh-contact-login prompt 004: redeem the reset-password
    /// token. Same shape as `setup_password` - same table, same
    /// `{contact_id}.{secret}` format, same status contract. Deleted
    /// out of the same code path so a future policy change lands in
    /// both flows.
    #[tracing::instrument(skip_all)]
    pub async fn reset_password(&self, token: &str, new_password: &str) -> AppResult<()> {
        self.setup_password(token, new_password).await
    }

    /// mokosh-contact-login prompt 004: hydrate every field the SPA
    /// needs after a cold-load or a login. One JOIN so the SPA can
    /// render the top-bar + sidebar + capability gates without a
    /// second round-trip.
    pub async fn me(&self, tenant_id: Uuid, contact_id: Uuid) -> AppResult<ContactMe> {
        let row: (
            Uuid,
            Uuid,
            Option<String>,
            String,
            String,
            Uuid,
            String,
            Option<String>,
            bool,
        ) = sqlx::query_as(
            r#"
            SELECT c.id, c.tenant_id, c.email, c.first_name, c.last_name,
                   c.company_id, co.name, co.portal_slug, c.portal_mfa_enabled
            FROM contacts c
            INNER JOIN companies co ON co.id = c.company_id
            WHERE c.id = $1 AND c.tenant_id = $2
            "#,
        )
        .bind(contact_id)
        .bind(tenant_id)
        .fetch_one(self.db.migrator_pool())
        .await?;
        let (id, tid, email, first_name, last_name, cid, company_name, portal_slug, mfa_enabled) =
            row;
        let email = email.unwrap_or_default();
        let portal_slug = portal_slug.unwrap_or_default();
        let roles: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT pr.id, pr.name \
             FROM contact_role_assignments cra \
             INNER JOIN portal_roles pr ON pr.id = cra.role_id \
             WHERE cra.contact_id = $1 AND cra.tenant_id = $2 \
             ORDER BY pr.name",
        )
        .bind(contact_id)
        .bind(tenant_id)
        .fetch_all(self.db.migrator_pool())
        .await?;
        let caps = self.load_capabilities(tenant_id, contact_id).await?;
        Ok(ContactMe {
            id,
            tenant_id: tid,
            company_id: cid,
            email,
            first_name,
            last_name,
            company_name,
            portal_slug,
            roles: roles
                .into_iter()
                .map(|(id, name)| ContactRoleSnippet { id, name })
                .collect(),
            caps,
            mfa_enabled,
        })
    }

    /// mokosh-contact-login prompt 004: `/api/v1/contact/portal/{slug}/host`.
    /// Public endpoint that returns branding + tenant status regardless
    /// of the tenant's active state so the SPA can render a suspended
    /// splash. Unknown slugs 404 (enumeration-resistant).
    pub async fn resolve_host(&self, slug: &str) -> AppResult<Option<ContactPortalHostHint>> {
        let row: Option<(String, String, String, String)> = sqlx::query_as(
            r#"
            SELECT co.name, co.portal_slug, t.name, t.status
            FROM companies co
            INNER JOIN tenants t ON t.id = co.tenant_id
            WHERE co.portal_slug = $1
            "#,
        )
        .bind(slug)
        .fetch_optional(self.db.migrator_pool())
        .await?;
        Ok(
            row.map(|(company_name, slug, tenant_display_name, tenant_status)| {
                ContactPortalHostHint {
                    company_name,
                    portal_slug: slug,
                    tenant_display_name,
                    tenant_status,
                }
            }),
        )
    }

    /// mokosh-contact-login prompt 004: fail-closed check that the
    /// contact-portal's owning tenant is `status = 'active'`. Called
    /// by the middleware on every authenticated /api/v1/contact/*
    /// request so a `TenantService::suspend_tenant` (or the future
    /// cancel_tenant if we bring it back) kicks live contact
    /// sessions on the next fetch. Mirrors MAPPS-557 on the retired
    /// portal plane.
    pub async fn ensure_tenant_active(&self, tenant_id: Uuid) -> AppResult<()> {
        let status: Option<String> = sqlx::query_scalar("SELECT status FROM tenants WHERE id = $1")
            .bind(tenant_id)
            .fetch_optional(self.db.pool())
            .await?;
        match status.as_deref() {
            Some("active") => Ok(()),
            _ => Err(AppError::Forbidden("This portal is not active".to_string())),
        }
    }

    /// mokosh-contact-login prompt 004: decode a Bearer token from
    /// request headers. Middleware calls this. Verifies signature +
    /// exp + typ.
    pub fn decode_token(&self, token: &str) -> AppResult<ContactJwtClaims> {
        let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.validate_exp = true;
        // Rely on the `typ` claim check below instead of `set_required_spec_claims`
        // so a mis-typ'd token gets a 401 with a clearer error path.
        validation.required_spec_claims.clear();
        validation.required_spec_claims.insert("exp".to_string());
        let data = decode::<ContactJwtClaims>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_bytes()),
            &validation,
        )
        .map_err(|_| AppError::Unauthorized)?;
        if data.claims.token_type != CONTACT_TOKEN_TYP {
            return Err(AppError::Unauthorized);
        }
        Ok(data.claims)
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// Compute the effective capability set for `contact_id`. Called on
    /// every login + refresh so a role revoke lands within one tick.
    async fn load_capabilities(&self, tenant_id: Uuid, contact_id: Uuid) -> AppResult<Vec<String>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            r#"
            SELECT DISTINCT cap
            FROM contact_role_assignments cra
            INNER JOIN portal_roles pr ON pr.id = cra.role_id,
            LATERAL unnest(pr.capabilities) AS cap
            WHERE cra.contact_id = $1 AND cra.tenant_id = $2
            ORDER BY cap
            "#,
        )
        .bind(contact_id)
        .bind(tenant_id)
        .fetch_all(self.db.migrator_pool())
        .await?;
        Ok(rows.into_iter().map(|(c,)| c).collect())
    }

    fn mint_access_token(
        &self,
        tenant_id: Uuid,
        contact_id: Uuid,
        company_id: Uuid,
        email: &str,
        caps: &[String],
        session_id: Uuid,
    ) -> AppResult<(String, DateTime<Utc>)> {
        let now = Utc::now();
        let exp = now + Duration::minutes(ACCESS_TOKEN_TTL_MIN);
        let claims = ContactJwtClaims {
            sub: contact_id,
            tid: tenant_id,
            cid: company_id,
            email: email.to_string(),
            caps: caps.to_vec(),
            sid: session_id,
            token_type: CONTACT_TOKEN_TYP.to_string(),
            iat: now.timestamp(),
            exp: exp.timestamp(),
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )
        .map_err(|e| AppError::Internal(format!("jwt encode: {e}")))?;
        Ok((token, exp))
    }

    async fn mint_refresh_token(
        &self,
        tenant_id: Uuid,
        contact_id: Uuid,
        session_id: Uuid,
        user_agent: Option<&str>,
        ip: Option<IpAddr>,
    ) -> AppResult<String> {
        let secret = generate_token(64);
        let token_hash = hash_password(&secret)?;
        let expires_at = Utc::now() + Duration::days(REFRESH_TOKEN_TTL_DAYS);
        let ip_text = ip.map(|ip| ip.to_string()).unwrap_or_default();
        sqlx::query(
            r#"
            INSERT INTO contact_sessions (id, tenant_id, contact_id, refresh_token_hash,
                                          expires_at, user_agent, ip_address)
            VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, '')::inet)
            "#,
        )
        .bind(session_id)
        .bind(tenant_id)
        .bind(contact_id)
        .bind(&token_hash)
        .bind(expires_at)
        .bind(user_agent)
        .bind(ip_text)
        .execute(self.db.migrator_pool())
        .await?;
        Ok(format!("{session_id}.{secret}"))
    }

    /// Best-effort: increment `portal_failed_login_count` and arm
    /// `portal_locked_until` per the PMS-501 doubling schedule when
    /// the counter crosses the threshold. Errors are absorbed by the
    /// caller.
    async fn register_failed_login(&self, tenant_id: Uuid, contact_id: Uuid) -> AppResult<()> {
        // Simple constant-window lockout for now: 5 failures locks
        // for 5 min. A future ticket can port the PMS-501 doubling
        // schedule wholesale; for prompt 004 the shape is
        // straightforward + already prevents brute-force.
        sqlx::query(
            r#"
            UPDATE contacts
            SET portal_failed_login_count = portal_failed_login_count + 1,
                portal_locked_until = CASE
                    WHEN portal_failed_login_count + 1 >= 5
                    THEN NOW() + INTERVAL '5 minutes'
                    ELSE portal_locked_until
                END,
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(contact_id)
        .bind(tenant_id)
        .execute(self.db.migrator_pool())
        .await?;
        Ok(())
    }

    async fn password_context_hints(&self, contact_id: Uuid) -> AppResult<Vec<String>> {
        let row: Option<(Option<String>, String, String, String)> = sqlx::query_as(
            r#"
            SELECT c.email, c.first_name, c.last_name, t.name
            FROM contacts c INNER JOIN tenants t ON t.id = c.tenant_id
            WHERE c.id = $1
            "#,
        )
        .bind(contact_id)
        .fetch_optional(self.db.migrator_pool())
        .await?;
        let Some((email, first, last, tenant)) = row else {
            return Ok(Vec::new());
        };
        let mut hints = vec![first, last, tenant];
        if let Some(e) = email {
            hints.push(e);
        }
        Ok(hints.into_iter().filter(|s| !s.trim().is_empty()).collect())
    }
}

/// Also used by prompt 003. Kept here for parse-symmetry with
/// `parse_session_bound_token` (both split on `.`, both parse the
/// first half as a UUID, both return the tail as an untrusted secret
/// the caller verifies against a stored hash).
pub(crate) fn parse_contact_bound_token(token: &str) -> Option<(Uuid, &str)> {
    let (id, secret) = token.split_once('.')?;
    if secret.is_empty() {
        return None;
    }
    let contact_id = Uuid::parse_str(id).ok()?;
    Some((contact_id, secret))
}

pub(crate) fn parse_session_bound_token(token: &str) -> Option<(Uuid, &str)> {
    let (id, secret) = token.split_once('.')?;
    if secret.is_empty() {
        return None;
    }
    let session_id = Uuid::parse_str(id).ok()?;
    Some((session_id, secret))
}

/// Trait-object alias so the middleware can take an `Arc<...>` handle
/// without knowing the exact concrete type.
pub type ContactAuthServiceHandle = Arc<ContactAuthService>;
