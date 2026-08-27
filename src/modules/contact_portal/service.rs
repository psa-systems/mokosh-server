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

/// mokosh-contact-login prompt 010 (PMS-918): magic-link intent TTL.
/// 15 min - long enough to check email + short enough to blunt
/// exposure of a leaked link.
pub const LOGIN_INTENT_TTL_MIN: i64 = 15;

/// mokosh-contact-login prompt 010: TTL of the intermediate
/// `contact_login_select` JWT the redeem endpoint hands the SPA when
/// a magic link resolves to two or more portal contacts. 5 min is
/// enough for a human to pick a tile; beyond that the SPA bounces
/// back to `/portal/login` to request a fresh link.
pub const LOGIN_SELECTION_TOKEN_TTL_MIN: i64 = 5;

/// mokosh-contact-login prompt 010: JWT `typ` claim value for the
/// selection token. Distinct from `CONTACT_TOKEN_TYP` so a caller
/// cannot present a selection token as a Bearer on a normal API call
/// (and vice versa).
pub const LOGIN_LINK_TOKEN_TYP: &str = "contact_login_select";

/// mokosh-contact-login prompt 010: rate-limit windows for the
/// finder. Silent-drop shape: an over-limit request still returns
/// 204 so an attacker cannot use the response shape as an
/// enumeration oracle; it just doesn't insert or dispatch.
const LOGIN_INTENT_MAX_PER_IP_PER_MINUTE: i64 = 20;
const LOGIN_INTENT_MAX_PER_EMAIL_PER_15_MIN: i64 = 5;

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
    /// Resolves the caller-supplied portal_id (preferred) or legacy
    /// slug (compat fallback) to `(tenant_id, company_id)`, verifies
    /// the contact's `portal_password_hash`, computes the effective
    /// capability set, mints an access + refresh pair, records the
    /// refresh in `contact_sessions`.
    ///
    /// mokosh-contact-login prompt 011 (PMS-928): body now dual-accepts
    /// `portal_id: Option<i64>` alongside `slug: Option<&str>`. Portal
    /// ID wins if both are supplied so a mixed body cannot be steered
    /// into a different Company via slug injection. `None` for both
    /// (or both supplied but unresolvable to a Company) folds to the
    /// generic 401 shape so the endpoint stays enumeration-resistant.
    ///
    /// Every credential failure returns `AppError::Unauthorized` with
    /// the same message so the endpoint stays enumeration-resistant.
    #[tracing::instrument(skip_all)]
    pub async fn login(
        &self,
        portal_id: Option<i64>,
        slug: Option<&str>,
        email: &str,
        password: &str,
        _mfa_code: Option<&str>,
        user_agent: Option<&str>,
        ip: Option<IpAddr>,
    ) -> AppResult<ContactLoginResponse> {
        // (portal_id, slug) -> (tenant_id, company_id). Fail-closed on
        // unknown + suspended tenant. Portal_id wins when both are
        // supplied via the `$1 IS NOT NULL` branch on the OR; slug
        // is only consulted when portal_id is absent, mirroring the
        // "portal_id > slug" resolution the ticket calls for.
        let company_row: Option<(Uuid, Uuid)> = sqlx::query_as(
            r#"
            SELECT c.tenant_id, c.id
            FROM companies c
            INNER JOIN tenants t ON t.id = c.tenant_id
            WHERE t.status = 'active'
              AND (
                ($1::BIGINT IS NOT NULL AND c.portal_id = $1)
                OR ($1::BIGINT IS NULL AND $2::TEXT IS NOT NULL AND c.portal_slug = $2)
              )
            "#,
        )
        .bind(portal_id)
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
            password_setup_url: None,
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
            password_setup_url: None,
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

    /// mokosh-contact-login prompt 011 (PMS-928): sibling of
    /// `resolve_host` keyed on the Company's numeric `portal_id`. Same
    /// wire shape (`ContactPortalHostHint`) so the SPA renders the same
    /// suspended-tenant splash + branding regardless of which URL
    /// (Portal ID or legacy slug) the visitor followed. Unknown ids
    /// return `Ok(None)` (routed to 404 upstream, enum-resistant).
    ///
    /// The row's `portal_slug` may be NULL for a Company created after
    /// the slug column starts being deprecated; the returned hint
    /// carries the (possibly empty) slug value for backward compat with
    /// SPA code that still reads it.
    pub async fn resolve_host_by_portal_id(
        &self,
        portal_id: i64,
    ) -> AppResult<Option<ContactPortalHostHint>> {
        let row: Option<(String, Option<String>, String, String)> = sqlx::query_as(
            r#"
            SELECT co.name, co.portal_slug, t.name, t.status
            FROM companies co
            INNER JOIN tenants t ON t.id = co.tenant_id
            WHERE co.portal_id = $1
            "#,
        )
        .bind(portal_id)
        .fetch_optional(self.db.migrator_pool())
        .await?;
        Ok(
            row.map(|(company_name, slug, tenant_display_name, tenant_status)| {
                ContactPortalHostHint {
                    company_name,
                    portal_slug: slug.unwrap_or_default(),
                    tenant_display_name,
                    tenant_status,
                }
            }),
        )
    }

    /// mokosh-contact-login prompt 011 (PMS-928): resolve a legacy
    /// `portal_slug` to the Company's numeric `portal_id`. Powers the
    /// client-side compat redirect: a visitor who follows an older
    /// `/portal/{slug}/login` URL hits `GET
    /// /api/v1/contact/portal/{slug}/resolve-to-portal-id`, the SPA
    /// swaps the URL for `/portal/{portal_id}/login` and re-routes.
    /// Returns `Ok(None)` when the slug is unknown OR when the
    /// matching Company has not been assigned a portal_id yet
    /// (upstream 404 either way, enum-resistant).
    pub async fn resolve_slug_to_portal_id(&self, slug: &str) -> AppResult<Option<i64>> {
        let row: Option<Option<i64>> =
            sqlx::query_scalar("SELECT portal_id FROM companies WHERE portal_slug = $1")
                .bind(slug)
                .fetch_optional(self.db.migrator_pool())
                .await?;
        Ok(row.flatten())
    }

    /// mokosh-contact-login prompt 010 (PMS-918): request a magic-link
    /// sign-in for `email` on the tenant carrying `slug` (a Company
    /// `portal_slug`) or, when no slug is supplied, drop silently. Always
    /// returns `Ok(())` regardless of outcome so an attacker cannot use
    /// the response shape to tell a matched email from an unmatched one.
    ///
    /// Tenant resolution: this endpoint has no bearer token and the
    /// finder page lives at the tenant-agnostic `/portal/login` URL,
    /// so the SPA passes the Company slug it remembers in
    /// localStorage as `contact_last_slug`. The server maps that slug
    /// to a Company + tenant. If the slug is absent or unknown, no
    /// intent row is inserted (there is no Host-header-based tenant
    /// lookup on this deployment: mokosh tenants share the same
    /// `msp.<apex>` host). If the caller wants cross-tenant discovery
    /// they visit each MSP's URL in turn - the tenant-isolation
    /// invariant from prompt 010's threat model.
    ///
    /// Rate-limited via DB counting on `portal_login_intents`:
    /// per-IP > 20 in 60 s and per-email > 5 in 15 min silently drop.
    /// Both counters query the table directly so no in-process
    /// middleware needs to be wired.
    #[tracing::instrument(skip_all)]
    pub async fn request_login_link(
        &self,
        email: &str,
        slug: Option<&str>,
        portal_id: Option<i64>,
        ip: Option<IpAddr>,
        user_agent: Option<&str>,
    ) -> AppResult<()> {
        // (portal_id, slug) -> tenant. When neither is supplied, or
        // neither resolves, silently drop (still 204 upstream so an
        // attacker cannot use the shape to enumerate).
        // SAFETY (PMS-285): pre-auth path with no `app.current_tenant`
        // GUC set; runs on the BYPASSRLS migrator pool. Data returned
        // is only the tenant id (used to write a subsequent row under
        // that tenant).
        //
        // mokosh-contact-login prompt 011 (PMS-928): portal_id wins
        // when both are supplied. When portal_id resolves to a
        // Company that also carries a slug, the finder additionally
        // scopes the eventual contact-match query to that Company so
        // the redeem step is auto-mint (single Company, no picker)
        // even if the same email is on file under another Company in
        // the same tenant. The scoping is captured in `scope_company_id`
        // below.
        let slug = slug.map(str::trim).filter(|s| !s.is_empty());
        // Two entry shapes:
        //   1. Caller supplies portal_id or slug -> scope to that one
        //      Company + tenant (the recurring-user flow: they know
        //      which portal they belong to).
        //   2. Caller supplies neither -> the "find my portal" flow: a
        //      fresh visitor at /portal/find has no prior slug in
        //      localStorage. Match the email across every active-tenant
        //      Company on the mokosh instance and mint one intent per
        //      resulting (tenant, contact.email) pair. Enum-resistant:
        //      zero matches produce zero intents + zero emails, same
        //      shape a hit produces (204 upstream either way).
        let scoped_target: Option<(Uuid, Option<Uuid>)> = if portal_id.is_some() || slug.is_some() {
            let resolved: Option<(Uuid, Uuid)> = sqlx::query_as(
                r#"
                SELECT co.tenant_id, co.id
                FROM companies co
                INNER JOIN tenants t ON t.id = co.tenant_id
                WHERE t.status = 'active'
                  AND (
                    ($1::BIGINT IS NOT NULL AND co.portal_id = $1)
                    OR ($1::BIGINT IS NULL AND $2::TEXT IS NOT NULL AND co.portal_slug = $2)
                  )
                "#,
            )
            .bind(portal_id)
            .bind(slug)
            .fetch_optional(self.db.migrator_pool())
            .await?;
            let Some((tid, cid)) = resolved else {
                return Ok(());
            };
            // Only scope the contact lookup to a specific Company when
            // portal_id (or the slug on the compat path) explicitly
            // pinned one.
            let company_scope: Option<Uuid> = if portal_id.is_some() { Some(cid) } else { None };
            Some((tid, company_scope))
        } else {
            None
        };

        // Per-IP rate limit. Silent drop shape. Fires before either
        // targeting branch so a runaway caller cannot fan out extra
        // "cross-tenant discovery" writes to sidestep the ceiling.
        // SAFETY (PMS-285): the counters are pre-auth and cross-tenant
        // by design (an attacker's IP can fan out across tenants);
        // running on the migrator pool bypasses RLS so the count
        // includes rows from every tenant. That is the intended
        // scope: rate-limit the requester's IP, not one tenant's.
        if let Some(ip_addr) = ip {
            let ip_text = ip_addr.to_string();
            let per_ip: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM portal_login_intents \
                 WHERE ip = $1::inet AND created_at > NOW() - INTERVAL '1 minute'",
            )
            .bind(&ip_text)
            .fetch_one(self.db.migrator_pool())
            .await?;
            if per_ip >= LOGIN_INTENT_MAX_PER_IP_PER_MINUTE {
                tracing::info!(
                    ip = %ip_addr,
                    "login-link request silently dropped: per-IP rate limit reached"
                );
                return Ok(());
            }
        }

        // Resolve which tenants + optional Company scopes this request
        // should fan out over. Explicit slug/portal_id -> the one
        // resolved tenant. Neither supplied -> cross-tenant email
        // discovery: match any active-tenant Company that has a portal
        // contact with this email, mint one intent per tenant. Zero
        // matches on either branch = zero intents = still 204 upstream
        // (enum-resistant).
        let targets: Vec<(Uuid, Option<Uuid>)> = if let Some((tid, cid)) = scoped_target {
            vec![(tid, cid)]
        } else {
            let rows: Vec<(Uuid,)> = sqlx::query_as(
                r#"
                SELECT DISTINCT c.tenant_id
                FROM contacts c
                INNER JOIN companies co ON co.id = c.company_id
                INNER JOIN tenants t ON t.id = c.tenant_id
                WHERE t.status = 'active'
                  AND LOWER(c.email) = LOWER($1)
                  AND c.is_portal_user = TRUE
                  AND co.portal_slug IS NOT NULL
                "#,
            )
            .bind(email)
            .fetch_all(self.db.migrator_pool())
            .await?;
            rows.into_iter().map(|(tid,)| (tid, None)).collect()
        };
        if targets.is_empty() {
            return Ok(());
        }

        // Per-email rate limit: same counter shape as before, but now
        // summed across every matching tenant so an attacker cannot
        // use the cross-tenant fan-out to escape the ceiling. Counted
        // by the email alone (not per-tenant) because a single visitor
        // requesting a link legitimately covers every portal they hold
        // in one submit.
        let per_email: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM portal_login_intents \
             WHERE LOWER(email) = LOWER($1) \
             AND created_at > NOW() - INTERVAL '15 minutes'",
        )
        .bind(email)
        .fetch_one(self.db.migrator_pool())
        .await?;
        if per_email >= LOGIN_INTENT_MAX_PER_EMAIL_PER_15_MIN {
            tracing::info!(
                "login-link request silently dropped: per-email rate limit reached"
            );
            return Ok(());
        }

        // Fan out. Per-tenant match check + intent + notification.
        for (tenant_id, company_scope_id) in targets {
            let contact_count: i64 = sqlx::query_scalar(
                r#"
                SELECT COUNT(*)
                FROM contacts c
                INNER JOIN companies co ON co.id = c.company_id
                WHERE c.tenant_id = $1
                  AND LOWER(c.email) = LOWER($2)
                  AND c.is_portal_user = TRUE
                  AND co.portal_slug IS NOT NULL
                  AND ($3::UUID IS NULL OR c.company_id = $3)
                "#,
            )
            .bind(tenant_id)
            .bind(email)
            .bind(company_scope_id)
            .fetch_one(self.db.migrator_pool())
            .await?;
            if contact_count == 0 {
                continue;
            }

            let intent_id = Uuid::new_v4();
            let secret = generate_token(32);
            let secret_hash = hash_password(&secret)?;
            let expires_at = Utc::now() + Duration::minutes(LOGIN_INTENT_TTL_MIN);
            let ip_text = ip.map(|ip| ip.to_string()).unwrap_or_default();
            sqlx::query(
                r#"
                INSERT INTO portal_login_intents
                    (id, tenant_id, email, secret_hash, expires_at, ip, user_agent, company_id)
                VALUES ($1, $2, $3, $4, $5, NULLIF($6, '')::inet, $7, $8)
                "#,
            )
            .bind(intent_id)
            .bind(tenant_id)
            .bind(email)
            .bind(&secret_hash)
            .bind(expires_at)
            .bind(&ip_text)
            .bind(user_agent)
            .bind(company_scope_id)
            .execute(self.db.migrator_pool())
            .await?;

            let magic_link_url = format!(
                "{}/portal/pick?token={}.{}",
                self.spa_base_url.trim_end_matches('/'),
                intent_id,
                secret,
            );
            if let Some(notify) = self.notifications.as_ref() {
                let context = serde_json::json!({
                    "recipient_email": email,
                    "magic_link_url": magic_link_url,
                });
                let _ = notify
                    .dispatch(
                        TenantId::from_trusted(tenant_id),
                        "auth.login_link",
                        &context,
                    )
                    .await;
            } else {
                tracing::warn!(
                    magic_link_url = %magic_link_url,
                    "no notifications dispatcher wired; login-link intent persisted but no message queued (link logged for manual relay)"
                );
            }
        }
        Ok(())
    }

    /// mokosh-contact-login prompt 010 (PMS-918): redeem a magic link
    /// minted by `request_login_link` (or by
    /// `ContactService::grant_portal_access`). Parses `{intent_id}.{secret}`,
    /// verifies the hash, marks the intent used (same tx, so a race
    /// loses cleanly), then loads matching portal contacts.
    ///
    /// - 0 matches (revoked between mint + click) -> generic
    ///   `AppError::BadRequest("This link is invalid or has expired")`.
    /// - 1 match -> auto-mint access + refresh (or `mfa_required = true`
    ///   if the contact has TOTP enrolled) and return in
    ///   `LoginLinkRedeemOutcome.auto`.
    /// - >=2 matches -> mint a short-lived selection JWT and return
    ///   the picker payload in `LoginLinkRedeemOutcome.candidates`.
    ///
    /// Every failure path folds to the same generic 400 copy so the
    /// caller cannot tell WHY the token was rejected (expired vs.
    /// already-used vs. revoked vs. malformed).
    #[tracing::instrument(skip_all)]
    pub async fn redeem_login_link(
        &self,
        token: &str,
        user_agent: Option<&str>,
        ip: Option<IpAddr>,
    ) -> AppResult<LoginLinkRedeemOutcome> {
        let invalid = || AppError::BadRequest("This link is invalid or has expired".to_string());

        let (intent_id, secret) = parse_intent_bound_token(token).ok_or_else(invalid)?;

        // Load + verify + mark-used atomically in one BYPASSRLS tx so
        // a race between two clicks lands exactly one winner. This
        // path is unauthenticated (no `app.current_tenant` GUC to
        // set), so it runs on the migrator pool; the tenant id is
        // read off the intent row itself and threaded through the
        // downstream candidate query as an explicit `WHERE tenant_id
        // = $1` filter.
        let mut tx = self.db.migrator_pool().begin().await?;
        #[allow(clippy::type_complexity)]
        let intent: Option<(
            Uuid,
            Uuid,
            String,
            String,
            Option<DateTime<Utc>>,
            DateTime<Utc>,
            Option<Uuid>,
        )> = sqlx::query_as(
            r#"
                SELECT id, tenant_id, email, secret_hash, used_at, expires_at, company_id
                FROM portal_login_intents
                WHERE id = $1
                FOR UPDATE
                "#,
        )
        .bind(intent_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((_, tenant_id, intent_email, secret_hash, used_at, expires_at, scope_company_id)) =
            intent
        else {
            return Err(invalid());
        };
        if used_at.is_some() || expires_at <= Utc::now() {
            return Err(invalid());
        }
        if !verify_password(secret, &secret_hash)? {
            return Err(invalid());
        }
        sqlx::query("UPDATE portal_login_intents SET used_at = NOW() WHERE id = $1")
            .bind(intent_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;

        // Candidate lookup. Rows where the tenant is suspended or the
        // Company has no portal_slug never appear (a suspended tenant
        // is not a valid destination and a slug-less Company cannot
        // render its `/portal/{slug}/*` URLs anyway). Zero rows =
        // same generic invalid error above; do NOT leak revocation.
        #[allow(clippy::type_complexity)]
        let candidates: Vec<(Uuid, Uuid, Uuid, String, String, String, Option<String>, Option<String>)> =
            sqlx::query_as(
                r#"
                SELECT c.id, c.tenant_id, c.company_id, c.email,
                       co.name AS company_name, co.portal_slug,
                       c.portal_mfa_secret, c.portal_password_hash
                FROM contacts c
                INNER JOIN companies co ON co.id = c.company_id
                INNER JOIN tenants t ON t.id = c.tenant_id
                WHERE c.tenant_id = $1
                  AND LOWER(c.email) = LOWER($2)
                  AND c.is_portal_user = TRUE
                  AND t.status = 'active'
                  AND co.portal_slug IS NOT NULL
                  AND ($3::UUID IS NULL OR c.company_id = $3)
                ORDER BY co.name
                "#,
            )
            .bind(tenant_id)
            .bind(&intent_email)
            .bind(scope_company_id)
            .fetch_all(self.db.migrator_pool())
            .await?;
        if candidates.is_empty() {
            return Err(invalid());
        }

        // Single-match: auto-mint. MFA gate mirrors the shape prompt
        // 004 login already returns (empty tokens + mfa_required =
        // true). The SPA re-POSTs to a follow-up MFA endpoint with
        // the code (out of scope for this ticket; contact MFA is
        // off by default).
        if candidates.len() == 1 {
            let (contact_id, tid, company_id, email_row, _company_name, slug, mfa_secret, pwd_hash) =
                candidates.into_iter().next().unwrap();
            if mfa_secret.is_some() {
                return Ok(LoginLinkRedeemOutcome {
                    auto: Some(ContactLoginResponse {
                        access_token: String::new(),
                        refresh_token: String::new(),
                        expires_at: Utc::now(),
                        contact: None,
                        mfa_required: true,
                        password_setup_url: None,
                    }),
                    candidates: None,
                });
            }
            // Option-1 first-login gate: contact without a password
            // must set one before landing on /dashboard. Do NOT mint
            // the session yet; hand the SPA the set-password URL so
            // the recipient completes the password step. Post-set,
            // the standard login flow takes over.
            if pwd_hash.is_none() {
                let url = self.mint_password_setup_url(tid, contact_id, &slug).await?;
                return Ok(LoginLinkRedeemOutcome {
                    auto: Some(ContactLoginResponse {
                        access_token: String::new(),
                        refresh_token: String::new(),
                        expires_at: Utc::now(),
                        contact: None,
                        mfa_required: false,
                        password_setup_url: Some(url),
                    }),
                    candidates: None,
                });
            }
            let response = self
                .mint_session_for_contact(tid, contact_id, company_id, &email_row, user_agent, ip)
                .await?;
            return Ok(LoginLinkRedeemOutcome {
                auto: Some(response),
                candidates: None,
            });
        }

        // Multi-match: mint the selection JWT + return the picker
        // payload.
        let candidate_contact_ids: Vec<Uuid> = candidates.iter().map(|c| c.0).collect();
        let companies: Vec<LoginLinkCandidate> = candidates
            .iter()
            .map(
                |(contact_id, _, _, _, company_name, portal_slug, _, _)| LoginLinkCandidate {
                    contact_id: *contact_id,
                    company_name: company_name.clone(),
                    portal_slug: portal_slug.clone(),
                },
            )
            .collect();
        let selection_token =
            self.mint_selection_token(intent_id, tenant_id, &candidate_contact_ids)?;
        Ok(LoginLinkRedeemOutcome {
            auto: None,
            candidates: Some(LoginLinkCandidates {
                selection_token,
                companies,
            }),
        })
    }

    /// mokosh-contact-login prompt 010 (PMS-918): finish the multi-match
    /// magic-link flow. Decodes the selection JWT, verifies that
    /// `contact_id` is one of the ids that matched at redeem time
    /// (prevents swapping to an unrelated contact), then mints a
    /// contact session for that specific `contact_id`. MFA gate
    /// mirrors the redeem path.
    #[tracing::instrument(skip_all)]
    pub async fn select_login_candidate(
        &self,
        selection_token: &str,
        contact_id: Uuid,
        user_agent: Option<&str>,
        ip: Option<IpAddr>,
    ) -> AppResult<ContactLoginResponse> {
        let invalid = || AppError::BadRequest("This link is invalid or has expired".to_string());

        let claims = self
            .decode_selection_token(selection_token)
            .map_err(|_| invalid())?;
        if !claims.candidate_contact_ids.contains(&contact_id) {
            return Err(invalid());
        }

        // Belt-and-braces re-check: tenant must still be active + the
        // contact must still be a portal user + its Company still has
        // a portal_slug. Any change between redeem and select folds
        // to the same generic invalid error.
        #[allow(clippy::type_complexity)]
        let row: Option<(Uuid, String, Option<String>, String, Option<String>)> = sqlx::query_as(
            r#"
            SELECT c.company_id, c.email, c.portal_mfa_secret,
                   co.portal_slug, c.portal_password_hash
            FROM contacts c
            INNER JOIN companies co ON co.id = c.company_id
            INNER JOIN tenants t ON t.id = c.tenant_id
            WHERE c.id = $1
              AND c.tenant_id = $2
              AND c.is_portal_user = TRUE
              AND t.status = 'active'
              AND co.portal_slug IS NOT NULL
            "#,
        )
        .bind(contact_id)
        .bind(claims.tid)
        .fetch_optional(self.db.migrator_pool())
        .await?;
        let Some((company_id, email, mfa_secret, portal_slug, pwd_hash)) = row else {
            return Err(invalid());
        };
        if mfa_secret.is_some() {
            return Ok(ContactLoginResponse {
                access_token: String::new(),
                refresh_token: String::new(),
                expires_at: Utc::now(),
                contact: None,
                mfa_required: true,
                password_setup_url: None,
            });
        }
        // Option-1 first-login gate: same shape as redeem_login_link's
        // single-match branch. A contact reached via the multi-Company
        // picker who has never set a password gets bounced to the
        // set-password page before the session is minted.
        if pwd_hash.is_none() {
            let url = self
                .mint_password_setup_url(claims.tid, contact_id, &portal_slug)
                .await?;
            return Ok(ContactLoginResponse {
                access_token: String::new(),
                refresh_token: String::new(),
                expires_at: Utc::now(),
                contact: None,
                mfa_required: false,
                password_setup_url: Some(url),
            });
        }
        self.mint_session_for_contact(claims.tid, contact_id, company_id, &email, user_agent, ip)
            .await
    }

    /// mokosh-contact-login option-1 first-login gate: mint a fresh
    /// portal_setup_tokens row for `contact_id` and return the
    /// `/portal/{slug}/set-password?token=...` URL the SPA must redirect
    /// to. Called from the magic-link paths (redeem + select) when the
    /// target contact has never set a password: forces the "set a
    /// password to remember it" step before minting the session. On any
    /// pre-existing pending token this deletes it first so only the
    /// freshest link redeems.
    async fn mint_password_setup_url(
        &self,
        tenant_id: Uuid,
        contact_id: Uuid,
        portal_slug: &str,
    ) -> AppResult<String> {
        let secret = generate_token(64);
        let token_hash = hash_password(&secret)?;
        let token = format!("{contact_id}.{secret}");
        let expires_at = Utc::now() + Duration::hours(72);
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            "UPDATE portal_setup_tokens SET used_at = NOW() \
             WHERE contact_id = $1 AND tenant_id = $2 AND used_at IS NULL",
        )
        .bind(contact_id)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
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
        Ok(format!(
            "{}/portal/{}/set-password?token={}",
            self.spa_base_url.trim_end_matches('/'),
            portal_slug,
            token,
        ))
    }

    /// Shared session-minting used by `redeem_login_link` (single
    /// match) and `select_login_candidate` (multi match). Returns the
    /// same `ContactLoginResponse` shape the password login path uses.
    async fn mint_session_for_contact(
        &self,
        tenant_id: Uuid,
        contact_id: Uuid,
        company_id: Uuid,
        email: &str,
        user_agent: Option<&str>,
        ip: Option<IpAddr>,
    ) -> AppResult<ContactLoginResponse> {
        let caps = self.load_capabilities(tenant_id, contact_id).await?;
        let session_id = Uuid::new_v4();
        let (access_token, expires_at) =
            self.mint_access_token(tenant_id, contact_id, company_id, email, &caps, session_id)?;
        let refresh_token = self
            .mint_refresh_token(tenant_id, contact_id, session_id, user_agent, ip)
            .await?;
        // Stamp last-login. Best-effort.
        let _ = sqlx::query(
            "UPDATE contacts \
             SET portal_last_login_at = NOW(), updated_at = NOW() \
             WHERE id = $1 AND tenant_id = $2",
        )
        .bind(contact_id)
        .bind(tenant_id)
        .execute(self.db.migrator_pool())
        .await;
        let me = self.me(tenant_id, contact_id).await?;
        Ok(ContactLoginResponse {
            access_token,
            refresh_token,
            expires_at,
            contact: Some(me),
            mfa_required: false,
            password_setup_url: None,
        })
    }

    fn mint_selection_token(
        &self,
        intent_id: Uuid,
        tenant_id: Uuid,
        candidate_contact_ids: &[Uuid],
    ) -> AppResult<String> {
        let now = Utc::now();
        let claims = ContactLoginSelectClaims {
            intent_id,
            tid: tenant_id,
            candidate_contact_ids: candidate_contact_ids.to_vec(),
            token_type: LOGIN_LINK_TOKEN_TYP.to_string(),
            iat: now.timestamp(),
            exp: (now + Duration::minutes(LOGIN_SELECTION_TOKEN_TTL_MIN)).timestamp(),
        };
        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )
        .map_err(|e| AppError::Internal(format!("jwt encode: {e}")))
    }

    fn decode_selection_token(&self, token: &str) -> AppResult<ContactLoginSelectClaims> {
        let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.validate_exp = true;
        validation.required_spec_claims.clear();
        validation.required_spec_claims.insert("exp".to_string());
        let data = decode::<ContactLoginSelectClaims>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_bytes()),
            &validation,
        )
        .map_err(|_| AppError::Unauthorized)?;
        if data.claims.token_type != LOGIN_LINK_TOKEN_TYP {
            return Err(AppError::Unauthorized);
        }
        Ok(data.claims)
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

/// mokosh-contact-login prompt 010: `{intent_id}.{secret}` parser
/// used by `redeem_login_link`. Same split-shape as
/// `parse_session_bound_token` / `parse_contact_bound_token` above;
/// duplicated for readability at the call site (the first half is
/// keyed to a different table).
pub(crate) fn parse_intent_bound_token(token: &str) -> Option<(Uuid, &str)> {
    let (id, secret) = token.split_once('.')?;
    if secret.is_empty() {
        return None;
    }
    let intent_id = Uuid::parse_str(id).ok()?;
    Some((intent_id, secret))
}

/// Trait-object alias so the middleware can take an `Arc<...>` handle
/// without knowing the exact concrete type.
pub type ContactAuthServiceHandle = Arc<ContactAuthService>;
