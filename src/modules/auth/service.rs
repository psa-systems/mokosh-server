//! Authentication service implementation

use crate::modules::auth::TenantId;
#[cfg(feature = "server")]
use chrono::{Duration, Utc};
#[cfg(feature = "server")]
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};

/// MAPPS-334: mokosh-server self-issuer string stamped on every legacy
/// HS256 access / refresh token. A future strict `decode_token` will
/// pin `iss` to this value; today it is emitted at mint time so the flip
/// is a no-op once the rolling refresh-TTL window has expired every
/// legacy live token.
pub const MOKOSH_JWT_ISSUER: &str = "mokosh-server";

/// MAPPS-334: self-audience string stamped on every legacy HS256 token.
/// Same migration shape as `MOKOSH_JWT_ISSUER`: minted now, validated
/// strictly in a follow-up ticket.
pub const MOKOSH_JWT_AUDIENCE: &str = "mokosh-server";
#[cfg(feature = "server")]
use std::sync::Arc;
#[cfg(feature = "server")]
use uuid::Uuid;

#[cfg(feature = "server")]
use crate::db::Database;
use crate::modules::audit::{audit_auth_event, audit_write, AuditAction, AuditCtx};
#[cfg(feature = "server")]
use crate::modules::notifications::NotificationsService;
#[cfg(feature = "server")]
use crate::utils::crypto::{generate_token, hash_password, verify_password};
#[cfg(feature = "server")]
use crate::utils::email::{LogMailer, Mailer};
#[cfg(feature = "server")]
use crate::utils::error::{AppError, AppResult};
use crate::utils::geoip::GeoIpService;
use std::net::IpAddr;

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
    /// PMS-657: IP -> country resolver for login-location alerts. `None` when
    /// `IP2LOCATION_DB_PATH` is unset or the DB failed to load, which disables
    /// the alert (login is never blocked). Wired via [`Self::with_geoip`].
    geoip: Option<Arc<GeoIpService>>,
    /// PMS-658: master switch for the suspicious-login notify-and-approve gate.
    /// Default false: the gate can withhold a login, so it is opt-in per
    /// deployment for a safe rollout (PMS-289 lesson). When false, login behaves
    /// exactly as before (PMS-657 alert only). Wired via
    /// [`Self::with_login_approval`].
    login_approval_enabled: bool,
}

/// PMS-658: outcome of screening a login for suspicious signals. `country` and
/// `device_hash` are the resolved values to record once the login clears (either
/// because it was not suspicious, or after the emailed approval code is entered).
#[cfg(feature = "server")]
struct LoginAssessment {
    country: Option<String>,
    device_hash: Option<String>,
    suspicious: bool,
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

    /// Database accessor so auth handlers can open a tenant-scoped
    /// transaction (`begin_with_tenant`) for out-of-band audit writes
    /// that must still carry the RLS `app.current_tenant` GUC (PMS-256).
    pub(crate) fn db(&self) -> &crate::db::Database {
        &self.db
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
            geoip: None,
            login_approval_enabled: false,
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
            geoip: None,
            login_approval_enabled: false,
        }
    }

    /// PMS-657: attach the IP -> country resolver used for login-location
    /// alerts. Called once at server startup (see `create_api_router`); absent
    /// in test fixtures, which leaves the feature disabled.
    #[must_use]
    pub fn with_geoip(mut self, geoip: Option<Arc<GeoIpService>>) -> Self {
        self.geoip = geoip;
        self
    }

    /// PMS-658: enable the suspicious-login notify-and-approve gate. Off by
    /// default; set from `LOGIN_APPROVAL_ENABLED` at server startup. Requires
    /// geoip for the country signal and/or a client-supplied `device_id` for the
    /// device signal; with neither available the gate never fires.
    #[must_use]
    pub fn with_login_approval(mut self, enabled: bool) -> Self {
        self.login_approval_enabled = enabled;
        self
    }

    /// PMS-657: on a genuine login, resolve the client IP to a country and, when
    /// it differs from the country recorded at the user's previous login (and
    /// the user has not opted out), email a "new sign-in" alert, then persist the
    /// new country. The first geolocatable login records the country silently.
    /// Entirely best-effort: every failure is logged and swallowed so it can
    /// never block a login, and the whole check no-ops when no IP2Location DB is
    /// configured.
    async fn check_login_location(&self, user: &User, ip: Option<&str>, user_agent: Option<&str>) {
        let Some(geoip) = self.geoip.as_ref() else {
            return;
        };
        let Some(parsed) = ip.and_then(|s| s.parse::<IpAddr>().ok()) else {
            return;
        };
        // Private / loopback / link-local / unspecified addresses never map to a
        // public country and only show up behind a proxy or in dev; skip them so
        // they cannot spuriously "change country".
        if Self::is_non_public_ip(&parsed) {
            return;
        }
        let Some(country) = geoip.country_code(parsed) else {
            return;
        };

        match login_location_decision(user.last_login_country.as_deref(), &country) {
            // Same country as last time: nothing to do.
            LoginLocationDecision::Unchanged => {}
            // First login we can attribute to a country: record it, no alert.
            LoginLocationDecision::Record => {
                if let Err(e) = self
                    .set_last_login_country(user.tenant_id, user.id, &country)
                    .await
                {
                    tracing::warn!(user_id = %user.id, error = %e, "Failed to record initial login country");
                }
            }
            // Country changed: alert (unless opted out), then persist the new one.
            LoginLocationDecision::Alert => {
                let previous = user.last_login_country.as_deref().unwrap_or("?");
                if user.login_location_alerts {
                    // Send the alert on a detached task so a slow or failing SMTP
                    // round-trip never adds latency to (or fails) the login. The
                    // direct mailer is used rather than the notifications
                    // dispatcher because no template is seeded for this event at
                    // all, so a queued dispatch would find no rule and drop the
                    // alert (PMS-701). Retry is intentionally not added here
                    // (best-effort security signal); see PMS-657.
                    let mailer = self.mailer.clone();
                    let email = user.email.clone();
                    let country = country.clone();
                    let ip = parsed.to_string();
                    let when = Utc::now().format("%Y-%m-%d %H:%M UTC").to_string();
                    let ua = user_agent.unwrap_or("unknown").to_string();
                    // No known deep-linkable SPA sessions route (only
                    // /reset-password/<token>, which needs a token), so point at
                    // the app root; the body tells them what to do there.
                    let security_link = self.frontend_base_url.clone();
                    let user_id = user.id;
                    tokio::spawn(async move {
                        if let Err(e) = mailer
                            .send_new_login_location(
                                &email,
                                &country,
                                &ip,
                                &when,
                                &ua,
                                &security_link,
                            )
                            .await
                        {
                            tracing::warn!(user_id = %user_id, error = %e, "Failed to send new-login-location email");
                        }
                    });
                }
                tracing::info!(user_id = %user.id, from = %previous, to = %country, "Login country changed");
                if let Err(e) = self
                    .set_last_login_country(user.tenant_id, user.id, &country)
                    .await
                {
                    tracing::warn!(user_id = %user.id, error = %e, "Failed to update login country");
                }
            }
        }
    }

    /// PMS-657: persist the ISO country of the user's most recent geolocatable
    /// login. Tenant-scoped like `update_last_login` so it carries the RLS GUC.
    async fn set_last_login_country(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        country: &str,
    ) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            "UPDATE users SET last_login_country = $1, updated_at = NOW() WHERE id = $2 AND tenant_id = $3",
        )
        .bind(country)
        .bind(user_id)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    // ===================== PMS-658: suspicious-login gate =====================
    //
    // After password + MFA succeed, a login is screened for a new country (the
    // PMS-657 signal) or a new device (a client-supplied `device_id`, hashed into
    // `user_login_devices`). When `login_approval_enabled` and the login looks
    // suspicious, the session/tokens are withheld: a single-use 6-digit code is
    // emailed and a `login_approvals` row is created; the client re-POSTs the
    // login with `approval_code` to complete it. A disabled or geoip-less
    // deployment keeps the PMS-657 alert-only behaviour untouched.

    /// Wrong-code attempts tolerated against a single approval challenge before
    /// it is destroyed and a fresh code must be requested.
    const LOGIN_APPROVAL_MAX_ATTEMPTS: i32 = 5;

    /// Resolve a client IP string to a public ISO country, or `None` when geoip
    /// is unconfigured or the IP is missing / unparseable / non-public.
    fn resolve_login_country(&self, ip: Option<&str>) -> Option<String> {
        let geoip = self.geoip.as_ref()?;
        let parsed = ip.and_then(|s| s.parse::<IpAddr>().ok())?;
        if Self::is_non_public_ip(&parsed) {
            return None;
        }
        geoip.country_code(parsed)
    }

    /// PMS-658: screen a login. Suspicious when the country changed (PMS-657
    /// `Alert`) OR the device is new. A device is "new" only once the user has at
    /// least one known device, so the first device(s) are baseline (mirroring how
    /// the first login country is recorded, not alerted). An absent/blank
    /// `device_id` contributes no device signal (country only). Returns the
    /// resolved country + device hash to record once the login clears.
    async fn assess_login(
        &self,
        user: &User,
        ip: Option<&str>,
        device_id: Option<&str>,
    ) -> AppResult<LoginAssessment> {
        let country = self.resolve_login_country(ip);
        let country_new = country.as_deref().is_some_and(|c| {
            matches!(
                login_location_decision(user.last_login_country.as_deref(), c),
                LoginLocationDecision::Alert
            )
        });

        let device_hash = device_id
            .map(str::trim)
            .filter(|d| !d.is_empty())
            .map(sha256_hex);
        let device_new = match device_hash.as_deref() {
            Some(h) => {
                self.has_known_device(user.tenant_id, user.id).await?
                    && !self.is_known_device(user.tenant_id, user.id, h).await?
            }
            None => false,
        };

        Ok(LoginAssessment {
            country,
            device_hash,
            suspicious: country_new || device_new,
        })
    }

    /// PMS-658: does the user have any recorded login device yet?
    async fn has_known_device(&self, tenant_id: Uuid, user_id: Uuid) -> AppResult<bool> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM user_login_devices WHERE tenant_id = $1 AND user_id = $2)",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(exists)
    }

    /// PMS-658: is this device hash already known for the user?
    async fn is_known_device(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        device_hash: &str,
    ) -> AppResult<bool> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM user_login_devices WHERE tenant_id = $1 AND user_id = $2 AND device_hash = $3)",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(device_hash)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(exists)
    }

    /// PMS-658: record (or refresh) a device as known for the user.
    async fn record_known_device(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        device_hash: &str,
        user_agent: Option<&str>,
    ) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            r#"
            INSERT INTO user_login_devices (tenant_id, user_id, device_hash, user_agent)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (tenant_id, user_id, device_hash)
            DO UPDATE SET last_seen_at = NOW(), user_agent = EXCLUDED.user_agent
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(device_hash)
        .bind(user_agent)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// PMS-658: record the country + device of a cleared login (not suspicious,
    /// or suspicious-then-approved) so the next login from here is recognised.
    /// Best-effort: a write failure is logged, never fatal to the login.
    async fn record_login_success(&self, user: &User, assessment: &LoginAssessment) {
        if let Some(country) = assessment.country.as_deref() {
            if user.last_login_country.as_deref() != Some(country) {
                if let Err(e) = self
                    .set_last_login_country(user.tenant_id, user.id, country)
                    .await
                {
                    tracing::warn!(user_id = %user.id, error = %e, "PMS-658: failed to record login country");
                }
            }
        }
        if let Some(device_hash) = assessment.device_hash.as_deref() {
            if let Err(e) = self
                .record_known_device(user.tenant_id, user.id, device_hash, None)
                .await
            {
                tracing::warn!(user_id = %user.id, error = %e, "PMS-658: failed to record login device");
            }
        }
    }

    /// PMS-658: mint a login-approval challenge - store the hashed 6-digit code,
    /// email the plaintext, and (by returning `Ok`) signal `approval_required`.
    /// Supersedes any prior unconsumed challenge so only the freshest code works.
    /// The email send is detached so it never adds latency to or fails the login.
    async fn issue_login_approval(
        &self,
        user: &User,
        assessment: &LoginAssessment,
        ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> AppResult<()> {
        let code = crate::utils::crypto::generate_numeric_code(6);
        let code_hash = sha256_hex(&code);
        let expires_at = Utc::now() + Duration::minutes(15);

        let mut tx = self.db.begin_with_tenant(user.tenant_id).await?;
        sqlx::query(
            "DELETE FROM login_approvals WHERE tenant_id = $1 AND user_id = $2 AND consumed_at IS NULL",
        )
        .bind(user.tenant_id)
        .bind(user.id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            r#"
            INSERT INTO login_approvals
                (tenant_id, user_id, code_hash, country, device_hash, ip_address, user_agent, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
        )
        .bind(user.tenant_id)
        .bind(user.id)
        .bind(&code_hash)
        .bind(assessment.country.as_deref())
        .bind(assessment.device_hash.as_deref())
        .bind(ip)
        .bind(user_agent)
        .bind(expires_at)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        let mailer = self.mailer.clone();
        let email = user.email.clone();
        let country = assessment.country.clone();
        let ip_s = ip.map(str::to_string);
        let ua = user_agent.unwrap_or("unknown").to_string();
        let when = Utc::now().format("%Y-%m-%d %H:%M UTC").to_string();
        let user_id = user.id;
        tokio::spawn(async move {
            if let Err(e) = mailer
                .send_login_approval_code(
                    &email,
                    &code,
                    country.as_deref(),
                    ip_s.as_deref(),
                    &when,
                    &ua,
                )
                .await
            {
                tracing::warn!(user_id = %user_id, error = %e, "PMS-658: failed to send login-approval email");
            }
        });
        Ok(())
    }

    /// PMS-658: verify an `approval_code` re-POSTed to complete a challenged
    /// login. On the freshest unconsumed, unexpired challenge: a matching code
    /// marks it consumed and returns `Ok`; a mismatch increments `attempts` and,
    /// past [`Self::LOGIN_APPROVAL_MAX_ATTEMPTS`], destroys the challenge (forcing
    /// a fresh code). Absent / expired / over-limit challenges are `Unauthorized`.
    async fn verify_login_approval(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        code: &str,
    ) -> AppResult<()> {
        let code_hash = sha256_hex(code.trim());
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: Option<(Uuid, String)> = sqlx::query_as(
            r#"
            SELECT id, code_hash
              FROM login_approvals
             WHERE tenant_id = $1 AND user_id = $2
               AND consumed_at IS NULL AND expires_at > NOW()
             ORDER BY created_at DESC
             LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;

        let Some((id, stored_hash)) = row else {
            tx.commit().await?;
            return Err(AppError::Unauthorized);
        };

        if constant_time_eq::constant_time_eq(stored_hash.as_bytes(), code_hash.as_bytes()) {
            sqlx::query("UPDATE login_approvals SET consumed_at = NOW() WHERE id = $1")
                .bind(id)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            Ok(())
        } else {
            // PMS-693: increment relatively and decide from the value the
            // UPDATE returns. Reading `attempts` and writing back `attempts +
            // 1` let a burst of concurrent guesses all read the same value and
            // collapse into a single tick, so the cap never bit. The UPDATE's
            // row lock serialises the burst instead.
            let next: i32 = sqlx::query_scalar(
                "UPDATE login_approvals SET attempts = attempts + 1 \
                 WHERE id = $1 RETURNING attempts",
            )
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
            if next >= Self::LOGIN_APPROVAL_MAX_ATTEMPTS {
                sqlx::query("DELETE FROM login_approvals WHERE id = $1")
                    .bind(id)
                    .execute(&mut *tx)
                    .await?;
            }
            tx.commit().await?;
            Err(AppError::Unauthorized)
        }
    }

    /// Post-code-review finding #10: agent side now delegates to the
    /// shared `crate::utils::login_location::is_non_public_ip`. The
    /// previous inherent method was byte-identical to the portal-side
    /// copy AND missed the IPv4-mapped IPv6 case (finding #9). Keeping
    /// the associated-function shape so every existing call site
    /// (`Self::is_non_public_ip(...)`) compiles unchanged.
    fn is_non_public_ip(ip: &IpAddr) -> bool {
        crate::utils::login_location::is_non_public_ip(ip)
    }

    /// Authenticate user with email and password
    #[tracing::instrument(skip_all)]
    pub async fn login(
        &self,
        request: &LoginRequest,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> AppResult<LoginResponse> {
        // Captured for audit (PMS-117 AC3); the originals flow into
        // create_session below.
        let audit_ip = ip_address.clone();
        let audit_ua = user_agent.clone();

        // PMS-138: bind the lookup to (tenant_id, email). Replaces
        // the prior email-only lookup with `ORDER BY created_at ASC
        // LIMIT 1` tiebreaker that silently routed multi-tenant
        // collisions to the wrong account.
        //
        // MAPPS-396: the standalone login form types a tenant slug
        // (e.g. `acme`) rather than a UUID, so the request may carry
        // `tenant_slug` instead of `tenant_id`. Resolve the slug here
        // to the same `tenant_id` shape the downstream lookup already
        // expects. When both are set `tenant_id` wins so a
        // host-derived hint is not silently overridden by a mistyped
        // slug. Falls closed (401) on an unknown or suspended slug so
        // the endpoint cannot enumerate valid tenants.
        //
        // PMS-728 AC1: the local password path now REJECTS a
        // credential presented without an explicit tenant identifier.
        // The historical fallback to the default tenant
        // (`00000000-0000-0000-0000-000000000001`) let a bare
        // email/password reach the default tenant's admin bootstrap
        // by accident; making the identifier mandatory closes that
        // seam and matches how `PortalAuthService::login` already
        // resolves its tenant. Google OAuth (`login_with_google`) is
        // unaffected: its JIT path still uses
        // `resolve_tenant_for_login(None)` deliberately, so that
        // helper is left untouched and only this local-password
        // branch takes the stricter posture.
        let tenant_hint = match request.tenant_id {
            Some(id) => Some(id),
            None => match request.tenant_slug.as_deref().map(str::trim) {
                Some(slug) if !slug.is_empty() => Some(self.resolve_tenant_slug(slug).await?),
                _ => None,
            },
        };
        let Some(tenant_id) = tenant_hint else {
            // Fail-closed with the same 401 shape as a bad-password
            // outcome so the endpoint does not distinguish "no tenant
            // identifier" from "wrong credentials" to an unauth caller.
            return Err(AppError::Unauthorized);
        };
        let user = self
            .find_user_by_email_for_tenant(tenant_id, &request.email)
            .await?;

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
            // Record the failed attempt (PMS-117 AC3) before bailing.
            let ctx = AuditCtx {
                tenant_id: Some(user.tenant_id),
                user_id: Some(user.id),
                ip: audit_ip.clone(),
                user_agent: audit_ua.clone(),
            };
            // Out-of-band on its own tenant-scoped tx; a log-write failure
            // must not fail the login. PMS-256: carry the RLS GUC even here.
            if let Ok(mut tx) = self.db.begin_with_tenant(user.tenant_id).await {
                let _ = audit_write(
                    &mut *tx,
                    // SAFETY (PMS-285): `user.tenant_id` is from the user row just
                    // resolved for this login (the caller's own authenticated
                    // tenant), and the row is written under the matching
                    // `begin_with_tenant(user.tenant_id)` GUC above.
                    TenantId::from_trusted(user.tenant_id),
                    &ctx,
                    AuditAction::Login,
                    "auth",
                    Some(user.id),
                    None,
                    Some(serde_json::json!({ "outcome": "failed", "reason": "bad_password" })),
                )
                .await;
                let _ = tx.commit().await;
            }
            return Err(AppError::Unauthorized);
        }

        // Check MFA if enabled. Accept either a recovery code (single
        // use) or a TOTP code. Absent both: signal mfa_required so the
        // SPA can prompt for the second factor.
        if user.mfa_enabled {
            // PMS-502: persistent second-factor lockout. Read the per-account
            // MFA attempt state once; if the account is inside an active
            // backoff window, reject before checking any code so the lockout
            // actually cuts the attacker's guess rate. Unlike the in-memory
            // login limiter, this survives a process restart, coordinates
            // across replicas (it lives in Postgres), and is budgeted
            // independently of the password-attempt bucket.
            let locked_until = self.mfa_locked_until(user.tenant_id, user.id).await?;
            if locked_until.is_some_and(|until| until > Utc::now()) {
                return Err(AppError::RateLimited);
            }

            if let Some(rc) = request.recovery_code.as_deref() {
                let candidate = recovery_code_hex_hash(rc);
                let mut tx = self.db.begin_with_tenant(user.tenant_id).await?;
                let removed: bool = sqlx::query_scalar(
                    r#"
                    WITH popped AS (
                        UPDATE users
                           SET mfa_recovery_codes_hashes = array_remove(mfa_recovery_codes_hashes, $1),
                               updated_at = NOW()
                         WHERE id = $2
                           AND tenant_id = $3
                           AND $1 = ANY(mfa_recovery_codes_hashes)
                        RETURNING TRUE
                    )
                    SELECT COALESCE((SELECT TRUE FROM popped), FALSE)
                    "#,
                )
                .bind(&candidate)
                .bind(user.id)
                .bind(user.tenant_id)
                .fetch_one(&mut *tx)
                .await?;
                tx.commit().await?;
                // PMS-694: a wrong recovery code is a failed second factor
                // like any other, so it feeds the same per-account counter.
                // Leaving it out gave an attacker unlimited guesses (and, since
                // nothing else arms the lockout, neutralised it for TOTP too).
                if !removed {
                    self.register_failed_mfa(user.tenant_id, user.id).await?;
                    return Err(AppError::Unauthorized);
                }
                // Symmetrically, a good recovery code clears the counter and
                // lockout. Not `record_mfa_success`: a recovery code is not a
                // TOTP step, so the anti-replay watermark must not advance.
                self.clear_mfa_lockout(user.tenant_id, user.id).await?;
            } else if let Some(code) = request.mfa_code.as_deref() {
                let secret_b32 = user
                    .mfa_secret
                    .as_ref()
                    .ok_or_else(|| AppError::Internal("MFA enabled without secret".to_string()))?;
                let secret = crate::utils::totp::base32_decode(secret_b32)
                    .map_err(|_| AppError::Internal("stored MFA secret is corrupt".to_string()))?;
                // +-1 step (30s) tolerance handles modest clock skew. The
                // verifier returns the matched step so we can enforce
                // anti-replay (PMS-502).
                // PMS-502 anti-replay: a captured code stays valid for its
                // whole +/-1 window, so only honour a step STRICTLY GREATER
                // than the last accepted one. PMS-693: that comparison is the
                // watermark UPDATE's own WHERE clause, so two concurrent
                // logins presenting the same code cannot both win it.
                let accepted = match crate::utils::totp::verify(&secret, code, Utc::now(), 1) {
                    Some(step) => {
                        self.record_mfa_success(user.tenant_id, user.id, step)
                            .await?
                    }
                    None => false,
                };
                // Wrong code, or a replay of an already-spent step: count it
                // against the per-account cap and (re)arm the lockout, then
                // fail closed.
                if !accepted {
                    self.register_failed_mfa(user.tenant_id, user.id).await?;
                    return Err(AppError::Unauthorized);
                }
            } else {
                return Ok(LoginResponse {
                    access_token: String::new(),
                    refresh_token: String::new(),
                    expires_at: Utc::now(),
                    // Withhold the user profile until the second factor
                    // is satisfied: no pre-2FA data leak.
                    user: None,
                    mfa_required: true,
                    approval_required: false,
                    needs_selection: false,
                    needs_setup: false,
                    identity_token: None,
                    memberships: None,
                });
            }
        }

        // PMS-658: suspicious-login gate. Only when enabled; otherwise fall
        // through to the PMS-657 post-hoc alert below (unchanged). Runs after
        // password + MFA, so a flagged sign-in is a genuine authenticated one.
        let assessment = if self.login_approval_enabled {
            let a = self
                .assess_login(&user, audit_ip.as_deref(), request.device_id.as_deref())
                .await?;
            if a.suspicious {
                match request.approval_code.as_deref() {
                    Some(code) if !code.trim().is_empty() => {
                        // Completing a challenge: the emailed code must match.
                        self.verify_login_approval(user.tenant_id, user.id, code)
                            .await?;
                    }
                    _ => {
                        // First suspicious hit: email a code, withhold tokens.
                        self.issue_login_approval(
                            &user,
                            &a,
                            audit_ip.as_deref(),
                            audit_ua.as_deref(),
                        )
                        .await?;
                        return Ok(LoginResponse {
                            access_token: String::new(),
                            refresh_token: String::new(),
                            expires_at: Utc::now(),
                            user: None,
                            mfa_required: false,
                            approval_required: true,
                            needs_selection: false,
                            needs_setup: false,
                            identity_token: None,
                            memberships: None,
                        });
                    }
                }
            }
            Some(a)
        } else {
            None
        };

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
        let (access_token, refresh_token, expires_at) =
            self.generate_tokens(&user, session_id).await?;

        // Update last login
        self.update_last_login(user.tenant_id, user.id).await?;
        // PMS-658/657: when the gate ran, record the cleared login's country +
        // device so it is recognised next time; otherwise fall back to the
        // PMS-657 post-hoc country alert (unchanged). Borrow the audit IP/UA
        // before the audit block below consumes them.
        match &assessment {
            Some(a) => self.record_login_success(&user, a).await,
            None => {
                self.check_login_location(&user, audit_ip.as_deref(), audit_ua.as_deref())
                    .await
            }
        }

        // Record the successful login (PMS-117 AC3). Out-of-band on its own
        // tenant-scoped tx; a log-write failure must not fail the login
        // itself. PMS-256: carry the RLS GUC even here.
        if let Ok(mut tx) = self.db.begin_with_tenant(user.tenant_id).await {
            let _ = audit_auth_event(
                &mut *tx,
                user.tenant_id,
                Some(user.id),
                AuditAction::Login,
                audit_ip,
                audit_ua,
            )
            .await;
            let _ = tx.commit().await;
        }

        Ok(LoginResponse {
            access_token,
            refresh_token,
            expires_at,
            user: Some(user.to_current_user()),
            mfa_required: false,
            approval_required: false,
            needs_selection: false,
            needs_setup: false,
            identity_token: None,
            memberships: None,
        })
    }

    /// Reject access when the owning tenant is not active (suspended or
    /// cancelled). Threaded into every session-minting path (password login,
    /// Google login, refresh) so a tenant suspension takes effect immediately
    /// instead of lingering until token expiry.
    /// MAPPS-337: cheap public guard the auth middleware can run after
    /// decoding a legacy HS256 access token. Loads the user, asserts
    /// `status == Active`, and asserts the owning tenant is active.
    /// Mirrors the checks `login()` runs at login time so a deactivated
    /// user or tenant cannot keep authenticating until token expiry.
    /// Validate a legacy access token against the live user + tenant on every
    /// request: the user must exist and be Active, the token must not predate
    /// the user's last password change (PMS-681), and the tenant must be active.
    /// Returns the user it loaded so the caller (the auth middleware) does not
    /// re-query it.
    pub async fn ensure_user_and_tenant_active(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        token_iat: i64,
    ) -> AppResult<User> {
        let user = self.get_user_by_id(tenant_id, user_id).await?;
        self.ensure_principal_usable(&user).await?;
        // PMS-681: reject an access token minted before the user's last password
        // change (reset or self-service), so a stolen token dies the moment the
        // password changes instead of living out its TTL. Read straight off the
        // row loaded above - no extra query. NULL = no cutoff.
        //
        // PMS-698: deliberately NOT part of `ensure_principal_usable`. Bunyip
        // owns the credential on the RS path, so a mokosh-side password change
        // is not a revocation signal for a bunyip token.
        if let Some(changed_at) = user.password_changed_at {
            if token_iat < changed_at.timestamp() {
                return Err(AppError::Forbidden(
                    "Access token predates a password change".to_string(),
                ));
            }
        }
        Ok(user)
    }

    /// MAPPS-459 (PMS-728 slice 3): upsert the per-tenant Bunyip
    /// entitlement row consulted by [`ensure_tenant_active`]. Called
    /// from the webhook path (or any future integration surface) with
    /// the Bunyip-supplied membership status. `unknown` is legal here
    /// so a "we lost contact, do not know" event can explicitly clear
    /// a prior state without inventing a new value.
    ///
    /// Runs on the migrator pool because the write is a cross-tenant
    /// integration write with no session GUC; the table is RLS-exempt
    /// for the same reason (auth reads on the pre-session path).
    pub async fn set_tenant_entitlement(
        &self,
        tenant_id: Uuid,
        status: &str,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
        reason: Option<&str>,
    ) -> AppResult<()> {
        if !matches!(status, "active" | "suspended" | "unknown") {
            return Err(AppError::validation_field(
                "status",
                "must be one of: active, suspended, unknown",
            ));
        }
        sqlx::query(
            r#"
            INSERT INTO tenant_membership_entitlements
                (tenant_id, status, checked_at, expires_at, reason, created_at, updated_at)
            VALUES ($1, $2, NOW(), $3, $4, NOW(), NOW())
            ON CONFLICT (tenant_id) DO UPDATE SET
                status = EXCLUDED.status,
                checked_at = NOW(),
                expires_at = EXCLUDED.expires_at,
                reason = EXCLUDED.reason,
                updated_at = NOW()
            "#,
        )
        .bind(tenant_id)
        .bind(status)
        .bind(expires_at)
        .bind(reason)
        .execute(self.db.migrator_pool())
        .await?;
        Ok(())
    }

    /// PMS-698: the shared "is this principal still usable" gate. Both auth
    /// paths run it - the legacy HS256 branch via
    /// [`Self::ensure_user_and_tenant_active`] and the bunyip RS branch via
    /// `middleware::place_bunyip_user` - so a deactivated user or a suspended
    /// tenant loses access on the very next request on either path.
    pub async fn ensure_principal_usable(&self, user: &User) -> AppResult<()> {
        if user.status != UserStatus::Active {
            return Err(AppError::Forbidden("Account is not active".to_string()));
        }
        self.ensure_tenant_active(user.tenant_id).await
    }

    async fn ensure_tenant_active(&self, tenant_id: Uuid) -> AppResult<()> {
        // SAFETY (PMS-285 / PMS-692): the `tenants` table is the isolation root
        // and is deliberately excluded from RLS (migration 038:
        // `table_name != 'tenants'`), so this single-row status read is safe on
        // the NOBYPASSRLS app pool with no GUC. `mokosh_app` holds SELECT on it.
        let status: Option<String> = sqlx::query_scalar("SELECT status FROM tenants WHERE id = $1")
            .bind(tenant_id)
            .fetch_optional(self.db.pool())
            .await?;
        match status.as_deref() {
            Some("active") => {}
            _ => {
                return Err(AppError::Forbidden(
                    "This organization is not active".to_string(),
                ));
            }
        }

        // MAPPS-459 (PMS-728 slice 3): consult the per-tenant Bunyip
        // entitlement. `unknown` (the seed state, or a tenant with no
        // integration wired yet) passes through so a fresh instance is
        // never locked out. `suspended` OR an expired entitlement
        // rejects with the same "not active" copy so the endpoint does
        // not distinguish billing vs. operator lifecycle to a caller.
        // The row lives on `tenant_membership_entitlements`
        // (migration 125), RLS-exempt like `tenants`.
        let entitlement: Option<(String, Option<chrono::DateTime<chrono::Utc>>)> = sqlx::query_as(
            "SELECT status, expires_at FROM tenant_membership_entitlements WHERE tenant_id = $1",
        )
        .bind(tenant_id)
        .fetch_optional(self.db.pool())
        .await?;
        if let Some((entitlement_status, expires_at)) = entitlement {
            let now = chrono::Utc::now();
            let expired = expires_at.is_some_and(|t| t < now);
            if entitlement_status == "suspended" || expired {
                return Err(AppError::Forbidden(
                    "This organization is not active".to_string(),
                ));
            }
        }

        Ok(())
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
        // SAFETY (PMS-258/PMS-285): this is a pre-auth, cross-tenant lookup - it
        // runs before the user is placed in a tenant, so it cannot set
        // `app.current_tenant`. user_oauth_identities now has FORCE RLS, so once
        // the app connection moves to a NOBYPASSRLS role (PMS-285) this query and
        // the last_used_at UPDATE below must run on the privileged (BYPASSRLS)
        // pool. The tenant-scoped unique key keeps it to at most one row per
        // tenant; a single human maps to one personal tenant, so it stays unique
        // in practice.
        let linked_user_id: Option<Uuid> = sqlx::query_scalar(
            "SELECT user_id FROM user_oauth_identities \
             WHERE provider = 'google' AND subject = $1",
        )
        .bind(&google.sub)
        .fetch_optional(self.db.migrator_pool())
        .await?;

        let user = if let Some(user_id) = linked_user_id {
            sqlx::query(
                "UPDATE user_oauth_identities SET last_used_at = NOW() \
                 WHERE provider = 'google' AND subject = $1",
            )
            .bind(&google.sub)
            .execute(self.db.migrator_pool())
            .await?;
            // Resolve the tenant from the linked row so the scoped
            // get_user_by_id lookup has the boundary it needs. The
            // OAuth callback path is the only place where we hold a
            // user_id without already knowing the tenant.
            // SAFETY (PMS-285): still pre-auth - this resolves which tenant the
            // Google-linked user lives in before any session/GUC exists. Reads
            // RLS-covered `users` by id on the migrator pool; the subsequent
            // `get_user_by_id` re-reads under that tenant's GUC.
            let tenant_id: Uuid = sqlx::query_scalar("SELECT tenant_id FROM users WHERE id = $1")
                .bind(user_id)
                .fetch_optional(self.db.migrator_pool())
                .await?
                .ok_or_else(|| AppError::NotFound("User".to_string()))?;
            self.get_user_by_id(tenant_id, user_id).await?
        } else {
            // 2. No identity row yet - find or create the user by email.
            // PMS-138: Google OAuth callback carries no SPA-provided
            // tenant hint (the OAuth state cookie does not encode one),
            // so the JIT-link lookup falls back to the default tenant.
            // Multi-tenant Google login is a separate story; it would
            // require baking tenant_id into the OAuth state at popup
            // open time and verifying it in the callback.
            let google_jit_tenant_id = Self::resolve_tenant_for_login(None);
            match self
                .find_user_by_email_for_tenant_optional(google_jit_tenant_id, &google.email)
                .await?
            {
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
                    // Runs inside the existing user's tenant so the row carries
                    // the tenant scope (PMS-258) and satisfies the WITH CHECK
                    // policy even under a NOBYPASSRLS connection.
                    let mut tx = self.db.begin_with_tenant(existing.tenant_id).await?;
                    sqlx::query(
                        "INSERT INTO user_oauth_identities \
                         (user_id, tenant_id, provider, subject, email) \
                         VALUES ($1, $2, 'google', $3, $4)",
                    )
                    .bind(existing.id)
                    .bind(existing.tenant_id)
                    .bind(&google.sub)
                    .bind(&google.email)
                    .execute(&mut *tx)
                    .await?;
                    tx.commit().await?;
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

        // 3b. Enforce MFA exactly like the password `login()` path. A
        // verified Google identity is NOT a substitute for the user's
        // locally-enabled second factor; minting tokens here without it
        // would silently bypass MFA for any account that links Google.
        // The Google callback carries no MFA code, so signal
        // `mfa_required` (with empty tokens) and let the SPA complete the
        // second factor, mirroring `login()`'s no-code branch.
        if user.mfa_enabled {
            return Ok(LoginResponse {
                access_token: String::new(),
                refresh_token: String::new(),
                expires_at: Utc::now(),
                // Omit the user profile until the second factor is satisfied,
                // mirroring the password `login()` mfa_required branch.
                user: None,
                mfa_required: true,
                approval_required: false,
                needs_selection: false,
                needs_setup: false,
                identity_token: None,
                memberships: None,
            });
        }

        // 4. Issue session + tokens identically to the password flow.
        // PMS-657: keep the client IP + UA for the login-location check below,
        // since create_session consumes the owned values.
        let loc_ip = ip_address.clone();
        let loc_ua = user_agent.clone();
        let session_id = self
            .create_session(user.tenant_id, user.id, ip_address, user_agent, false)
            .await?;
        let (access_token, refresh_token, expires_at) =
            self.generate_tokens(&user, session_id).await?;
        self.update_last_login(user.tenant_id, user.id).await?;
        self.check_login_location(&user, loc_ip.as_deref(), loc_ua.as_deref())
            .await;

        Ok(LoginResponse {
            access_token,
            refresh_token,
            expires_at,
            user: Some(user.to_current_user()),
            mfa_required: false,
            approval_required: false,
            needs_selection: false,
            needs_setup: false,
            identity_token: None,
            memberships: None,
        })
    }

    /// Auto-provision a user from a verified Google identity. FAIL-CLOSED:
    /// only exact emails in `self.super_admin_emails` may auto-provision.
    /// Any other unrecognized Google identity is rejected - real users
    /// must be invited rather than silently dropped into the default
    /// tenant.
    ///
    /// MAPPS-518: the allowlisted Google identity now lands as a tenant
    /// `admin`, not `super_admin`. The platform super-admin persona
    /// lives in `platform_admins` and is bootstrapped via
    /// `ADMIN_EMAIL` / `ADMIN_PASSWORD` (see `auth::bootstrap`); the
    /// Google auto-provision flow can no longer mint platform-level
    /// privilege. The environment variable name (`super_admin_emails`)
    /// is unchanged for backwards-compat.
    async fn provision_user_from_google(
        &self,
        google: &google_oauth_flow::GoogleUserInfo,
    ) -> AppResult<User> {
        if !is_allowlisted_email(&self.super_admin_emails, &google.email) {
            return Err(AppError::Forbidden(
                "No account is provisioned for this Google identity. Ask an administrator for an invite.".to_string(),
            ));
        }
        let role = "admin";

        let user_id = Uuid::new_v4();
        // Bootstrap super-admins land in the default tenant seeded by
        // migrations/002_seed_data.sql. Everyone else is invited into a
        // specific tenant via the invite flow, not this path.
        let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001")
            .expect("default tenant UUID is valid");

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
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
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "INSERT INTO user_oauth_identities \
             (user_id, tenant_id, provider, subject, email) \
             VALUES ($1, $2, 'google', $3, $4)",
        )
        .bind(user_id)
        .bind(tenant_id)
        .bind(&google.sub)
        .bind(&google.email)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        self.get_user_by_id(tenant_id, user_id).await
    }

    /// Look up a user by `(tenant_id, email)`; returns `Ok(None)`
    /// instead of `Err(Unauthorized)` when no row matches.
    /// Tenant-bound sibling of `find_user_by_email_for_tenant` for
    /// the Google JIT-link path. PMS-138.
    async fn find_user_by_email_for_tenant_optional(
        &self,
        tenant_id: Uuid,
        email: &str,
    ) -> AppResult<Option<User>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row = sqlx::query_as::<_, UserRow>(
            r#"
            SELECT id, tenant_id, email, password_hash, first_name, last_name,
                   phone, mobile, title, avatar_url, timezone, locale,
                   date_format_string, theme_base_mode, theme_accent_id, role,
                   status, email_verified_at, last_login_at, last_login_country,
                   login_location_alerts, mfa_enabled,
                   mfa_secret, notification_preferences, settings,
                   created_at, updated_at, profile_completed_at,
                   (SELECT own_company_id FROM tenants WHERE id = users.tenant_id) AS own_company_id,
                   (SELECT kind FROM tenants WHERE id = users.tenant_id) AS tenant_kind
            FROM users
            WHERE tenant_id = $1 AND email = $2
            "#,
        )
        .bind(tenant_id)
        .bind(email)
        .fetch_optional(&mut *tx)
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

        // Verify session exists and is valid. PMS-4 AC6: bind both
        // tenant and id so a forged refresh token whose `tid` does
        // not match the session's tenant cannot rotate tokens.
        let session = self.get_session(claims.tid, claims.sid).await?;

        if session.is_none() {
            return Err(AppError::Unauthorized);
        }

        // Get user
        let user = self.get_user_by_id(claims.tid, claims.sub).await?;

        if user.status != UserStatus::Active {
            return Err(AppError::Forbidden("Account is not active".to_string()));
        }
        // A tenant suspended after the session was minted is rejected here, so
        // refreshing can't outlive the suspension.
        self.ensure_tenant_active(user.tenant_id).await?;

        // Generate new tokens
        let (access_token, new_refresh_token, expires_at) =
            self.generate_tokens(&user, claims.sid).await?;

        // Update session activity
        self.update_session_activity(claims.tid, claims.sid).await?;

        Ok(RefreshTokenResponse {
            access_token,
            refresh_token: new_refresh_token,
            expires_at,
        })
    }

    /// Logout - invalidate session
    #[tracing::instrument(skip_all)]
    pub async fn logout(&self, session_id: Uuid) -> AppResult<()> {
        // SAFETY (PMS-285): logout targets a single session by its primary key,
        // the unguessable session id the caller already holds. The handler does
        // not thread the tenant here, so it runs on the migrator pool; the
        // `WHERE id = $1` predicate keeps the blast radius to exactly that one
        // session. `user_sessions` carries `tenant_id` and is RLS-covered, so an
        // app-pool delete with no GUC would silently no-op instead.
        sqlx::query("DELETE FROM user_sessions WHERE id = $1")
            .bind(session_id)
            .execute(self.db.migrator_pool())
            .await?;

        Ok(())
    }

    /// Logout all sessions for a user. PMS-260: scoped to the caller's tenant
    /// as well as the user so logout cannot span tenants when a `user_id`
    /// exists under more than one tenant.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn logout_all(&self, tenant_id: Uuid, user_id: Uuid) -> AppResult<()> {
        // Tenant is in scope, so run under the GUC: RLS scopes the delete to the
        // caller's tenant in addition to the explicit `WHERE tenant_id`.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query("DELETE FROM user_sessions WHERE user_id = $1 AND tenant_id = $2")
            .bind(user_id)
            .bind(tenant_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;

        Ok(())
    }

    /// Request password reset. PMS-138: the optional `tenant_hint`
    /// flows in from `ForgotPasswordRequest::tenant_id` so a
    /// multi-tenant deployment can target the correct user when
    /// the same email exists under several tenants. `None` falls
    /// back to the default tenant.
    #[tracing::instrument(skip_all)]
    pub async fn request_password_reset(
        &self,
        tenant_hint: Option<Uuid>,
        email: &str,
    ) -> AppResult<()> {
        // Find user - don't reveal if user exists
        let tenant_id = Self::resolve_tenant_for_login(tenant_hint);
        let user = match self.find_user_by_email_for_tenant(tenant_id, email).await {
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
        let mut tx = self.db.begin_with_tenant(user.tenant_id).await?;
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
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        let reset_link = format!("{}/reset-password/{}", self.frontend_base_url, token);
        match &self.notifications {
            Some(notify) => {
                let context = serde_json::json!({
                    "recipient_user_id": user.id.to_string(),
                    "recipient_email": user.email,
                    "reset_link": reset_link,
                });
                // SAFETY (PMS-261): `user.tenant_id` is read off the `users`
                // row resolved by the reset request (a real tenant id, not
                // caller input); `dispatch` re-derives the GUC per query via
                // `begin_with_tenant`. `from_trusted` bridges the legacy auth
                // path (not yet swept to `TenantScoped`) into the typed scope.
                if let Err(e) = notify
                    .dispatch(
                        TenantId::from_trusted(user.tenant_id),
                        "auth.password_reset",
                        &context,
                    )
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
            // PMS-700: the body copy lives in the `auth.password_reset`
            // template, so there is no direct-send fallback to duplicate it.
            // Only fixtures built without a dispatcher land here.
            None => {
                tracing::warn!(
                    user_id = %user.id,
                    "no notifications dispatcher wired; password reset token persisted but no message queued",
                );
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

        // Pull tenant_id alongside the token hash so the subsequent
        // user UPDATE can bind it (PMS-4 AC6). Multiple candidate rows
        // are possible if the user requested several resets and none
        // expired yet; verify each in turn.
        // SAFETY (PMS-285): password reset runs pre-auth - the user is not in a
        // session, so there is no `app.current_tenant` to set, and the row's
        // tenant is exactly what this lookup resolves (the user can live under
        // one tenant only via the user-bound token's `user_id`). Runs on the
        // migrator pool; `password_reset_tokens` is RLS-covered, so an app-pool
        // read with no GUC would fail closed and break reset entirely.
        let candidates = sqlx::query_as::<_, (Uuid, String)>(
            r#"
            SELECT tenant_id, token_hash
            FROM password_reset_tokens
            WHERE user_id = $1 AND used_at IS NULL AND expires_at > NOW()
            ORDER BY created_at DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(self.db.migrator_pool())
        .await?;

        let mut matched: Option<Uuid> = None;
        for (tenant_id, token_hash) in &candidates {
            if verify_password(secret, token_hash)? {
                matched = Some(*tenant_id);
                break;
            }
        }
        let tenant_id = match matched {
            Some(t) => t,
            None => {
                return Err(AppError::BadRequest(
                    "Invalid or expired reset token".to_string(),
                ));
            }
        };

        // Hash new password
        let new_hash = hash_password(&request.new_password)?;

        // Update password. PMS-681: stamp `password_changed_at` so the auth
        // middleware rejects every access token issued before now (the `logout_all`
        // below only revokes refresh sessions).
        //
        // MAPPS-502 (MAPPS-496 stage 2d): identities is source of truth
        // for password_hash (same shape as MAPPS-499 change_password);
        // the MAPPS-498 bidir mirror keeps every matching users row
        // current. `password_changed_at` is users-only (PMS-681
        // revocation gate) and stays on the users UPDATE below.
        //
        // MAPPS-548: the `password_reset_tokens` table is reused by the
        // tenant-admin welcome-email flow (see
        // `TenantService::send_admin_welcome`) as a first-time setup
        // path, not just for existing users doing a forgot-password
        // reset. Detect the setup path by the users row's
        // `password_hash IS NULL` state at the moment of the reset
        // (a real user reset always has a hash to overwrite); when
        // it's a setup, flip the migration-134 session guard so the
        // password write lands on THIS users row only. A pre-existing
        // account at the same email (mokosh super-admin, another
        // tenant's admin, another client's admin) keeps its
        // credential untouched. Existing forgot-password path is
        // unaffected: their users row has a hash, the flag stays
        // unset, the identity mirror fires exactly as before.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: Option<(String, Option<String>)> = sqlx::query_as(
            "SELECT email, password_hash FROM users WHERE id = $1 AND tenant_id = $2",
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await?;
        let (email, current_hash) = row.ok_or_else(|| AppError::NotFound("User".to_string()))?;
        let is_first_time_setup = current_hash.is_none();
        if is_first_time_setup {
            // Use set_config('name', 'val', true) rather than a
            // `SET LOCAL name = val` statement: same semantics
            // (transaction-scoped), matches how
            // `Database::begin_with_tenant` already sets
            // `app.current_tenant`, and reliably runs on the
            // transaction connection through the sqlx executor
            // instead of opening a parser-level ambiguity around
            // the reserved `SET LOCAL` form.
            sqlx::query("SELECT set_config('app.skip_users_identity_mirror', 'on', true)")
                .execute(&mut *tx)
                .await?;
            // Setup path writes only to the users row's password_hash.
            // Skip the identities UPDATE entirely; the migration-134
            // guard would short-circuit the trigger even if we did,
            // but avoiding the UPDATE avoids clobbering identity data
            // for an existing identity at the same email. Also flip
            // `status` to `'active'` in the same write - the row was
            // seeded as `'pending'` by `create_tenant`, and
            // `ensure_principal_usable` refuses to authenticate a
            // non-active users row, so the setup flow has to promote
            // the row for the newly-set password to actually be
            // usable at login time.
            sqlx::query(
                "UPDATE users SET password_hash = $1, status = 'active', \
                 password_changed_at = NOW(), updated_at = NOW() \
                 WHERE id = $2 AND tenant_id = $3",
            )
            .bind(&new_hash)
            .bind(user_id)
            .bind(tenant_id)
            .execute(&mut *tx)
            .await?;
        } else {
            sqlx::query(
                "UPDATE identities SET password_hash = $1, updated_at = NOW() \
                 WHERE lower(email) = lower($2)",
            )
            .bind(&new_hash)
            .bind(&email)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "UPDATE users SET password_changed_at = NOW(), updated_at = NOW() \
                 WHERE id = $1 AND tenant_id = $2",
            )
            .bind(user_id)
            .bind(tenant_id)
            .execute(&mut *tx)
            .await?;
        }

        // Mark token as used
        sqlx::query(
            "UPDATE password_reset_tokens SET used_at = NOW() \
             WHERE user_id = $1 AND tenant_id = $2 AND used_at IS NULL",
        )
        .bind(user_id)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;

        // PMS-681: revoke all refresh sessions in the SAME transaction as the
        // password change, so a revoke failure rolls the whole reset back
        // (fail-closed) instead of leaving a usable refresh token behind. The
        // password_changed_at stamp above kills the already-issued access tokens.
        sqlx::query("DELETE FROM user_sessions WHERE user_id = $1 AND tenant_id = $2")
            .bind(user_id)
            .bind(tenant_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;

        Ok(())
    }

    /// Change password (when logged in). PMS-4 AC6: bound to the
    /// caller's tenant on both SELECT and UPDATE.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn change_password(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        request: &ChangePasswordRequest,
    ) -> AppResult<()> {
        if request.new_password != request.confirm_password {
            return Err(AppError::validation_field(
                "confirm_password",
                "Passwords do not match",
            ));
        }

        // Get current password hash + email (need the email to
        // resolve the identity row for the MAPPS-499 write).
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: Option<(String, String)> = sqlx::query_as(
            "SELECT password_hash, email FROM users WHERE id = $1 AND tenant_id = $2",
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await?;
        let (current_hash, email) = row.ok_or_else(|| AppError::NotFound("User".to_string()))?;

        // Verify current password
        if !verify_password(&request.current_password, &current_hash)? {
            return Err(AppError::validation_field(
                "current_password",
                "Current password is incorrect",
            ));
        }

        // Hash and update new password
        let new_hash = hash_password(&request.new_password)?;

        // MAPPS-499 (MAPPS-496 stage 2a): identities is now the source
        // of truth for password_hash. The bidir trigger from
        // migration 130 (MAPPS-498) mirrors this write back to every
        // matching users.password_hash so legacy readers still see
        // the new value. `password_changed_at` is users-only (PMS-681
        // access-token revocation gate) and stays on the users
        // UPDATE below. Both writes share the same tenant-scoped tx;
        // identities is RLS-exempt so its UPDATE runs cleanly under
        // any tenant GUC.
        sqlx::query(
            "UPDATE identities SET password_hash = $1, updated_at = NOW() \
             WHERE lower(email) = lower($2)",
        )
        .bind(&new_hash)
        .bind(&email)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "UPDATE users SET password_changed_at = NOW(), updated_at = NOW() \
             WHERE id = $1 AND tenant_id = $2",
        )
        .bind(user_id)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;

        // PMS-681: a self-service password change logs the user out everywhere.
        // Revoke all refresh sessions in the SAME transaction as the password
        // update (so a revoke failure rolls the change back); the
        // `password_changed_at` stamp above makes the middleware reject every
        // already-issued access token on its next request, including this
        // device's, so the user signs in again after changing their password.
        sqlx::query("DELETE FROM user_sessions WHERE user_id = $1 AND tenant_id = $2")
            .bind(user_id)
            .bind(tenant_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;

        Ok(())
    }

    /// Create a new user
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_user(
        &self,
        tenant_id: Uuid,
        request: &CreateUserRequest,
        ctx: &AuditCtx,
    ) -> AppResult<User> {
        // Check if email already exists
        let exists: bool = {
            let mut tx = self.db.begin_with_tenant(tenant_id).await?;
            sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM users WHERE tenant_id = $1 AND email = $2)",
            )
            .bind(tenant_id)
            .bind(&request.email)
            .fetch_one(&mut *tx)
            .await?
        };

        if exists {
            return Err(AppError::conflict("A user with this email already exists"));
        }

        let user_id = Uuid::new_v4();
        let timezone = request
            .timezone
            .clone()
            .unwrap_or_else(|| "UTC".to_string());

        // Mutation + audit row in one transaction so a rollback drops
        // both. CREATE: old = None, after captured by the new row id.
        // Secret columns (password_hash, mfa_secret) are stripped from the
        // snapshot. PMS-117.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            r#"
            INSERT INTO users (
                id, tenant_id, email, first_name, last_name, phone, mobile,
                title, role, timezone, date_format_string, theme_base_mode,
                theme_accent_id, status
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, 'pending')
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
        .bind(&request.date_format_string)
        .bind(&request.theme_base_mode)
        .bind(&request.theme_accent_id)
        .execute(&mut *tx)
        .await?;

        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) - 'password_hash' - 'mfa_secret' FROM users t WHERE id = $1",
        )
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;

        // SAFETY (PMS-261): `tenant_id` is the authenticated scope `create_user`
        // was called with; the whole method runs inside `begin_with_tenant`, so
        // the audit row is written under the same GUC. `from_trusted` only
        // bridges the legacy auth `Uuid` into the typed scope `audit_write`
        // requires (auth not yet swept to `TenantScoped`).
        audit_write(
            &mut *tx,
            TenantId::from_trusted(tenant_id),
            ctx,
            AuditAction::Create,
            "users",
            Some(user_id),
            None,
            after,
        )
        .await?;
        tx.commit().await?;

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
            let mut tx = self.db.begin_with_tenant(tenant_id).await?;
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
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;

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
                    // SAFETY (PMS-261): same authenticated `tenant_id` scope as
                    // the surrounding `create_user`; `dispatch` sets the GUC per
                    // query via `begin_with_tenant`. `from_trusted` bridges the
                    // legacy auth `Uuid` into the typed scope.
                    if let Err(e) = notify
                        .dispatch(TenantId::from_trusted(tenant_id), "auth.welcome", &context)
                        .await
                    {
                        tracing::warn!(
                            user_id = %user_id,
                            error = ?e,
                            "welcome notify dispatch failed; setup token persisted but no message queued",
                        );
                    } else {
                        tracing::info!(user_id = %user_id, "welcome email queued via notifications dispatcher");
                    }
                }
                // PMS-700: the body copy lives in the `auth.welcome` template,
                // so there is no direct-send fallback to duplicate it. Only
                // fixtures built without a dispatcher land here.
                None => {
                    tracing::warn!(
                        user_id = %user_id,
                        "no notifications dispatcher wired; setup token persisted but no welcome message queued",
                    );
                }
            }
        }

        self.get_user_by_id(tenant_id, user_id).await
    }

    /// Update user
    #[allow(unused_assignments)]
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        request: &UpdateUserRequest,
        ctx: &AuditCtx,
    ) -> AppResult<User> {
        // Build dynamic update query. `$1 = user_id`, `$2 = tenant_id`,
        // remaining params for field binds.
        let mut updates = Vec::new();
        let mut param_idx = 3;

        if request.email.is_some() {
            updates.push(format!("email = ${}", param_idx));
            param_idx += 1;
        }
        // PMS-512: no `first_name` / `last_name` / `phone` branches. The names
        // are a read-only cache of bunyip's claims and `phone` has no source
        // yet, so none of the three is settable through this API.
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
            param_idx += 1;
        }
        if request.date_format_string.is_some() {
            updates.push(format!("date_format_string = ${}", param_idx));
            // Invariant: every conditional update advances `param_idx` so
            // the next field added below is numbered correctly (PMS-197).
            param_idx += 1;
        }
        if request.theme_base_mode.is_some() {
            updates.push(format!("theme_base_mode = ${}", param_idx));
            param_idx += 1;
        }
        if request.theme_accent_id.is_some() {
            updates.push(format!("theme_accent_id = ${}", param_idx));
            param_idx += 1;
        }
        if request.login_location_alerts.is_some() {
            updates.push(format!("login_location_alerts = ${}", param_idx));
            // Last field today, so this increment is currently unread
            // (`#[allow(unused_assignments)]` on the fn); keep it so the
            // pattern stays copy-paste safe (PMS-197).
            param_idx += 1;
        }

        if updates.is_empty() {
            return self.get_user_by_id(tenant_id, user_id).await;
        }

        updates.push("updated_at = NOW()".to_string());

        // PMS-512: this handler no longer accepts names, so it can no longer
        // be the thing that completes a profile. `profile_completed_at` is
        // stamped by `upsert_user_from_oidc` on the login whose bunyip claims
        // carry both names.

        // $1 = user_id, $2 = tenant_id (PMS-4 AC6).
        let query = format!(
            "UPDATE users SET {} WHERE id = $1 AND tenant_id = $2",
            updates.join(", ")
        );

        let mut query_builder = sqlx::query(&query).bind(user_id).bind(tenant_id);

        if let Some(ref email) = request.email {
            query_builder = query_builder.bind(email);
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
        if let Some(ref date_format_string) = request.date_format_string {
            query_builder = query_builder.bind(date_format_string);
        }
        if let Some(ref theme_base_mode) = request.theme_base_mode {
            query_builder = query_builder.bind(theme_base_mode);
        }
        if let Some(ref theme_accent_id) = request.theme_accent_id {
            query_builder = query_builder.bind(theme_accent_id);
        }
        if let Some(login_location_alerts) = request.login_location_alerts {
            query_builder = query_builder.bind(login_location_alerts);
        }

        // Mutation + audit row in one transaction: snapshot the row
        // before and after (Postgres to_jsonb captures exact stored
        // state, secret columns stripped) and write the audit entry on
        // the same tx so a rollback drops both. The snapshot SELECTs
        // include `AND tenant_id = $2` so the audit cannot accidentally
        // capture another tenant's row even if the caller threads a
        // wrong user_id. PMS-117 + PMS-4 AC6.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;

        let before: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) - 'password_hash' - 'mfa_secret' FROM users t \
             WHERE id = $1 AND tenant_id = $2",
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await?;

        query_builder.execute(&mut *tx).await?;

        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) - 'password_hash' - 'mfa_secret' FROM users t \
             WHERE id = $1 AND tenant_id = $2",
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await?;

        // SAFETY (PMS-261): `tenant_id` is the authenticated scope `update_user`
        // was called with; the snapshot SELECTs above filter `AND tenant_id =
        // $2` and the whole method runs inside `begin_with_tenant`, so the audit
        // row is confined to that tenant. `from_trusted` bridges the legacy auth
        // `Uuid` into the typed scope (auth not yet swept to `TenantScoped`).
        audit_write(
            &mut *tx,
            TenantId::from_trusted(tenant_id),
            ctx,
            AuditAction::Update,
            "users",
            Some(user_id),
            before,
            after,
        )
        .await?;
        tx.commit().await?;

        self.get_user_by_id(tenant_id, user_id).await
    }

    /// Begin MFA enrollment. Generates a fresh TOTP secret, persists it
    /// on `users.mfa_secret`, and returns the base32 secret plus the
    /// `otpauth://` provisioning URI. `mfa_enabled` is NOT flipped here
    /// — the caller must complete enrollment by submitting a valid code
    /// via [`AuthService::enable_mfa`]. Refusing partial enrollment
    /// guarantees that an authenticator that was misconfigured (wrong
    /// time, wrong algorithm) cannot lock the user out.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn start_mfa_enrollment(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> AppResult<crate::modules::auth::models::MfaSetupResponse> {
        let user = self.get_user_by_id(tenant_id, user_id).await?;
        if user.mfa_enabled {
            return Err(AppError::Conflict("MFA is already enabled".to_string()));
        }

        let secret = crate::utils::totp::generate_secret();
        let secret_b32 = crate::utils::totp::base32_encode(&secret);

        // MAPPS-501 (MAPPS-496 stage 2c): identities is now the source
        // of truth for mfa_secret; MAPPS-498 mirror back-propagates to
        // every users.mfa_secret this identity backs.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            "UPDATE identities SET mfa_secret = $1, updated_at = NOW() \
             WHERE lower(email) = lower($2)",
        )
        .bind(&secret_b32)
        .bind(&user.email)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        let label = format!("Mokosh:{}", user.email);
        let provisioning_uri = crate::utils::totp::provisioning_uri(&secret_b32, &label, "Mokosh");

        Ok(crate::modules::auth::models::MfaSetupResponse {
            secret: secret_b32,
            provisioning_uri,
        })
    }

    /// Finish MFA enrollment. Verifies one TOTP code against the secret
    /// staged by [`AuthService::start_mfa_enrollment`]; on success flips
    /// `mfa_enabled = true` AND mints 10 single-use recovery codes
    /// (PMS-4 AC3). The recovery codes are returned to the caller
    /// ONCE in [`MfaEnableResponse`]; only their SHA-256 hashes are
    /// persisted to `users.mfa_recovery_codes_hashes`.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn enable_mfa(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        code: &str,
    ) -> AppResult<crate::modules::auth::models::MfaEnableResponse> {
        // PMS-4 AC6: `get_user_by_id` binds `AND tenant_id = $2`, so
        // any user_id from another tenant comes back as NotFound here.
        let user = self.get_user_by_id(tenant_id, user_id).await?;
        let secret_b32 = user.mfa_secret.as_ref().ok_or_else(|| {
            AppError::BadRequest("MFA enrollment has not been started".to_string())
        })?;
        let secret = crate::utils::totp::base32_decode(secret_b32)
            .map_err(|_| AppError::Internal("stored MFA secret is corrupt".to_string()))?;
        if crate::utils::totp::verify(&secret, code, Utc::now(), 1).is_none() {
            return Err(AppError::BadRequest("Invalid MFA code".to_string()));
        }

        let recovery_codes = crate::utils::recovery::generate_set();
        let hashes: Vec<String> = recovery_codes
            .iter()
            .map(|c| recovery_code_hex_hash(c))
            .collect();

        // MAPPS-501 (MAPPS-496 stage 2c): flip mfa_enabled + reset
        // watermark on identities (source of truth); recovery-code
        // hashes remain a users-only column (added by migration 029,
        // not mirrored to identities).
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            "UPDATE identities SET mfa_enabled = TRUE, \
                                   mfa_last_totp_step = 0, \
                                   updated_at = NOW() \
             WHERE lower(email) = lower($1)",
        )
        .bind(&user.email)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE users SET mfa_recovery_codes_hashes = $1, updated_at = NOW() \
             WHERE id = $2 AND tenant_id = $3",
        )
        .bind(&hashes)
        .bind(user_id)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        Ok(crate::modules::auth::models::MfaEnableResponse { recovery_codes })
    }

    /// Disable MFA. Requires the user's current password (re-auth) so a
    /// stolen session cannot quietly weaken the account. Zeroes the
    /// recovery code set for symmetry with `enable_mfa`.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn disable_mfa(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        password: &str,
    ) -> AppResult<()> {
        let user = self.get_user_by_id(tenant_id, user_id).await?;
        let hash = user
            .password_hash
            .as_ref()
            .ok_or_else(|| AppError::BadRequest("This account has no password".to_string()))?;
        if !verify_password(password, hash)? {
            return Err(AppError::Unauthorized);
        }

        // MAPPS-501 (MAPPS-496 stage 2c): clear mfa_enabled + mfa_secret
        // + watermark on identities (source of truth); clear recovery
        // hashes on users (users-only column). Both writes share the
        // same tx.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            "UPDATE identities SET mfa_enabled = FALSE, \
                                   mfa_secret = NULL, \
                                   mfa_last_totp_step = 0, \
                                   updated_at = NOW() \
             WHERE lower(email) = lower($1)",
        )
        .bind(&user.email)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE users SET mfa_recovery_codes_hashes = '{}', updated_at = NOW() \
             WHERE id = $1 AND tenant_id = $2",
        )
        .bind(user_id)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

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
        ctx: &AuditCtx,
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

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
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
        .fetch_one(&mut *tx)
        .await?;

        // CREATE: old = None. Strip `key_hash` (the argon2 secret) from the
        // snapshot so the audit row never persists key material. PMS-117.
        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) - 'key_hash' FROM api_keys t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        audit_write(
            &mut *tx,
            TenantId::from_trusted(tenant_id),
            ctx,
            AuditAction::Create,
            "api_keys",
            Some(id),
            None,
            after,
        )
        .await?;
        tx.commit().await?;

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
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM api_keys WHERE tenant_id = $1 AND user_id = $2",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_one(&mut *tx)
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
        .fetch_all(&mut *tx)
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
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let affected =
            sqlx::query("DELETE FROM api_keys WHERE id = $1 AND tenant_id = $2 AND user_id = $3")
                .bind(key_id)
                .bind(tenant_id)
                .bind(user_id)
                .execute(&mut *tx)
                .await?
                .rows_affected();
        tx.commit().await?;

        if affected == 0 {
            return Err(AppError::NotFound("API key".to_string()));
        }
        Ok(())
    }

    /// List users in a tenant, paginated and filterable. Audit F1 +
    /// PMS-4 AC1 closeout. Two parallel WHERE clauses are built so
    /// the data query and the count query can have different param
    /// numbering: data has `$1 = tenant_id, $2 = limit, $3 = offset,
    /// $4+ = filters`; count has `$1 = tenant_id, $2+ = filters`.
    /// Same condition set, different placeholder offsets.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_users(
        &self,
        tenant_id: Uuid,
        filter: &crate::modules::auth::ListUsersFilter,
        pagination: &crate::utils::pagination::PaginationParams,
    ) -> AppResult<(Vec<User>, u64)> {
        let offset = pagination.offset() as i64;
        let limit = pagination.limit() as i64;

        let mut data_conds: Vec<String> = vec!["tenant_id = $1".to_string()];
        let mut count_conds: Vec<String> = vec!["tenant_id = $1".to_string()];
        let mut data_idx: i32 = 4;
        let mut count_idx: i32 = 2;

        if filter.q.is_some() {
            data_conds.push(format!(
                "(email ILIKE ${idx} OR first_name ILIKE ${idx} OR last_name ILIKE ${idx})",
                idx = data_idx
            ));
            count_conds.push(format!(
                "(email ILIKE ${idx} OR first_name ILIKE ${idx} OR last_name ILIKE ${idx})",
                idx = count_idx
            ));
            data_idx += 1;
            count_idx += 1;
        }
        if filter.role.is_some() {
            data_conds.push(format!("role = ${data_idx}"));
            count_conds.push(format!("role = ${count_idx}"));
            data_idx += 1;
            count_idx += 1;
        }
        if filter.status.is_some() {
            data_conds.push(format!("status = ${data_idx}"));
            count_conds.push(format!("status = ${count_idx}"));
            // last bind; intentionally no increment.
        }
        let data_where = data_conds.join(" AND ");
        let count_where = count_conds.join(" AND ");

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

        let data_query = format!(
            r#"
            SELECT id, tenant_id, email, password_hash, first_name, last_name,
                   phone, mobile, title, avatar_url, timezone, locale,
                   date_format_string, theme_base_mode, theme_accent_id, role,
                   status, email_verified_at, last_login_at, last_login_country,
                   login_location_alerts, mfa_enabled,
                   mfa_secret, notification_preferences, settings,
                   created_at, updated_at, profile_completed_at,
                   (SELECT own_company_id FROM tenants WHERE id = users.tenant_id) AS own_company_id,
                   (SELECT kind FROM tenants WHERE id = users.tenant_id) AS tenant_kind
            FROM users
            WHERE {data_where}
            ORDER BY {order_by}
            LIMIT $2 OFFSET $3
            "#
        );
        let count_query = format!("SELECT COUNT(*) FROM users WHERE {count_where}");

        let mut data = sqlx::query_as::<_, UserRow>(&data_query)
            .bind(tenant_id)
            .bind(limit)
            .bind(offset);
        let mut count = sqlx::query_scalar::<_, i64>(&count_query).bind(tenant_id);

        if let Some(ref needle) = filter.q {
            let pat = format!("%{needle}%");
            data = data.bind(pat.clone());
            count = count.bind(pat);
        }
        if let Some(role) = filter.role {
            data = data.bind(role.as_str());
            count = count.bind(role.as_str());
        }
        if let Some(status) = filter.status {
            data = data.bind(status.as_str());
            count = count.bind(status.as_str());
        }

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows = data.fetch_all(&mut *tx).await?;
        let total = count.fetch_one(&mut *tx).await?;

        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    /// Get user by ID, scoped to a tenant. PMS-4 AC6 closeout (cross-
    /// cutting issue #8 for the auth module): every read of `users`
    /// binds `tenant_id` in WHERE so an internal caller that forgets
    /// to thread the boundary cannot leak rows across tenants.
    /// Cross-tenant lookups return `NotFound` so the response shape
    /// stays opaque to a probing client.
    ///
    /// Where a user currently lives, by global user id (`sub`): `(tenant_id,
    /// role)`. `None` if the user has no row yet. The bunyip path uses this
    /// (PMS-244) to decide between joining an invited tenant, staying put, or
    /// self-signup, and (PMS-245) to back-fill non-admin users out of the shared
    /// default tenant - the `role` lets it exempt platform `super_admin`s.
    ///
    /// PMS-260: this lookup is deliberately NOT tenant-scoped - resolving which
    /// tenant a `sub` belongs to is its whole job, so it must read across
    /// tenants. That is only safe because its sole caller is the pre-session
    /// bunyip login/placement path (`middleware::place_bunyip_user`), which runs
    /// before any `AuthState`/tenant context exists. It must NEVER be wired into
    /// a request handler, where it would let an authenticated caller probe other
    /// tenants' placement. The `routes_do_not_reach_global_login_helpers`
    /// regression test (`tests/auth.rs`) pins that no `routes.rs` references it.
    pub async fn find_user_placement(&self, user_id: Uuid) -> AppResult<Option<(Uuid, String)>> {
        // SAFETY (PMS-285/PMS-260): resolving which tenant a `sub` belongs to is
        // this helper's whole job, so it reads `users` across tenants. It runs
        // only on the pre-session bunyip placement path before any tenant
        // context exists (pinned by `routes_do_not_reach_global_login_helpers`),
        // so it has no GUC to set and runs on the privileged migrator pool;
        // `users` is RLS-covered and would otherwise fail closed to `None`.
        // PMS-591: skip tombstoned users so a stale Bunyip JWT that arrives
        // after the account_deleted webhook has landed cannot resurrect a
        // deleted account through the JIT placement path. A live user has
        // `deleted_at IS NULL`; a tombstoned row here reads as "no placement",
        // which the caller treats as "drop the bunyip path" and short-circuits
        // to legacy auth (which then fails closed at get_user_by_id).
        Ok(sqlx::query_as::<_, (Uuid, String)>(
            "SELECT tenant_id, role FROM users WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(user_id)
        .fetch_optional(self.db.migrator_pool())
        .await?)
    }

    /// MAPPS-348: probe whether a user row exists in the tombstoned state.
    /// The auth middleware runs this on the error path (when the normal
    /// `deleted_at IS NULL` lookup returned nothing) to distinguish
    /// "the user's Bunyip account was deleted" from "no matching row at
    /// all" (a stale JWT for a sub that never mirrored, a tenant mismatch,
    /// etc). Returns true only when the row physically exists AND its
    /// `deleted_at` is set - both a truly-missing row and an active row
    /// return false. Runs unscoped by tenant so it works both for the
    /// bunyip-RS path (which knows only the sub) and the legacy HS256
    /// path.
    pub async fn is_user_tombstoned(&self, user_id: Uuid) -> AppResult<bool> {
        let found: Option<(bool,)> =
            sqlx::query_as("SELECT (deleted_at IS NOT NULL) FROM users WHERE id = $1")
                .bind(user_id)
                // SAFETY (PMS-285 / PMS-692): deliberately tenant-unscoped - the
                // middleware error path knows only the sub, not the tenant, so
                // there is no `app.current_tenant` GUC to set. Runs on the
                // migrator pool; `users` is RLS-covered, so on the app pool this
                // would always read "not tombstoned" (case E) and the MAPPS-348
                // 410 ACCOUNT_DELETED branch would be dead code.
                .fetch_optional(self.db.migrator_pool())
                .await?;
        Ok(found.map(|(is_deleted,)| is_deleted).unwrap_or(false))
    }

    /// PMS-752: stamp `profile_completed_at` for a user who has been through
    /// the SPA's onboarding screen.
    ///
    /// PMS-512 left `upsert_user_from_oidc` as the only writer of this column,
    /// stamping it on a login whose bunyip claims carry both names. A user
    /// whose claims did not carry them landed on the onboarding screen with no
    /// way to leave it: the screen's `PUT /auth/me` cannot set names (bunyip
    /// owns them) and therefore could not complete the profile either.
    ///
    /// `COALESCE` keeps the first timestamp, so this is idempotent: a double
    /// submit records when onboarding was actually finished, not when it was
    /// last re-submitted.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn mark_profile_completed(&self, tenant_id: Uuid, user_id: Uuid) -> AppResult<User> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            "UPDATE users SET profile_completed_at = COALESCE(profile_completed_at, NOW()), \
                              updated_at = NOW() \
             WHERE id = $1 AND tenant_id = $2",
        )
        .bind(user_id)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        self.get_user_by_id(tenant_id, user_id).await
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_user_by_id(&self, tenant_id: Uuid, user_id: Uuid) -> AppResult<User> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row = sqlx::query_as::<_, UserRow>(
            r#"
            SELECT id, tenant_id, email, password_hash, first_name, last_name,
                   phone, mobile, title, avatar_url, timezone, locale,
                   date_format_string, theme_base_mode, theme_accent_id, role,
                   status, email_verified_at, last_login_at, last_login_country,
                   login_location_alerts, mfa_enabled,
                   mfa_secret, notification_preferences, settings,
                   created_at, updated_at, password_changed_at, profile_completed_at,
                   (SELECT own_company_id FROM tenants WHERE id = users.tenant_id) AS own_company_id,
                   (SELECT kind FROM tenants WHERE id = users.tenant_id) AS tenant_kind
            FROM users
            -- PMS-591: a tombstoned user (deleted via the Bunyip
            -- account_deleted webhook) reads as NotFound so every
            -- extractor that resolves the current user through this
            -- path fails closed with 401. The tombstoned row itself
            -- stays for FK-owned history (time_entries, audit_log, ...).
            WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
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
    ///
    /// BUNYIP-141 (slice C of BUNYIP-103): `given_name` and `family_name`
    /// hints come from the bunyip `/oauth2/userinfo` response when the user
    /// consented to the `profile` scope. Both are optional:
    /// - `Some(non-empty)`: seed the column with the claim value on insert.
    /// - `None` or empty: fall back to `synthetic_name_from_email`.
    ///
    /// PMS-512: bunyip is the identity source of truth, so `first_name` /
    /// `last_name` are a read-only local cache. The `ON CONFLICT DO UPDATE`
    /// branch OVERWRITES both from the hints on every run, not just on
    /// insert; the local columns are no longer editable through the mokosh
    /// API. Both columns are `NOT NULL`, so an absent or empty hint binds
    /// NULL and `COALESCE` leaves the existing value intact rather than
    /// writing an empty string. See [`Self::refresh_names_from_oidc`] for the
    /// already-provisioned-user half of the same refresh.
    #[allow(clippy::too_many_arguments)]
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn upsert_user_from_oidc(
        &self,
        sub: Uuid,
        tenant_id: Uuid,
        email: &str,
        role: UserRole,
        given_name_hint: Option<&str>,
        family_name_hint: Option<&str>,
        // MAPPS-335: stamp `email_verified_at = NOW()` only when the IdP
        // (Bunyip via `/oauth2/userinfo`) actually reports the email
        // verified. Previously this column was unconditionally NOW(),
        // including the placeholder `sub@unresolved.invalid` branch
        // taken when `email_verified=false`. Downstream gates that read
        // `email_verified_at IS NOT NULL` (invite consumption, certain
        // admin paths) were getting a false positive.
        email_verified: bool,
    ) -> AppResult<User> {
        // Use the bunyip claim hints when both are present and non-empty;
        // fall back to the email-derived placeholder otherwise. `users.
        // first_name` / `last_name` are NOT NULL, so an empty hint must
        // never reach the INSERT - the synthetic helper always returns
        // non-empty strings (its tests pin that contract).
        let first_hint = given_name_hint
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let last_hint = family_name_hint
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        // MAPPS-329: when both hints came in non-empty, the user already
        // entered their first + last name in Bunyip (BUNYIP-206 forces it
        // pre-signup), so the mokosh `/onboarding/profile` page would just
        // re-collect the same data. Stamp `profile_completed_at` on first
        // INSERT so the AuthGuard never bounces the user there. Hints
        // missing -> seed_name falls back to the email-derived placeholder
        // AND `profile_completed_at` stays NULL so the existing onboarding
        // page kicks in as the fallback.
        let names_complete = first_hint.is_some() && last_hint.is_some();
        let (default_first, default_last) = synthetic_name_from_email(email);
        let seed_first = first_hint.clone().unwrap_or(default_first);
        let seed_last = last_hint.clone().unwrap_or(default_last);
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        // `COALESCE` on UPDATE keeps a pre-existing `profile_completed_at`
        // intact (legacy user who already completed mokosh-side onboarding
        // pre-MAPPS-329 - the timestamp stands). On INSERT, when
        // `names_complete`, the `$7` arg is `Some(NOW())`-equivalent (we
        // bind a fresh `Utc::now()`); otherwise `None` so the column stays
        // NULL and the SPA's fallback onboarding page gates.
        let profile_completed_at = if names_complete {
            Some(chrono::Utc::now())
        } else {
            None
        };
        // MAPPS-335: bind `email_verified_at` to the actual outcome
        // reported by the IdP. The placeholder `sub@unresolved.invalid`
        // branch passes `email_verified=false` and lands with a NULL
        // column so downstream gates (invite consumption, admin paths)
        // get the truthful answer.
        let email_verified_at = if email_verified {
            Some(chrono::Utc::now())
        } else {
            None
        };
        sqlx::query(
            r#"
            INSERT INTO users (
                id, tenant_id, email, role, status, email_verified_at, timezone,
                first_name, last_name, profile_completed_at
            )
            VALUES ($1, $2, $3, $4, 'active', $8, 'UTC', $5, $6, $7)
            ON CONFLICT (id) DO UPDATE SET
                email = EXCLUDED.email,
                -- PMS-512: bunyip owns the names; refresh them on every run.
                -- $9 / $10 are the raw hints (NULL when absent or empty), so
                -- COALESCE keeps the existing NOT NULL value rather than
                -- overwriting it with the synthetic EXCLUDED placeholder.
                first_name = COALESCE($9, users.first_name),
                last_name = COALESCE($10, users.last_name),
                email_verified_at = COALESCE(
                    users.email_verified_at,
                    EXCLUDED.email_verified_at
                ),
                profile_completed_at = COALESCE(
                    users.profile_completed_at,
                    EXCLUDED.profile_completed_at
                ),
                updated_at = NOW()
            WHERE users.tenant_id = EXCLUDED.tenant_id
            "#,
        )
        .bind(sub)
        .bind(tenant_id)
        .bind(email)
        .bind(role.as_str())
        .bind(&seed_first)
        .bind(&seed_last)
        .bind(profile_completed_at)
        .bind(email_verified_at)
        .bind(&first_hint)
        .bind(&last_hint)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        self.get_user_by_id(tenant_id, sub).await
    }

    /// PMS-635: replace the JIT placeholder address with the real one once the
    /// IdP reports the email verified. [`Self::upsert_user_from_oidc`] runs on
    /// first sight only, so a user provisioned before verifying kept
    /// `{sub}@unresolved.invalid` forever: every mokosh-side email to them was
    /// addressed to a reserved, non-routable domain and bounced, and every
    /// `email_verified_at IS NOT NULL` gate (invite consumption) stayed shut.
    ///
    /// The `WHERE` clause re-checks the placeholder domain so a concurrent
    /// request can never overwrite a real address, which also makes the repair
    /// idempotent (the second run matches no row and just re-reads).
    /// `email_verified_at` is stamped in the same statement because the caller
    /// only reaches here on a verified address.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn repair_placeholder_email(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        email: &str,
    ) -> AppResult<User> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            r#"
            UPDATE users
            SET email = $3,
                email_verified_at = COALESCE(email_verified_at, NOW()),
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
              AND split_part(email, '@', 2) = $4
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .bind(email)
        .bind(UNRESOLVED_EMAIL_DOMAIN)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        self.get_user_by_id(tenant_id, user_id).await
    }

    /// PMS-512: refresh the read-only `first_name` / `last_name` cache from
    /// bunyip's `given_name` / `family_name` claims for a user who already
    /// has a local row (so [`Self::upsert_user_from_oidc`] never runs again).
    ///
    /// Both columns are `NOT NULL`: a hint that is `None` (or empty after
    /// trimming) binds NULL and `COALESCE` leaves the stored value alone, so
    /// a user whose bunyip profile has no name keeps their seeded synthetic
    /// one. Callers skip this entirely when neither hint differs from the
    /// cached value; the bunyip path runs per request, not per login.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn refresh_names_from_oidc(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        given_name_hint: Option<&str>,
        family_name_hint: Option<&str>,
    ) -> AppResult<User> {
        let first_hint = given_name_hint.map(str::trim).filter(|s| !s.is_empty());
        let last_hint = family_name_hint.map(str::trim).filter(|s| !s.is_empty());
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            r#"
            UPDATE users
            SET first_name = COALESCE($3, first_name),
                last_name = COALESCE($4, last_name),
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .bind(first_hint)
        .bind(last_hint)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        self.get_user_by_id(tenant_id, user_id).await
    }

    /// Lazy backfill (PMS-243): re-home a user row from `from_tenant` to
    /// `to_tenant`, but ONLY if it is currently in `from_tenant`. Used by the
    /// bunyip path to migrate users who were JIT-mirrored into the shared
    /// default tenant before per-org tenants existed (PMS-240): on the first
    /// login whose token resolves to a real org tenant, the user's row moves
    /// there. Scoped to `from_tenant` so a user already correctly placed in
    /// another tenant is never moved, and idempotent (a no-op once moved).
    ///
    /// Only the `users` row moves. Data created while many orgs shared the
    /// default tenant is co-mingled and cannot be auto-attributed to one org,
    /// so it stays put for separate triage (see PMS-243). Returns whether a row
    /// was actually moved.
    pub async fn rehome_user_between_tenants(
        &self,
        user_id: Uuid,
        from_tenant: Uuid,
        to_tenant: Uuid,
    ) -> AppResult<bool> {
        if from_tenant == to_tenant {
            return Ok(false);
        }
        // SAFETY (PMS-285): this moves a `users` row BETWEEN tenants
        // (`from_tenant` -> `to_tenant`), which by definition no single
        // `app.current_tenant` GUC can satisfy under WITH CHECK. It runs only on
        // the pre-session bunyip placement/backfill path (PMS-243/245), so it
        // uses the privileged migrator pool. The `id` + `from_tenant` predicate
        // makes it idempotent and confines it to the one row being rehomed.
        let res = sqlx::query(
            "UPDATE users SET tenant_id = $1, updated_at = NOW() WHERE id = $2 AND tenant_id = $3",
        )
        .bind(to_tenant)
        .bind(user_id)
        .bind(from_tenant)
        .execute(self.db.migrator_pool())
        .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Find a user by `(tenant_id, email)`. PMS-138 closeout of
    /// PMS-4 AC6's residual cross-cutting #8 leak: the previous
    /// shape keyed on email alone and used `ORDER BY created_at
    /// ASC LIMIT 1` as a deterministic-but-wrong tiebreaker for
    /// multi-tenant deployments. Now the lookup binds both
    /// columns; the `users.UNIQUE(tenant_id, email)` constraint
    /// guarantees at most one row.
    async fn find_user_by_email_for_tenant(&self, tenant_id: Uuid, email: &str) -> AppResult<User> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row = sqlx::query_as::<_, UserRow>(
            r#"
            SELECT id, tenant_id, email, password_hash, first_name, last_name,
                   phone, mobile, title, avatar_url, timezone, locale,
                   date_format_string, theme_base_mode, theme_accent_id, role,
                   status, email_verified_at, last_login_at, last_login_country,
                   login_location_alerts, mfa_enabled,
                   mfa_secret, notification_preferences, settings,
                   created_at, updated_at, profile_completed_at,
                   (SELECT own_company_id FROM tenants WHERE id = users.tenant_id) AS own_company_id,
                   (SELECT kind FROM tenants WHERE id = users.tenant_id) AS tenant_kind
            FROM users
            WHERE tenant_id = $1 AND email = $2
            "#,
        )
        .bind(tenant_id)
        .bind(email)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(AppError::Unauthorized)?;

        Ok(row.into())
    }

    /// PMS-502: read the per-account second-factor lockout window for
    /// `user_id`. Tenant-scoped (`begin_with_tenant`) like every other `users`
    /// access on the login path so RLS is satisfied.
    async fn mfa_locked_until(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> AppResult<Option<chrono::DateTime<Utc>>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: (Option<chrono::DateTime<Utc>>,) =
            sqlx::query_as("SELECT mfa_locked_until FROM users WHERE id = $1 AND tenant_id = $2")
                .bind(user_id)
                .bind(tenant_id)
                .fetch_one(&mut *tx)
                .await?;
        tx.commit().await?;
        Ok(row.0)
    }

    /// PMS-502: record one more failed (or replayed) second-factor code for
    /// `user_id` and (re)arm the exponential-backoff lockout once the
    /// failures cross the threshold (see [`mfa_lockout_until`]).
    ///
    /// PMS-693: the increment is relative (`mfa_failed_attempts + 1`) and the
    /// new lock window is derived from the post-increment value inside the
    /// same statement, so a burst of concurrent wrong codes counts every one
    /// of them. Taking no `prior_count` makes the stale-read defect
    /// unrepresentable.
    async fn register_failed_mfa(&self, tenant_id: Uuid, user_id: Uuid) -> AppResult<()> {
        // A NULL window (still under the threshold) leaves any existing
        // lockout in place rather than clearing it.
        let sql = format!(
            "UPDATE users \
             SET mfa_failed_attempts = mfa_failed_attempts + 1, \
                 mfa_locked_until = COALESCE( \
                     NOW() + make_interval(secs => {secs}), mfa_locked_until), \
                 updated_at = NOW() \
             WHERE id = $1 AND tenant_id = $2",
            secs = mfa_lock_seconds_sql("mfa_failed_attempts + 1"),
        );
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(&sql)
            .bind(user_id)
            .bind(tenant_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// PMS-502: an accepted TOTP code advances the anti-replay watermark to
    /// its step and clears the failed-attempt counter + lockout so a later
    /// legitimate login is never penalised.
    ///
    /// PMS-693: the watermark comparison lives in the `WHERE` clause, so the
    /// advance is a compare-and-set. Returns `false` when no row moved, which
    /// means the step was already spent (a replay, possibly by a concurrent
    /// request that won the race); the caller must then fail closed.
    async fn record_mfa_success(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        used_step: i64,
    ) -> AppResult<bool> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let result = sqlx::query(
            "UPDATE users \
             SET mfa_last_used_step = $1, mfa_failed_attempts = 0, \
                 mfa_locked_until = NULL, updated_at = NOW() \
             WHERE id = $2 AND tenant_id = $3 \
               AND (mfa_last_used_step IS NULL OR mfa_last_used_step < $1)",
        )
        .bind(used_step)
        .bind(user_id)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(result.rows_affected() > 0)
    }

    /// PMS-694: clear the failed-attempt counter and lockout after a second
    /// factor that is not a TOTP step (an accepted recovery code), leaving
    /// `mfa_last_used_step` untouched so the anti-replay watermark cannot be
    /// dragged forward by a non-TOTP credential.
    async fn clear_mfa_lockout(&self, tenant_id: Uuid, user_id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            "UPDATE users \
             SET mfa_failed_attempts = 0, mfa_locked_until = NULL, updated_at = NOW() \
             WHERE id = $1 AND tenant_id = $2",
        )
        .bind(user_id)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// PMS-138 backward-compat fallback: when the caller does not
    /// supply a tenant hint, resolve to the default tenant
    /// `Uuid::from_u128(1)`. This matches `OIDC_DEFAULT_TENANT_ID` in
    /// `auth::middleware` (`default_bunyip_tenant_id`), so behaviour
    /// converges across the legacy login path and the Bunyip-issued
    /// at+jwt path. Keep the literal value in lockstep with that site
    /// if it ever changes. PMS-262: the `single-tenant` feature's
    /// `db::tenant::default_tenant_id()` that this used to mirror has
    /// been removed; the default tenant is now infra-only.
    fn resolve_tenant_for_login(hint: Option<Uuid>) -> Uuid {
        hint.unwrap_or_else(|| Uuid::from_u128(1))
    }

    /// MAPPS-396: resolve a tenant slug (e.g. `acme`) to its `tenant_id`
    /// for the standalone login form. Only `status = 'active'` rows
    /// match so a suspended tenant reads as "not a tenant" from the
    /// login endpoint's point of view, matching the fail-closed posture
    /// the portal side already uses for its host-to-tenant mapping
    /// (`src/modules/portal/host_tenant.rs`). Runs on the migrator pool
    /// because the request is pre-auth (no session GUC to set).
    ///
    /// Returns `AppError::Unauthorized` on an unknown or suspended
    /// slug so the response is indistinguishable from a wrong password
    /// (same status the downstream password-verify path returns), so
    /// the endpoint cannot be walked to enumerate tenant slugs.
    async fn resolve_tenant_slug(&self, slug: &str) -> AppResult<Uuid> {
        let row: Option<(Uuid,)> =
            sqlx::query_as("SELECT id FROM tenants WHERE slug = $1 AND status = 'active'")
                .bind(slug)
                .fetch_optional(self.db.migrator_pool())
                .await?;
        row.map(|(id,)| id).ok_or(AppError::Unauthorized)
    }

    /// Validate token and return claims.
    ///
    /// MAPPS-334: explicit `Validation::new(Algorithm::HS256)` instead of
    /// `Validation::default()`. The default already defaults to HS256, but
    /// pinning the algorithm explicitly makes the protocol contract
    /// readable + greppable and stops a future jsonwebtoken bump from
    /// silently changing the default. `validate_exp` stays on; iss / aud
    /// pinning is intentionally deferred to a follow-up ticket: enabling
    /// it today would 401 every legacy access + refresh token in flight
    /// (they were minted without iss / aud claims), forcing a re-login
    /// storm. The mint side now emits iss / aud / nbf so the strict flip
    /// becomes a no-op after a rolling refresh-TTL window has rotated
    /// every live token.
    pub fn decode_token(&self, token: &str) -> AppResult<JwtClaims> {
        let decoding_key = DecodingKey::from_secret(self.jwt_secret.as_bytes());
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        // MAPPS-334: iss / aud pinning is deferred to the follow-up
        // ticket; the mint side now stamps both, but flipping strict
        // validation today would 401 every in-flight legacy token.
        // `Validation::new` defaults `validate_aud = true` with no
        // allowed-aud set, which would reject the newly-minted tokens
        // outright with `InvalidAudience`. Disable it explicitly until
        // the follow-up ticket pins the expected values.
        validation.validate_aud = false;
        // Modest clock-skew tolerance, matching the Bunyip RS verifier
        // at `src/modules/auth/oidc_rs.rs`. 30s is a defensible default.
        validation.leeway = 30;

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
        // The `user_sessions.token_hash` column must never hold a plaintext
        // secret. Generate a random token and store only its SHA-256 hex
        // digest. (The session is keyed and validated by `id` + `tenant_id`;
        // this column is a defence-in-depth opaque handle, not a credential
        // returned to the client.)
        let token_hash = sha256_hex(&generate_token(32));
        let expires_at = if remember_me {
            Utc::now() + Duration::days(30)
        } else {
            Utc::now() + Duration::days(7)
        };

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
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
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        Ok(session_id)
    }

    /// Get session by ID, scoped to a tenant. PMS-4 AC6.
    async fn get_session(&self, tenant_id: Uuid, session_id: Uuid) -> AppResult<Option<Uuid>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let result: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM user_sessions \
             WHERE id = $1 AND tenant_id = $2 AND expires_at > NOW()",
        )
        .bind(session_id)
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await?;

        Ok(result)
    }

    /// Update session last activity. PMS-4 AC6.
    async fn update_session_activity(&self, tenant_id: Uuid, session_id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            "UPDATE user_sessions SET last_activity_at = NOW() \
             WHERE id = $1 AND tenant_id = $2",
        )
        .bind(session_id)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        Ok(())
    }

    /// Update user's last login timestamp. PMS-4 AC6.
    ///
    /// MAPPS-500 (MAPPS-496 stage 2b): identities is now the source of
    /// truth for `last_login_at`; the MAPPS-498 back-mirror propagates
    /// the timestamp to every users row this identity backs across all
    /// tenants they hold a membership in. `tenant_id + user_id` is
    /// still consulted first to resolve the email, so a stray
    /// cross-tenant `user_id` returns no email and the write is
    /// silently a no-op (matches the pre-500 shape which was a
    /// 0-rows-affected users UPDATE for the same case).
    async fn update_last_login(&self, tenant_id: Uuid, user_id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let email: Option<String> =
            sqlx::query_scalar("SELECT email FROM users WHERE id = $1 AND tenant_id = $2")
                .bind(user_id)
                .bind(tenant_id)
                .fetch_optional(&mut *tx)
                .await?;
        let Some(email) = email else {
            return Ok(());
        };
        sqlx::query(
            "UPDATE identities SET last_login_at = NOW(), updated_at = NOW() \
             WHERE lower(email) = lower($1)",
        )
        .bind(&email)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        Ok(())
    }

    /// Reconcile a user's role (PMS-172). The Bunyip RS auth path calls this
    /// to keep the local `users.role` in sync with the role derived from the
    /// Bunyip `bunyip_role` claim. Deliberately a plain UPDATE with no audit
    /// row: this is a system reconciliation on login, not an operator action,
    /// and the caller only invokes it when the role actually changed.
    pub async fn set_user_role(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        role: UserRole,
    ) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            "UPDATE users SET role = $1, updated_at = NOW() WHERE id = $2 AND tenant_id = $3",
        )
        .bind(role.as_str())
        .bind(user_id)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        Ok(())
    }

    /// Generate access and refresh tokens
    async fn generate_tokens(
        &self,
        user: &User,
        session_id: Uuid,
    ) -> AppResult<(String, String, chrono::DateTime<Utc>)> {
        let now = Utc::now();
        let access_expires = now + self.access_token_ttl;
        let refresh_expires = now + self.refresh_token_ttl;

        // MAPPS-334: every freshly minted token now carries iss / aud / nbf
        // so a future strict-validation flip is a no-op once the rolling
        // refresh-TTL window has rotated every live legacy token.
        let iss = MOKOSH_JWT_ISSUER.to_string();
        let aud = MOKOSH_JWT_AUDIENCE.to_string();

        // MAPPS-491 (phase 2): mint carries the active `tenant_memberships.id`.
        // `None` is tolerated (bootstrap paths may run before the identity
        // plane is populated); verify falls back to a repo lookup so a
        // missing `mid` never fails a request.
        let mid = crate::db::identity::MembershipRepo::find_id_by_email_and_tenant(
            self.db.migrator_pool(),
            &user.email,
            user.tenant_id,
        )
        .await
        .ok()
        .flatten();

        let access_claims = JwtClaims {
            sub: user.id,
            tid: user.tenant_id,
            email: user.email.clone(),
            role: user.role,
            iat: now.timestamp(),
            nbf: now.timestamp(),
            exp: access_expires.timestamp(),
            iss: iss.clone(),
            aud: aud.clone(),
            typ: "access".to_string(),
            sid: session_id,
            mid,
        };

        let refresh_claims = JwtClaims {
            sub: user.id,
            tid: user.tenant_id,
            email: user.email.clone(),
            role: user.role,
            iat: now.timestamp(),
            nbf: now.timestamp(),
            exp: refresh_expires.timestamp(),
            iss,
            aud,
            typ: "refresh".to_string(),
            sid: session_id,
            mid,
        };

        let encoding_key = EncodingKey::from_secret(self.jwt_secret.as_bytes());

        let access_token = encode(&Header::default(), &access_claims, &encoding_key)?;
        let refresh_token = encode(&Header::default(), &refresh_claims, &encoding_key)?;

        Ok((access_token, refresh_token, access_expires))
    }

    // ========================================================================
    // MAPPS-492 (MAPPS-474 phase 3): identity-first login primitives.
    // ========================================================================

    /// Mint a short-lived (5 min) identity token used to bridge the login
    /// picker step. `typ="identity"` so `auth_middleware` (which only
    /// accepts `typ="access"`) never treats it as a general-purpose
    /// bearer. Carries `sub=identity_id` and `email` only; `tid` is
    /// `Uuid::nil()` (no tenant is scoped yet); `role`/`sid`/`mid`
    /// are placeholders.
    pub fn mint_identity_token(&self, identity_id: Uuid, email: &str) -> AppResult<String> {
        let now = Utc::now();
        let claims = JwtClaims {
            sub: identity_id,
            tid: Uuid::nil(),
            email: email.to_string(),
            role: UserRole::Technician,
            iat: now.timestamp(),
            nbf: now.timestamp(),
            exp: (now + Duration::minutes(5)).timestamp(),
            iss: MOKOSH_JWT_ISSUER.to_string(),
            aud: MOKOSH_JWT_AUDIENCE.to_string(),
            typ: "identity".to_string(),
            sid: Uuid::nil(),
            mid: None,
        };
        let encoding_key = EncodingKey::from_secret(self.jwt_secret.as_bytes());
        Ok(encode(&Header::default(), &claims, &encoding_key)?)
    }

    /// Verify an identity token and return `(identity_id, email)`.
    /// Enforces `typ == "identity"` and standard exp validation. Wrong
    /// type or expired -> `AppError::Unauthorized`. Mirrors the
    /// `decode_token` validation shape: audience pinning is deferred
    /// (MAPPS-334 follow-up), 30s leeway matches the bunyip RS verifier.
    pub fn decode_identity_token(&self, token: &str) -> AppResult<(Uuid, String)> {
        let decoding_key = DecodingKey::from_secret(self.jwt_secret.as_bytes());
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        validation.validate_aud = false;
        validation.leeway = 30;
        let claims = decode::<JwtClaims>(token, &decoding_key, &validation)
            .map_err(|_| AppError::Unauthorized)?
            .claims;
        if claims.typ != "identity" {
            return Err(AppError::Unauthorized);
        }
        Ok((claims.sub, claims.email))
    }

    /// Identity-first login (MAPPS-492 phase 3). Called when the login
    /// request has no tenant hint. Verifies (email, password) against
    /// `identities`, runs the identity-level MFA gate, enumerates active
    /// memberships, and branches:
    ///
    /// - 1 membership: mints a full session for that tenant and returns
    ///   a scoped `LoginResponse` (single membership auto-scope).
    /// - N > 1: returns a `needs_selection` response with the
    ///   `identity_token` + membership list. Client re-POSTs to
    ///   `/auth/select-tenant` to finish.
    /// - 0: returns a `needs_setup` response with the `identity_token`.
    ///   Phase 4 wires the "create your organization" flow that
    ///   redeems it.
    ///
    /// Login-approval (PMS-658) is intentionally NOT applied on this
    /// branch in phase 3; the follow-up plan tracks integration. The
    /// tenant-hint `login()` path keeps its existing approval gate.
    pub async fn authenticate_identity_first(
        &self,
        request: &LoginRequest,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> AppResult<LoginResponse> {
        // 1. Resolve identity by email. Unauthorized rather than 404 so
        //    email enumeration is no easier than the tenant-hint path.
        let pool = self.db.migrator_pool();
        let identity = crate::db::identity::IdentityRepo::find_by_email(pool, &request.email)
            .await
            .map_err(|_| AppError::Unauthorized)?
            .ok_or(AppError::Unauthorized)?;

        // 2. Password check against the identity plane. Bunyip-only
        //    identities have no hash -> Unauthorized (this path is
        //    password-only, bunyip callers go through the bunyip
        //    verifier in the middleware).
        let hash = identity
            .password_hash
            .as_deref()
            .ok_or(AppError::Unauthorized)?;
        if !verify_password(&request.password, hash)? {
            return Err(AppError::Unauthorized);
        }

        // 3. MFA at the identity level. Mirrors the tenant-hint branch's
        //    contract: no code -> `mfa_required` shape (empty tokens,
        //    user=None). Verification uses the identity's mfa_secret,
        //    which the phase-1 trigger keeps in sync with users.mfa_secret.
        if identity.mfa_enabled {
            let code = request
                .mfa_code
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty());
            match code {
                None => {
                    return Ok(LoginResponse {
                        access_token: String::new(),
                        refresh_token: String::new(),
                        expires_at: Utc::now(),
                        user: None,
                        mfa_required: true,
                        approval_required: false,
                        needs_selection: false,
                        needs_setup: false,
                        identity_token: None,
                        memberships: None,
                    });
                }
                Some(code) => {
                    // Same base32-decode + +/-1 step tolerance the
                    // tenant-hint path uses (see MFA branch above).
                    // MAPPS-497 item 4 (PMS-502 identity extension):
                    // burn the accepted step on the identity plane so
                    // a captured code cannot be replayed against this
                    // path within its ~60s window. Compare-and-set on
                    // `identities.mfa_last_totp_step`; 0 rows
                    // affected == replay.
                    let secret_b32 = identity.mfa_secret.as_deref().ok_or_else(|| {
                        AppError::Internal("MFA enabled without secret".to_string())
                    })?;
                    let secret = crate::utils::totp::base32_decode(secret_b32).map_err(|_| {
                        AppError::Internal("stored MFA secret is corrupt".to_string())
                    })?;
                    let step = match crate::utils::totp::verify(&secret, code, Utc::now(), 1) {
                        Some(step) => step,
                        None => return Err(AppError::Unauthorized),
                    };
                    let advanced = crate::db::identity::IdentityRepo::record_identity_mfa_success(
                        pool,
                        identity.id,
                        step,
                    )
                    .await
                    .map_err(|_| AppError::Unauthorized)?;
                    if !advanced {
                        // Replay of an already-spent step. Fail closed;
                        // the caller sees the same 401 a wrong code
                        // yields, so timing does not leak "replay vs
                        // wrong code" to an attacker.
                        return Err(AppError::Unauthorized);
                    }
                }
            }
        }

        // 4. Enumerate active memberships across all tenants.
        let memberships =
            crate::db::identity::MembershipRepo::list_views_for_identity(pool, identity.id, None)
                .await
                .map_err(|_| AppError::Unauthorized)?;

        match memberships.len() {
            0 => {
                let identity_token = self.mint_identity_token(identity.id, &identity.email)?;
                Ok(LoginResponse {
                    access_token: String::new(),
                    refresh_token: String::new(),
                    expires_at: Utc::now(),
                    user: None,
                    mfa_required: false,
                    approval_required: false,
                    needs_selection: false,
                    needs_setup: true,
                    identity_token: Some(identity_token),
                    memberships: None,
                })
            }
            1 => {
                // MAPPS-497 item 5 (PMS-658 identity-first extension):
                // resolve the user + run the approval gate BEFORE
                // session mint. The tenant-hint `login` path runs the
                // same gate at the same spot; identity-first now
                // matches for the single-membership (auto-scope) case.
                let tenant_id = memberships[0].tenant_id;
                let user = self
                    .find_user_by_email_for_tenant(tenant_id, &identity.email)
                    .await?;
                self.ensure_principal_usable(&user).await?;
                if let Some(response) = self
                    .check_login_approval(
                        &user,
                        request.device_id.as_deref(),
                        request.approval_code.as_deref(),
                        ip_address.as_deref(),
                        user_agent.as_deref(),
                    )
                    .await?
                {
                    return Ok(response);
                }
                self.mint_session_for_user(&user, ip_address, user_agent)
                    .await
            }
            _ => {
                let identity_token = self.mint_identity_token(identity.id, &identity.email)?;
                Ok(LoginResponse {
                    access_token: String::new(),
                    refresh_token: String::new(),
                    expires_at: Utc::now(),
                    user: None,
                    mfa_required: false,
                    approval_required: false,
                    needs_selection: true,
                    needs_setup: false,
                    identity_token: Some(identity_token),
                    memberships: Some(memberships),
                })
            }
        }
    }

    /// MAPPS-492: helper. Given an identity/email that has just
    /// authenticated and a specific tenant_id it holds a membership in,
    /// resolve the users row, run the principal gate, create a session,
    /// mint tokens, and return the scoped `LoginResponse`. Shared by the
    /// auto-scope branch of `authenticate_identity_first`, by
    /// `select_tenant_for_identity`, and (phase 4, MAPPS-493) by the
    /// `/tenants/self-serve` handler which needs to mint a session for
    /// the freshly-created admin of a self-serve tenant.
    pub(crate) async fn mint_session_for_membership(
        &self,
        tenant_id: Uuid,
        email: &str,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> AppResult<LoginResponse> {
        let user = self.find_user_by_email_for_tenant(tenant_id, email).await?;
        self.ensure_principal_usable(&user).await?;
        self.mint_session_for_user(&user, ip_address, user_agent)
            .await
    }

    /// MAPPS-497 item 5: session-mint tail extracted from
    /// `mint_session_for_membership` so the PMS-658 approval gate can
    /// run BETWEEN principal-check and session-mint on the identity-
    /// first branch. Callers that have already resolved a user and run
    /// `ensure_principal_usable` invoke this directly.
    pub(crate) async fn mint_session_for_user(
        &self,
        user: &User,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> AppResult<LoginResponse> {
        let session_id = self
            .create_session(user.tenant_id, user.id, ip_address, user_agent, false)
            .await?;
        let (access_token, refresh_token, expires_at) =
            self.generate_tokens(user, session_id).await?;
        self.update_last_login(user.tenant_id, user.id).await?;

        Ok(LoginResponse {
            access_token,
            refresh_token,
            expires_at,
            user: Some(user.to_current_user()),
            mfa_required: false,
            approval_required: false,
            needs_selection: false,
            needs_setup: false,
            identity_token: None,
            memberships: None,
        })
    }

    /// MAPPS-497 item 5 (PMS-658 identity-first extension): apply the
    /// suspicious-login approval gate on any code path that has already
    /// resolved a `User`. Returns:
    /// - `Ok(None)` when the gate is disabled, the login is not
    ///   suspicious, OR the emailed approval code was supplied and
    ///   verified. Caller continues with session mint.
    /// - `Ok(Some(response))` when suspicious + no code was supplied.
    ///   The response carries `approval_required: true` + empty tokens
    ///   (same shape the tenant-hint `login` path emits); the caller
    ///   propagates it up so the SPA prompts for the code.
    ///
    /// Wired into `authenticate_identity_first` for the auto-scope
    /// branch (single-membership case). The multi-membership picker
    /// branch defers the gate to a follow-up ticket (would require
    /// adding `approval_code` + `device_id` to `SelectTenantRequest`).
    async fn check_login_approval(
        &self,
        user: &User,
        device_id: Option<&str>,
        approval_code: Option<&str>,
        ip: Option<&str>,
        ua: Option<&str>,
    ) -> AppResult<Option<LoginResponse>> {
        if !self.login_approval_enabled {
            return Ok(None);
        }
        let assessment = self.assess_login(user, ip, device_id).await?;
        if !assessment.suspicious {
            return Ok(None);
        }
        match approval_code.map(str::trim).filter(|s| !s.is_empty()) {
            Some(code) => {
                self.verify_login_approval(user.tenant_id, user.id, code)
                    .await?;
                Ok(None)
            }
            None => {
                self.issue_login_approval(user, &assessment, ip, ua).await?;
                Ok(Some(LoginResponse {
                    access_token: String::new(),
                    refresh_token: String::new(),
                    expires_at: Utc::now(),
                    user: None,
                    mfa_required: false,
                    approval_required: true,
                    needs_selection: false,
                    needs_setup: false,
                    identity_token: None,
                    memberships: None,
                }))
            }
        }
    }

    /// MAPPS-492: complete a `needs_selection` login. Consumes an
    /// identity token minted by `authenticate_identity_first`, verifies
    /// the caller has a membership in the chosen tenant, and returns a
    /// full scoped session.
    ///
    /// Errors:
    /// - `Unauthorized` on token decode failure, wrong `typ`, or expiry.
    /// - `NotFound` when the identity holds no active membership in
    ///   `tenant_id`.
    pub async fn select_tenant_for_identity(
        &self,
        identity_token: &str,
        tenant_id: Uuid,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> AppResult<LoginResponse> {
        let (identity_id, email) = self.decode_identity_token(identity_token)?;
        // Reject when the identity holds no active membership in the
        // requested tenant. Consulted via the shared repo helper so the
        // (identity, tenant) status filter stays in one place.
        let membership = crate::db::identity::MembershipRepo::find(
            self.db.migrator_pool(),
            identity_id,
            tenant_id,
        )
        .await
        .map_err(|_| AppError::Unauthorized)?
        .ok_or_else(|| AppError::NotFound("Membership not found for this tenant".to_string()))?;
        if membership.status != "active" {
            return Err(AppError::NotFound("Membership is not active".to_string()));
        }

        self.mint_session_for_membership(tenant_id, &email, ip_address, user_agent)
            .await
    }

    /// Get all active sessions for a user. PMS-260: scoped to the caller's
    /// tenant as well as the user so a `user_id` that exists under more than
    /// one tenant cannot enumerate sessions outside the caller's tenant.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_user_sessions(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        current_session_id: Uuid,
        pagination: &crate::utils::pagination::PaginationParams,
    ) -> AppResult<(Vec<SessionInfo>, u64)> {
        // Tenant is in scope: run both reads under the GUC so RLS scopes them.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM user_sessions \
             WHERE user_id = $1 AND tenant_id = $2 AND expires_at > NOW()",
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_one(&mut *tx)
        .await?;

        let rows = sqlx::query_as::<_, SessionRow>(
            r#"
            SELECT id, ip_address, user_agent, last_activity_at, created_at
            FROM user_sessions
            WHERE user_id = $1 AND tenant_id = $2 AND expires_at > NOW()
            ORDER BY last_activity_at DESC
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;

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
        // SAFETY (PMS-285): self-service delete of one session by its primary key
        // plus owning `user_id`; the handler does not thread the tenant here, so
        // it runs on the migrator pool. The `id` + `user_id` predicate confines
        // it to the caller's own session row. `user_sessions` is RLS-covered, so
        // an app-pool delete with no GUC would silently no-op.
        sqlx::query("DELETE FROM user_sessions WHERE id = $1 AND user_id = $2")
            .bind(session_id)
            .bind(user_id)
            .execute(self.db.migrator_pool())
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
    date_format_string: Option<String>,
    theme_base_mode: Option<String>,
    theme_accent_id: Option<String>,
    role: String,
    status: String,
    email_verified_at: Option<chrono::DateTime<Utc>>,
    last_login_at: Option<chrono::DateTime<Utc>>,
    last_login_country: Option<String>,
    login_location_alerts: bool,
    mfa_enabled: bool,
    mfa_secret: Option<String>,
    notification_preferences: serde_json::Value,
    settings: serde_json::Value,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
    // PMS-681: only `get_user_by_id` (the per-request auth load) selects this;
    // the other UserRow queries omit it, so `#[sqlx(default)]` maps it to None
    // there - those paths never read it.
    #[sqlx(default)]
    password_changed_at: Option<chrono::DateTime<Utc>>,
    profile_completed_at: Option<chrono::DateTime<Utc>>,
    // PMS-413: the owning tenant's own-company id, pulled in by a correlated
    // subquery against `tenants` in each user-load query (tenant-scoped, not a
    // `users` column).
    own_company_id: Option<Uuid>,
    // PMS-791 / MAPPS-462: the owning tenant's `kind` column, pulled in by
    // the same correlated-subquery pattern. `#[sqlx(default)]` so the JIT
    // placement path in middleware (which constructs a UserRow from claims,
    // not a live SELECT) does not have to know about this column.
    #[sqlx(default)]
    tenant_kind: Option<String>,
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
            date_format_string: row.date_format_string,
            theme_base_mode: row.theme_base_mode,
            theme_accent_id: row.theme_accent_id,
            role: UserRole::from_str(&row.role).unwrap_or_default(),
            status: UserStatus::from_str(&row.status).unwrap_or_default(),
            email_verified_at: row.email_verified_at,
            last_login_at: row.last_login_at,
            last_login_country: row.last_login_country,
            login_location_alerts: row.login_location_alerts,
            mfa_enabled: row.mfa_enabled,
            mfa_secret: row.mfa_secret,
            notification_preferences: row.notification_preferences,
            settings: row.settings,
            created_at: row.created_at,
            updated_at: row.updated_at,
            password_changed_at: row.password_changed_at,
            profile_completed_at: row.profile_completed_at,
            own_company_id: row.own_company_id,
            tenant_kind: row.tenant_kind.unwrap_or_default(),
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

/// PMS-502: exponential-backoff lockout schedule for failed second-factor
/// codes. Mirrors the portal-login schedule
/// (`portal::service::lockout_until`) but is STRICTER: a TOTP code is
/// machine-generated, so it has none of the legitimate fat-finger budget a
/// typed password does, and the lockout arms after fewer failures.
///
/// | failed_count | lock window |
/// |--------------|-------------|
/// | 1..=2        | none        |
/// | 3            | 30s         |
/// | 4            | 60s         |
/// | 5            | 120s        |
/// | ...          | ...         |
/// | 10+          | 3600s (cap) |
///
/// Returns `None` while under the threshold (no lockout yet).
///
/// PMS-693: `pub` so the DB-backed parity test can pin
/// [`mfa_lock_seconds_sql`], the SQL twin that `register_failed_mfa` runs,
/// against this Rust definition of the schedule.
#[cfg(feature = "server")]
pub fn mfa_lockout_until(
    failed_count: i32,
    now: chrono::DateTime<Utc>,
) -> Option<chrono::DateTime<Utc>> {
    /// Failed codes tolerated before any lockout arms. Lower than the
    /// password threshold (5): a couple of mistypes is plausible, a third
    /// failed second-factor code is suspicious.
    const LOCKOUT_THRESHOLD: i32 = 3;
    /// Lock window for the first threshold-crossing failure.
    const LOCKOUT_BASE_SECONDS: i64 = 30;
    /// Ceiling on a single lock window.
    const LOCKOUT_MAX_SECONDS: i64 = 3600;

    if failed_count < LOCKOUT_THRESHOLD {
        return None;
    }
    // Exponent capped so the shift cannot overflow; the value is clamped to
    // the max window anyway, so a larger exponent buys nothing.
    let exp = (failed_count - LOCKOUT_THRESHOLD).min(20) as u32;
    let secs = LOCKOUT_BASE_SECONDS
        .checked_shl(exp)
        .unwrap_or(LOCKOUT_MAX_SECONDS)
        .min(LOCKOUT_MAX_SECONDS);
    Some(now + Duration::seconds(secs))
}

/// PMS-693: SQL twin of [`mfa_lockout_until`], as an expression yielding the
/// lock window in seconds (NULL under the threshold) for the post-increment
/// failure count `count_expr`. `register_failed_mfa` needs the schedule
/// evaluated inside its `UPDATE` so the window is derived from the counter
/// value the database just produced, never from a stale read. Keeping it in
/// one place lets `mfa_lock_seconds_sql_matches_rust_schedule`
/// (`tests/auth.rs`) pin it against the Rust helper.
///
/// `count_expr` is a caller-supplied SQL fragment (a column expression or a
/// bind placeholder), never user input.
#[cfg(feature = "server")]
pub fn mfa_lock_seconds_sql(count_expr: &str) -> String {
    format!(
        "CASE WHEN ({count_expr}) >= 3 \
         THEN LEAST(3600, 30 * 2 ^ LEAST(20, ({count_expr}) - 3))::double precision END"
    )
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

/// Lowercase hex SHA-256 of an arbitrary string (avoids storing a plaintext
/// secret in a `TEXT` column such as `user_sessions.token_hash`).
#[cfg(feature = "server")]
fn sha256_hex(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(input.as_bytes());
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Hex SHA-256 of the canonical MFA recovery code form. Mirrors
/// `crate::utils::recovery::hash_code` but returns lowercase hex
/// so the hash fits a `TEXT[]` column instead of `BYTEA[]`. Reusing
/// `recovery::hash_code` keeps canonicalisation (strip whitespace
/// + hyphens, uppercase) consistent with code generation.
#[cfg(feature = "server")]
fn recovery_code_hex_hash(code: &str) -> String {
    let raw = crate::utils::recovery::hash_code(code);
    let mut out = String::with_capacity(raw.len() * 2);
    for b in raw {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Case-insensitive exact-match against an email allowlist. Allowlist entries
/// are expected already lowercased (config parsing lowercases them); the
/// candidate is lowercased here for safety.
#[cfg(feature = "server")]
fn is_allowlisted_email(allowlist: &[String], email: &str) -> bool {
    let email = email.to_ascii_lowercase();
    allowlist.iter().any(|e| e == &email)
}

/// Domain of the JIT placeholder address (`{sub}@unresolved.invalid`) stored
/// when bunyip has not yet verified the user's email. `.invalid` is reserved by
/// RFC 2606 and never resolves, so mail addressed to it is guaranteed to bounce.
pub const UNRESOLVED_EMAIL_DOMAIN: &str = "unresolved.invalid";

/// Whether `email` is mokosh's own JIT placeholder rather than a real address
/// (PMS-635). Used to decide when a mirrored user row still needs repairing.
pub fn is_unresolved_placeholder_email(email: &str) -> bool {
    email
        .rsplit_once('@')
        .is_some_and(|(_, domain)| domain.eq_ignore_ascii_case(UNRESOLVED_EMAIL_DOMAIN))
}

/// Build a placeholder `(first_name, last_name)` from an email for JIT
/// inserts. The OIDC at+jwt has no name claims so the local row needs a
/// default for the NOT NULL schema columns. Splits the local-part on
/// `.`, `_`, or `-` and title-cases the first two segments; the user is
/// expected to overwrite this later from Settings.
///
/// `(first, last)` falls back to `("Mokosh", "User")` when the email
/// is shaped like `…@unresolved.invalid` (mokosh-server's own JIT
/// placeholder, see `ensure_user_from_bunyip`), when the local-part
/// reads as a UUID (the placeholder is `{sub}@unresolved.invalid`, so
/// `sub` lands in the local-part), or when the local-part has no
/// usable segments. Empty strings are still valid VARCHAR values for
/// NOT NULL columns, so the insert always succeeds.
///
/// The earlier version of this helper only checked the segment
/// splitter; on a UUID local-part like `7fa2b249-6132-4abc-90de-...`
/// it happily produced first_name = "7fa2b249", last_name = "6132",
/// which then surfaced on the profile page as a UUID-fragment name.
/// The fallback name is meant to be a clearly-placeholder string the
/// user is expected to overwrite from the profile screen.
/// The `(first, last)` this helper returns when it could not derive anything
/// real. PMS-743 reads it so tenant naming can tell "derived from the user"
/// from "gave up", rather than naming a tenant after the placeholder.
#[cfg(feature = "server")]
pub(crate) const SYNTHETIC_NAME_FALLBACK: (&str, &str) = ("Mokosh", "User");

#[cfg(feature = "server")]
pub(crate) fn synthetic_name_from_email(email: &str) -> (String, String) {
    const FALLBACK: (&str, &str) = SYNTHETIC_NAME_FALLBACK;

    let local = email.split_once('@').map(|(l, _)| l).unwrap_or(email);

    // mokosh-server's own JIT placeholder: there is no real email here,
    // so anything we synthesise from the local-part would just look
    // like the user's bunyip sub. Land on the explicit placeholder.
    if is_unresolved_placeholder_email(email) {
        return (FALLBACK.0.to_string(), FALLBACK.1.to_string());
    }

    let parts: Vec<&str> = local
        .split(['.', '_', '-'])
        .filter(|p| !p.is_empty())
        .collect();

    // UUIDs have five hex-only segments at canonical widths 8-4-4-4-12.
    // If splitting the local-part produced any segment that's hex-only
    // and at least 4 characters, treat the whole local-part as opaque
    // (a stray UUID fragment, or some other machine-generated id) and
    // fall back to the placeholder rather than name the user after a
    // database id. Real first/last names contain non-hex letters.
    let looks_like_uuid_fragment = parts
        .iter()
        .any(|p| p.len() >= 4 && p.chars().all(|c| c.is_ascii_hexdigit()));
    if looks_like_uuid_fragment {
        return (FALLBACK.0.to_string(), FALLBACK.1.to_string());
    }

    let titlecase = |s: &str| {
        let mut chars = s.chars();
        match chars.next() {
            Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
            None => String::new(),
        }
    };
    match parts.as_slice() {
        [] => (FALLBACK.0.to_string(), FALLBACK.1.to_string()),
        [one] => (titlecase(one), String::new()),
        [one, two, ..] => (titlecase(one), titlecase(two)),
    }
}

// Post-code-review finding #10: agent-side login-location types moved
// to `crate::utils::login_location`. Both the enum and the branch
// function are aliased through so existing call sites at auth/service.rs
// keep resolving.
#[cfg(feature = "server")]
use crate::utils::login_location::{login_location_decision, LoginLocationDecision};

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

    // ── mfa_lockout_until (PMS-502) ────────────────────────────────────────

    #[test]
    fn mfa_no_lockout_under_threshold() {
        let now = Utc::now();
        for count in 0..3 {
            assert!(
                mfa_lockout_until(count, now).is_none(),
                "count {count} should not lock the second factor"
            );
        }
    }

    #[test]
    fn mfa_lockout_arms_at_threshold() {
        let now = Utc::now();
        let until = mfa_lockout_until(3, now).expect("3rd failed code locks");
        assert_eq!((until - now).num_seconds(), 30);
    }

    #[test]
    fn mfa_lockout_window_doubles() {
        let now = Utc::now();
        assert_eq!((mfa_lockout_until(4, now).unwrap() - now).num_seconds(), 60);
        assert_eq!(
            (mfa_lockout_until(5, now).unwrap() - now).num_seconds(),
            120
        );
        assert_eq!(
            (mfa_lockout_until(6, now).unwrap() - now).num_seconds(),
            240
        );
    }

    #[test]
    fn mfa_lockout_window_is_capped() {
        let now = Utc::now();
        // Far past the doubling sequence: clamped to the 1h ceiling, and a
        // huge count must not panic on shift overflow.
        assert_eq!(
            (mfa_lockout_until(50, now).unwrap() - now).num_seconds(),
            3600
        );
        assert_eq!(
            (mfa_lockout_until(i32::MAX, now).unwrap() - now).num_seconds(),
            3600
        );
    }

    /// PMS-693: the persistent attempt counters must never go back to being
    /// computed from a value read in an earlier transaction. Fail if any
    /// counter write assigns a bind placeholder instead of incrementing the
    /// column, or if either `register_failed_*` regrows a count parameter.
    #[test]
    fn attempt_counters_are_incremented_in_sql() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let sources = [
            root.join("src/modules/auth/service.rs"),
            root.join("src/modules/portal/service.rs"),
        ];
        let banned = [
            concat!("SET mfa_failed_attempts", " = $"),
            concat!("SET portal_failed_login_count", " = $"),
            concat!("SET attempts", " = $"),
            concat!(
                "register_failed_mfa(&self, tenant_id: Uuid, ",
                "user_id: Uuid,"
            ),
            concat!("register_failed_login(&self, ", "contact_id: Uuid,"),
        ];
        let mut hits: Vec<String> = Vec::new();
        for path in sources {
            let text = std::fs::read_to_string(&path).expect("read source file");
            for needle in banned {
                if text.contains(needle) {
                    hits.push(format!("{}: {needle}", path.display()));
                }
            }
        }
        assert!(
            hits.is_empty(),
            "a stale-read attempt counter is back: {hits:?}"
        );
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

    /// PMS-635: the predicate that decides whether a mirrored row still needs
    /// its address repaired. It must match the JIT placeholder (in any case)
    /// and nothing that could be a real, routable address.
    #[test]
    fn placeholder_email_predicate_matches_only_the_jit_placeholder() {
        let sub = "7fa2b249-6132-4abc-90de-1234567890ab";
        assert!(is_unresolved_placeholder_email(&format!(
            "{sub}@{UNRESOLVED_EMAIL_DOMAIN}"
        )));
        assert!(is_unresolved_placeholder_email(&format!(
            "{sub}@UNRESOLVED.INVALID"
        )));
        assert!(!is_unresolved_placeholder_email("david@niceguyit.biz"));
        assert!(
            !is_unresolved_placeholder_email("david@unresolved.invalid.example.com"),
            "a real domain that merely contains the placeholder is not a placeholder"
        );
        assert!(!is_unresolved_placeholder_email("no-at-sign"));
    }

    // ── synthetic_name_from_email ──────────────────────────────────────────

    #[test]
    fn synthetic_name_unresolved_invalid_returns_placeholder() {
        // The JIT placeholder shape: `{sub}@unresolved.invalid`. The local-
        // part is the bunyip user uuid and must not surface as a "name".
        let (first, last) =
            synthetic_name_from_email("7fa2b249-6132-4abc-90de-1234567890ab@unresolved.invalid");
        assert_eq!(first, "Mokosh");
        assert_eq!(last, "User");
    }

    #[test]
    fn synthetic_name_uuid_fragment_local_part_returns_placeholder() {
        // Even if the domain is real, a UUID-shaped local-part is a database
        // id and must not be split into a "first / last name".
        let (first, last) =
            synthetic_name_from_email("7fa2b249-6132-4abc-90de-1234567890ab@example.com");
        assert_eq!(first, "Mokosh");
        assert_eq!(last, "User");
    }

    #[test]
    fn synthetic_name_normal_first_last() {
        let (first, last) = synthetic_name_from_email("alex.foo@a8n.run");
        assert_eq!(first, "Alex");
        assert_eq!(last, "Foo");
    }

    #[test]
    fn synthetic_name_first_only() {
        let (first, last) = synthetic_name_from_email("alex@a8n.run");
        assert_eq!(first, "Alex");
        assert_eq!(last, "");
    }

    #[test]
    fn synthetic_name_underscore_separator() {
        let (first, last) = synthetic_name_from_email("first_last@a8n.run");
        assert_eq!(first, "First");
        assert_eq!(last, "Last");
    }

    // PMS-657: None -> Record / same -> Unchanged / differ -> Alert decides
    // whether a login sends the new-location email.
    #[test]
    fn login_location_decision_branches() {
        assert_eq!(
            login_location_decision(None, "US"),
            LoginLocationDecision::Record
        );
        assert_eq!(
            login_location_decision(Some("US"), "US"),
            LoginLocationDecision::Unchanged
        );
        assert_eq!(
            login_location_decision(Some("US"), "GB"),
            LoginLocationDecision::Alert
        );
    }

    // PMS-657: only genuinely public client IPs may drive a country-change
    // alert; loopback / RFC1918 / link-local / unspecified must be ignored.
    #[test]
    fn non_public_ip_detection() {
        let non_public = [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.10.10",
            "0.0.0.0",
            "::1",
            "::",
            "fd00::1",
            "fe80::1",
        ];
        for ip in non_public {
            assert!(
                AuthService::is_non_public_ip(&ip.parse().unwrap()),
                "{ip} should be treated as non-public"
            );
        }

        let public = ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"];
        for ip in public {
            assert!(
                !AuthService::is_non_public_ip(&ip.parse().unwrap()),
                "{ip} should be treated as public"
            );
        }
    }
}
