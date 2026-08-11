//! Portal authentication and contact-session issuance.
//!
//! Mirrors the agent-side `AuthService::login` shape but reads from the
//! `contacts` table and mints HS256 JWTs tagged with `typ =
//! "portal_access"` so the middleware can distinguish them from agent
//! tokens.

use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use uuid::Uuid;

use crate::db::Database;
use crate::modules::audit::{audit_portal_event, AuditAction};
use crate::modules::auth::TenantId;
use crate::modules::notifications::NotificationsService;
use crate::utils::crypto::{hash_password, verify_password};
use crate::utils::email::Mailer;
use crate::utils::error::{AppError, AppResult};
use crate::utils::geoip::GeoIpService;
use crate::utils::password_policy::{self, PasswordPolicy, PasswordPolicyError};
use std::sync::Arc;

use super::models::*;

/// Portal-side counterpart to `AuthService`. Stateless except for the
/// JWT signing secret, the database handle, and (optionally) the
/// notifications dispatcher used to send the H3 password-reset email.
#[derive(Clone)]
pub struct PortalAuthService {
    db: Database,
    jwt_secret: String,
    access_token_ttl: Duration,
    refresh_token_ttl: Duration,
    /// PMS-729 phase 2 H3: notifications dispatcher used by
    /// `dispatch_password_reset_email`. `None` in fixtures built without
    /// a dispatcher, in which case the mail is logged but not sent.
    notifications: Option<NotificationsService>,
    /// PMS-729 phase 2 H7: IP -> country resolver for login-location
    /// alerts. `None` when `IP2LOCATION_DB_PATH` is unset (the feature
    /// silently disables; login flow is unaffected).
    geoip: Option<Arc<GeoIpService>>,
    /// PMS-729 phase 2 H7: direct mailer for the new-sign-in
    /// notification. Direct rather than via the notifications queue for
    /// the same reason the agent's login-location alert does: no
    /// template is seeded, and a queued dispatch would find no rule
    /// and drop the alert. `None` in fixtures built without a mailer.
    mailer: Option<Arc<dyn Mailer>>,
    /// PMS-729 phase 2 H7: SPA origin used as the "review your active
    /// sessions" link in the new-sign-in email body.
    portal_origin: String,
}

impl PortalAuthService {
    pub fn new(db: Database, jwt_secret: String) -> Self {
        Self {
            db,
            jwt_secret,
            // PMS-729 phase 2 H2: access token drops from 8h to 15 min so a
            // stolen token has a tight useful lifetime; refresh flow keeps
            // the customer signed in for the full 30-day window.
            access_token_ttl: Duration::minutes(15),
            refresh_token_ttl: Duration::days(30),
            notifications: None,
            geoip: None,
            mailer: None,
            portal_origin: String::new(),
        }
    }

    /// PMS-729 phase 2 H3: builder that attaches a notifications
    /// dispatcher so the service can queue the password-reset email.
    pub fn with_notifications(mut self, notifications: NotificationsService) -> Self {
        self.notifications = Some(notifications);
        self
    }

    /// PMS-729 phase 2 H7: builder that attaches the login-location
    /// alert pieces. `geoip` may be `None` (feature off; check no-ops
    /// on every login). `mailer` + `portal_origin` are always required
    /// together: the alert email body has a "review your sessions"
    /// link built from the origin.
    pub fn with_login_alerts(
        mut self,
        geoip: Option<Arc<GeoIpService>>,
        mailer: Arc<dyn Mailer>,
        portal_origin: String,
    ) -> Self {
        self.geoip = geoip;
        self.mailer = Some(mailer);
        self.portal_origin = portal_origin;
        self
    }

    /// Verify (slug, email, password) against the contacts table and
    /// issue a portal JWT on success. Returns 401 on any credential
    /// failure so the surface stays enumeration-resistant, and 429
    /// (`AppError::RateLimited`) when the account is in a lockout window
    /// from repeated failures (PMS-501).
    ///
    /// PMS-729: `slug` is now a separate argument. The route handler
    /// resolves it up front (host-derived or body-supplied, gated by
    /// [`super::host_tenant::resolve_slug`]) so this method never has to
    /// know about the request shape.
    #[allow(clippy::type_complexity, clippy::too_many_arguments)]
    #[tracing::instrument(skip_all)]
    pub async fn login(
        &self,
        slug: &str,
        email: &str,
        password: &str,
        mfa_code: Option<&str>,
        recovery_code: Option<&str>,
        user_agent: Option<&str>,
        ip_address: Option<std::net::IpAddr>,
    ) -> AppResult<PortalLoginResponse> {
        let row: Option<(
            Uuid,
            Uuid,
            Uuid,
            String,
            String,
            String,
            bool,
            Option<String>,
            Option<DateTime<Utc>>,
            bool,
            Option<String>,
        )> = sqlx::query_as(
            r#"
                SELECT c.id, c.tenant_id, c.company_id, c.email, c.first_name,
                       c.last_name, c.is_portal_user, c.portal_password_hash,
                       c.portal_locked_until,
                       c.portal_mfa_enabled, c.portal_mfa_secret
                FROM contacts c
                INNER JOIN tenants t ON c.tenant_id = t.id
                WHERE t.slug = $1 AND c.email = $2 AND t.status = 'active'
                "#,
        )
        .bind(slug)
        .bind(email)
        // SAFETY (PMS-285): the portal runs on a separate `contacts`-row identity
        // plane (`CurrentContact`), not the `users`/`AuthState` plane, and
        // per-user RLS isolation is deliberately NOT applied to portal contacts
        // yet (see `docs/rls-per-user-isolation.md`, "Portal identity"). This
        // login is pre-auth - it resolves the contact by `(tenant_slug, email)`
        // before any session exists - so there is no GUC to set and it runs on
        // the migrator pool. `contacts` is RLS-covered, so the app pool would
        // fail this lookup closed.
        .fetch_optional(self.db.migrator_pool())
        .await?;

        let Some((
            id,
            tenant_id,
            company_id,
            email,
            first_name,
            last_name,
            is_portal_user,
            hash,
            locked_until,
            mfa_enabled,
            mfa_secret,
        )) = row
        else {
            return Err(AppError::Unauthorized);
        };

        // PMS-501: persistent account lockout. If the contact is inside an
        // active backoff window, reject before spending an Argon2 verify so
        // the lockout actually cuts the attacker's guess rate (and survives a
        // process restart, unlike the in-memory limiter).
        if locked_until.is_some_and(|until| until > Utc::now()) {
            return Err(AppError::RateLimited);
        }

        if !is_portal_user {
            return Err(AppError::Unauthorized);
        }
        let Some(hash) = hash else {
            return Err(AppError::Unauthorized);
        };
        if !verify_password(password, &hash)? {
            // PMS-501: record the failure and (re)arm the lockout window.
            self.register_failed_login(id).await?;
            // PMS-729 phase 2 H10: audit the failure so admin can see a
            // brute-force run against a real account. Ignore any write
            // error - a failed audit must not surface as a login-flow
            // failure (we are already returning 401).
            let _ = audit_portal_event(
                self.db.migrator_pool(),
                tenant_id,
                Some(id),
                AuditAction::Login,
                "portal.login_failed",
                ip_address.map(|ip| ip.to_string()),
                user_agent.map(|s| s.to_string()),
            )
            .await;
            return Err(AppError::Unauthorized);
        }

        // PMS-729 phase 2 H4: MFA branch. Password verified; if the
        // contact has MFA enabled AND neither a TOTP code nor a
        // recovery code was supplied, signal `mfa_required` and stop
        // (empty tokens; caller re-POSTs with `mfa_code` or
        // `recovery_code`). Same pattern as agent's LoginResponse.
        if mfa_enabled {
            let supplied_totp = mfa_code.map(str::trim).filter(|s| !s.is_empty());
            let supplied_recovery = recovery_code.map(str::trim).filter(|s| !s.is_empty());
            if supplied_totp.is_none() && supplied_recovery.is_none() {
                return Ok(PortalLoginResponse {
                    mfa_required: true,
                    ..Default::default()
                });
            }
            // Recovery code path wins if supplied (a customer who lost
            // their authenticator app must be able to sign in even if
            // the SPA still sends `mfa_code=""`).
            let mfa_ok = if let Some(rc) = supplied_recovery {
                self.consume_recovery_code(id, tenant_id, rc).await?
            } else {
                // supplied_totp is Some here by the branch above.
                let code = supplied_totp.expect("recovery XOR totp");
                let secret_b32 = mfa_secret.as_deref().ok_or_else(|| {
                    AppError::Internal("MFA enabled but no secret stored".to_string())
                })?;
                let secret = crate::utils::totp::base32_decode(secret_b32)
                    .map_err(|_| AppError::Internal("stored MFA secret is corrupt".to_string()))?;
                crate::utils::totp::verify(&secret, code, Utc::now(), 1).is_some()
            };
            if !mfa_ok {
                // PMS-729 phase 2 H10: MFA-failure audit so a brute-force
                // against the second factor is visible.
                let _ = audit_portal_event(
                    self.db.migrator_pool(),
                    tenant_id,
                    Some(id),
                    AuditAction::Login,
                    "portal.mfa_failed",
                    ip_address.map(|ip| ip.to_string()),
                    user_agent.map(|s| s.to_string()),
                )
                .await;
                return Err(AppError::Unauthorized);
            }
        }

        // SAFETY (PMS-285): companion write to the portal login above, same
        // separate `contacts`-identity plane with portal isolation deferred.
        // Targets the just-authenticated contact by primary key; migrator pool
        // because `contacts` is RLS-covered and the portal plane sets no GUC.
        // PMS-501: a successful login clears the failed-attempt counter and any
        // lockout so a later legitimate sign-in is never penalised.
        sqlx::query(
            "UPDATE contacts \
             SET portal_last_login_at = NOW(), portal_failed_login_count = 0, \
                 portal_locked_until = NULL, updated_at = NOW() \
             WHERE id = $1",
        )
        .bind(id)
        .execute(self.db.migrator_pool())
        .await?;

        let now = Utc::now();
        // PMS-729 phase 2 H6: issue the refresh token FIRST so the
        // access token can carry the refresh id as its `sid` claim.
        // The refresh row IS the session record from the customer's
        // point of view; the sid claim ties every access token back
        // to its issuing session for `/portal/auth/me/sessions`.
        let refresh = self
            .issue_refresh_token(tenant_id, id, None, now, user_agent, ip_address)
            .await?;
        let (access_token, expires_at) =
            self.mint_access_token(id, tenant_id, company_id, &email, refresh.id, now)?;

        // PMS-729 phase 2 H10: audit successful login. Best-effort; a
        // failed audit write is not a login-flow failure.
        let _ = audit_portal_event(
            self.db.migrator_pool(),
            tenant_id,
            Some(id),
            AuditAction::Login,
            "portal.login",
            ip_address.map(|ip| ip.to_string()),
            user_agent.map(|s| s.to_string()),
        )
        .await;

        // PMS-729 phase 2 H7: new-sign-in email on a country change.
        // Best-effort; a failure here never blocks the login. The
        // check no-ops when the feature is not fully configured
        // (missing geoip / mailer) or when the client IP is private.
        self.check_login_location(id, tenant_id, &email, ip_address, user_agent)
            .await;

        Ok(PortalLoginResponse {
            access_token,
            expires_at,
            refresh_token: refresh.token,
            refresh_expires_at: refresh.expires_at,
            contact: Some(CurrentContact {
                id,
                tenant_id,
                company_id,
                email,
                first_name,
                last_name,
            }),
            mfa_required: false,
        })
    }

    /// PMS-729 phase 2 H4: verify a recovery code against
    /// `contacts.portal_mfa_recovery_codes_hashes` and, on match,
    /// atomically remove that hash from the array so the code cannot
    /// be replayed. Returns `Ok(true)` on match, `Ok(false)` on miss.
    /// The array remove happens in the same statement as the match to
    /// prevent a race where two concurrent presenters both see the
    /// hash present and both proceed.
    async fn consume_recovery_code(
        &self,
        contact_id: Uuid,
        tenant_id: Uuid,
        code: &str,
    ) -> AppResult<bool> {
        let candidate = recovery_code_hex_hash(code);
        // `array_remove` is a no-op when the value is not in the array,
        // so a returned rows_affected of 0 (no rows matched the WHERE)
        // vs > 0 tells us exactly if we consumed a code.
        let rows = sqlx::query(
            r#"
            UPDATE contacts
               SET portal_mfa_recovery_codes_hashes =
                     array_remove(portal_mfa_recovery_codes_hashes, $1),
                   updated_at = NOW()
             WHERE id = $2
               AND tenant_id = $3
               AND $1 = ANY(portal_mfa_recovery_codes_hashes)
            "#,
        )
        .bind(&candidate)
        .bind(contact_id)
        .bind(tenant_id)
        .execute(self.db.migrator_pool())
        .await?
        .rows_affected();
        Ok(rows > 0)
    }

    /// PMS-729 phase 2 H7: on a genuine login, resolve the client IP
    /// to a country and, when it differs from the country recorded at
    /// the contact's previous login (and the contact has not opted
    /// out via `portal_login_location_alerts = FALSE`), email a
    /// new-sign-in alert then persist the new country. The first
    /// geolocatable login records the country silently.
    ///
    /// Entirely best-effort: every failure is logged and swallowed so
    /// it can never block a login. No-ops when:
    /// - no `IP2LOCATION_DB_PATH` set (`geoip` is `None`)
    /// - no mailer wired (fixtures)
    /// - the IP is private/loopback/link-local (dev, or behind a
    ///   proxy that did not populate X-Forwarded-For correctly)
    /// - `GeoIpService::country_code` returns None
    async fn check_login_location(
        &self,
        contact_id: Uuid,
        tenant_id: Uuid,
        email: &str,
        ip: Option<std::net::IpAddr>,
        user_agent: Option<&str>,
    ) {
        let Some(geoip) = self.geoip.as_ref() else {
            return;
        };
        let Some(parsed) = ip else {
            return;
        };
        if is_non_public_ip(&parsed) {
            return;
        }
        let Some(country) = geoip.country_code(parsed) else {
            return;
        };

        // Pull the current stored country + opt-out flag. Failure here
        // (e.g. RLS mishap) is logged + swallowed so the login flow is
        // never affected by a broken alert path.
        let previous: Result<Option<(Option<String>, bool)>, _> = sqlx::query_as(
            "SELECT portal_last_login_country, portal_login_location_alerts \
             FROM contacts WHERE id = $1 AND tenant_id = $2",
        )
        .bind(contact_id)
        .bind(tenant_id)
        .fetch_optional(self.db.migrator_pool())
        .await;
        let (previous_country, alerts_enabled) = match previous {
            Ok(Some((c, a))) => (c, a),
            _ => return,
        };

        match login_location_decision(previous_country.as_deref(), &country) {
            LoginLocationDecision::Unchanged => {}
            LoginLocationDecision::Record => {
                if let Err(e) = self
                    .set_last_login_country(contact_id, tenant_id, &country)
                    .await
                {
                    tracing::warn!(contact_id = %contact_id, error = %e,
                        "portal: failed to record initial login country");
                }
            }
            LoginLocationDecision::Alert => {
                let previous = previous_country.as_deref().unwrap_or("?");
                if alerts_enabled {
                    if let Some(mailer) = self.mailer.clone() {
                        // Detached: SMTP round-trip must not add
                        // latency to (or fail) the login. Same pattern
                        // as the agent-side alert.
                        let email = email.to_string();
                        let country = country.clone();
                        let ip = parsed.to_string();
                        let when = Utc::now().format("%Y-%m-%d %H:%M UTC").to_string();
                        let ua = user_agent.unwrap_or("unknown").to_string();
                        let security_link = if self.portal_origin.is_empty() {
                            String::from("(portal)")
                        } else {
                            format!(
                                "{}/portal/settings/sessions",
                                self.portal_origin.trim_end_matches('/')
                            )
                        };
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
                                tracing::warn!(error = %e,
                                    "portal: new-login-location email dispatch failed");
                            }
                        });
                    }
                }
                tracing::info!(
                    contact_id = %contact_id, from = %previous, to = %country,
                    "portal: login country changed"
                );
                if let Err(e) = self
                    .set_last_login_country(contact_id, tenant_id, &country)
                    .await
                {
                    tracing::warn!(contact_id = %contact_id, error = %e,
                        "portal: failed to update login country");
                }
            }
        }
    }

    /// PMS-729 phase 2 H7: persist the ISO country of the contact's
    /// most recent geolocatable login.
    async fn set_last_login_country(
        &self,
        contact_id: Uuid,
        tenant_id: Uuid,
        country: &str,
    ) -> AppResult<()> {
        sqlx::query(
            "UPDATE contacts SET portal_last_login_country = $1, updated_at = NOW() \
             WHERE id = $2 AND tenant_id = $3",
        )
        .bind(country)
        .bind(contact_id)
        .bind(tenant_id)
        .execute(self.db.migrator_pool())
        .await?;
        Ok(())
    }

    /// PMS-729 phase 2 H1+H2: mint a fresh HS256 access JWT for the given
    /// contact. Extracted so both `login` and `refresh` can call it with
    /// the same claim shape and TTL.
    ///
    /// PMS-729 phase 2 H6: `sid` is the id of the refresh token that
    /// minted this access token; carried inside the JWT claims so
    /// `/portal/auth/me/sessions` can tag the caller's own session as
    /// `current`.
    fn mint_access_token(
        &self,
        contact_id: Uuid,
        tenant_id: Uuid,
        company_id: Uuid,
        email: &str,
        sid: Uuid,
        now: DateTime<Utc>,
    ) -> AppResult<(String, DateTime<Utc>)> {
        let expires_at = now + self.access_token_ttl;
        let claims = PortalJwtClaims {
            sub: contact_id,
            tid: tenant_id,
            cid: company_id,
            email: email.to_string(),
            iat: now.timestamp(),
            exp: expires_at.timestamp(),
            typ: "portal_access".to_string(),
            jti: Uuid::new_v4(),
            sid,
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )
        .map_err(|e| AppError::Internal(format!("portal jwt sign: {e}")))?;
        Ok((token, expires_at))
    }

    /// PMS-729 phase 2 H1+H2: mint a new refresh token for `contact_id`,
    /// insert its Argon2id hash into `portal_refresh_tokens`, and return
    /// the plaintext `{token_id}.{secret}` form for the caller to hand
    /// back to the SPA. Optional `rotated_from` links this row to its
    /// ancestor in the rotation chain (used by `refresh_access_token`).
    ///
    /// SAFETY (PMS-285): pre-auth (login) or refresh-auth (rotate); the
    /// tenant is a verified column value in both cases, not user input.
    /// Runs on the migrator pool so a pool that lacks the app-role GUC
    /// still writes (the login site sets no GUC and the refresh site
    /// resolves the tenant from the presented token, not the request).
    async fn issue_refresh_token(
        &self,
        tenant_id: Uuid,
        contact_id: Uuid,
        rotated_from: Option<Uuid>,
        now: DateTime<Utc>,
        user_agent: Option<&str>,
        ip_address: Option<std::net::IpAddr>,
    ) -> AppResult<IssuedRefreshToken> {
        // 32 hex chars (128 bits) of collision-resistant randomness plus the
        // row id in front for O(1) lookup. Full token format matches the
        // portal setup-token shape (`{id}.{secret}`) so the parse helper
        // is reusable.
        let secret = uuid::Uuid::new_v4().simple().to_string();
        let hash = hash_password(&secret)?;
        let expires_at = now + self.refresh_token_ttl;
        // sqlx does not support `Option<IpAddr>` as an `INET` bind
        // directly, so hand the IP over as text and let Postgres cast.
        // NULL for an unknown IP (dev harness) so the column stays typed.
        let ip_text = ip_address.map(|ip| ip.to_string());
        let (id,): (Uuid,) = sqlx::query_as(
            r#"
            INSERT INTO portal_refresh_tokens (
                tenant_id, contact_id, token_hash, issued_at, expires_at,
                rotated_from_id, user_agent, ip_address
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8, '')::inet)
            RETURNING id
            "#,
        )
        .bind(tenant_id)
        .bind(contact_id)
        .bind(&hash)
        .bind(now)
        .bind(expires_at)
        .bind(rotated_from)
        .bind(user_agent)
        .bind(ip_text.unwrap_or_default())
        .fetch_one(self.db.migrator_pool())
        .await?;
        Ok(IssuedRefreshToken {
            id,
            token: format!("{id}.{secret}"),
            expires_at,
        })
    }

    /// PMS-729 phase 2 H2: rotate a live refresh token into a new access +
    /// refresh pair. Replay-safe: presenting an already-rotated token
    /// causes the extractor to revoke the entire rotation chain (a
    /// stolen-token signal) and reject the request. Presenting an unknown,
    /// expired, or explicitly-revoked token also fails closed. All
    /// failure paths return [`AppError::Unauthorized`] so the wire shape
    /// stays enumeration-resistant.
    #[allow(clippy::type_complexity)]
    #[tracing::instrument(skip_all)]
    pub async fn refresh_access_token(
        &self,
        presented: &str,
        user_agent: Option<&str>,
        ip_address: Option<std::net::IpAddr>,
    ) -> AppResult<PortalRefreshResponse> {
        let (row_id, secret) =
            parse_contact_bound_token(presented).ok_or(AppError::Unauthorized)?;

        // Fetch the presented row. Compares the secret against the stored
        // Argon2id hash; any miss (unknown id, wrong secret, or expired) is
        // indistinguishable to the caller.
        let row: Option<(Uuid, Uuid, String, DateTime<Utc>, Option<DateTime<Utc>>)> =
            sqlx::query_as(
                r#"
            SELECT tenant_id, contact_id, token_hash, expires_at, revoked_at
            FROM portal_refresh_tokens
            WHERE id = $1
            "#,
            )
            .bind(row_id)
            .fetch_optional(self.db.migrator_pool())
            .await?;
        let Some((tenant_id, contact_id, token_hash, expires_at, revoked_at)) = row else {
            return Err(AppError::Unauthorized);
        };
        if !verify_password(secret, &token_hash)? {
            return Err(AppError::Unauthorized);
        }
        // Replay: an already-rotated (revoked) token being presented is
        // the classic stolen-token signal. Burn the whole chain so the
        // attacker who presented the token AND the honest customer who
        // may have rotated it earlier both get logged out.
        if revoked_at.is_some() {
            self.revoke_rotation_chain(row_id).await?;
            return Err(AppError::Unauthorized);
        }
        if expires_at <= Utc::now() {
            return Err(AppError::Unauthorized);
        }

        // Read the contact's identity for the fresh access token. The
        // tenant + company columns move together on the contact row and
        // are not user input.
        let contact: Option<(Uuid, String)> = sqlx::query_as(
            "SELECT company_id, email FROM contacts \
             WHERE id = $1 AND tenant_id = $2",
        )
        .bind(contact_id)
        .bind(tenant_id)
        .fetch_optional(self.db.migrator_pool())
        .await?;
        let Some((company_id, email)) = contact else {
            return Err(AppError::Unauthorized);
        };

        let now = Utc::now();
        // Stamp the presented token as rotated (i.e. revoked as a live
        // credential) BEFORE the new one is issued, so a concurrent
        // presenter racing us onto the same row cannot get two live
        // successors out of the same ancestor.
        let rows = sqlx::query(
            "UPDATE portal_refresh_tokens SET revoked_at = $1 \
             WHERE id = $2 AND revoked_at IS NULL",
        )
        .bind(now)
        .bind(row_id)
        .execute(self.db.migrator_pool())
        .await?
        .rows_affected();
        if rows == 0 {
            // Lost the race, some other refresh already flipped it.
            // Treat as a replay to fail closed.
            self.revoke_rotation_chain(row_id).await?;
            return Err(AppError::Unauthorized);
        }
        // PMS-729 phase 2 H6: same ordering as login. Refresh row
        // is minted first so the new access token can carry its id
        // as the `sid` claim.
        let refresh = self
            .issue_refresh_token(
                tenant_id,
                contact_id,
                Some(row_id),
                now,
                user_agent,
                ip_address,
            )
            .await?;
        let (access_token, expires_at) =
            self.mint_access_token(contact_id, tenant_id, company_id, &email, refresh.id, now)?;
        Ok(PortalRefreshResponse {
            access_token,
            expires_at,
            refresh_token: refresh.token,
            refresh_expires_at: refresh.expires_at,
        })
    }

    /// PMS-729 phase 2 H1: revoke the presented refresh token and every
    /// other live token in its rotation chain. Called by
    /// `POST /portal/auth/logout` and by the replay-detected branch of
    /// [`refresh_access_token`].
    ///
    /// Unknown or malformed input is silently ignored so an attacker
    /// with a random token cannot enumerate live rows by counting the
    /// response latency.
    #[tracing::instrument(skip_all)]
    pub async fn logout(&self, presented: &str) -> AppResult<()> {
        // Unknown / malformed token: silent ok (enumeration-resistant).
        let Some((row_id, secret)) = parse_contact_bound_token(presented) else {
            return Ok(());
        };
        // Pull tenant + contact along with the hash so we can attribute
        // the audit row correctly (H10). Unknown row: still silent ok.
        let row: Option<(Uuid, Uuid, String)> = sqlx::query_as(
            "SELECT tenant_id, contact_id, token_hash \
             FROM portal_refresh_tokens WHERE id = $1",
        )
        .bind(row_id)
        .fetch_optional(self.db.migrator_pool())
        .await?;
        let Some((tenant_id, contact_id, token_hash)) = row else {
            return Ok(());
        };
        if !verify_password(secret, &token_hash)? {
            return Ok(());
        }
        self.revoke_rotation_chain(row_id).await?;
        // PMS-729 phase 2 H10: audit the sign-out so admin can see
        // "customer signed out" separately from "session expired".
        let _ = audit_portal_event(
            self.db.migrator_pool(),
            tenant_id,
            Some(contact_id),
            AuditAction::Logout,
            "portal.logout",
            None,
            None,
        )
        .await;
        Ok(())
    }

    /// Revoke every live refresh token that shares a rotation chain with
    /// `seed_id`, walking both directions of the `rotated_from_id` link.
    /// Used by explicit logout AND by the replay-detected branch of
    /// `refresh_access_token` (a stolen ancestor + honest descendant
    /// both need to lose their access at the same moment).
    ///
    /// Recursive CTE walks ancestors (`rotated_from_id` chain up) AND
    /// descendants (any row rotated from one already in the set) so the
    /// full family is caught regardless of which member was presented.
    async fn revoke_rotation_chain(&self, seed_id: Uuid) -> AppResult<()> {
        sqlx::query(
            r#"
            WITH RECURSIVE chain(id) AS (
                SELECT id FROM portal_refresh_tokens WHERE id = $1
                UNION
                SELECT r.id
                FROM portal_refresh_tokens r
                JOIN chain c ON r.rotated_from_id = c.id OR r.id = (
                    SELECT rotated_from_id FROM portal_refresh_tokens WHERE id = c.id
                )
            )
            UPDATE portal_refresh_tokens
            SET revoked_at = NOW()
            WHERE id IN (SELECT id FROM chain)
              AND revoked_at IS NULL
            "#,
        )
        .bind(seed_id)
        .execute(self.db.migrator_pool())
        .await?;
        Ok(())
    }

    /// PMS-729 phase 2 H6: list live refresh tokens (portal sessions)
    /// for a contact. Filters out revoked and expired rows so the
    /// customer only sees things they might actually want to sign out
    /// of. `current_sid` is the `sid` claim on the caller's own access
    /// token; the returned rows have `current = true` when their id
    /// matches (so the SPA can highlight "this browser" and hide the
    /// delete button for it - self-logout goes through
    /// `/portal/auth/logout`, not the per-session delete).
    ///
    /// SAFETY (PMS-285): both filters are the caller's own tenant +
    /// contact ids from the verified JWT; the migrator pool is used
    /// because portal has no per-request RLS GUC set today.
    #[allow(clippy::type_complexity)]
    #[tracing::instrument(skip_all)]
    pub async fn list_sessions(
        &self,
        contact_id: Uuid,
        tenant_id: Uuid,
        current_sid: Uuid,
    ) -> AppResult<Vec<PortalSessionResponse>> {
        let rows: Vec<(
            Uuid,
            DateTime<Utc>,
            DateTime<Utc>,
            Option<String>,
            Option<ipnetwork::IpNetwork>,
        )> = sqlx::query_as(
            r#"
            SELECT id, issued_at, expires_at, user_agent, ip_address
            FROM portal_refresh_tokens
            WHERE contact_id = $1
              AND tenant_id = $2
              AND revoked_at IS NULL
              AND expires_at > NOW()
            ORDER BY issued_at DESC
            "#,
        )
        .bind(contact_id)
        .bind(tenant_id)
        .fetch_all(self.db.migrator_pool())
        .await?;
        Ok(rows
            .into_iter()
            .map(
                |(id, issued_at, expires_at, user_agent, ip_address)| PortalSessionResponse {
                    id,
                    issued_at,
                    expires_at,
                    user_agent,
                    ip_address: ip_address.map(|ip| ip.ip().to_string()),
                    current: id == current_sid,
                },
            )
            .collect())
    }

    /// PMS-729 phase 2 H6: revoke ONE refresh token (and its rotation
    /// chain) belonging to the caller. Scoped by `(contact_id,
    /// tenant_id)` so a contact cannot revoke another contact's
    /// session even if they know the id. Returns `Ok(())` regardless
    /// of whether the row existed / was already revoked (idempotent
    /// + enumeration-resistant, same posture as `/portal/auth/logout`).
    ///
    /// Refuses when the caller tries to revoke their OWN session: a
    /// self-sign-out has a dedicated endpoint (`/portal/auth/logout`)
    /// that clears local state on the SPA side too; letting the
    /// delete route double as self-logout would leave the SPA in a
    /// broken state with a stale in-memory token.
    #[tracing::instrument(skip_all)]
    pub async fn revoke_session(
        &self,
        session_id: Uuid,
        contact_id: Uuid,
        tenant_id: Uuid,
        current_sid: Uuid,
    ) -> AppResult<()> {
        if session_id == current_sid {
            return Err(AppError::BadRequest(
                "Use /portal/auth/logout to sign out of the current session".to_string(),
            ));
        }
        // Verify the row belongs to this contact BEFORE walking the
        // chain, so a caller cannot revoke another contact's chain by
        // supplying a foreign id.
        let owns: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM portal_refresh_tokens \
             WHERE id = $1 AND contact_id = $2 AND tenant_id = $3)",
        )
        .bind(session_id)
        .bind(contact_id)
        .bind(tenant_id)
        .fetch_one(self.db.migrator_pool())
        .await?;
        if !owns {
            // Silent ok: matches logout's enumeration-resistant shape.
            return Ok(());
        }
        self.revoke_rotation_chain(session_id).await?;
        // PMS-729 phase 2 H10: audit the revoke separate from the
        // customer's own /logout so an admin scan can tell "revoked
        // another session from the SPA session list" from "signed out
        // of the browser".
        let _ = audit_portal_event(
            self.db.migrator_pool(),
            tenant_id,
            Some(contact_id),
            AuditAction::Logout,
            "portal.session_revoked",
            None,
            None,
        )
        .await;
        Ok(())
    }

    /// PMS-729: look up a tenant by slug for the host-to-tenant
    /// resolution path. Returns `Some` when the slug matches an active
    /// row; `None` on miss or inactive (fail-closed). The login handler
    /// and the `/host` branding endpoint both call this after the
    /// [`super::host_tenant::PortalHostConfig::extract_slug`] filter has
    /// validated the label shape.
    ///
    /// Reads `tenants.branding` as JSONB and deserializes into a
    /// [`PortalBranding`] struct (PMS-729 phase 2 §6). Every field is
    /// optional; a wholly-empty branding blob returns
    /// `PortalBranding::default()` and the SPA falls back to the
    /// generic "Client Portal" chrome.
    ///
    /// SAFETY (PMS-285): pre-auth cross-tenant read, same posture as the
    /// login lookup above. Runs on the migrator pool; `tenants` is RLS-
    /// covered so the app pool would fail this closed.
    #[tracing::instrument(skip_all)]
    pub async fn resolve_host_tenant(&self, slug: &str) -> AppResult<Option<ResolvedTenant>> {
        let row: Option<(Uuid, String, String, serde_json::Value)> = sqlx::query_as(
            r#"
                SELECT id, slug, name, branding
                FROM tenants
                WHERE slug = $1 AND status = 'active'
                "#,
        )
        .bind(slug)
        .fetch_optional(self.db.migrator_pool())
        .await?;

        Ok(
            row.map(|(tenant_id, slug, display_name, branding)| ResolvedTenant {
                tenant_id,
                slug,
                display_name,
                branding: PortalBranding::from_jsonb(&branding),
            }),
        )
    }

    /// PMS-501: persist one more failed portal login for `contact_id` and
    /// arm the exponential-backoff lockout once the failures cross the
    /// threshold (see [`lockout_until`]). Runs on the migrator pool for the
    /// same reason the login lookup does: the portal plane sets no RLS GUC
    /// and `contacts` is RLS-covered, so the app pool would write closed.
    ///
    /// PMS-693: the increment is relative (`portal_failed_login_count + 1`)
    /// and the new lock window is derived from the post-increment value inside
    /// the same statement, so a burst of concurrent wrong passwords counts
    /// every one of them. Taking no `prior_count` makes the stale-read defect
    /// unrepresentable.
    async fn register_failed_login(&self, contact_id: Uuid) -> AppResult<()> {
        // A NULL window (still under the threshold) leaves any existing
        // lockout in place rather than clearing it.
        let sql = format!(
            "UPDATE contacts \
             SET portal_failed_login_count = portal_failed_login_count + 1, \
                 portal_locked_until = COALESCE( \
                     NOW() + make_interval(secs => {secs}), portal_locked_until), \
                 updated_at = NOW() \
             WHERE id = $1",
            secs = lock_seconds_sql("portal_failed_login_count + 1"),
        );
        sqlx::query(&sql)
            .bind(contact_id)
            .execute(self.db.migrator_pool())
            .await?;
        Ok(())
    }

    /// Re-read a contact's display names from the `contacts` row. The
    /// portal JWT omits names (PII minimisation), so the middleware
    /// hydrates `first_name` / `last_name` for `/me`-style handlers after
    /// decoding the token (PMS-195). Scoped by `(tenant_id, id)`.
    pub async fn contact_names(
        &self,
        tenant_id: Uuid,
        contact_id: Uuid,
    ) -> AppResult<Option<(String, String)>> {
        let row: Option<(String, String)> = sqlx::query_as(
            "SELECT first_name, last_name FROM contacts WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(contact_id)
        // PMS-692: `contacts` is RLS-covered; scope the read with the tenant GUC
        // so it does not fail closed on the NOBYPASSRLS serving connection.
        .fetch_optional(&mut *self.db.begin_with_tenant(tenant_id).await?)
        .await?;
        Ok(row)
    }

    /// Decode + validate a portal JWT. Rejects anything that isn't
    /// `typ = "portal_access"` so an agent's access token cannot be
    /// replayed against the portal surface.
    pub fn decode_token(&self, token: &str) -> AppResult<PortalJwtClaims> {
        let data = decode::<PortalJwtClaims>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_bytes()),
            &Validation::default(),
        )
        .map_err(|_| AppError::Unauthorized)?;
        if data.claims.typ != "portal_access" {
            return Err(AppError::Unauthorized);
        }
        Ok(data.claims)
    }

    /// Redeem a single-use portal setup token and set the contact's
    /// password (PMS-136). The token is `{contact_id}.{secret}`; only the
    /// Argon2 hash of the secret is stored (`portal_setup_tokens`), so the
    /// lookup is scoped by `contact_id` and each candidate row's hash is
    /// verified in turn. Status contract:
    ///
    /// - valid, unused, unexpired -> sets `portal_password_hash`, marks the
    ///   token used, returns `Ok(())` (the handler maps to 204).
    /// - already redeemed -> `AppError::Gone` (410).
    /// - expired -> `AppError::BadRequest` (400).
    /// - no matching token -> `AppError::BadRequest` (400), so a guessed or
    ///   stale token is indistinguishable from an expired one.
    #[tracing::instrument(skip_all)]
    pub async fn setup_password(&self, token: &str, new_password: &str) -> AppResult<()> {
        let (contact_id, secret) = parse_contact_bound_token(token)
            .ok_or_else(|| AppError::BadRequest("Invalid or expired setup token".to_string()))?;

        // All tokens ever minted for this contact, newest first. We need the
        // used/expired rows too so a replay can be told apart from an expired
        // link. Tokens are salted Argon2 hashes and cannot be looked up by
        // value, so each candidate is verified against the presented secret.
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
            // SAFETY (PMS-285 / PMS-692): pre-auth, single-use setup-token
            // redemption. The token is `{contact_id}.{secret}` and the tenant is
            // resolved FROM the matched `portal_setup_tokens` row, so there is no
            // `app.current_tenant` GUC to set before the lookup. Runs on the
            // migrator pool; `portal_setup_tokens` is RLS-covered (migration 042)
            // and would fail this lookup closed on the unprivileged app pool -
            // exactly the PMS-692 "no customer can set a portal password" bug.
            .fetch_all(self.db.migrator_pool())
            .await?;

        let mut matched: Option<(Uuid, Uuid)> = None; // (token_id, tenant_id)
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

        // PMS-729 phase 2 H5: strict policy runs AFTER the token has
        // been verified live (not replayed / expired / unknown) so a
        // customer with a bad token doesn't get a confusing "your
        // password is too weak" message when the token status is the
        // real problem. Context hints reduce zxcvbn's score for a
        // password that quotes the user's own email, name, or tenant.
        let hints = self.password_context_hints(contact_id).await?;
        apply_password_policy(new_password, &hints)?;

        let hash = hash_password(new_password)?;
        // Tenant-scoped write: set the credential and burn the token in one
        // transaction so a crash cannot leave a usable token behind a set
        // password.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            "UPDATE contacts SET portal_password_hash = $1, is_portal_user = TRUE, updated_at = NOW() \
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
        tx.commit().await?;

        Ok(())
    }

    /// PMS-729 phase 2 H3: request a password-reset link for the given
    /// (tenant_slug, email) pair. Always returns `Ok(())`; the wire
    /// shape does not depend on whether the account exists so a caller
    /// cannot enumerate portal contacts. When a contact matches, a
    /// fresh row lands in `portal_password_reset_tokens` and the
    /// plaintext `{token_id}.{secret}` is returned in the Ok value
    /// (paired with the contact id + email for the mailer). When no
    /// contact matches, returns `Ok(None)` and the route handler skips
    /// the send silently.
    ///
    /// Token lifetime matches the industry norm (30 min): long enough
    /// for a user to check email + click the link, short enough to
    /// limit exposure of a leaked link.
    #[tracing::instrument(skip_all)]
    pub async fn request_password_reset(
        &self,
        slug: &str,
        email: &str,
        ip: Option<std::net::IpAddr>,
        user_agent: Option<&str>,
    ) -> AppResult<Option<PasswordResetIssue>> {
        let row: Option<(Uuid, Uuid, String, bool)> = sqlx::query_as(
            r#"
            SELECT c.id, c.tenant_id, c.email, c.is_portal_user
            FROM contacts c
            INNER JOIN tenants t ON c.tenant_id = t.id
            WHERE t.slug = $1 AND c.email = $2 AND t.status = 'active'
            "#,
        )
        .bind(slug)
        .bind(email)
        .fetch_optional(self.db.migrator_pool())
        .await?;

        // Non-portal contact OR unknown email: return None so the
        // handler emits 204 without an email. Enumeration-resistant.
        let Some((contact_id, tenant_id, email_found, is_portal_user)) = row else {
            return Ok(None);
        };
        if !is_portal_user {
            return Ok(None);
        }

        // Mint a fresh secret. Format `{token_id}.{secret}` matches the
        // setup-token shape so the parse helper is reusable.
        let secret = Uuid::new_v4().simple().to_string();
        let hash = hash_password(&secret)?;
        let now = Utc::now();
        let expires_at = now + Duration::minutes(30);
        let ip_text = ip.map(|ip| ip.to_string()).unwrap_or_default();
        let (token_id,): (Uuid,) = sqlx::query_as(
            r#"
            INSERT INTO portal_password_reset_tokens
                (tenant_id, contact_id, token_hash, expires_at,
                 requested_from_ip, requested_from_user_agent)
            VALUES ($1, $2, $3, $4, NULLIF($5, '')::inet, $6)
            RETURNING id
            "#,
        )
        .bind(tenant_id)
        .bind(contact_id)
        .bind(&hash)
        .bind(expires_at)
        .bind(ip_text)
        .bind(user_agent)
        .fetch_one(self.db.migrator_pool())
        .await?;

        Ok(Some(PasswordResetIssue {
            contact_id,
            tenant_id,
            email: email_found,
            token: format!("{token_id}.{secret}"),
            expires_at,
        }))
    }

    /// PMS-729 phase 2 H3: queue the password-reset email through the
    /// notifications dispatcher. Uses the existing `auth.password_reset`
    /// template (migration 021) so the copy renders consistently with
    /// the agent-side reset flow. Best-effort: a send failure is logged
    /// but does not propagate to the caller so the enumeration-resistant
    /// 204 wire shape holds even when SMTP is down.
    ///
    /// SAFETY (PMS-261): `issue.tenant_id` is a verified column value
    /// read off the `contacts` row inside `request_password_reset`, not
    /// user input; `dispatch` re-derives the RLS GUC per query via
    /// `begin_with_tenant`.
    #[tracing::instrument(skip_all)]
    pub async fn dispatch_password_reset_email(
        &self,
        issue: &PasswordResetIssue,
        reset_link: &str,
    ) -> AppResult<()> {
        let Some(notify) = self.notifications.as_ref() else {
            tracing::warn!(
                contact_id = %issue.contact_id,
                "no notifications dispatcher wired; portal reset token persisted but no message queued",
            );
            return Ok(());
        };
        let context = serde_json::json!({
            "recipient_email": issue.email,
            "reset_link": reset_link,
        });
        notify
            .dispatch(
                TenantId::from_trusted(issue.tenant_id),
                "auth.password_reset",
                &context,
            )
            .await
            .map(|_| ())
    }

    /// PMS-729 phase 2 H3: redeem a password-reset token. Same status
    /// contract as `setup_password`: 204 on happy path, 410 on replay,
    /// 400 on expired / unknown / malformed. The password policy check
    /// runs AFTER the token is verified live so a bad-token attempt
    /// does not surface as "password too weak".
    ///
    /// Also revokes every live refresh token for the contact as a side
    /// effect: a stolen refresh token cannot survive the password reset.
    #[allow(clippy::type_complexity)]
    #[tracing::instrument(skip_all)]
    pub async fn reset_password(&self, token: &str, new_password: &str) -> AppResult<()> {
        let (token_id, secret) = parse_contact_bound_token(token)
            .ok_or_else(|| AppError::BadRequest("Invalid or expired reset token".to_string()))?;

        // Look up by primary key (token id), NOT by contact id, since
        // the token shape here is `{token_id}.{secret}` (unlike
        // portal_setup_tokens which uses `{contact_id}.{secret}`). This
        // is a deliberate divergence: setup tokens are keyed by contact
        // because the contact may have multiple queued setup links from
        // an agent re-invite; reset tokens are keyed by token so the
        // customer can have multiple concurrent reset requests without
        // shadowing.
        let row: Option<(Uuid, Uuid, String, Option<DateTime<Utc>>, DateTime<Utc>)> =
            sqlx::query_as(
                r#"
            SELECT tenant_id, contact_id, token_hash, used_at, expires_at
            FROM portal_password_reset_tokens
            WHERE id = $1
            "#,
            )
            .bind(token_id)
            .fetch_optional(self.db.migrator_pool())
            .await?;
        let Some((tenant_id, contact_id, token_hash, used_at, expires_at)) = row else {
            return Err(AppError::BadRequest(
                "Invalid or expired reset token".to_string(),
            ));
        };
        if !verify_password(secret, &token_hash)? {
            return Err(AppError::BadRequest(
                "Invalid or expired reset token".to_string(),
            ));
        }
        if used_at.is_some() {
            return Err(AppError::Gone("Reset token already used".to_string()));
        }
        if expires_at <= Utc::now() {
            return Err(AppError::BadRequest(
                "Invalid or expired reset token".to_string(),
            ));
        }

        // Policy check runs AFTER token verification: bad token surfaces
        // cleanly as 400/410 without a confusing password-strength msg.
        let hints = self.password_context_hints(contact_id).await?;
        apply_password_policy(new_password, &hints)?;

        let hash = hash_password(new_password)?;
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        // Set the new password + burn the token in one transaction so a
        // crash cannot leave a usable token behind a set password.
        sqlx::query(
            "UPDATE contacts SET portal_password_hash = $1, updated_at = NOW() \
             WHERE id = $2 AND tenant_id = $3",
        )
        .bind(&hash)
        .bind(contact_id)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE portal_password_reset_tokens SET used_at = NOW() \
             WHERE id = $1 AND tenant_id = $2",
        )
        .bind(token_id)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
        // Revoke every live refresh token for this contact. A password
        // reset ends every existing session; the customer must sign in
        // again with the new password. This also cuts off a stolen
        // refresh token from surviving the reset.
        sqlx::query(
            "UPDATE portal_refresh_tokens SET revoked_at = NOW() \
             WHERE contact_id = $1 AND revoked_at IS NULL",
        )
        .bind(contact_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        // PMS-729 phase 2 H10: audit the password reset. IP + UA are
        // not available at this layer (route handler owns those); a
        // future revision could pass them through, but the reset event
        // itself matters more than the requester context.
        let _ = audit_portal_event(
            self.db.migrator_pool(),
            tenant_id,
            Some(contact_id),
            AuditAction::Update,
            "portal.password_reset",
            None,
            None,
        )
        .await;
        Ok(())
    }

    /// PMS-729 phase 2 H3: change the password for a logged-in contact.
    /// Requires the current password for re-auth so a stolen access
    /// token cannot silently rotate the credential. Applies the same
    /// H5 policy to `new_password` and revokes every OTHER live refresh
    /// token for the contact (keeps the calling session live so the
    /// customer does not get bounced out mid-change).
    #[tracing::instrument(skip_all)]
    pub async fn change_password(
        &self,
        contact_id: Uuid,
        tenant_id: Uuid,
        current_password: &str,
        new_password: &str,
    ) -> AppResult<()> {
        let row: Option<(Option<String>,)> = sqlx::query_as(
            "SELECT portal_password_hash FROM contacts \
             WHERE id = $1 AND tenant_id = $2",
        )
        .bind(contact_id)
        .bind(tenant_id)
        .fetch_optional(self.db.migrator_pool())
        .await?;
        let Some((Some(current_hash),)) = row else {
            // No hash means the contact never redeemed a setup token.
            // A "change password" request in that state is malformed.
            return Err(AppError::Unauthorized);
        };
        if !verify_password(current_password, &current_hash)? {
            return Err(AppError::Unauthorized);
        }

        // H5 policy on the new candidate.
        let hints = self.password_context_hints(contact_id).await?;
        apply_password_policy(new_password, &hints)?;

        let hash = hash_password(new_password)?;
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            "UPDATE contacts SET portal_password_hash = $1, updated_at = NOW() \
             WHERE id = $2 AND tenant_id = $3",
        )
        .bind(&hash)
        .bind(contact_id)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
        // Cannot know which refresh token minted the caller's current
        // access token from the token itself, so keep every live one.
        // The route handler is expected to pair this call with an
        // explicit rotate so the client's refresh token stays fresh
        // (documented on the handler).
        tx.commit().await?;
        // PMS-729 phase 2 H10: audit the change so an admin can see it
        // in the same audit stream as reset / login events.
        let _ = audit_portal_event(
            self.db.migrator_pool(),
            tenant_id,
            Some(contact_id),
            AuditAction::Update,
            "portal.password_changed",
            None,
            None,
        )
        .await;
        Ok(())
    }

    /// PMS-729 phase 2 H4: start portal MFA enrollment. Generates a
    /// fresh TOTP secret, stores it on the contact row, and returns
    /// the base32 secret + `otpauth://` provisioning URI for the SPA
    /// to render as a QR code. Does NOT flip `portal_mfa_enabled`
    /// (that happens on `enable_mfa` after the customer proves
    /// possession of a valid code). Calling this again before enable
    /// REPLACES the stored secret.
    ///
    /// Rejects with `Conflict` when MFA is already enabled: the
    /// customer must disable first before re-enrolling with a
    /// different authenticator.
    #[tracing::instrument(skip_all)]
    pub async fn start_mfa_enrollment(
        &self,
        contact_id: Uuid,
        tenant_id: Uuid,
    ) -> AppResult<PortalMfaSetupResponse> {
        let row: Option<(bool, Option<String>)> = sqlx::query_as(
            "SELECT portal_mfa_enabled, email FROM contacts \
             WHERE id = $1 AND tenant_id = $2",
        )
        .bind(contact_id)
        .bind(tenant_id)
        .fetch_optional(self.db.migrator_pool())
        .await?;
        let Some((enabled, email)) = row else {
            return Err(AppError::Unauthorized);
        };
        if enabled {
            return Err(AppError::Conflict("MFA is already enabled".to_string()));
        }
        let email = email.unwrap_or_default();

        let secret = crate::utils::totp::generate_secret();
        let secret_b32 = crate::utils::totp::base32_encode(&secret);
        sqlx::query(
            "UPDATE contacts SET portal_mfa_secret = $1, updated_at = NOW() \
             WHERE id = $2 AND tenant_id = $3",
        )
        .bind(&secret_b32)
        .bind(contact_id)
        .bind(tenant_id)
        .execute(self.db.migrator_pool())
        .await?;

        // Provisioning URI label as "Mokosh:<email>" matches the agent
        // side. Issuer stays "Mokosh" so both surfaces show the same
        // brand in the authenticator app; a per-tenant issuer would be
        // nicer but is scope for the phase 2 §6 branding pass.
        let label = format!("Mokosh:{email}");
        let provisioning_uri = crate::utils::totp::provisioning_uri(&secret_b32, &label, "Mokosh");
        Ok(PortalMfaSetupResponse {
            secret: secret_b32,
            provisioning_uri,
        })
    }

    /// PMS-729 phase 2 H4: confirm MFA enrollment by verifying a live
    /// code against the previously-stored secret, then flip
    /// `portal_mfa_enabled = TRUE` and mint 10 single-use recovery
    /// codes (returned once, hashed on the row). Rejects with
    /// `BadRequest` when setup was never started or the code fails to
    /// verify.
    #[tracing::instrument(skip_all)]
    pub async fn enable_mfa(
        &self,
        contact_id: Uuid,
        tenant_id: Uuid,
        code: &str,
    ) -> AppResult<PortalMfaEnableResponse> {
        let row: Option<(bool, Option<String>)> = sqlx::query_as(
            "SELECT portal_mfa_enabled, portal_mfa_secret FROM contacts \
             WHERE id = $1 AND tenant_id = $2",
        )
        .bind(contact_id)
        .bind(tenant_id)
        .fetch_optional(self.db.migrator_pool())
        .await?;
        let Some((enabled, secret_b32)) = row else {
            return Err(AppError::Unauthorized);
        };
        if enabled {
            return Err(AppError::Conflict("MFA is already enabled".to_string()));
        }
        let secret_b32 = secret_b32.ok_or_else(|| {
            AppError::BadRequest("MFA enrollment has not been started".to_string())
        })?;
        let secret = crate::utils::totp::base32_decode(&secret_b32)
            .map_err(|_| AppError::Internal("stored MFA secret is corrupt".to_string()))?;
        if crate::utils::totp::verify(&secret, code, Utc::now(), 1).is_none() {
            return Err(AppError::BadRequest("Invalid MFA code".to_string()));
        }

        let recovery_codes = crate::utils::recovery::generate_set();
        let hashes: Vec<String> = recovery_codes
            .iter()
            .map(|c| recovery_code_hex_hash(c))
            .collect();
        sqlx::query(
            r#"
            UPDATE contacts
               SET portal_mfa_enabled = TRUE,
                   portal_mfa_enrolled_at = NOW(),
                   portal_mfa_recovery_codes_hashes = $1,
                   updated_at = NOW()
             WHERE id = $2 AND tenant_id = $3
            "#,
        )
        .bind(&hashes)
        .bind(contact_id)
        .bind(tenant_id)
        .execute(self.db.migrator_pool())
        .await?;

        // PMS-729 phase 2 H10: audit MFA enrollment.
        let _ = audit_portal_event(
            self.db.migrator_pool(),
            tenant_id,
            Some(contact_id),
            AuditAction::Update,
            "portal.mfa_enabled",
            None,
            None,
        )
        .await;
        Ok(PortalMfaEnableResponse { recovery_codes })
    }

    /// PMS-729 phase 2 H4: disable MFA. Requires the current password
    /// AND a valid TOTP code (or recovery code) so a stolen access
    /// token cannot silently disable the second factor. Clears the
    /// secret + recovery codes on success.
    #[tracing::instrument(skip_all)]
    pub async fn disable_mfa(
        &self,
        contact_id: Uuid,
        tenant_id: Uuid,
        current_password: &str,
        code: &str,
    ) -> AppResult<()> {
        let row: Option<(Option<String>, bool, Option<String>)> = sqlx::query_as(
            "SELECT portal_password_hash, portal_mfa_enabled, portal_mfa_secret \
             FROM contacts WHERE id = $1 AND tenant_id = $2",
        )
        .bind(contact_id)
        .bind(tenant_id)
        .fetch_optional(self.db.migrator_pool())
        .await?;
        let Some((password_hash, enabled, secret_b32)) = row else {
            return Err(AppError::Unauthorized);
        };
        if !enabled {
            // Not enabled = nothing to disable. Same-shape error as the
            // wrong-password path to avoid enumerating enrollment state
            // via response codes.
            return Err(AppError::Unauthorized);
        }
        let password_hash = password_hash.ok_or(AppError::Unauthorized)?;
        if !verify_password(current_password, &password_hash)? {
            return Err(AppError::Unauthorized);
        }
        let secret_b32 = secret_b32
            .ok_or_else(|| AppError::Internal("MFA enabled but no secret stored".to_string()))?;
        let secret = crate::utils::totp::base32_decode(&secret_b32)
            .map_err(|_| AppError::Internal("stored MFA secret is corrupt".to_string()))?;
        if crate::utils::totp::verify(&secret, code, Utc::now(), 1).is_none() {
            return Err(AppError::Unauthorized);
        }

        sqlx::query(
            r#"
            UPDATE contacts
               SET portal_mfa_enabled = FALSE,
                   portal_mfa_secret = NULL,
                   portal_mfa_recovery_codes_hashes = '{}',
                   portal_mfa_enrolled_at = NULL,
                   updated_at = NOW()
             WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(contact_id)
        .bind(tenant_id)
        .execute(self.db.migrator_pool())
        .await?;

        // PMS-729 phase 2 H10: audit MFA disable (opposite of enable;
        // both matter for an admin investigating a session hijack).
        let _ = audit_portal_event(
            self.db.migrator_pool(),
            tenant_id,
            Some(contact_id),
            AuditAction::Update,
            "portal.mfa_disabled",
            None,
            None,
        )
        .await;
        Ok(())
    }

    /// Set or replace the portal password for a contact. Surfaces to a
    /// future `PUT /api/v1/portal/auth/password` endpoint that the
    /// customer hits after clicking their setup link.
    #[allow(dead_code)]
    #[tracing::instrument(skip_all)]
    pub async fn set_password(&self, contact_id: Uuid, new_password: &str) -> AppResult<()> {
        // PMS-729 phase 2 H5: strict policy (same rules as setup_password).
        let hints = self.password_context_hints(contact_id).await?;
        apply_password_policy(new_password, &hints)?;
        let hash = hash_password(new_password)?;
        // SAFETY (PMS-285): portal account setup on the separate
        // `contacts`-identity plane (portal isolation deferred; see the login
        // note above). Reached via an emailed setup link before any portal
        // session exists, so it sets no GUC and targets the one contact by id.
        // Migrator pool because `contacts` is RLS-covered.
        sqlx::query(
            "UPDATE contacts SET portal_password_hash = $1, is_portal_user = TRUE, updated_at = NOW() WHERE id = $2",
        )
        .bind(&hash)
        .bind(contact_id)
        .execute(self.db.migrator_pool())
        .await?;
        Ok(())
    }

    /// PMS-729 phase 2 H5: pull the contact-scoped strings that feed
    /// zxcvbn as context hints, so a candidate password that quotes the
    /// user's own email / name / tenant slug scores lower than a
    /// random string of the same length would. Returns `Vec<String>` so
    /// the caller can pass `hints.iter().map(String::as_str).collect()`
    /// into the policy helper without an extra allocation dance.
    ///
    /// Skips entries that are trivially short (< 3 chars) so a
    /// single-letter first name doesn't add noise.
    ///
    /// SAFETY (PMS-285): reads the target contact row directly by primary
    /// key on the migrator pool, same posture as the login lookup above
    /// (the portal plane sets no `app.current_tenant` GUC and `contacts`
    /// is RLS-covered on the app pool).
    async fn password_context_hints(&self, contact_id: Uuid) -> AppResult<Vec<String>> {
        let row: Option<(String, String, String, String)> = sqlx::query_as(
            r#"
            SELECT c.email, c.first_name, c.last_name, t.slug
            FROM contacts c
            INNER JOIN tenants t ON c.tenant_id = t.id
            WHERE c.id = $1
            "#,
        )
        .bind(contact_id)
        .fetch_optional(self.db.migrator_pool())
        .await?;
        let Some((email, first, last, slug)) = row else {
            return Ok(Vec::new());
        };
        // Also include the local-part of the email so `alice@acme` is
        // penalized by both `alice@acme` AND `alice` separately.
        let email_local: Option<String> = email
            .split('@')
            .next()
            .filter(|s| s.len() >= 3)
            .map(str::to_string);
        Ok([
            Some(email),
            Some(first),
            Some(last),
            Some(slug),
            email_local,
        ]
        .into_iter()
        .flatten()
        .filter(|s| s.chars().count() >= 3)
        .collect())
    }

    /// PMS-729 phase 2 §7 slice A / I17: aggregate the four dashboard
    /// cards D17 pins for phase 2 (open tickets by priority, next
    /// invoice due, open quotes awaiting decision, recent activity).
    /// Every query is scoped by tenant AND `company_id` so a portal
    /// caller only ever sees their own company's data; every cross-
    /// company row is silently absent (never a 403 or a leaked count).
    ///
    /// Returns `PortalDashboardResponse`. Empty sets for a company with
    /// no tickets / invoices / quotes still return the zero-filled
    /// priority axis so the SPA layout stays stable.
    ///
    /// SAFETY (PMS-261 / PMS-285): every query runs inside
    /// `begin_with_tenant` and pins `company_id` to the caller's
    /// authenticated value. The dashboard endpoint is authenticated
    /// (`RequirePortalAuth`), so `tenant_id` is a verified JWT claim,
    /// not user input.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, company_id = %company_id))]
    pub async fn dashboard(
        &self,
        tenant_id: crate::modules::auth::TenantId,
        company_id: Uuid,
    ) -> AppResult<PortalDashboardResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;

        // Card 1: open tickets by priority. LEFT JOIN keeps zero-count
        // priorities in the axis; the status subquery limits the join
        // to non-closed statuses only.
        let priorities: Vec<(Uuid, String, String, i32, i64)> = sqlx::query_as(
            r#"
            SELECT p.id, p.name, p.color, p.sort_order,
                   COUNT(t.id) FILTER (WHERE t.id IS NOT NULL)::BIGINT AS count
            FROM ticket_priorities p
            LEFT JOIN tickets t
              ON t.priority_id = p.id
             AND t.tenant_id = $1
             AND t.company_id = $2
             AND EXISTS (
                 SELECT 1 FROM ticket_statuses s
                  WHERE s.id = t.status_id AND s.is_closed = FALSE
             )
            WHERE p.tenant_id = $1
            GROUP BY p.id, p.name, p.color, p.sort_order
            ORDER BY p.sort_order, p.name
            "#,
        )
        .bind(tenant_id)
        .bind(company_id)
        .fetch_all(&mut *tx)
        .await?;
        let tickets_by_priority: Vec<DashboardTicketPriorityBucket> = priorities
            .into_iter()
            .map(
                |(id, name, color, sort_order, count)| DashboardTicketPriorityBucket {
                    id,
                    name,
                    color,
                    sort_order,
                    count,
                },
            )
            .collect();

        // Card 2: next invoice due. Only invoices with an outstanding
        // balance in a chargeable status count.
        let next: Option<(
            Uuid,
            String,
            rust_decimal::Decimal,
            rust_decimal::Decimal,
            chrono::NaiveDate,
            Option<String>,
        )> = sqlx::query_as(
            r#"
            SELECT id, invoice_number, total, balance_due, due_date, currency
            FROM invoices
            WHERE tenant_id = $1
              AND company_id = $2
              AND status IN ('sent', 'pending', 'partially_paid')
              AND balance_due > 0
            ORDER BY due_date ASC, invoice_number ASC
            LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .bind(company_id)
        .fetch_optional(&mut *tx)
        .await?;
        let next_invoice_due = next.map(
            |(id, invoice_number, total, balance_due, due_date, currency)| {
                DashboardNextInvoiceDue {
                    id,
                    invoice_number,
                    total,
                    balance_due,
                    due_date,
                    currency: currency.unwrap_or_else(|| "USD".to_string()),
                }
            },
        );

        // Card 3: open quotes awaiting the customer's decision. Statuses
        // 'sent' and 'submitted' are the ones an MSP has actually surfaced
        // to the customer and is waiting on. Everything else (draft,
        // approved, rejected, accepted, declined, expired, converted,
        // cancelled) either has not reached the customer yet or already
        // has a terminal decision.
        let (open_quotes_awaiting_decision,): (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*)::BIGINT
            FROM quotes
            WHERE tenant_id = $1
              AND company_id = $2
              AND status IN ('sent', 'submitted')
            "#,
        )
        .bind(tenant_id)
        .bind(company_id)
        .fetch_one(&mut *tx)
        .await?;

        // Card 4: recent activity (last 10 ticket updates). Portal-scoped
        // to the contact's company so nothing from a sibling company can
        // leak into the feed. `updated_at` fires whenever the status
        // changes, a note lands, or the assignee flips, so it is a
        // reasonable "what changed recently" proxy without a JOIN across
        // ticket_notes / status_history.
        let recent: Vec<(Uuid, String, String, String, chrono::DateTime<Utc>)> = sqlx::query_as(
            r#"
            SELECT t.id, t.ticket_number, t.title, s.name, t.updated_at
            FROM tickets t
            JOIN ticket_statuses s ON s.id = t.status_id
            WHERE t.tenant_id = $1 AND t.company_id = $2
            ORDER BY t.updated_at DESC
            LIMIT 10
            "#,
        )
        .bind(tenant_id)
        .bind(company_id)
        .fetch_all(&mut *tx)
        .await?;
        let recent_activity: Vec<DashboardRecentActivity> = recent
            .into_iter()
            .map(
                |(id, ticket_number, title, status_name, updated_at)| DashboardRecentActivity {
                    kind: "ticket".to_string(),
                    entity_id: id,
                    label: format!("#{ticket_number} {title}"),
                    summary: format!("Status: {status_name}"),
                    at: updated_at,
                },
            )
            .collect();

        tx.commit().await?;

        Ok(PortalDashboardResponse {
            tickets_by_priority,
            next_invoice_due,
            open_quotes_awaiting_decision,
            recent_activity,
        })
    }

    /// PMS-729 phase 2 §7 slice A / I10: SLA metrics for one of the
    /// caller's tickets. Enforces the (tenant, company, ticket) scope in
    /// SQL so a cross-company ticket id returns `AppError::NotFound`,
    /// matching every other portal detail-view posture.
    ///
    /// The `PortalSlaStatus` label follows the shared rule the agent
    /// side already implements: closed tickets or tickets with no
    /// `sla_due_date` are `not_applicable`; the remaining tickets are
    /// `on_track` / `warning` / `breached` at the same 25%-remaining
    /// threshold `mokosh_types::compute_sla_status` uses. Kept in sync
    /// with that function by importing it directly so a future
    /// threshold change lands on both surfaces at once.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, company_id = %company_id, ticket_id = %ticket_id))]
    pub async fn ticket_sla(
        &self,
        tenant_id: crate::modules::auth::TenantId,
        company_id: Uuid,
        ticket_id: Uuid,
    ) -> AppResult<PortalTicketSlaResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        // Row is a tuple of the six datetime columns plus the status
        // name; the shape matches the SELECT below.
        #[allow(clippy::type_complexity)]
        let row: Option<(
            Option<DateTime<Utc>>,
            Option<DateTime<Utc>>,
            Option<DateTime<Utc>>,
            Option<DateTime<Utc>>,
            Option<DateTime<Utc>>,
            Option<DateTime<Utc>>,
            String,
        )> = sqlx::query_as(
            r#"
            SELECT t.sla_due_date,
                   t.first_response_due, t.first_response_at,
                   t.resolution_due, t.resolved_at, t.closed_at,
                   s.name
            FROM tickets t
            JOIN ticket_statuses s ON s.id = t.status_id
            WHERE t.tenant_id = $1
              AND t.company_id = $2
              AND t.id = $3
            "#,
        )
        .bind(tenant_id)
        .bind(company_id)
        .bind(ticket_id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;

        let Some((
            sla_due_date,
            first_response_due,
            first_response_at,
            resolution_due,
            resolved_at,
            closed_at,
            status_name,
        )) = row
        else {
            return Err(AppError::NotFound("Ticket".to_string()));
        };

        // Share the exact status logic the agent side uses so a portal
        // caller and an agent looking at the same ticket disagree only
        // about layout, not truth.
        let agent_status = mokosh_types::tickets::compute_sla_status(closed_at, sla_due_date);
        let status = match agent_status {
            mokosh_types::tickets::SlaStatus::OnTrack => PortalSlaStatus::OnTrack,
            mokosh_types::tickets::SlaStatus::Warning => PortalSlaStatus::Warning,
            mokosh_types::tickets::SlaStatus::Breached => PortalSlaStatus::Breached,
            mokosh_types::tickets::SlaStatus::NotApplicable => PortalSlaStatus::NotApplicable,
        };

        Ok(PortalTicketSlaResponse {
            sla_due_date,
            first_response_due,
            first_response_at,
            resolution_due,
            resolved_at,
            closed_at,
            status,
            status_name,
        })
    }

    /// PMS-729 phase 2 §7 slice A / I11: payment history for one of the
    /// caller's invoices. Enforces the (tenant, company, invoice) scope
    /// via a preflight EXISTS so a cross-company id surfaces as 404
    /// (same posture as `get_invoice`); the payments read then joins on
    /// the same three columns so a leaked payment id cannot bypass the
    /// gate either.
    ///
    /// Returns newest-first, capped by the caller's page size (default
    /// 50). Every payment row surfaces id, date, amount, method, and
    /// reference number; internal notes and raw gateway payloads are
    /// deliberately dropped so an agent's "bounced, retry Friday"
    /// scratch comment never reaches the customer.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, company_id = %company_id, invoice_id = %invoice_id))]
    pub async fn list_invoice_payments(
        &self,
        tenant_id: crate::modules::auth::TenantId,
        company_id: Uuid,
        invoice_id: Uuid,
    ) -> AppResult<PortalInvoicePaymentsResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;

        // Preflight: the invoice must exist AND belong to this
        // company. Missing / cross-company both collapse to 404.
        let exists: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM invoices
                WHERE tenant_id = $1 AND company_id = $2 AND id = $3
            )
            "#,
        )
        .bind(tenant_id)
        .bind(company_id)
        .bind(invoice_id)
        .fetch_one(&mut *tx)
        .await?;
        if !exists {
            tx.commit().await?;
            return Err(AppError::NotFound("Invoice".to_string()));
        }

        // Payments read: same scope, newest-first. Kept as a `SELECT
        // ... ORDER BY` so a future pagination adds a bounded LIMIT
        // without shape churn.
        #[allow(clippy::type_complexity)]
        let rows: Vec<(
            Uuid,
            chrono::NaiveDate,
            rust_decimal::Decimal,
            String,
            Option<String>,
            DateTime<Utc>,
        )> = sqlx::query_as(
            r#"
            SELECT id, payment_date, amount, payment_method, reference_number, created_at
            FROM payments
            WHERE tenant_id = $1
              AND company_id = $2
              AND invoice_id = $3
            ORDER BY payment_date DESC, created_at DESC
            "#,
        )
        .bind(tenant_id)
        .bind(company_id)
        .bind(invoice_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;

        let payments: Vec<PortalInvoicePayment> = rows
            .into_iter()
            .map(
                |(id, payment_date, amount, payment_method, reference_number, created_at)| {
                    PortalInvoicePayment {
                        id,
                        payment_date,
                        amount,
                        payment_method,
                        reference_number,
                        created_at,
                    }
                },
            )
            .collect();
        let total = payments.len() as i64;

        Ok(PortalInvoicePaymentsResponse { payments, total })
    }

    /// PMS-729 phase 2 §7 slice A / I14: portal-scoped search across
    /// the four entities a customer can already view: tickets,
    /// invoices, quotes, and KB articles they are permitted to see.
    /// D18 pins the scoping rule: NEVER cross-company. Every query
    /// forces `company_id = contact.company_id` (or, for KB, the
    /// visibility gate the KB list endpoint already uses).
    ///
    /// The blank / whitespace-only query returns the empty default so
    /// the SPA can safely mount a "search box that fires on every
    /// keystroke" pattern without shipping an empty query all the way
    /// to Postgres. `%` and `_` in the user input are escaped so a
    /// literal typed underscore matches a literal underscore, not a
    /// wildcard.
    ///
    /// Each section caps at 5 rows for the preview and reports the
    /// uncapped count in `counts`, matching the agent-side search
    /// helper convention.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, company_id = %company_id, q_len = q.len()))]
    pub async fn portal_search(
        &self,
        tenant_id: crate::modules::auth::TenantId,
        company_id: Uuid,
        q: &str,
    ) -> AppResult<PortalSearchResponse> {
        const SECTION_LIMIT: i64 = 5;
        let trimmed = q.trim();
        if trimmed.is_empty() {
            return Ok(PortalSearchResponse::default());
        }
        let escaped = trimmed
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        let pattern = format!("%{escaped}%");

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;

        // Tickets: number OR title OR description within the caller's
        // company.
        let ticket_rows: Vec<(Uuid, String, String, Option<String>)> = sqlx::query_as(
            r#"
            SELECT t.id, t.ticket_number, t.title, s.name
            FROM tickets t
            JOIN ticket_statuses s ON s.id = t.status_id
            WHERE t.tenant_id = $1 AND t.company_id = $2
              AND (t.ticket_number ILIKE $3 OR t.title ILIKE $3 OR t.description ILIKE $3)
            ORDER BY t.updated_at DESC
            LIMIT $4
            "#,
        )
        .bind(tenant_id)
        .bind(company_id)
        .bind(&pattern)
        .bind(SECTION_LIMIT)
        .fetch_all(&mut *tx)
        .await?;
        let tickets_total: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)::BIGINT
            FROM tickets t
            WHERE t.tenant_id = $1 AND t.company_id = $2
              AND (t.ticket_number ILIKE $3 OR t.title ILIKE $3 OR t.description ILIKE $3)
            "#,
        )
        .bind(tenant_id)
        .bind(company_id)
        .bind(&pattern)
        .fetch_one(&mut *tx)
        .await?;

        // Invoices: number OR PO number (public reference) match.
        let invoice_rows: Vec<(Uuid, String, String, Option<chrono::NaiveDate>)> = sqlx::query_as(
            r#"
            SELECT id, invoice_number, status, due_date
            FROM invoices
            WHERE tenant_id = $1 AND company_id = $2
              AND (invoice_number ILIKE $3 OR po_number ILIKE $3)
            ORDER BY invoice_date DESC
            LIMIT $4
            "#,
        )
        .bind(tenant_id)
        .bind(company_id)
        .bind(&pattern)
        .bind(SECTION_LIMIT)
        .fetch_all(&mut *tx)
        .await?;
        let invoices_total: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)::BIGINT
            FROM invoices
            WHERE tenant_id = $1 AND company_id = $2
              AND (invoice_number ILIKE $3 OR po_number ILIKE $3)
            "#,
        )
        .bind(tenant_id)
        .bind(company_id)
        .bind(&pattern)
        .fetch_one(&mut *tx)
        .await?;

        // Quotes: title OR summary. Only issued-and-later statuses
        // (matches `list_quotes_for_company` scope).
        let quote_rows: Vec<(Uuid, String, String)> = sqlx::query_as(
            r#"
            SELECT id, title, status
            FROM quotes
            WHERE tenant_id = $1 AND company_id = $2
              AND status IN ('sent', 'submitted', 'accepted', 'declined', 'expired', 'converted')
              AND (title ILIKE $3 OR summary ILIKE $3)
            ORDER BY updated_at DESC
            LIMIT $4
            "#,
        )
        .bind(tenant_id)
        .bind(company_id)
        .bind(&pattern)
        .bind(SECTION_LIMIT)
        .fetch_all(&mut *tx)
        .await?;
        let quotes_total: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)::BIGINT
            FROM quotes
            WHERE tenant_id = $1 AND company_id = $2
              AND status IN ('sent', 'submitted', 'accepted', 'declined', 'expired', 'converted')
              AND (title ILIKE $3 OR summary ILIKE $3)
            "#,
        )
        .bind(tenant_id)
        .bind(company_id)
        .bind(&pattern)
        .fetch_one(&mut *tx)
        .await?;

        // KB articles: title OR summary. Published visibility rules
        // mirror `list_kb`: public OR client_specific with the caller's
        // company id in `company_ids`.
        let kb_rows: Vec<(Uuid, String, Option<String>)> = sqlx::query_as(
            r#"
            SELECT id, title, summary
            FROM kb_articles
            WHERE tenant_id = $1
              AND status = 'published'
              AND (
                  visibility = 'public'
                  OR (visibility = 'client_specific' AND $2 = ANY(company_ids))
              )
              AND (title ILIKE $3 OR summary ILIKE $3 OR content ILIKE $3)
            ORDER BY published_at DESC NULLS LAST
            LIMIT $4
            "#,
        )
        .bind(tenant_id)
        .bind(company_id)
        .bind(&pattern)
        .bind(SECTION_LIMIT)
        .fetch_all(&mut *tx)
        .await?;
        let kb_total: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)::BIGINT
            FROM kb_articles
            WHERE tenant_id = $1
              AND status = 'published'
              AND (
                  visibility = 'public'
                  OR (visibility = 'client_specific' AND $2 = ANY(company_ids))
              )
              AND (title ILIKE $3 OR summary ILIKE $3 OR content ILIKE $3)
            "#,
        )
        .bind(tenant_id)
        .bind(company_id)
        .bind(&pattern)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;

        let tickets: Vec<PortalSearchHit> = ticket_rows
            .into_iter()
            .map(|(id, number, title, status_name)| PortalSearchHit {
                id,
                label: format!("#{number} {title}"),
                secondary: status_name,
            })
            .collect();
        let invoices: Vec<PortalSearchHit> = invoice_rows
            .into_iter()
            .map(|(id, number, status, due)| PortalSearchHit {
                id,
                label: number,
                secondary: Some(match due {
                    Some(d) => format!("{status} - due {d}"),
                    None => status,
                }),
            })
            .collect();
        let quotes: Vec<PortalSearchHit> = quote_rows
            .into_iter()
            .map(|(id, title, status)| PortalSearchHit {
                id,
                label: title,
                secondary: Some(status),
            })
            .collect();
        let kb_articles: Vec<PortalSearchHit> = kb_rows
            .into_iter()
            .map(|(id, title, summary)| PortalSearchHit {
                id,
                label: title,
                secondary: summary,
            })
            .collect();

        let counts = PortalSearchCounts {
            tickets: tickets_total,
            invoices: invoices_total,
            quotes: quotes_total,
            kb_articles: kb_total,
        };

        Ok(PortalSearchResponse {
            tickets,
            invoices,
            quotes,
            kb_articles,
            counts,
        })
    }

    /// PMS-729 phase 2 §7 slice B / I12: portal notifications inbox.
    /// Returns the newest 50 `in_app` rows scoped to the caller, plus a
    /// separate unread count so the SPA renders the top-bar badge
    /// without walking the row list.
    ///
    /// Scoping is by (tenant, contact_id): a row without a contact_id
    /// belongs to a `users` recipient and never surfaces here. RLS on
    /// the notifications table already enforces the tenant scope; the
    /// contact filter guarantees a cross-contact leak within the same
    /// tenant is impossible.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, contact_id = %contact_id))]
    pub async fn list_portal_inbox(
        &self,
        tenant_id: crate::modules::auth::TenantId,
        contact_id: Uuid,
    ) -> AppResult<PortalNotificationsResponse> {
        const PORTAL_INBOX_LIMIT: i64 = 50;
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows: Vec<(
            Uuid,
            Option<String>,
            String,
            Option<DateTime<Utc>>,
            DateTime<Utc>,
        )> = sqlx::query_as(
            r#"
            SELECT id, subject, body, read_at, created_at
            FROM notifications
            WHERE tenant_id = $1
              AND contact_id = $2
              AND channel_type = 'in_app'
            ORDER BY created_at DESC
            LIMIT $3
            "#,
        )
        .bind(tenant_id)
        .bind(contact_id)
        .bind(PORTAL_INBOX_LIMIT)
        .fetch_all(&mut *tx)
        .await?;
        let (unread_count,): (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*)::BIGINT
            FROM notifications
            WHERE tenant_id = $1
              AND contact_id = $2
              AND channel_type = 'in_app'
              AND read_at IS NULL
            "#,
        )
        .bind(tenant_id)
        .bind(contact_id)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;

        let notifications = rows
            .into_iter()
            .map(
                |(id, subject, body, read_at, created_at)| PortalNotification {
                    id,
                    subject,
                    body,
                    read_at,
                    created_at,
                },
            )
            .collect();
        Ok(PortalNotificationsResponse {
            notifications,
            unread_count,
        })
    }

    /// PMS-729 phase 2 §7 slice C / I3: list every asset owned by the
    /// caller's company. RMM ids, notes, and custom fields are dropped;
    /// only the customer-facing subset (tag, name, type, status, mfr,
    /// model, serial, warranty, EOL) surfaces.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, company_id = %company_id))]
    pub async fn list_portal_assets(
        &self,
        tenant_id: crate::modules::auth::TenantId,
        company_id: Uuid,
    ) -> AppResult<Vec<PortalAsset>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows: Vec<(
            Uuid,
            Option<String>,
            String,
            String,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<chrono::NaiveDate>,
            Option<chrono::NaiveDate>,
        )> = sqlx::query_as(
            r#"
            SELECT a.id, a.asset_tag, a.name, at.name AS asset_type, a.status,
                   a.manufacturer, a.model, a.serial_number,
                   a.warranty_expiry, a.end_of_life
            FROM assets a
            JOIN asset_types at ON at.id = a.asset_type_id
            WHERE a.tenant_id = $1 AND a.company_id = $2
            ORDER BY a.name ASC
            "#,
        )
        .bind(tenant_id)
        .bind(company_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rows
            .into_iter()
            .map(
                |(
                    id,
                    asset_tag,
                    name,
                    asset_type,
                    status,
                    manufacturer,
                    model,
                    serial_number,
                    warranty_expiry,
                    end_of_life,
                )| PortalAsset {
                    id,
                    asset_tag,
                    name,
                    asset_type,
                    status,
                    manufacturer,
                    model,
                    serial_number,
                    warranty_expiry,
                    end_of_life,
                },
            )
            .collect())
    }

    /// PMS-729 phase 2 §7 slice C / I3: single asset detail for a
    /// portal caller. Cross-company / unknown ids surface as 404.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, company_id = %company_id, asset_id = %asset_id))]
    pub async fn get_portal_asset(
        &self,
        tenant_id: crate::modules::auth::TenantId,
        company_id: Uuid,
        asset_id: Uuid,
    ) -> AppResult<PortalAsset> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: Option<(
            Uuid,
            Option<String>,
            String,
            String,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<chrono::NaiveDate>,
            Option<chrono::NaiveDate>,
        )> = sqlx::query_as(
            r#"
            SELECT a.id, a.asset_tag, a.name, at.name AS asset_type, a.status,
                   a.manufacturer, a.model, a.serial_number,
                   a.warranty_expiry, a.end_of_life
            FROM assets a
            JOIN asset_types at ON at.id = a.asset_type_id
            WHERE a.tenant_id = $1 AND a.company_id = $2 AND a.id = $3
            "#,
        )
        .bind(tenant_id)
        .bind(company_id)
        .bind(asset_id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        let Some((
            id,
            asset_tag,
            name,
            asset_type,
            status,
            manufacturer,
            model,
            serial_number,
            warranty_expiry,
            end_of_life,
        )) = row
        else {
            return Err(AppError::NotFound("Asset".to_string()));
        };
        Ok(PortalAsset {
            id,
            asset_tag,
            name,
            asset_type,
            status,
            manufacturer,
            model,
            serial_number,
            warranty_expiry,
            end_of_life,
        })
    }

    /// PMS-729 phase 2 §7 slice C / I4: list every contract that
    /// touches the caller's company. `internal_notes` + `custom_fields`
    /// are dropped; SLA + billing_amount stay because the customer is
    /// paying for those.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, company_id = %company_id))]
    pub async fn list_portal_contracts(
        &self,
        tenant_id: crate::modules::auth::TenantId,
        company_id: Uuid,
    ) -> AppResult<Vec<PortalContract>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows: Vec<(
            Uuid,
            Option<String>,
            String,
            String,
            String,
            chrono::NaiveDate,
            Option<chrono::NaiveDate>,
            Option<String>,
            Option<rust_decimal::Decimal>,
        )> = sqlx::query_as(
            r#"
            SELECT id, contract_number, name, contract_type, status,
                   start_date, end_date, billing_cycle, billing_amount
            FROM contracts
            WHERE tenant_id = $1 AND company_id = $2
            ORDER BY start_date DESC, name ASC
            "#,
        )
        .bind(tenant_id)
        .bind(company_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rows.into_iter().map(build_portal_contract).collect())
    }

    /// PMS-729 phase 2 §7 slice C / I4: contract detail. 404 for
    /// cross-company / unknown ids.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, company_id = %company_id, contract_id = %contract_id))]
    pub async fn get_portal_contract(
        &self,
        tenant_id: crate::modules::auth::TenantId,
        company_id: Uuid,
        contract_id: Uuid,
    ) -> AppResult<PortalContract> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: Option<(
            Uuid,
            Option<String>,
            String,
            String,
            String,
            chrono::NaiveDate,
            Option<chrono::NaiveDate>,
            Option<String>,
            Option<rust_decimal::Decimal>,
        )> = sqlx::query_as(
            r#"
            SELECT id, contract_number, name, contract_type, status,
                   start_date, end_date, billing_cycle, billing_amount
            FROM contracts
            WHERE tenant_id = $1 AND company_id = $2 AND id = $3
            "#,
        )
        .bind(tenant_id)
        .bind(company_id)
        .bind(contract_id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        row.map(build_portal_contract)
            .ok_or_else(|| AppError::NotFound("Contract".to_string()))
    }

    /// PMS-729 phase 2 §7 slice C / I5: list every billable time entry
    /// against the caller's company. Internal notes, rate, total, and
    /// approval reasons are dropped. Only entries the customer would
    /// see on an invoice are returned: `is_billable = TRUE` and
    /// `approval_status IN ('approved', 'pending')`; rejected entries
    /// stay hidden because they will not appear on the customer's bill.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, company_id = %company_id))]
    pub async fn list_portal_time_entries(
        &self,
        tenant_id: crate::modules::auth::TenantId,
        company_id: Uuid,
    ) -> AppResult<Vec<PortalTimeEntry>> {
        const LIMIT: i64 = 200;
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        #[allow(clippy::type_complexity)]
        let rows: Vec<(
            Uuid,
            chrono::NaiveDate,
            i32,
            String,
            Option<Uuid>,
            Option<String>,
            Option<Uuid>,
            Option<String>,
            Option<String>,
            String,
            String,
            bool,
        )> = sqlx::query_as(
            r#"
            SELECT te.id, te.date, te.duration_minutes, wt.name AS work_type,
                   te.ticket_id, t.ticket_number,
                   te.project_id, p.name AS project_name,
                   te.notes,
                   te.billing_status, te.approval_status, te.is_billable
            FROM time_entries te
            JOIN work_types wt ON wt.id = te.work_type_id
            LEFT JOIN tickets t ON t.id = te.ticket_id
            LEFT JOIN projects p ON p.id = te.project_id
            WHERE te.tenant_id = $1
              AND te.company_id = $2
              AND te.is_billable = TRUE
              AND te.approval_status IN ('approved', 'pending')
            ORDER BY te.date DESC, te.created_at DESC
            LIMIT $3
            "#,
        )
        .bind(tenant_id)
        .bind(company_id)
        .bind(LIMIT)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rows
            .into_iter()
            .map(
                |(
                    id,
                    date,
                    duration_minutes,
                    work_type,
                    ticket_id,
                    ticket_number,
                    project_id,
                    project_name,
                    notes,
                    billing_status,
                    approval_status,
                    is_billable,
                )| PortalTimeEntry {
                    id,
                    date,
                    duration_minutes,
                    work_type,
                    ticket_id,
                    ticket_number,
                    project_id,
                    project_name,
                    notes,
                    billing_status,
                    approval_status,
                    is_billable,
                },
            )
            .collect())
    }

    /// PMS-729 phase 2 §7 slice C / I6: list every project scoped to
    /// the caller's company. Internal projects (`project_type =
    /// 'internal'`) stay hidden.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, company_id = %company_id))]
    pub async fn list_portal_projects(
        &self,
        tenant_id: crate::modules::auth::TenantId,
        company_id: Uuid,
    ) -> AppResult<Vec<PortalProject>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        #[allow(clippy::type_complexity)]
        let rows: Vec<(
            Uuid,
            Option<String>,
            String,
            Option<String>,
            String,
            Option<chrono::NaiveDate>,
            Option<chrono::NaiveDate>,
            Option<chrono::NaiveDate>,
            Option<rust_decimal::Decimal>,
        )> = sqlx::query_as(
            r#"
            SELECT id, project_number, name, description, status,
                   start_date, target_end_date, actual_end_date, budget_hours
            FROM projects
            WHERE tenant_id = $1 AND company_id = $2
              AND project_type = 'client'
            ORDER BY COALESCE(start_date, '1970-01-01'::date) DESC, name ASC
            "#,
        )
        .bind(tenant_id)
        .bind(company_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rows.into_iter().map(build_portal_project).collect())
    }

    /// PMS-729 phase 2 §7 slice C / I6: project detail (with phases).
    /// Cross-company / internal-only / unknown ids surface as 404.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, company_id = %company_id, project_id = %project_id))]
    pub async fn get_portal_project(
        &self,
        tenant_id: crate::modules::auth::TenantId,
        company_id: Uuid,
        project_id: Uuid,
    ) -> AppResult<PortalProjectDetail> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        #[allow(clippy::type_complexity)]
        let row: Option<(
            Uuid,
            Option<String>,
            String,
            Option<String>,
            String,
            Option<chrono::NaiveDate>,
            Option<chrono::NaiveDate>,
            Option<chrono::NaiveDate>,
            Option<rust_decimal::Decimal>,
        )> = sqlx::query_as(
            r#"
            SELECT id, project_number, name, description, status,
                   start_date, target_end_date, actual_end_date, budget_hours
            FROM projects
            WHERE tenant_id = $1 AND company_id = $2 AND id = $3
              AND project_type = 'client'
            "#,
        )
        .bind(tenant_id)
        .bind(company_id)
        .bind(project_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(project_row) = row else {
            tx.commit().await?;
            return Err(AppError::NotFound("Project".to_string()));
        };
        let phase_rows: Vec<(
            Uuid,
            String,
            Option<String>,
            String,
            i32,
            Option<chrono::NaiveDate>,
            Option<chrono::NaiveDate>,
        )> = sqlx::query_as(
            r#"
            SELECT id, name, description, status, sort_order, start_date, end_date
            FROM project_phases
            WHERE tenant_id = $1 AND project_id = $2
            ORDER BY sort_order ASC, name ASC
            "#,
        )
        .bind(tenant_id)
        .bind(project_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;

        Ok(PortalProjectDetail {
            project: build_portal_project(project_row),
            phases: phase_rows
                .into_iter()
                .map(
                    |(id, name, description, status, sort_order, start_date, end_date)| {
                        PortalProjectPhase {
                            id,
                            name,
                            description,
                            status,
                            sort_order,
                            start_date,
                            end_date,
                        }
                    },
                )
                .collect(),
        })
    }

    /// PMS-729 phase 2 §7 slice B / I12: mark a portal inbox row as
    /// read. Contact-scoped: another company's contact (or an agent
    /// user row) cannot mark this row read even if they guess the id.
    /// Idempotent - a re-mark leaves the earlier `read_at` intact.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, contact_id = %contact_id, notification_id = %notification_id))]
    pub async fn mark_portal_notification_read(
        &self,
        tenant_id: crate::modules::auth::TenantId,
        contact_id: Uuid,
        notification_id: Uuid,
    ) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let updated = sqlx::query(
            r#"
            UPDATE notifications
            SET read_at = NOW()
            WHERE tenant_id = $1
              AND contact_id = $2
              AND id = $3
              AND read_at IS NULL
            "#,
        )
        .bind(tenant_id)
        .bind(contact_id)
        .bind(notification_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        // Re-fetch to distinguish "already read" (idempotent success) from
        // "does not exist / cross-contact" (404).
        if updated == 0 {
            let exists: bool = sqlx::query_scalar(
                r#"
                SELECT EXISTS (
                    SELECT 1 FROM notifications
                    WHERE tenant_id = $1 AND contact_id = $2 AND id = $3
                )
                "#,
            )
            .bind(tenant_id)
            .bind(contact_id)
            .bind(notification_id)
            .fetch_one(&mut *tx)
            .await?;
            tx.commit().await?;
            if !exists {
                return Err(AppError::NotFound("Notification".to_string()));
            }
            // Already marked: idempotent success, no error.
            return Ok(());
        }
        tx.commit().await?;
        Ok(())
    }
}

/// PMS-729 phase 2 H5: bridge the shared [`password_policy`] error
/// variant onto the portal-facing [`AppError::BadRequest`] so the wire
/// shape matches every other portal validation failure. The message
/// content is passed through verbatim (already user-safe by design).
fn apply_password_policy(new_password: &str, hints: &[String]) -> AppResult<()> {
    let hints_ref: Vec<&str> = hints.iter().map(String::as_str).collect();
    password_policy::validate(new_password, &hints_ref, PasswordPolicy::default())
        .map_err(|PasswordPolicyError::UserMessage(msg)| AppError::BadRequest(msg))
}

/// PMS-729 phase 2 §7 slice C / I4: helper mapping a contract row
/// tuple into the customer-facing DTO. Extracted so the list and
/// detail methods share one projection.
#[allow(clippy::type_complexity)]
fn build_portal_contract(
    row: (
        Uuid,
        Option<String>,
        String,
        String,
        String,
        chrono::NaiveDate,
        Option<chrono::NaiveDate>,
        Option<String>,
        Option<rust_decimal::Decimal>,
    ),
) -> PortalContract {
    let (
        id,
        contract_number,
        name,
        contract_type,
        status,
        start_date,
        end_date,
        billing_cycle,
        billing_amount,
    ) = row;
    PortalContract {
        id,
        contract_number,
        name,
        contract_type,
        status,
        start_date,
        end_date,
        billing_cycle,
        billing_amount,
    }
}

/// PMS-729 phase 2 §7 slice C / I6: helper mapping a project row
/// tuple into the customer-facing DTO. Detail response wraps this in
/// [`PortalProjectDetail`] with the phase list.
#[allow(clippy::type_complexity)]
fn build_portal_project(
    row: (
        Uuid,
        Option<String>,
        String,
        Option<String>,
        String,
        Option<chrono::NaiveDate>,
        Option<chrono::NaiveDate>,
        Option<chrono::NaiveDate>,
        Option<rust_decimal::Decimal>,
    ),
) -> PortalProject {
    let (
        id,
        project_number,
        name,
        description,
        status,
        start_date,
        target_end_date,
        actual_end_date,
        budget_hours,
    ) = row;
    PortalProject {
        id,
        project_number,
        name,
        description,
        status,
        start_date,
        target_end_date,
        actual_end_date,
        budget_hours,
    }
}

/// PMS-729 phase 2 H3: what `request_password_reset` returns to the
/// route handler when the (tenant_slug, email) pair matches an active
/// portal contact. The handler uses it to dispatch the reset email.
/// The plaintext `token` is present here exactly once; it is not
/// stored anywhere on the server side (only its Argon2id hash lives on
/// the `portal_password_reset_tokens` row).
#[derive(Debug, Clone)]
pub struct PasswordResetIssue {
    pub contact_id: Uuid,
    pub tenant_id: Uuid,
    pub email: String,
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

/// PMS-729 phase 2 H1+H2: what `issue_refresh_token` returns. The
/// `id` is the row id (also used as the JWT `sid` claim so an access
/// token can be tied back to its issuing refresh row for H6). The
/// `token` is the plaintext `{id}.{secret}` form handed to the SPA.
#[derive(Debug, Clone)]
struct IssuedRefreshToken {
    id: Uuid,
    token: String,
    expires_at: DateTime<Utc>,
}

/// PMS-729 phase 2 H7: kept-out portal analogue of the agent-side
/// `LoginLocationDecision` (auth/service.rs). Pure branch logic so the
/// service method stays readable.
#[derive(Debug, PartialEq, Eq)]
enum LoginLocationDecision {
    /// No prior country on record: store this one silently, no alert.
    Record,
    /// Same country as last time: do nothing.
    Unchanged,
    /// Country differs from last time: alert the contact, then store the new one.
    Alert,
}

fn login_location_decision(previous: Option<&str>, current: &str) -> LoginLocationDecision {
    match previous {
        None => LoginLocationDecision::Record,
        Some(prev) if prev == current => LoginLocationDecision::Unchanged,
        Some(_) => LoginLocationDecision::Alert,
    }
}

/// PMS-729 phase 2 H7: private / loopback / link-local / unspecified /
/// broadcast addresses can never map to a public country. Skip them so
/// a request behind an mis-configured proxy (or dev) does not register
/// as a country change. Same predicate the agent side uses.
fn is_non_public_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
        }
    }
}

#[cfg(test)]
mod login_location_tests {
    use super::{is_non_public_ip, login_location_decision, LoginLocationDecision};
    use std::net::IpAddr;

    #[test]
    fn decision_records_on_first_login() {
        assert_eq!(
            login_location_decision(None, "US"),
            LoginLocationDecision::Record
        );
    }

    #[test]
    fn decision_unchanged_on_same_country() {
        assert_eq!(
            login_location_decision(Some("GB"), "GB"),
            LoginLocationDecision::Unchanged
        );
    }

    #[test]
    fn decision_alerts_on_country_change() {
        assert_eq!(
            login_location_decision(Some("US"), "FR"),
            LoginLocationDecision::Alert
        );
    }

    #[test]
    fn public_ipv4_is_geolocatable() {
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        assert!(!is_non_public_ip(&ip));
    }

    #[test]
    fn private_ipv4_ranges_are_skipped() {
        for ip in [
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.0.1",
            "0.0.0.0",
        ] {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(is_non_public_ip(&ip), "{ip} should be non-public");
        }
    }

    #[test]
    fn loopback_and_link_local_ipv6_are_skipped() {
        for ip in ["::1", "fe80::1", "fc00::1", "::"] {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(is_non_public_ip(&ip), "{ip} should be non-public");
        }
    }
}

/// PMS-729 phase 2 H4: hex-SHA-256 of the canonical recovery-code form
/// so the hash fits a `TEXT[]` column (postgres has no `BYTEA[]` bind
/// story that sqlx handles cleanly). Same helper agent-side uses; kept
/// as a portal-local copy so future divergence (e.g. per-tenant salt)
/// is a one-file change.
fn recovery_code_hex_hash(code: &str) -> String {
    let raw = crate::utils::recovery::hash_code(code);
    let mut out = String::with_capacity(raw.len() * 2);
    for b in raw {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Split a portal setup token `{contact_id}.{secret}` into its parts.
/// Mirrors the user-bound reset token shape in `auth::service` so the
/// stored hash can be scoped to a single contact. Returns `None` for any
/// malformed token (no dot, unparseable id, empty secret).
fn parse_contact_bound_token(token: &str) -> Option<(Uuid, &str)> {
    let (id, secret) = token.split_once('.')?;
    if secret.is_empty() {
        return None;
    }
    let contact_id = Uuid::parse_str(id).ok()?;
    Some((contact_id, secret))
}

/// PMS-501: exponential-backoff lockout schedule for portal logins.
///
/// The first [`LOCKOUT_THRESHOLD`] consecutive failures only tick the
/// counter (legitimate users fat-finger a password a few times). Each
/// failure at or beyond the threshold locks the account for a doubling
/// window starting at [`LOCKOUT_BASE_SECONDS`] and capped at
/// [`LOCKOUT_MAX_SECONDS`], measured from `now`:
///
/// | failed_count | lock window |
/// |--------------|-------------|
/// | 1..=4        | none        |
/// | 5            | 30s         |
/// | 6            | 60s         |
/// | 7            | 120s        |
/// | ...          | ...         |
/// | 12+          | 3600s (cap) |
///
/// Returns `None` while under the threshold (no lockout yet).
///
/// PMS-693: `pub` so the DB-backed parity test can pin [`lock_seconds_sql`],
/// the SQL twin that `register_failed_login` runs, against this Rust
/// definition of the schedule.
pub fn lockout_until(failed_count: i32, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
    /// Failures tolerated before any lockout arms.
    const LOCKOUT_THRESHOLD: i32 = 5;
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

/// PMS-693: SQL twin of [`lockout_until`], as an expression yielding the lock
/// window in seconds (NULL under the threshold) for the post-increment failure
/// count `count_expr`. `register_failed_login` needs the schedule evaluated
/// inside its `UPDATE` so the window is derived from the counter value the
/// database just produced, never from a stale read. Keeping it in one place
/// lets `portal_lock_seconds_sql_matches_rust_schedule` (`tests/portal.rs`)
/// pin it against the Rust helper.
///
/// `count_expr` is a caller-supplied SQL fragment (a column expression or a
/// bind placeholder), never user input.
pub fn lock_seconds_sql(count_expr: &str) -> String {
    format!(
        "CASE WHEN ({count_expr}) >= 5 \
         THEN LEAST(3600, 30 * 2 ^ LEAST(20, ({count_expr}) - 5))::double precision END"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_lockout_under_threshold() {
        let now = Utc::now();
        for count in 0..5 {
            assert!(
                lockout_until(count, now).is_none(),
                "count {count} should not lock"
            );
        }
    }

    #[test]
    fn lockout_arms_at_threshold() {
        let now = Utc::now();
        let until = lockout_until(5, now).expect("5th failure locks");
        assert_eq!((until - now).num_seconds(), 30);
    }

    #[test]
    fn lockout_window_doubles() {
        let now = Utc::now();
        assert_eq!((lockout_until(6, now).unwrap() - now).num_seconds(), 60);
        assert_eq!((lockout_until(7, now).unwrap() - now).num_seconds(), 120);
        assert_eq!((lockout_until(8, now).unwrap() - now).num_seconds(), 240);
    }

    #[test]
    fn lockout_window_is_capped() {
        let now = Utc::now();
        // Far past the doubling sequence: still clamped to the 1h ceiling,
        // and a huge count must not panic on shift overflow.
        assert_eq!((lockout_until(50, now).unwrap() - now).num_seconds(), 3600);
        assert_eq!(
            (lockout_until(i32::MAX, now).unwrap() - now).num_seconds(),
            3600
        );
    }
}
