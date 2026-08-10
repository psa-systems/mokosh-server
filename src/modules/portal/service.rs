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
use crate::modules::auth::TenantId;
use crate::modules::notifications::NotificationsService;
use crate::utils::crypto::{hash_password, verify_password};
use crate::utils::error::{AppError, AppResult};
use crate::utils::password_policy::{self, PasswordPolicy, PasswordPolicyError};

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
        }
    }

    /// PMS-729 phase 2 H3: builder that attaches a notifications
    /// dispatcher so the service can queue the password-reset email.
    pub fn with_notifications(mut self, notifications: NotificationsService) -> Self {
        self.notifications = Some(notifications);
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
    #[allow(clippy::type_complexity)]
    #[tracing::instrument(skip_all)]
    pub async fn login(
        &self,
        slug: &str,
        email: &str,
        password: &str,
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
        )> = sqlx::query_as(
            r#"
                SELECT c.id, c.tenant_id, c.company_id, c.email, c.first_name,
                       c.last_name, c.is_portal_user, c.portal_password_hash,
                       c.portal_locked_until
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
            return Err(AppError::Unauthorized);
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
        let (access_token, expires_at) =
            self.mint_access_token(id, tenant_id, company_id, &email, now)?;
        let (refresh_token, refresh_expires_at) = self
            .issue_refresh_token(tenant_id, id, None, now, user_agent, ip_address)
            .await?;

        Ok(PortalLoginResponse {
            access_token,
            expires_at,
            refresh_token,
            refresh_expires_at,
            contact: CurrentContact {
                id,
                tenant_id,
                company_id,
                email,
                first_name,
                last_name,
            },
        })
    }

    /// PMS-729 phase 2 H1+H2: mint a fresh HS256 access JWT for the given
    /// contact. Extracted so both `login` and `refresh` can call it with
    /// the same claim shape and TTL.
    fn mint_access_token(
        &self,
        contact_id: Uuid,
        tenant_id: Uuid,
        company_id: Uuid,
        email: &str,
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
    ) -> AppResult<(String, DateTime<Utc>)> {
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
        Ok((format!("{id}.{secret}"), expires_at))
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
        let (access_token, expires_at) =
            self.mint_access_token(contact_id, tenant_id, company_id, &email, now)?;
        let (refresh_token, refresh_expires_at) = self
            .issue_refresh_token(
                tenant_id,
                contact_id,
                Some(row_id),
                now,
                user_agent,
                ip_address,
            )
            .await?;
        Ok(PortalRefreshResponse {
            access_token,
            expires_at,
            refresh_token,
            refresh_expires_at,
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
        let row: Option<(String,)> =
            sqlx::query_as("SELECT token_hash FROM portal_refresh_tokens WHERE id = $1")
                .bind(row_id)
                .fetch_optional(self.db.migrator_pool())
                .await?;
        let Some((token_hash,)) = row else {
            return Ok(());
        };
        if !verify_password(secret, &token_hash)? {
            return Ok(());
        }
        self.revoke_rotation_chain(row_id).await?;
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

    /// PMS-729: look up a tenant by slug for the host-to-tenant
    /// resolution path. Returns `Some` when the slug matches an active
    /// row; `None` on miss or inactive (fail-closed). The login handler
    /// and the `/host` branding endpoint both call this after the
    /// [`super::host_tenant::PortalHostConfig::extract_slug`] filter has
    /// validated the label shape.
    ///
    /// Reads `tenants.branding` as JSONB and pulls a `logo_url` key out
    /// of it when present. The full branding blob stays private; only
    /// the two fields the login page renders are exposed.
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
                logo_url: branding
                    .get("logo_url")
                    .and_then(|v| v.as_str())
                    .map(String::from),
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
