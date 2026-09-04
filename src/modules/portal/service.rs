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
use crate::utils::crypto::{generate_token, hash_password, verify_password};
use crate::utils::error::{AppError, AppResult};

use super::models::*;

/// Lifetime of a portal self-service reset token (PMS-820). Shorter than
/// the 72h agent-minted setup link: the customer asked for this one
/// seconds ago and is waiting on it.
const PORTAL_RESET_TOKEN_TTL_HOURS: i64 = 24;

/// Portal-side counterpart to `AuthService`. Stateless except for the
/// JWT signing secret, the database handle and (PMS-820) the delivery
/// wiring the self-service reset mail needs.
#[derive(Clone)]
pub struct PortalAuthService {
    db: Database,
    jwt_secret: String,
    access_token_ttl: Duration,
    /// SPA origin the emailed `/portal/reset-password?token=...` link is
    /// built from. Empty when the service was built without delivery.
    app_url: String,
    /// Dispatcher the reset mail is queued through. `None` in fixtures
    /// built with [`PortalAuthService::new`]; the token is still persisted
    /// and the miss is logged.
    notifications: Option<NotificationsService>,
}

impl PortalAuthService {
    pub fn new(db: Database, jwt_secret: String) -> Self {
        Self {
            db,
            jwt_secret,
            access_token_ttl: Duration::hours(8),
            app_url: String::new(),
            notifications: None,
        }
    }

    /// PMS-820: same service with the reset-mail delivery wiring. `app_url`
    /// is the SPA origin (the base of the `/portal/reset-password` page),
    /// matching what `ContactService` uses for the setup link.
    pub fn with_delivery(
        db: Database,
        jwt_secret: String,
        app_url: String,
        notifications: NotificationsService,
    ) -> Self {
        Self {
            app_url,
            notifications: Some(notifications),
            ..Self::new(db, jwt_secret)
        }
    }

    /// Verify (tenant_slug, email, password) against the contacts table
    /// and issue a portal JWT on success. Returns 401 on any credential
    /// failure so the surface stays enumeration-resistant, and 429
    /// (`AppError::RateLimited`) when the account is in a lockout window
    /// from repeated failures (PMS-501).
    #[allow(clippy::type_complexity)]
    #[tracing::instrument(skip_all)]
    pub async fn login(&self, request: &PortalLoginRequest) -> AppResult<PortalLoginResponse> {
        // `c.company_id` is `Option<Uuid>`: PMS-402 made it nullable and PMS-812
        // makes deleting a company null it out rather than delete the contact.
        // Decoding it as a bare `Uuid` turned that row into a decode error, so a
        // customer whose company was deleted got a 500 from the login endpoint.
        let row: Option<(
            Uuid,
            Uuid,
            Option<Uuid>,
            String,
            String,
            String,
            bool,
            Option<String>,
            Option<DateTime<Utc>>,
            bool,
        )> = sqlx::query_as(
            r#"
                SELECT c.id, c.tenant_id, c.company_id, c.email, c.first_name,
                       c.last_name, c.is_portal_user, c.portal_password_hash,
                       c.portal_locked_until,
                       -- PMS-993: the billing role for the company this session
                       -- scopes to, so the login response says up front whether
                       -- the invoice surface is reachable. A correlated EXISTS,
                       -- not a join: `company_id` is nullable, and a join would
                       -- drop the row and turn a company-less contact's login
                       -- into "unknown credential".
                       EXISTS(SELECT 1 FROM companies co
                              WHERE co.tenant_id = c.tenant_id
                                AND co.id = c.company_id
                                AND co.default_billing_contact_id = c.id)
                FROM contacts c
                INNER JOIN tenants t ON c.tenant_id = t.id
                WHERE t.slug = $1 AND c.email = $2 AND t.status = 'active'
                "#,
        )
        .bind(&request.tenant_slug)
        .bind(&request.email)
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
            is_billing_contact,
        )) = row
        else {
            return Err(AppError::Unauthorized);
        };

        // PMS-501: persistent account lockout. If the contact is inside an
        // active backoff window, reject before spending an Argon2 verify so
        // the lockout actually cuts the attacker's guess rate (and survives a
        // process restart, unlike the in-memory limiter).
        if locked_until.is_some_and(|until| until > Utc::now()) {
            // No wait is disclosed here on purpose: unlike the MFA lockout the
            // caller has not proved possession of the password, so the window
            // would tell an enumerator which addresses are real accounts.
            return Err(AppError::RateLimited {
                retry_after_seconds: None,
            });
        }

        if !is_portal_user {
            return Err(AppError::Unauthorized);
        }
        let Some(hash) = hash else {
            return Err(AppError::Unauthorized);
        };
        if !verify_password(&request.password, &hash)? {
            // PMS-501: record the failure and (re)arm the lockout window.
            self.register_failed_login(id).await?;
            return Err(AppError::Unauthorized);
        }

        // PMS-812: every portal read is scoped by `CurrentContact.company_id`
        // (tickets, invoices, quotes, KB articles), so a contact with no company
        // has nothing to scope a session to. Reject explicitly, and log it: the
        // password was correct, so this is a real customer locked out by an
        // agent deleting their company, and a bare 401 gives the operator no way
        // to find that out.
        let Some(company_id) = company_id else {
            tracing::warn!(
                contact_id = %id,
                tenant_id = %tenant_id,
                "portal login rejected: contact has no company (its company was \
                 deleted or never set); re-link the contact to a company",
            );
            return Err(AppError::Unauthorized);
        };

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
        let expires_at = now + self.access_token_ttl;
        let claims = PortalJwtClaims {
            sub: id,
            tid: tenant_id,
            cid: company_id,
            email: email.clone(),
            iat: now.timestamp(),
            exp: expires_at.timestamp(),
            typ: "portal_access".to_string(),
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )
        .map_err(|e| AppError::Internal(format!("portal jwt sign: {e}")))?;

        Ok(PortalLoginResponse {
            access_token: token,
            expires_at,
            contact: CurrentContact {
                id,
                tenant_id,
                company_id,
                email,
                first_name,
                last_name,
                is_billing_contact,
            },
        })
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

    /// Re-read the per-request facts the middleware needs from the
    /// `contacts` row: the display names, and MAPPS-532's revocation cutoff.
    ///
    /// The portal JWT omits names (PII minimisation), so the middleware
    /// hydrates `first_name` / `last_name` for `/me`-style handlers after
    /// decoding the token (PMS-195). The cutoff comes back in the same read
    /// because the row is already being loaded. Scoped by `(tenant_id, id)`.
    ///
    /// PMS-993: `company_id` is the token's `cid` claim, and the billing role
    /// rides along as a correlated EXISTS rather than a join. A join to
    /// `companies` would drop the `contacts` row for a contact whose company is
    /// missing, and this read IS MAPPS-532's revocation check: no row means the
    /// middleware degrades to empty names instead of rejecting the token, so a
    /// query that can lose the row turns sign-out-everywhere into a no-op.
    pub async fn contact_snapshot(
        &self,
        tenant_id: Uuid,
        contact_id: Uuid,
        company_id: Uuid,
    ) -> AppResult<Option<PortalContactSnapshot>> {
        let row: Option<(String, String, Option<DateTime<Utc>>, bool)> = sqlx::query_as(
            "SELECT c.first_name, c.last_name, c.portal_tokens_valid_from, \
                    EXISTS(SELECT 1 FROM companies co \
                           WHERE co.tenant_id = c.tenant_id AND co.id = $3 \
                             AND co.default_billing_contact_id = c.id) \
             FROM contacts c WHERE c.tenant_id = $1 AND c.id = $2",
        )
        .bind(tenant_id)
        .bind(contact_id)
        .bind(company_id)
        // PMS-692: `contacts` is RLS-covered; scope the read with the tenant GUC
        // so it does not fail closed on the NOBYPASSRLS serving connection.
        .fetch_optional(&mut *self.db.begin_with_tenant(tenant_id).await?)
        .await?;
        Ok(row.map(
            |(first_name, last_name, tokens_valid_from, is_billing_contact)| {
                PortalContactSnapshot {
                    first_name,
                    last_name,
                    tokens_valid_from,
                    is_billing_contact,
                }
            },
        ))
    }

    /// MAPPS-532: end every portal session this contact holds.
    ///
    /// The portal plane is stateless - `login` mints a JWT and writes no
    /// session row, and `PortalJwtClaims` carries no session id - so there is
    /// nothing to delete the way `AuthService::logout` deletes a
    /// `user_sessions` row. Stamping the contact instead invalidates every
    /// token issued before now, which is sign-out-everywhere: the right
    /// default for a customer with one credential, no session manager and a
    /// possibly shared machine.
    #[tracing::instrument(skip(self))]
    pub async fn logout(&self, tenant_id: Uuid, contact_id: Uuid) -> AppResult<()> {
        // The caller came through `RequirePortalAuth`, so the tenant is the
        // verified `tid` claim: a tenant-scoped write on the RLS-covered
        // `contacts` table, no migrator pool needed.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            "UPDATE contacts SET portal_tokens_valid_from = NOW(), updated_at = NOW() \
             WHERE id = $1 AND tenant_id = $2",
        )
        .bind(contact_id)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
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

    /// PMS-820: start a portal self-service password reset.
    ///
    /// Resolves the identity inside the portal's own scope only - a
    /// `contacts` row under the tenant named by `tenant_slug`, exactly the
    /// resolution [`login`](Self::login) does - so it can never reach a
    /// `users` row, whatever platform account shares the address. Only a
    /// contact that already HAS portal access gets a token: minting for a
    /// contact whose `is_portal_user` is false would let anyone in the
    /// tenant's address book grant themselves a portal login.
    ///
    /// Always returns `Ok(())`. An unknown address gets the same body, the
    /// same status and (via the dummy Argon2 hash below) the same cost as a
    /// known one, so the endpoint does not enumerate customers.
    ///
    /// A duplicated address inside one tenant mints one token per matching
    /// portal contact: `contacts.email` is only indexed, not unique, and
    /// `login` picks whichever row the planner returns first, so minting for
    /// exactly one of them could hand out a link for the identity the
    /// customer cannot sign into.
    #[tracing::instrument(skip_all)]
    pub async fn request_password_reset(&self, tenant_slug: &str, email: &str) -> AppResult<()> {
        // SAFETY (PMS-285): pre-auth, the same `(tenant_slug, email)` lookup
        // `login` runs and for the same reason - there is no session yet, so no
        // `app.current_tenant` GUC to set, and `contacts` is RLS-covered so the
        // app pool would fail this read closed.
        let contacts: Vec<(Uuid, Uuid, String, String)> = sqlx::query_as(
            r#"
                SELECT c.id, c.tenant_id, c.email, c.first_name
                FROM contacts c
                INNER JOIN tenants t ON c.tenant_id = t.id
                WHERE t.slug = $1 AND c.email = $2 AND t.status = 'active'
                  AND c.is_portal_user = TRUE
                ORDER BY c.created_at
                "#,
        )
        .bind(tenant_slug)
        .bind(email)
        .fetch_all(self.db.migrator_pool())
        .await?;

        if contacts.is_empty() {
            // Spend one Argon2 hash anyway so an unknown address costs the same
            // wall-clock as a known one; without it the response time answers
            // the question the flat 200 refuses to.
            hash_password(&generate_token(64))?;
            tracing::info!(
                tenant_slug,
                "portal password reset requested for an address with no portal contact; \
                 responding 200 without minting a token",
            );
            return Ok(());
        }

        for (contact_id, tenant_id, contact_email, first_name) in contacts {
            let secret = generate_token(64);
            let token_hash = hash_password(&secret)?;
            let token = format!("{contact_id}.{secret}");
            let expires_at = Utc::now() + Duration::hours(PORTAL_RESET_TOKEN_TTL_HOURS);

            // Same table and same token shape as the agent-minted setup link
            // (PMS-136), so the portal has one contact-bound token to redeem
            // and one replay contract rather than two.
            let mut tx = self.db.begin_with_tenant(tenant_id).await?;
            sqlx::query(
                r#"
                INSERT INTO portal_setup_tokens (tenant_id, contact_id, token_hash, expires_at)
                VALUES ($1, $2, $3, $4)
                "#,
            )
            .bind(tenant_id)
            .bind(contact_id)
            .bind(&token_hash)
            .bind(expires_at)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;

            self.send_reset_email(tenant_id, contact_id, &contact_email, &first_name, &token)
                .await;
        }

        Ok(())
    }

    /// Queue the portal reset mail through the `auth.password_reset`
    /// dispatch (PMS-820). Best effort: the token row is already committed,
    /// so a delivery failure is logged and the customer can ask again rather
    /// than rolling the mint back.
    async fn send_reset_email(
        &self,
        tenant_id: Uuid,
        contact_id: Uuid,
        email: &str,
        first_name: &str,
        token: &str,
    ) {
        let reset_link = format!(
            "{}/portal/reset-password?token={}",
            self.app_url.trim_end_matches('/'),
            token,
        );
        let Some(notify) = self.notifications.as_ref() else {
            tracing::warn!(
                contact_id = %contact_id,
                "no notifications dispatcher wired; portal reset token persisted but no message queued",
            );
            return;
        };
        let context = serde_json::json!({
            // No `recipient_user_id`: the recipient is a contact, so the fanout
            // is by address only and never resolves a `users` row.
            "recipient_email": email,
            "salutation": crate::utils::email::salutation(first_name),
            "display_name": first_name,
            "reset_link": reset_link,
        });
        // SAFETY (PMS-261): `tenant_id` is read off the contact row this reset
        // resolved, not from caller input; `dispatch` re-derives the RLS GUC per
        // query via `begin_with_tenant`.
        match notify
            .dispatch(
                TenantId::from_trusted(tenant_id),
                "auth.password_reset",
                &context,
            )
            .await
        {
            // A zero fanout is a delivered-nothing outcome, not a success: the
            // tenant has no active `auth.password_reset` rule, so the customer
            // is waiting on a mail that will never arrive.
            Ok(0) => tracing::warn!(
                contact_id = %contact_id,
                "portal reset token persisted but the tenant has no active auth.password_reset \
                 rule, so no message was queued",
            ),
            Ok(fanout) => {
                tracing::info!(contact_id = %contact_id, fanout, "portal password reset queued")
            }
            Err(e) => tracing::warn!(
                contact_id = %contact_id,
                error = ?e,
                "portal reset email dispatch failed; token persisted but link unreachable",
            ),
        }
    }

    /// Redeem a portal reset token and set the contact's password
    /// (PMS-820). Deliberately the same redemption as
    /// [`setup_password`](Self::setup_password): one contact-bound token
    /// shape in this module means one single-use rule, one expiry rule and
    /// one replay status (410) for both ways a customer arrives here.
    #[tracing::instrument(skip_all)]
    pub async fn reset_password(&self, token: &str, new_password: &str) -> AppResult<()> {
        self.setup_password(token, new_password).await
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
        if new_password.len() < 8 {
            return Err(AppError::BadRequest(
                "Password must be at least 8 characters".to_string(),
            ));
        }

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
                    return Err(AppError::Gone(
                        "This setup token has already been used".to_string(),
                    ));
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

        let hash = hash_password(new_password)?;
        // Tenant-scoped write: set the credential, revoke the tokens it
        // replaces, and burn the token, in one transaction so a crash cannot
        // leave a usable token behind a set password.
        //
        // PMS-877: `portal_tokens_valid_from` is stamped here for the same
        // reason `AuthService` stamps `users.password_changed_at` on the
        // platform side (PMS-681). The portal plane is stateless - no session
        // row to delete - so a password change that did not move the cutoff
        // left every token minted before it decoding into a session for up to
        // the full 8-hour TTL. That is the case a reset is most often for: a
        // customer resets precisely because they think someone else is holding
        // their password, and the reset has to end that someone's session, not
        // just stop them signing in again.
        //
        // This runs for an initial PMS-136 setup link too, since one method
        // serves both arrivals. Not merely harmless: a contact redeeming a
        // first link holds no portal token yet, and an agent who re-issues a
        // link to a contact who DOES hold one is changing the credential, so
        // ending those sessions is the wanted behaviour rather than a side
        // effect.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            "UPDATE contacts SET portal_password_hash = $1, is_portal_user = TRUE, \
                                 portal_tokens_valid_from = NOW(), updated_at = NOW() \
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

    /// Set or replace the portal password for a contact. Surfaces to a
    /// future `PUT /api/v1/portal/auth/password` endpoint that the
    /// customer hits after clicking their setup link.
    #[allow(dead_code)]
    #[tracing::instrument(skip_all)]
    pub async fn set_password(&self, contact_id: Uuid, new_password: &str) -> AppResult<()> {
        if new_password.len() < 8 {
            return Err(AppError::BadRequest(
                "Password must be at least 8 characters".to_string(),
            ));
        }
        let hash = hash_password(new_password)?;
        // SAFETY (PMS-285): portal account setup on the separate
        // `contacts`-identity plane (portal isolation deferred; see the login
        // note above). Reached via an emailed setup link before any portal
        // session exists, so it sets no GUC and targets the one contact by id.
        // Migrator pool because `contacts` is RLS-covered.
        //
        // PMS-877: stamped here as well as in `setup_password`. This method has
        // no caller today, and the endpoint it is waiting for is a signed-in
        // customer changing their own password - the one arrival that certainly
        // DOES hold a live portal token. Leaving the stamp to be remembered when
        // that route is wired up is how the gap PMS-877 closed would come back,
        // so the writer carries it rather than the caller.
        sqlx::query(
            "UPDATE contacts SET portal_password_hash = $1, is_portal_user = TRUE, \
                                 portal_tokens_valid_from = NOW(), updated_at = NOW() \
             WHERE id = $2",
        )
        .bind(&hash)
        .bind(contact_id)
        .execute(self.db.migrator_pool())
        .await?;
        Ok(())
    }
}

/// The contact a portal token is bound to, or `None` for a malformed one.
/// PMS-820: the reset route rate-limits per (IP, contact) and the contact
/// is only knowable from the token, so the handler needs this before the
/// service ever touches the database.
pub fn token_contact_id(token: &str) -> Option<Uuid> {
    parse_contact_bound_token(token).map(|(contact_id, _)| contact_id)
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
