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
use crate::utils::crypto::{hash_password, verify_password};
use crate::utils::error::{AppError, AppResult};

use super::models::*;

/// Portal-side counterpart to `AuthService`. Stateless except for the
/// JWT signing secret and the database handle.
#[derive(Clone)]
pub struct PortalAuthService {
    db: Database,
    jwt_secret: String,
    access_token_ttl: Duration,
}

impl PortalAuthService {
    pub fn new(db: Database, jwt_secret: String) -> Self {
        Self {
            db,
            jwt_secret,
            access_token_ttl: Duration::hours(8),
        }
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
            },
        })
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
        sqlx::query(
            "UPDATE contacts SET portal_password_hash = $1, is_portal_user = TRUE, updated_at = NOW() WHERE id = $2",
        )
        .bind(&hash)
        .bind(contact_id)
        .execute(self.db.migrator_pool())
        .await?;
        Ok(())
    }
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
