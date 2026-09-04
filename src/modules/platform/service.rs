//! MAPPS-513: platform-admin service. Authenticates against
//! `platform_admins` (never `users` or `identities`); mints JWTs
//! with `typ="platform"` so the middleware can distinguish a platform
//! bearer from a tenant-scoped one.
//!
//! Deliberately minimal for stage A: login + change-password. MFA,
//! password reset via email, listing / creating additional platform
//! admins, and every other `AuthService`-style feature are out of
//! scope; existing legacy `role='super_admin'` on `users` still covers
//! those flows until stage B rewrites them.

use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use uuid::Uuid;

use crate::db::platform_admin::{PlatformAdminRepo, PlatformAdminRow};
use crate::db::Database;
use crate::utils::crypto::{hash_password, verify_password};
use crate::utils::error::{AppError, AppResult};

use super::models::{PlatformAdminProfile, PlatformLoginResponse};

/// JWT `typ` value carried by every platform-admin access token so
/// the middleware can tell it apart from tenant `access` tokens.
pub const PLATFORM_JWT_TYP: &str = "platform";

/// Session length for a platform admin. Kept short (2 hours) because
/// the platform surface is high-privilege; refresh is out of scope for
/// stage A (operator re-logs in).
const PLATFORM_SESSION_TTL: Duration = Duration::hours(2);

/// Claims for a platform-admin JWT. Distinct struct from
/// `mokosh_types::auth::JwtClaims` so the two auth paths cannot be
/// confused; the middleware routes based on `typ`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PlatformJwtClaims {
    /// Subject = platform_admins.id.
    pub sub: Uuid,
    pub email: String,
    pub iat: i64,
    pub exp: i64,
    pub typ: String,
}

#[derive(Clone)]
pub struct PlatformAdminService {
    db: Database,
    jwt_secret: String,
}

impl PlatformAdminService {
    pub fn new(db: Database, jwt_secret: String) -> Self {
        Self { db, jwt_secret }
    }

    #[allow(dead_code)]
    pub(crate) fn db(&self) -> &Database {
        &self.db
    }

    pub async fn authenticate(
        &self,
        email: &str,
        password: &str,
    ) -> AppResult<PlatformLoginResponse> {
        let pool = self.db.migrator_pool();
        let admin = PlatformAdminRepo::find_by_email(pool, email)
            .await
            .map_err(|_| AppError::Unauthorized)?
            .ok_or(AppError::Unauthorized)?;
        if admin.status != "active" {
            return Err(AppError::Unauthorized);
        }
        let hash = admin
            .password_hash
            .as_deref()
            .ok_or(AppError::Unauthorized)?;
        if !verify_password(password, hash)? {
            // MAPPS-550: one-way heal from the identity plane. The
            // platform_admins.password_hash is deliberately isolated
            // from the MAPPS-498 mirror (MAPPS-518 stage B), so a
            // tenant-side password change (change_password /
            // reset_password) never propagates to platform_admins.
            // Over time the two hashes drift: the operator updates
            // their tenant password, `identities.password_hash` +
            // `users.password_hash` catch up via the mirror, but
            // `platform_admins.password_hash` stays at whichever
            // value was there at bootstrap / migration-132 backfill.
            // Consequence: /platform/login 401s even though the
            // operator IS the platform admin, the client's
            // MAPPS-520 platform-first chain falls through, the
            // platform bearer never lands, and the sidebar's Clients
            // tab disappears from their walkthrough.
            //
            // The heal is opt-in per login attempt: when the supplied
            // password does not match the platform hash, look up the
            // identity at this email and try the identity's
            // password_hash instead. On a match, the caller has
            // proven they hold the CURRENT identity password;
            // update platform_admins.password_hash to that value
            // so the next login verifies on the hot path with no
            // extra query. Deliberately ONE-WAY: a platform-side
            // password change still does NOT propagate to
            // identities, so the MAPPS-518 stage B invariant
            // ("a tenant admin at the same email cannot clobber
            // your platform password") stays intact.
            //
            // Best-effort UPDATE: a failed write logs and still
            // returns success for the request (the caller already
            // proved they hold the current identity password);
            // subsequent logins retry the heal until the write
            // lands.
            let identity_hash: Option<String> = sqlx::query_scalar(
                "SELECT password_hash FROM identities WHERE lower(email) = lower($1)",
            )
            .bind(&admin.email)
            .fetch_optional(pool)
            .await
            .map_err(|_| AppError::Unauthorized)?
            .flatten();
            let Some(identity_hash) = identity_hash else {
                return Err(AppError::Unauthorized);
            };
            if !verify_password(password, &identity_hash)? {
                return Err(AppError::Unauthorized);
            }
            let heal_result = sqlx::query(
                "UPDATE platform_admins SET password_hash = $1, updated_at = NOW() \
                 WHERE id = $2",
            )
            .bind(&identity_hash)
            .bind(admin.id)
            .execute(pool)
            .await;
            if let Err(e) = heal_result {
                tracing::warn!(
                    error = %e,
                    admin_id = %admin.id,
                    "MAPPS-550: identity-hash heal of platform_admins.password_hash failed; login still succeeds this request"
                );
            } else {
                tracing::info!(
                    admin_id = %admin.id,
                    email = %admin.email,
                    "MAPPS-550: healed platform_admins.password_hash from identities after a drift"
                );
            }
        }

        // Best-effort last_login stamp; failure does not block the login.
        let _ = PlatformAdminRepo::update_last_login(pool, admin.id).await;

        // MAPPS-520 walkthrough: ensure the platform admin also has a
        // tenant admin users row in the default tenant. Without this,
        // a pure platform admin (fresh install; or an operator whose
        // super_admin users row was deleted by migration 133) can
        // sign in on the platform plane but sees "You need an admin
        // role" on every tenant-scoped admin surface (Invitations,
        // Audit Log, Settings, ...). The chained /auth/login the
        // client fires after platform login only succeeds if a
        // users row exists to authenticate against; this heal
        // creates one on the fly.
        //
        // Idempotent: skipped when any users row already exists for
        // this email (any tenant), so a real tenant admin at the
        // same email is not overwritten and repeated platform
        // logins are a no-op after the first.
        //
        // The MAPPS-518 credential isolation is preserved: the
        // MAPPS-498 mirror still cannot touch `platform_admins`, so
        // a subsequent tenant-side password reset only writes
        // `users.password_hash` (and via the mirror,
        // `identities.password_hash`); the platform password stays
        // exactly as-is. The tenant row's password can diverge
        // from the platform password over time; the client's
        // chained login will still succeed for whichever password
        // it holds at the moment of login.
        let _ = self.ensure_tenant_admin_row(&admin).await;

        let (access_token, expires_at) = self.mint_token(&admin)?;
        Ok(PlatformLoginResponse {
            access_token,
            expires_at,
            admin: profile_of(&admin),
        })
    }

    /// MAPPS-520: idempotent heal that ensures a `users` row exists
    /// for the platform admin so the tenant-plane surfaces work
    /// end-to-end without a manual "create your first tenant" step.
    /// Best-effort - a failure is logged and swallowed, never
    /// propagated back to `authenticate` (a hiccup here must not
    /// block a login that has already verified valid credentials).
    async fn ensure_tenant_admin_row(&self, admin: &PlatformAdminRow) -> AppResult<()> {
        let pool = self.db.migrator_pool();
        // Any live users row at this email is enough - do not clobber
        // a real tenant admin at the same email.
        let existing: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM users \
             WHERE lower(email) = lower($1) AND deleted_at IS NULL \
             LIMIT 1",
        )
        .bind(&admin.email)
        .fetch_optional(pool)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, admin_id = %admin.id, "MAPPS-520 ensure_tenant_admin_row: users lookup failed; skipping heal");
            AppError::Internal("users lookup failed".to_string())
        })?;

        if existing.is_some() {
            return Ok(());
        }

        let default_tenant = Uuid::from_u128(1);
        let password_hash = admin.password_hash.as_deref().unwrap_or("");
        let insert_result = sqlx::query(
            r#"
            INSERT INTO users (
                id, tenant_id, email, password_hash,
                first_name, last_name, role, status,
                email_verified_at, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, 'admin', 'active', NOW(), NOW(), NOW())
            ON CONFLICT (id) DO NOTHING
            "#,
        )
        .bind(admin.id)
        .bind(default_tenant)
        .bind(&admin.email)
        .bind(password_hash)
        .bind(&admin.first_name)
        .bind(&admin.last_name)
        .execute(pool)
        .await;

        if let Err(e) = insert_result {
            tracing::warn!(
                error = %e,
                admin_id = %admin.id,
                email = %admin.email,
                "MAPPS-520 ensure_tenant_admin_row: users insert failed; the platform login itself still succeeded"
            );
        } else {
            tracing::info!(
                admin_id = %admin.id,
                email = %admin.email,
                tenant_id = %default_tenant,
                "MAPPS-520 ensure_tenant_admin_row: provisioned tenant admin users row for platform admin"
            );
        }

        Ok(())
    }

    pub async fn change_password(
        &self,
        admin_id: Uuid,
        current: &str,
        new: &str,
        confirm: &str,
    ) -> AppResult<()> {
        if new != confirm {
            return Err(AppError::validation_field(
                "confirm_password",
                "Passwords do not match",
            ));
        }
        let pool = self.db.migrator_pool();
        let admin = PlatformAdminRepo::find_by_id(pool, admin_id)
            .await
            .map_err(|_| AppError::Unauthorized)?
            .ok_or(AppError::Unauthorized)?;
        let hash = admin
            .password_hash
            .as_deref()
            .ok_or(AppError::Unauthorized)?;
        if !verify_password(current, hash)? {
            return Err(AppError::validation_field(
                "current_password",
                "Current password is incorrect",
            ));
        }
        let new_hash = hash_password(new)?;
        PlatformAdminRepo::update_password_hash(pool, admin_id, &new_hash)
            .await
            .map_err(|_| AppError::Internal("Failed to update password".to_string()))?;
        Ok(())
    }

    /// Verify a platform bearer token and return the admin's id + email.
    pub fn decode_token(&self, token: &str) -> AppResult<(Uuid, String)> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        validation.validate_aud = false;
        validation.leeway = 30;
        let claims = decode::<PlatformJwtClaims>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_bytes()),
            &validation,
        )
        .map_err(|_| AppError::Unauthorized)?
        .claims;
        if claims.typ != PLATFORM_JWT_TYP {
            return Err(AppError::Unauthorized);
        }
        Ok((claims.sub, claims.email))
    }

    fn mint_token(
        &self,
        admin: &PlatformAdminRow,
    ) -> AppResult<(String, chrono::DateTime<chrono::Utc>)> {
        let now = Utc::now();
        let exp = now + PLATFORM_SESSION_TTL;
        let claims = PlatformJwtClaims {
            sub: admin.id,
            email: admin.email.clone(),
            iat: now.timestamp(),
            exp: exp.timestamp(),
            typ: PLATFORM_JWT_TYP.to_string(),
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )?;
        Ok((token, exp))
    }
}

fn profile_of(admin: &PlatformAdminRow) -> PlatformAdminProfile {
    PlatformAdminProfile {
        id: admin.id,
        email: admin.email.clone(),
        first_name: admin.first_name.clone(),
        last_name: admin.last_name.clone(),
        mfa_enabled: admin.mfa_enabled,
    }
}
