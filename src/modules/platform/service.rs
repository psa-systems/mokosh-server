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
use crate::modules::auth::mfa_secret;
use crate::utils::crypto::{hash_password, verify_password};
use crate::utils::error::{AppError, AppResult};

use super::models::{
    PlatformAdminProfile, PlatformLoginResponse, PlatformMfaEnableResponse,
    PlatformMfaSetupResponse,
};

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
    /// Opens `platform_admins.mfa_secret` (same PMS-871 sealing as `users`).
    encryption_key: [u8; 32],
}

impl PlatformAdminService {
    pub fn new(db: Database, jwt_secret: String) -> Self {
        Self {
            db,
            jwt_secret,
            encryption_key: [0u8; 32],
        }
    }

    pub fn with_encryption_key(mut self, key: [u8; 32]) -> Self {
        self.encryption_key = key;
        self
    }

    #[allow(dead_code)]
    pub(crate) fn db(&self) -> &Database {
        &self.db
    }

    /// Re-checks the admin's current status against `platform_admins`,
    /// so an offboarded admin is rejected on their next request rather
    /// than riding out their token's TTL (mirrors the tenant plane's
    /// per-request `ensure_principal_usable` gate).
    pub async fn ensure_admin_active(&self, admin_id: Uuid) -> AppResult<()> {
        let pool = self.db.migrator_pool();
        let admin = PlatformAdminRepo::find_by_id(pool, admin_id)
            .await
            .map_err(|_| AppError::Unauthorized)?
            .ok_or(AppError::Unauthorized)?;
        if admin.status != "active" {
            return Err(AppError::Unauthorized);
        }
        Ok(())
    }

    pub async fn authenticate(
        &self,
        email: &str,
        password: &str,
        mfa_code: Option<&str>,
        recovery_code: Option<&str>,
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
        // PMS-1219: the MAPPS-550 identity-plane heal was removed.
        // Migration 164 (MAPPS-551) stopped mirroring
        // platform_admins.password_hash writes into
        // identities.password_hash, which made platform_admins the
        // sole authoritative hash for this plane; the heal kept
        // reading identities.password_hash as if it still tracked
        // the current password, so a stale hash from before a
        // rotation could authenticate indefinitely and even
        // overwrite the rotated hash back to the old one. There is
        // no live case where a real platform_admins row should trust
        // an older hash from another plane.
        if !verify_password(password, hash).await? {
            return Err(AppError::Unauthorized);
        }

        // An enrolled admin needs a valid second factor. A missing code, a
        // wrong code and a replayed step all answer the same 401 as a bad
        // password, so the response does not reveal which factor failed. A
        // `mfa_code` alongside a `recovery_code` wins so a live TOTP does not
        // spend a recovery, and a recovery code is single-use through
        // `spend_recovery_code`.
        if admin.mfa_enabled {
            let accepted = match (mfa_code, recovery_code) {
                (Some(code), _) => {
                    let stored = admin.mfa_secret.as_deref().ok_or_else(|| {
                        AppError::Internal("MFA enabled without secret".to_string())
                    })?;
                    let stored = mfa_secret::open(stored, &self.encryption_key)?;
                    let secret =
                        crate::utils::totp::base32_decode(stored.secret_b32()).map_err(|_| {
                            AppError::Internal("stored MFA secret is corrupt".to_string())
                        })?;
                    match crate::utils::totp::verify(&secret, code, Utc::now(), 1) {
                        Some(step) => PlatformAdminRepo::advance_totp_step(pool, admin.id, step)
                            .await
                            .map_err(|_| AppError::Unauthorized)?,
                        None => false,
                    }
                }
                (None, Some(code)) => {
                    let hash = crate::utils::recovery::hash_code_hex(code);
                    PlatformAdminRepo::spend_recovery_code(pool, admin.id, &hash)
                        .await
                        .map_err(|_| AppError::Unauthorized)?
                }
                (None, None) => return Err(AppError::Unauthorized),
            };
            if !accepted {
                return Err(AppError::Unauthorized);
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

    /// Current-password re-auth, shared by every MFA endpoint, so a stolen
    /// access token cannot enrol an authenticator, finish one it started,
    /// or remove the factor. The two failure arms both answer 401 so a probe
    /// cannot map an id to a wrong password.
    async fn reauthenticate(&self, admin_id: Uuid, password: &str) -> AppResult<PlatformAdminRow> {
        let pool = self.db.migrator_pool();
        let admin = PlatformAdminRepo::find_by_id(pool, admin_id)
            .await
            .map_err(|_| AppError::Unauthorized)?
            .ok_or(AppError::Unauthorized)?;
        let hash = admin
            .password_hash
            .as_deref()
            .ok_or(AppError::Unauthorized)?;
        if !verify_password(password, hash).await? {
            return Err(AppError::Unauthorized);
        }
        Ok(admin)
    }

    /// Stage a fresh TOTP secret WITHOUT flipping `mfa_enabled`, same
    /// contract the contact plane's `start_mfa_enrollment` has: only
    /// `enable_mfa`, after a live code verifies, turns MFA on, so a mis-set
    /// authenticator cannot lock the operator out. Calling this again before
    /// enable replaces the staged secret. 409 when MFA is already on:
    /// disable first.
    #[tracing::instrument(skip_all)]
    pub async fn start_mfa_enrollment(
        &self,
        admin_id: Uuid,
        current_password: &str,
    ) -> AppResult<PlatformMfaSetupResponse> {
        let admin = self.reauthenticate(admin_id, current_password).await?;
        if admin.mfa_enabled {
            return Err(AppError::Conflict("MFA is already enabled".to_string()));
        }
        let secret = crate::utils::totp::generate_secret();
        let secret_b32 = crate::utils::totp::base32_encode(&secret);
        let sealed = mfa_secret::seal(&secret_b32, &self.encryption_key)?;
        PlatformAdminRepo::stage_mfa_secret(self.db.migrator_pool(), admin.id, &sealed)
            .await
            .map_err(|_| AppError::Internal("Failed to stage MFA secret".to_string()))?;
        // The issuer the authenticator shows beside the code. Sanitize the
        // colon out of the app name, the same shape the tenant and contact
        // planes use, because a colon inside the label splits the otpauth
        // string once the app decodes it.
        let app = crate::utils::app_name::app_name().replace(':', " ");
        let label = format!("{app}:{email}", email = admin.email);
        let provisioning_uri = crate::utils::totp::provisioning_uri(&secret_b32, &label, &app);
        Ok(PlatformMfaSetupResponse {
            secret: secret_b32,
            provisioning_uri,
        })
    }

    /// Finish MFA enrolment. Re-verifies the password, checks one live code
    /// against the staged secret, flips `mfa_enabled`, and mints the
    /// single-use recovery codes, returned once and stored as hashes.
    #[tracing::instrument(skip_all)]
    pub async fn enable_mfa(
        &self,
        admin_id: Uuid,
        current_password: &str,
        code: &str,
    ) -> AppResult<PlatformMfaEnableResponse> {
        let admin = self.reauthenticate(admin_id, current_password).await?;
        if admin.mfa_enabled {
            return Err(AppError::Conflict("MFA is already enabled".to_string()));
        }
        let stored = admin.mfa_secret.as_deref().ok_or_else(|| {
            AppError::BadRequest("MFA enrollment has not been started".to_string())
        })?;
        let opened = mfa_secret::open(stored, &self.encryption_key)?;
        let secret = crate::utils::totp::base32_decode(opened.secret_b32())
            .map_err(|_| AppError::Internal("stored MFA secret is corrupt".to_string()))?;
        if crate::utils::totp::verify(&secret, code, Utc::now(), 1).is_none() {
            return Err(AppError::BadRequest("Invalid MFA code".to_string()));
        }
        let recovery_codes = crate::utils::recovery::generate_set();
        let hashes: Vec<String> = recovery_codes
            .iter()
            .map(|c| crate::utils::recovery::hash_code_hex(c))
            .collect();
        // Reseal so a secret staged before the encryption key was wired
        // (or by a seed) does not stay plaintext past this write, the
        // contact plane's shape.
        let sealed = mfa_secret::seal(opened.secret_b32(), &self.encryption_key)?;
        PlatformAdminRepo::enable_mfa(self.db.migrator_pool(), admin.id, &sealed, &hashes)
            .await
            .map_err(|_| AppError::Internal("Failed to enable MFA".to_string()))?;
        Ok(PlatformMfaEnableResponse { recovery_codes })
    }

    /// Remove MFA. Needs the current password AND a live code (TOTP or an
    /// unspent recovery code), so a stolen access token cannot quietly
    /// weaken the account. Not enabled is the same 401 as a wrong password,
    /// so the response does not say which failed.
    #[tracing::instrument(skip_all)]
    pub async fn disable_mfa(
        &self,
        admin_id: Uuid,
        current_password: &str,
        code: &str,
    ) -> AppResult<()> {
        let admin = self.reauthenticate(admin_id, current_password).await?;
        if !admin.mfa_enabled {
            return Err(AppError::Unauthorized);
        }
        let pool = self.db.migrator_pool();
        let code = code.trim();
        let looks_like_totp = !code.is_empty() && code.chars().all(|c| c.is_ascii_digit());
        let accepted = if looks_like_totp {
            let stored = admin
                .mfa_secret
                .as_deref()
                .ok_or_else(|| AppError::Internal("MFA enabled without secret".to_string()))?;
            let stored = mfa_secret::open(stored, &self.encryption_key)?;
            let secret = crate::utils::totp::base32_decode(stored.secret_b32())
                .map_err(|_| AppError::Internal("stored MFA secret is corrupt".to_string()))?;
            match crate::utils::totp::verify(&secret, code, Utc::now(), 1) {
                Some(step) => PlatformAdminRepo::advance_totp_step(pool, admin.id, step)
                    .await
                    .map_err(|_| AppError::Unauthorized)?,
                None => false,
            }
        } else {
            let hash = crate::utils::recovery::hash_code_hex(code);
            PlatformAdminRepo::spend_recovery_code(pool, admin.id, &hash)
                .await
                .map_err(|_| AppError::Unauthorized)?
        };
        if !accepted {
            return Err(AppError::Unauthorized);
        }
        PlatformAdminRepo::disable_mfa(pool, admin.id)
            .await
            .map_err(|_| AppError::Internal("Failed to disable MFA".to_string()))?;
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
        if !verify_password(current, hash).await? {
            return Err(AppError::validation_field(
                "current_password",
                "Current password is incorrect",
            ));
        }
        let new_hash = hash_password(new).await?;
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
