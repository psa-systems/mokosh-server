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
            return Err(AppError::Unauthorized);
        }

        // Best-effort last_login stamp; failure does not block the login.
        let _ = PlatformAdminRepo::update_last_login(pool, admin.id).await;

        let (access_token, expires_at) = self.mint_token(&admin)?;
        Ok(PlatformLoginResponse {
            access_token,
            expires_at,
            admin: profile_of(&admin),
        })
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
