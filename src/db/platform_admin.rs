//! MAPPS-513 (MAPPS-474 stage A follow-up): read + write helpers for
//! `platform_admins`. The platform super-admin persona lives outside
//! the tenant identity model (`users` / `identities` /
//! `tenant_memberships`) so its credential lifecycle does not
//! intersect with any tenant admin's identity.
//!
//! Table is RLS-exempt (cross-cutting on the pre-auth login path); all
//! reads/writes run on the migrator pool.

use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PlatformAdminRow {
    pub id: Uuid,
    pub email: String,
    pub password_hash: Option<String>,
    pub first_name: String,
    pub last_name: String,
    pub timezone: String,
    pub locale: String,
    pub email_verified_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_login_at: Option<chrono::DateTime<chrono::Utc>>,
    pub mfa_enabled: bool,
    pub mfa_secret: Option<String>,
    #[sqlx(default)]
    pub mfa_last_totp_step: i64,
    pub notification_preferences: serde_json::Value,
    pub settings: serde_json::Value,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

pub struct PlatformAdminRepo;

impl PlatformAdminRepo {
    const SELECT_LIST: &'static str = "id, email, password_hash, first_name, last_name, \
        timezone, locale, email_verified_at, last_login_at, \
        mfa_enabled, mfa_secret, mfa_last_totp_step, notification_preferences, settings, \
        status, created_at, updated_at";

    pub async fn find_by_email(
        pool: &PgPool,
        email: &str,
    ) -> Result<Option<PlatformAdminRow>, sqlx::Error> {
        let sql = format!(
            "SELECT {} FROM platform_admins WHERE lower(email) = lower($1)",
            Self::SELECT_LIST
        );
        sqlx::query_as::<_, PlatformAdminRow>(&sql)
            .bind(email)
            .fetch_optional(pool)
            .await
    }

    pub async fn find_by_id(
        pool: &PgPool,
        id: Uuid,
    ) -> Result<Option<PlatformAdminRow>, sqlx::Error> {
        let sql = format!(
            "SELECT {} FROM platform_admins WHERE id = $1",
            Self::SELECT_LIST
        );
        sqlx::query_as::<_, PlatformAdminRow>(&sql)
            .bind(id)
            .fetch_optional(pool)
            .await
    }

    pub async fn update_password_hash(
        pool: &PgPool,
        admin_id: Uuid,
        new_hash: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE platform_admins SET password_hash = $1, updated_at = NOW() WHERE id = $2",
        )
        .bind(new_hash)
        .bind(admin_id)
        .execute(pool)
        .await?;
        Ok(())
    }

    pub async fn update_last_login(pool: &PgPool, admin_id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE platform_admins SET last_login_at = NOW(), updated_at = NOW() WHERE id = $1",
        )
        .bind(admin_id)
        .execute(pool)
        .await?;
        Ok(())
    }
}
