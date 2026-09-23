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
    #[sqlx(default)]
    pub mfa_recovery_codes_hashes: Vec<String>,
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
        mfa_enabled, mfa_secret, mfa_last_totp_step, mfa_recovery_codes_hashes, \
        notification_preferences, settings, \
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

    /// Anti-replay watermark: advances `mfa_last_totp_step` only to a step
    /// strictly greater than the stored one, so two logins presenting the same
    /// code cannot both win. Returns whether this call won it.
    pub async fn advance_totp_step(
        pool: &PgPool,
        admin_id: Uuid,
        step: i64,
    ) -> Result<bool, sqlx::Error> {
        let res = sqlx::query(
            "UPDATE platform_admins SET mfa_last_totp_step = $1, updated_at = NOW() \
             WHERE id = $2 AND mfa_last_totp_step < $1",
        )
        .bind(step)
        .bind(admin_id)
        .execute(pool)
        .await?;
        Ok(res.rows_affected() == 1)
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

    /// Stage a sealed TOTP secret WITHOUT flipping `mfa_enabled`. Enable is
    /// a second call after a live code proves the authenticator works, so a
    /// mis-set app cannot lock the operator out of the platform.
    pub async fn stage_mfa_secret(
        pool: &PgPool,
        admin_id: Uuid,
        sealed_secret: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE platform_admins \
             SET mfa_secret = $1, mfa_enabled = FALSE, mfa_last_totp_step = 0, \
                 mfa_recovery_codes_hashes = '{}', updated_at = NOW() \
             WHERE id = $2",
        )
        .bind(sealed_secret)
        .bind(admin_id)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Flip `mfa_enabled` and store the recovery-code hashes in one write,
    /// after the live code confirmed the staged secret. Resets the
    /// anti-replay watermark so the code the operator just proved against
    /// does not itself get treated as spent for the next login.
    pub async fn enable_mfa(
        pool: &PgPool,
        admin_id: Uuid,
        sealed_secret: &str,
        recovery_hashes: &[String],
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE platform_admins \
             SET mfa_enabled = TRUE, mfa_secret = $1, \
                 mfa_recovery_codes_hashes = $2, mfa_last_totp_step = 0, \
                 updated_at = NOW() \
             WHERE id = $3",
        )
        .bind(sealed_secret)
        .bind(recovery_hashes)
        .bind(admin_id)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Clear the whole MFA trio in one write. Same shape the contact plane's
    /// disable takes: enabled off, secret gone, watermark back to zero,
    /// recovery codes cleared. Reads that predate a fresh enrolment can
    /// never see a stale code.
    pub async fn disable_mfa(pool: &PgPool, admin_id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE platform_admins \
             SET mfa_enabled = FALSE, mfa_secret = NULL, mfa_last_totp_step = 0, \
                 mfa_recovery_codes_hashes = '{}', updated_at = NOW() \
             WHERE id = $1",
        )
        .bind(admin_id)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Spend one recovery code by removing its hash from the array. Returns
    /// true when the row's set actually changed (the code was live and is
    /// now gone), false when the hash was already absent (an unknown code,
    /// or a replay after a concurrent login spent it).
    pub async fn spend_recovery_code(
        pool: &PgPool,
        admin_id: Uuid,
        hash_hex: &str,
    ) -> Result<bool, sqlx::Error> {
        let res = sqlx::query(
            "UPDATE platform_admins \
             SET mfa_recovery_codes_hashes = array_remove(mfa_recovery_codes_hashes, $1), \
                 updated_at = NOW() \
             WHERE id = $2 AND $1 = ANY(mfa_recovery_codes_hashes)",
        )
        .bind(hash_hex)
        .bind(admin_id)
        .execute(pool)
        .await?;
        Ok(res.rows_affected() == 1)
    }
}
