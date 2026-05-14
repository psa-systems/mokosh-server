//! Postgres-backed `TotpRepository`.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mokosh_auth_core::{AuthError, TenantId, TotpEnrollment, TotpRepository, UserId};
use uuid::Uuid;

use crate::conv::db_err;
use crate::pool::AuthPool;

const SELECT_TOTP: &str = r#"
    SELECT id, user_id, tenant_id, secret_encrypted, key_version,
           confirmed_at, last_used_step, created_at, updated_at
    FROM mokosh_auth.user_totp
"#;

pub struct PgTotpRepository {
    pool: AuthPool,
}

impl PgTotpRepository {
    pub fn new(pool: AuthPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct TotpRow {
    id: Uuid,
    user_id: Uuid,
    tenant_id: Uuid,
    secret_encrypted: serde_json::Value,
    key_version: i16,
    confirmed_at: Option<DateTime<Utc>>,
    last_used_step: Option<i64>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl TryFrom<TotpRow> for TotpEnrollment {
    type Error = AuthError;
    fn try_from(r: TotpRow) -> Result<Self, Self::Error> {
        if r.key_version < 0 {
            return Err(AuthError::Storage(format!(
                "user_totp.key_version is negative ({}); column is SMALLINT but values must be unsigned",
                r.key_version
            )));
        }
        Ok(Self {
            id: r.id,
            user_id: UserId(r.user_id),
            tenant_id: TenantId(r.tenant_id),
            secret_encrypted: r.secret_encrypted,
            key_version: r.key_version as u16,
            confirmed_at: r.confirmed_at,
            last_used_step: r.last_used_step,
            created_at: r.created_at,
            updated_at: r.updated_at,
        })
    }
}

#[async_trait]
impl TotpRepository for PgTotpRepository {
    async fn start_enrollment(
        &self,
        user_id: UserId,
        tenant_id: TenantId,
        encrypted_secret: serde_json::Value,
        key_version: u16,
    ) -> Result<TotpEnrollment, AuthError> {
        // The (user_id) is UNIQUE on the table so we can ON CONFLICT.
        // For the "row exists confirmed" case the ON CONFLICT clause
        // must not silently overwrite the existing secret. Resolve in
        // a small tx: SELECT FOR UPDATE, branch on confirmed_at.
        let mut tx = self.pool.pg().begin().await.map_err(db_err)?;

        let row: Option<TotpRow> =
            sqlx::query_as(&format!("{SELECT_TOTP} WHERE user_id = $1 FOR UPDATE"))
                .bind(user_id.0)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_err)?;

        if let Some(existing) = row {
            if existing.confirmed_at.is_some() {
                tx.rollback().await.map_err(db_err)?;
                return Err(AuthError::Conflict("already_enrolled".into()));
            }
            // Unconfirmed row already exists. Rotate the secret so the
            // setup flow is idempotent in the same way password-reset
            // is: every fresh /mfa/setup call returns a fresh secret +
            // fresh recovery codes. The previous (unconfirmed) secret
            // is overwritten in place to preserve the FK to
            // recovery_codes (which we re-issue on every confirm).
            let updated: TotpRow = sqlx::query_as(
                "UPDATE mokosh_auth.user_totp
                 SET secret_encrypted = $1, key_version = $2, updated_at = NOW()
                 WHERE id = $3
                 RETURNING id, user_id, tenant_id, secret_encrypted, key_version,
                           confirmed_at, last_used_step, created_at, updated_at",
            )
            .bind(&encrypted_secret)
            .bind(key_version as i16)
            .bind(existing.id)
            .fetch_one(&mut *tx)
            .await
            .map_err(db_err)?;
            tx.commit().await.map_err(db_err)?;
            return TotpEnrollment::try_from(updated);
        }

        let inserted: TotpRow = sqlx::query_as(
            "INSERT INTO mokosh_auth.user_totp
                (user_id, tenant_id, secret_encrypted, key_version)
             VALUES ($1, $2, $3, $4)
             RETURNING id, user_id, tenant_id, secret_encrypted, key_version,
                       confirmed_at, last_used_step, created_at, updated_at",
        )
        .bind(user_id.0)
        .bind(tenant_id.0)
        .bind(&encrypted_secret)
        .bind(key_version as i16)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err)?;

        tx.commit().await.map_err(db_err)?;
        TotpEnrollment::try_from(inserted)
    }

    async fn find_for_user(&self, user_id: UserId) -> Result<Option<TotpEnrollment>, AuthError> {
        let row: Option<TotpRow> = sqlx::query_as(&format!("{SELECT_TOTP} WHERE user_id = $1"))
            .bind(user_id.0)
            .fetch_optional(self.pool.pg())
            .await
            .map_err(db_err)?;
        row.map(TotpEnrollment::try_from).transpose()
    }

    async fn confirm(&self, user_id: UserId) -> Result<(), AuthError> {
        const MAX_ATTEMPTS: u32 = 3;
        for attempt in 0..MAX_ATTEMPTS {
            match self.confirm_once(user_id).await {
                Err(AuthError::Storage(msg))
                    if msg.contains("40001") && attempt + 1 < MAX_ATTEMPTS =>
                {
                    tracing::debug!(attempt, "totp confirm serialization conflict; retrying");
                    continue;
                }
                other => return other,
            }
        }
        unreachable!("loop returns or continues at most MAX_ATTEMPTS times")
    }

    async fn consume_step(&self, user_id: UserId, step: i64) -> Result<(), AuthError> {
        let res = sqlx::query(
            "UPDATE mokosh_auth.user_totp
             SET last_used_step = $2, updated_at = NOW()
             WHERE user_id = $1
               AND (last_used_step IS NULL OR last_used_step < $2)",
        )
        .bind(user_id.0)
        .bind(step)
        .execute(self.pool.pg())
        .await
        .map_err(db_err)?;
        if res.rows_affected() == 0 {
            return Err(AuthError::InvalidGrant("replayed_step".into()));
        }
        Ok(())
    }

    async fn disenroll(&self, user_id: UserId) -> Result<(), AuthError> {
        const MAX_ATTEMPTS: u32 = 3;
        for attempt in 0..MAX_ATTEMPTS {
            match self.disenroll_once(user_id).await {
                Err(AuthError::Storage(msg))
                    if msg.contains("40001") && attempt + 1 < MAX_ATTEMPTS =>
                {
                    tracing::debug!(attempt, "totp disenroll serialization conflict; retrying");
                    continue;
                }
                other => return other,
            }
        }
        unreachable!("loop returns or continues at most MAX_ATTEMPTS times")
    }
}

impl PgTotpRepository {
    async fn confirm_once(&self, user_id: UserId) -> Result<(), AuthError> {
        let mut tx = self.pool.pg().begin().await.map_err(db_err)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;

        // Lock + check the row.
        #[derive(sqlx::FromRow)]
        struct Locked {
            id: Uuid,
            confirmed_at: Option<DateTime<Utc>>,
        }
        let row: Option<Locked> = sqlx::query_as(
            "SELECT id, confirmed_at
             FROM mokosh_auth.user_totp
             WHERE user_id = $1 FOR UPDATE",
        )
        .bind(user_id.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?;
        let row = row.ok_or(AuthError::NotFound)?;
        if row.confirmed_at.is_some() {
            return Err(AuthError::Conflict("already_enrolled".into()));
        }

        sqlx::query(
            "UPDATE mokosh_auth.user_totp
             SET confirmed_at = NOW(), updated_at = NOW()
             WHERE id = $1",
        )
        .bind(row.id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

        sqlx::query(
            "UPDATE mokosh_auth.users
             SET mfa_enrolled = TRUE,
                 mfa_disenrolled_at = NULL,
                 updated_at = NOW()
             WHERE id = $1",
        )
        .bind(user_id.0)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

        tx.commit().await.map_err(db_err)?;
        Ok(())
    }

    async fn disenroll_once(&self, user_id: UserId) -> Result<(), AuthError> {
        let mut tx = self.pool.pg().begin().await.map_err(db_err)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;

        sqlx::query("DELETE FROM mokosh_auth.recovery_codes WHERE user_id = $1")
            .bind(user_id.0)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        sqlx::query("DELETE FROM mokosh_auth.user_totp WHERE user_id = $1")
            .bind(user_id.0)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        sqlx::query(
            "UPDATE mokosh_auth.users
             SET mfa_enrolled = FALSE,
                 mfa_disenrolled_at = NOW(),
                 updated_at = NOW()
             WHERE id = $1",
        )
        .bind(user_id.0)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

        tx.commit().await.map_err(db_err)?;
        Ok(())
    }
}
