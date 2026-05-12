//! Postgres-backed `RecoveryCodeRepository`.

use async_trait::async_trait;
use mokosh_auth_core::{AuthError, RecoveryCodeRepository, TenantId, UserId};
use uuid::Uuid;

use crate::conv::db_err;
use crate::pool::AuthPool;

pub struct PgRecoveryCodeRepository {
    pool: AuthPool,
}

impl PgRecoveryCodeRepository {
    pub fn new(pool: AuthPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RecoveryCodeRepository for PgRecoveryCodeRepository {
    async fn consume_unused(
        &self,
        user_id: UserId,
        code_hash: [u8; 32],
    ) -> Result<(), AuthError> {
        const MAX_ATTEMPTS: u32 = 3;
        for attempt in 0..MAX_ATTEMPTS {
            match self.consume_unused_once(user_id, code_hash).await {
                Err(AuthError::Storage(msg))
                    if msg.contains("40001") && attempt + 1 < MAX_ATTEMPTS =>
                {
                    tracing::debug!(
                        attempt,
                        "recovery code consume serialization conflict; retrying"
                    );
                    continue;
                }
                other => return other,
            }
        }
        unreachable!("loop returns or continues at most MAX_ATTEMPTS times")
    }

    async fn count_unused(&self, user_id: UserId) -> Result<usize, AuthError> {
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM mokosh_auth.recovery_codes
             WHERE user_id = $1 AND used_at IS NULL",
        )
        .bind(user_id.0)
        .fetch_one(self.pool.pg())
        .await
        .map_err(db_err)?;
        Ok(n.max(0) as usize)
    }

    async fn replace_all(
        &self,
        user_id: UserId,
        tenant_id: TenantId,
        user_totp_id: Uuid,
        new_hashes: &[[u8; 32]],
    ) -> Result<(), AuthError> {
        const MAX_ATTEMPTS: u32 = 3;
        for attempt in 0..MAX_ATTEMPTS {
            match self
                .replace_all_once(user_id, tenant_id, user_totp_id, new_hashes)
                .await
            {
                Err(AuthError::Storage(msg))
                    if msg.contains("40001") && attempt + 1 < MAX_ATTEMPTS =>
                {
                    tracing::debug!(
                        attempt,
                        "recovery codes replace_all serialization conflict; retrying"
                    );
                    continue;
                }
                other => return other,
            }
        }
        unreachable!("loop returns or continues at most MAX_ATTEMPTS times")
    }
}

impl PgRecoveryCodeRepository {
    async fn consume_unused_once(
        &self,
        user_id: UserId,
        code_hash: [u8; 32],
    ) -> Result<(), AuthError> {
        let mut tx = self.pool.pg().begin().await.map_err(db_err)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;

        let res = sqlx::query(
            "UPDATE mokosh_auth.recovery_codes
             SET used_at = NOW()
             WHERE user_id = $1
               AND code_hash = $2
               AND used_at IS NULL",
        )
        .bind(user_id.0)
        .bind(&code_hash[..])
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

        if res.rows_affected() == 0 {
            // Roll back; same NotFound shape as the verify-time
            // wrong-code response, so the response body the user sees
            // does not let them distinguish "code wrong" from "code
            // already used."
            tx.rollback().await.map_err(db_err)?;
            return Err(AuthError::NotFound);
        }

        tx.commit().await.map_err(db_err)?;
        Ok(())
    }

    async fn replace_all_once(
        &self,
        user_id: UserId,
        tenant_id: TenantId,
        user_totp_id: Uuid,
        new_hashes: &[[u8; 32]],
    ) -> Result<(), AuthError> {
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

        for hash in new_hashes {
            sqlx::query(
                "INSERT INTO mokosh_auth.recovery_codes
                    (user_totp_id, user_id, tenant_id, code_hash)
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(user_totp_id)
            .bind(user_id.0)
            .bind(tenant_id.0)
            .bind(&hash[..])
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        }

        tx.commit().await.map_err(db_err)?;
        Ok(())
    }
}
