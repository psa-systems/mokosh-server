//! Postgres-backed `PasswordResetTokenRepository`.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mokosh_auth_core::{
    AuthError, NewPasswordResetToken, PasswordResetToken, PasswordResetTokenRepository, UserId,
};
use uuid::Uuid;

use crate::conv::db_err;
use crate::pool::AuthPool;

const SELECT_RESET: &str = r#"
    SELECT id, email, token_hash, issued_at, expires_at, used_at, user_id
    FROM mokosh_auth.password_reset_tokens
"#;

pub struct PgPasswordResetTokenRepository {
    pool: AuthPool,
}

impl PgPasswordResetTokenRepository {
    pub fn new(pool: AuthPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct ResetRow {
    id: Uuid,
    email: String,
    token_hash: Vec<u8>,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    used_at: Option<DateTime<Utc>>,
    user_id: Option<Uuid>,
}

impl TryFrom<ResetRow> for PasswordResetToken {
    type Error = AuthError;
    fn try_from(r: ResetRow) -> Result<Self, Self::Error> {
        let mut hash = [0u8; 32];
        if r.token_hash.len() != 32 {
            return Err(AuthError::Storage(format!(
                "password_reset token_hash length = {} (expected 32)",
                r.token_hash.len()
            )));
        }
        hash.copy_from_slice(&r.token_hash);
        Ok(Self {
            id: r.id,
            email: r.email,
            token_hash: hash,
            issued_at: r.issued_at,
            expires_at: r.expires_at,
            used_at: r.used_at,
            user_id: r.user_id.map(UserId),
        })
    }
}

#[async_trait]
impl PasswordResetTokenRepository for PgPasswordResetTokenRepository {
    async fn issue(&self, new: NewPasswordResetToken) -> Result<PasswordResetToken, AuthError> {
        let row: ResetRow = sqlx::query_as(
            "INSERT INTO mokosh_auth.password_reset_tokens (email, token_hash, expires_at)
             VALUES ($1, $2, $3)
             RETURNING id, email, token_hash, issued_at, expires_at, used_at, user_id",
        )
        .bind(&new.email)
        .bind(&new.token_hash[..])
        .bind(new.expires_at)
        .fetch_one(self.pool.pg())
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                AuthError::Conflict("password reset token hash collision".into())
            }
            _ => db_err(e),
        })?;
        PasswordResetToken::try_from(row)
    }

    async fn find_by_token_hash(
        &self,
        token_hash: [u8; 32],
    ) -> Result<Option<PasswordResetToken>, AuthError> {
        let row: Option<ResetRow> =
            sqlx::query_as(&format!("{SELECT_RESET} WHERE token_hash = $1"))
                .bind(&token_hash[..])
                .fetch_optional(self.pool.pg())
                .await
                .map_err(db_err)?;
        row.map(PasswordResetToken::try_from).transpose()
    }

    async fn find_open_by_email(
        &self,
        email: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<PasswordResetToken>, AuthError> {
        let row: Option<ResetRow> = sqlx::query_as(&format!(
            "{SELECT_RESET}
             WHERE email = $1 AND used_at IS NULL AND expires_at > $2
             ORDER BY issued_at DESC
             LIMIT 1"
        ))
        .bind(email)
        .bind(now)
        .fetch_optional(self.pool.pg())
        .await
        .map_err(db_err)?;
        row.map(PasswordResetToken::try_from).transpose()
    }

    async fn complete(
        &self,
        token_hash: [u8; 32],
        new_password_hash: &str,
    ) -> Result<UserId, AuthError> {
        const MAX_ATTEMPTS: u32 = 3;
        for attempt in 0..MAX_ATTEMPTS {
            match self.complete_once(token_hash, new_password_hash).await {
                Err(AuthError::Storage(msg))
                    if msg.contains("40001") && attempt + 1 < MAX_ATTEMPTS =>
                {
                    tracing::debug!(
                        attempt,
                        "password reset complete serialization conflict; retrying"
                    );
                    continue;
                }
                other => return other,
            }
        }
        unreachable!("loop returns or continues at most MAX_ATTEMPTS times")
    }
}

impl PgPasswordResetTokenRepository {
    async fn complete_once(
        &self,
        token_hash: [u8; 32],
        new_password_hash: &str,
    ) -> Result<UserId, AuthError> {
        let mut tx = self.pool.pg().begin().await.map_err(db_err)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;

        // 1. Lock the token row.
        #[derive(sqlx::FromRow)]
        struct Locked {
            email: String,
            expires_at: DateTime<Utc>,
            used_at: Option<DateTime<Utc>>,
        }
        let row: Option<Locked> = sqlx::query_as(
            "SELECT email, expires_at, used_at
             FROM mokosh_auth.password_reset_tokens
             WHERE token_hash = $1
             FOR UPDATE",
        )
        .bind(&token_hash[..])
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?;

        let row = row.ok_or(AuthError::NotFound)?;
        if row.used_at.is_some() {
            return Err(AuthError::NotFound);
        }
        if row.expires_at < Utc::now() {
            return Err(AuthError::NotFound);
        }

        // 2. Find the user by email globally. With the global-unique
        //    email index there is at most one row.
        let user_row: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM mokosh_auth.users
             WHERE email = $1 AND deleted_at IS NULL
             LIMIT 1",
        )
        .bind(&row.email)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?;
        let user_id = match user_row {
            Some((id,)) => UserId(id),
            None => return Err(AuthError::NotFound),
        };

        // 3. Update password.
        sqlx::query(
            "UPDATE mokosh_auth.users
             SET password_hash = $1, updated_at = NOW()
             WHERE id = $2",
        )
        .bind(new_password_hash)
        .bind(user_id.0)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

        // 4. Mark token used (with race guard).
        let res = sqlx::query(
            "UPDATE mokosh_auth.password_reset_tokens
             SET used_at = NOW(), user_id = $1
             WHERE token_hash = $2 AND used_at IS NULL",
        )
        .bind(user_id.0)
        .bind(&token_hash[..])
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
        if res.rows_affected() == 0 {
            return Err(AuthError::NotFound);
        }

        // 5. Boot every active session for this user. The handler
        //    layer also revokes refresh families bound to those
        //    sessions (mirrors /v1/auth/logout's cascade) - it can do
        //    that outside the tx because session ids are stable once
        //    we've issued the revoke in this tx.
        sqlx::query(
            "UPDATE mokosh_auth.op_sessions
             SET revoked_at = NOW()
             WHERE user_id = $1 AND revoked_at IS NULL",
        )
        .bind(user_id.0)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

        // 6. Revoke refresh families bound to those sessions. Could
        //    be done in the handler outside the tx, but doing it in
        //    the same tx makes the "atomic boot everywhere" property
        //    legible: if the tx commits, the password is new AND
        //    every old session+family is dead. If it rolls back,
        //    nothing changed.
        sqlx::query(
            "UPDATE mokosh_auth.refresh_token_families
             SET revoked_at = NOW(), revoke_reason = 'password_reset'
             WHERE user_id = $1 AND revoked_at IS NULL",
        )
        .bind(user_id.0)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
        sqlx::query(
            "UPDATE mokosh_auth.refresh_tokens rt
             SET revoked_at = NOW()
             FROM mokosh_auth.refresh_token_families f
             WHERE rt.family_id = f.id
               AND f.user_id = $1
               AND rt.revoked_at IS NULL",
        )
        .bind(user_id.0)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

        tx.commit().await.map_err(db_err)?;
        Ok(user_id)
    }
}
