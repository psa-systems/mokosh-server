//! Postgres-backed `SignupTokenRepository`.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mokosh_auth_core::{
    AuthError, NewSignupToken, SignupToken, SignupTokenRepository, UserId,
};
use uuid::Uuid;

use crate::conv::db_err;
use crate::pool::AuthPool;

const SELECT_SIGNUP: &str = r#"
    SELECT id, email, token_hash, issued_at, expires_at, used_at, user_id
    FROM mokosh_auth.signup_tokens
"#;

pub struct PgSignupTokenRepository {
    pool: AuthPool,
}

impl PgSignupTokenRepository {
    pub fn new(pool: AuthPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct SignupRow {
    id: Uuid,
    email: String,
    token_hash: Vec<u8>,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    used_at: Option<DateTime<Utc>>,
    user_id: Option<Uuid>,
}

impl TryFrom<SignupRow> for SignupToken {
    type Error = AuthError;
    fn try_from(r: SignupRow) -> Result<Self, Self::Error> {
        let mut hash = [0u8; 32];
        if r.token_hash.len() != 32 {
            return Err(AuthError::Storage(format!(
                "signup token_hash length = {} (expected 32)",
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
impl SignupTokenRepository for PgSignupTokenRepository {
    async fn issue(&self, new: NewSignupToken) -> Result<SignupToken, AuthError> {
        let row: SignupRow = sqlx::query_as(
            "INSERT INTO mokosh_auth.signup_tokens (email, token_hash, expires_at)
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
                // Hash collision (extraordinarily improbable) or
                // identical bytes from a previous issue. Treat as a
                // hard error - the caller will surface only the
                // generic 200, so the body never leaves the server.
                AuthError::Conflict("signup token hash collision".into())
            }
            _ => db_err(e),
        })?;
        SignupToken::try_from(row)
    }

    async fn find_by_token_hash(
        &self,
        token_hash: [u8; 32],
    ) -> Result<Option<SignupToken>, AuthError> {
        let row: Option<SignupRow> = sqlx::query_as(&format!(
            "{SELECT_SIGNUP} WHERE token_hash = $1"
        ))
        .bind(&token_hash[..])
        .fetch_optional(self.pool.pg())
        .await
        .map_err(db_err)?;
        row.map(SignupToken::try_from).transpose()
    }

    async fn find_open_by_email(
        &self,
        email: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<SignupToken>, AuthError> {
        let row: Option<SignupRow> = sqlx::query_as(&format!(
            "{SELECT_SIGNUP}
             WHERE email = $1 AND used_at IS NULL AND expires_at > $2
             ORDER BY issued_at DESC
             LIMIT 1"
        ))
        .bind(email)
        .bind(now)
        .fetch_optional(self.pool.pg())
        .await
        .map_err(db_err)?;
        row.map(SignupToken::try_from).transpose()
    }

    async fn mark_used(
        &self,
        token_hash: [u8; 32],
        user_id: UserId,
        at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        // The WHERE includes `used_at IS NULL` so a double-redeem
        // returns row_count = 0 and we surface that as NotFound.
        // Callers run this inside the SERIALIZABLE accept tx so the
        // race is closed at the isolation level too; this guard is
        // belt-and-suspenders.
        let res = sqlx::query(
            "UPDATE mokosh_auth.signup_tokens
             SET used_at = $1, user_id = $2
             WHERE token_hash = $3 AND used_at IS NULL",
        )
        .bind(at)
        .bind(user_id.0)
        .bind(&token_hash[..])
        .execute(self.pool.pg())
        .await
        .map_err(db_err)?;
        if res.rows_affected() == 0 {
            Err(AuthError::NotFound)
        } else {
            Ok(())
        }
    }
}
