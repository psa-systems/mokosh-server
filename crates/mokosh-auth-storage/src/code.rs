//! Postgres-backed `AuthCodeRepository`.
//!
//! The `consume` operation is the security-critical path: it must mark
//! the code consumed and return its row in a single atomic step, so two
//! concurrent token requests cannot both succeed against the same code.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mokosh_auth_core::{
    AuthCodeRepository, AuthError, AuthorizationCode, ClientId, NewAuthCode, OpSessionId,
    TenantId, UserId,
};
use uuid::Uuid;

use crate::conv::db_err;
use crate::pool::AuthPool;

pub struct PgAuthCodeRepository {
    pool: AuthPool,
}

impl PgAuthCodeRepository {
    pub fn new(pool: AuthPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct AuthCodeRow {
    code_hash: Vec<u8>,
    client_id: Uuid,
    user_id: Uuid,
    tenant_id: Uuid,
    op_session_id: Uuid,
    redirect_uri: String,
    scope: Vec<String>,
    code_challenge: String,
    nonce: Option<String>,
    auth_time: DateTime<Utc>,
    acr: String,
    amr: Vec<String>,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    consumed_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
}

impl TryFrom<AuthCodeRow> for AuthorizationCode {
    type Error = AuthError;
    fn try_from(r: AuthCodeRow) -> Result<Self, Self::Error> {
        let mut hash = [0u8; 32];
        if r.code_hash.len() != 32 {
            return Err(AuthError::Storage("code_hash wrong length".into()));
        }
        hash.copy_from_slice(&r.code_hash);
        Ok(AuthorizationCode {
            code_hash: hash,
            client_id: ClientId(r.client_id),
            user_id: UserId(r.user_id),
            tenant_id: TenantId(r.tenant_id),
            op_session_id: OpSessionId(r.op_session_id),
            redirect_uri: r.redirect_uri,
            scope: r.scope,
            code_challenge: r.code_challenge,
            nonce: r.nonce,
            auth_time: r.auth_time,
            acr: r.acr,
            amr: r.amr,
            issued_at: r.issued_at,
            expires_at: r.expires_at,
            consumed_at: r.consumed_at,
            revoked_at: r.revoked_at,
        })
    }
}

#[async_trait]
impl AuthCodeRepository for PgAuthCodeRepository {
    async fn insert(&self, new: NewAuthCode) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO mokosh_auth.oauth_authorization_codes
                (code_hash, client_id, user_id, tenant_id, op_session_id,
                 redirect_uri, scope, code_challenge, code_challenge_method,
                 nonce, auth_time, acr, amr, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'S256', $9, $10, $11, $12, $13)",
        )
        .bind(&new.code_hash[..])
        .bind(new.client_id.0)
        .bind(new.user_id.0)
        .bind(new.tenant_id.0)
        .bind(new.op_session_id.0)
        .bind(&new.redirect_uri)
        .bind(&new.scope)
        .bind(&new.code_challenge)
        .bind(&new.nonce)
        .bind(new.auth_time)
        .bind(&new.acr)
        .bind(&new.amr)
        .bind(new.expires_at)
        .execute(self.pool.pg())
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn consume(
        &self,
        code_hash: [u8; 32],
        at: DateTime<Utc>,
    ) -> Result<AuthorizationCode, AuthError> {
        // Atomic: only the first caller for a given hash gets the row.
        // The WHERE clause filters out already-consumed, revoked, and
        // expired rows so we don't need a separate read step.
        let row: Option<AuthCodeRow> = sqlx::query_as(
            "UPDATE mokosh_auth.oauth_authorization_codes
             SET consumed_at = $1
             WHERE code_hash = $2
               AND consumed_at IS NULL
               AND revoked_at IS NULL
               AND expires_at > $1
             RETURNING code_hash, client_id, user_id, tenant_id, op_session_id,
                       redirect_uri, scope, code_challenge, nonce, auth_time,
                       acr, amr, issued_at, expires_at, consumed_at, revoked_at",
        )
        .bind(at)
        .bind(&code_hash[..])
        .fetch_optional(self.pool.pg())
        .await
        .map_err(db_err)?;

        match row {
            Some(r) => AuthorizationCode::try_from(r),
            None => {
                // The code is unknown OR was already consumed OR is expired.
                // We do not differentiate (would leak information about
                // which codes have been used). The OIDC engine treats this
                // as a hard `invalid_grant` and, on detection of replay,
                // revokes the refresh-token family.
                Err(AuthError::InvalidGrant("unknown or used code".into()))
            }
        }
    }
}
