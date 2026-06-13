//! Postgres-backed `MfaChallengeRepository`.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use mokosh_auth_core::{
    AuthError, ClientId, MfaChallenge, MfaChallengePurpose, MfaChallengeRepository,
    NewMfaChallenge, TenantId, UserId,
};
use std::net::IpAddr;
use uuid::Uuid;

use crate::conv::{db_err, retry_serializable};
use crate::pool::AuthPool;

const SELECT_CHALLENGE: &str = r#"
    SELECT id, user_id, tenant_id, token_hash, client_id, scope,
           active_tenant_id, purpose, expires_at, consumed_at, created_at
    FROM mokosh_auth.mfa_challenges
"#;

pub struct PgMfaChallengeRepository {
    pool: AuthPool,
}

impl PgMfaChallengeRepository {
    pub fn new(pool: AuthPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct ChallengeRow {
    id: Uuid,
    user_id: Uuid,
    tenant_id: Uuid,
    token_hash: Vec<u8>,
    client_id: Option<Uuid>,
    scope: Vec<String>,
    active_tenant_id: Uuid,
    purpose: String,
    expires_at: DateTime<Utc>,
    consumed_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

impl TryFrom<ChallengeRow> for MfaChallenge {
    type Error = AuthError;
    fn try_from(r: ChallengeRow) -> Result<Self, Self::Error> {
        let mut hash = [0u8; 32];
        if r.token_hash.len() != 32 {
            return Err(AuthError::Storage(format!(
                "mfa_challenges.token_hash length = {} (expected 32)",
                r.token_hash.len()
            )));
        }
        hash.copy_from_slice(&r.token_hash);
        let purpose = MfaChallengePurpose::parse(&r.purpose).ok_or_else(|| {
            AuthError::Storage(format!("mfa_challenges.purpose unknown: {}", r.purpose))
        })?;
        Ok(Self {
            id: r.id,
            user_id: UserId(r.user_id),
            tenant_id: TenantId(r.tenant_id),
            token_hash: hash,
            client_id: r.client_id.map(ClientId),
            scope: r.scope,
            active_tenant_id: TenantId(r.active_tenant_id),
            purpose,
            expires_at: r.expires_at,
            consumed_at: r.consumed_at,
            created_at: r.created_at,
        })
    }
}

#[async_trait]
impl MfaChallengeRepository for PgMfaChallengeRepository {
    async fn issue(&self, new: NewMfaChallenge) -> Result<MfaChallenge, AuthError> {
        let ip_net: Option<IpNetwork> = new.ip.map(IpAddr::into);
        let row: ChallengeRow = sqlx::query_as(
            "INSERT INTO mokosh_auth.mfa_challenges
                (user_id, tenant_id, token_hash, client_id, scope,
                 active_tenant_id, purpose, expires_at, ip, user_agent)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
             RETURNING id, user_id, tenant_id, token_hash, client_id, scope,
                       active_tenant_id, purpose, expires_at, consumed_at, created_at",
        )
        .bind(new.user_id.0)
        .bind(new.tenant_id.0)
        .bind(&new.token_hash[..])
        .bind(new.client_id.map(|c| c.0))
        .bind(&new.scope)
        .bind(new.active_tenant_id.0)
        .bind(new.purpose.as_str())
        .bind(new.expires_at)
        .bind(ip_net)
        .bind(new.user_agent.as_deref())
        .fetch_one(self.pool.pg())
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                AuthError::Conflict("mfa challenge token hash collision".into())
            }
            _ => db_err(e),
        })?;
        MfaChallenge::try_from(row)
    }

    async fn find_by_token_hash(
        &self,
        token_hash: [u8; 32],
    ) -> Result<Option<MfaChallenge>, AuthError> {
        let row: Option<ChallengeRow> =
            sqlx::query_as(&format!("{SELECT_CHALLENGE} WHERE token_hash = $1"))
                .bind(&token_hash[..])
                .fetch_optional(self.pool.pg())
                .await
                .map_err(db_err)?;
        row.map(MfaChallenge::try_from).transpose()
    }

    async fn consume(
        &self,
        token_hash: [u8; 32],
        expected_purpose: MfaChallengePurpose,
    ) -> Result<MfaChallenge, AuthError> {
        retry_serializable("mfa challenge consume", || {
            self.consume_once(token_hash, expected_purpose)
        })
        .await
    }
}

impl PgMfaChallengeRepository {
    async fn consume_once(
        &self,
        token_hash: [u8; 32],
        expected_purpose: MfaChallengePurpose,
    ) -> Result<MfaChallenge, AuthError> {
        let mut tx = self.pool.pg().begin().await.map_err(db_err)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;

        let row: Option<ChallengeRow> = sqlx::query_as(&format!(
            "{SELECT_CHALLENGE} WHERE token_hash = $1 FOR UPDATE"
        ))
        .bind(&token_hash[..])
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?;

        let row = row.ok_or(AuthError::NotFound)?;
        if row.consumed_at.is_some() {
            return Err(AuthError::NotFound);
        }
        if row.expires_at < Utc::now() {
            return Err(AuthError::NotFound);
        }
        if row.purpose != expected_purpose.as_str() {
            return Err(AuthError::NotFound);
        }

        sqlx::query(
            "UPDATE mokosh_auth.mfa_challenges
             SET consumed_at = NOW()
             WHERE id = $1",
        )
        .bind(row.id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

        tx.commit().await.map_err(db_err)?;

        let mut challenge = MfaChallenge::try_from(row)?;
        challenge.consumed_at = Some(Utc::now());
        Ok(challenge)
    }
}
