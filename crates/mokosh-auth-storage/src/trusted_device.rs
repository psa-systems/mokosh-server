//! Postgres-backed `TrustedDeviceRepository`.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use mokosh_auth_core::{
    AuthError, NewTrustedDevice, TenantId, TrustedDevice, TrustedDeviceRepository, UserId,
};
use uuid::Uuid;

use crate::conv::{db_err, ip_to_inet};
use crate::pool::AuthPool;

pub struct PgTrustedDeviceRepository {
    pool: AuthPool,
}

impl PgTrustedDeviceRepository {
    pub fn new(pool: AuthPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct Row {
    id: Uuid,
    user_id: Uuid,
    tenant_id: Uuid,
    token_hash: Vec<u8>,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
    user_agent: Option<String>,
    ip: Option<IpNetwork>,
}

impl TryFrom<Row> for TrustedDevice {
    type Error = AuthError;
    fn try_from(r: Row) -> Result<Self, Self::Error> {
        let mut hash = [0u8; 32];
        if r.token_hash.len() != 32 {
            return Err(AuthError::Storage(format!(
                "trusted_devices.token_hash length = {} (expected 32)",
                r.token_hash.len()
            )));
        }
        hash.copy_from_slice(&r.token_hash);
        Ok(Self {
            id: r.id,
            user_id: UserId(r.user_id),
            tenant_id: TenantId(r.tenant_id),
            token_hash: hash,
            issued_at: r.issued_at,
            expires_at: r.expires_at,
            last_used_at: r.last_used_at,
            revoked_at: r.revoked_at,
            user_agent: r.user_agent,
            ip: r.ip.map(|n| n.ip()),
        })
    }
}

#[async_trait]
impl TrustedDeviceRepository for PgTrustedDeviceRepository {
    async fn issue(&self, new: NewTrustedDevice) -> Result<TrustedDevice, AuthError> {
        let ip_net = ip_to_inet(new.ip);
        let row: Row = sqlx::query_as(
            "INSERT INTO mokosh_auth.trusted_devices
                (user_id, tenant_id, token_hash, expires_at, ip, user_agent)
             VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING id, user_id, tenant_id, token_hash, issued_at, expires_at,
                       last_used_at, revoked_at, user_agent, ip",
        )
        .bind(new.user_id.0)
        .bind(new.tenant_id.0)
        .bind(&new.token_hash[..])
        .bind(new.expires_at)
        .bind(ip_net)
        .bind(new.user_agent.as_deref())
        .fetch_one(self.pool.pg())
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                AuthError::Conflict("trust token hash collision".into())
            }
            _ => db_err(e),
        })?;
        TrustedDevice::try_from(row)
    }

    async fn find_active_and_touch(
        &self,
        token_hash: [u8; 32],
    ) -> Result<Option<TrustedDevice>, AuthError> {
        let row: Option<Row> = sqlx::query_as(
            "UPDATE mokosh_auth.trusted_devices
             SET last_used_at = NOW()
             WHERE token_hash = $1
               AND revoked_at IS NULL
               AND expires_at > NOW()
             RETURNING id, user_id, tenant_id, token_hash, issued_at, expires_at,
                       last_used_at, revoked_at, user_agent, ip",
        )
        .bind(&token_hash[..])
        .fetch_optional(self.pool.pg())
        .await
        .map_err(db_err)?;
        row.map(TrustedDevice::try_from).transpose()
    }

    async fn list_active_for_user(&self, user_id: UserId) -> Result<Vec<TrustedDevice>, AuthError> {
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT id, user_id, tenant_id, token_hash, issued_at, expires_at,
                    last_used_at, revoked_at, user_agent, ip
             FROM mokosh_auth.trusted_devices
             WHERE user_id = $1
               AND revoked_at IS NULL
               AND expires_at > NOW()
             ORDER BY issued_at DESC",
        )
        .bind(user_id.0)
        .fetch_all(self.pool.pg())
        .await
        .map_err(db_err)?;
        rows.into_iter().map(TrustedDevice::try_from).collect()
    }

    async fn revoke(&self, id: Uuid, user_id: UserId) -> Result<(), AuthError> {
        sqlx::query(
            "UPDATE mokosh_auth.trusted_devices
             SET revoked_at = NOW()
             WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL",
        )
        .bind(id)
        .bind(user_id.0)
        .execute(self.pool.pg())
        .await
        .map_err(db_err)?;
        Ok(())
    }
}
