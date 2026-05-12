//! Postgres-backed `OpSessionRepository`.

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use mokosh_auth_core::{
    AuthError, OpSession, OpSessionId, OpSessionRepository, TenantId, UserId,
};

use crate::conv::{db_err, ip_to_inet, OpSessionRow};
use crate::pool::AuthPool;

const SELECT_OP_SESSION: &str = r#"
    SELECT id, sid, user_id, tenant_id, created_at, last_active_at,
           expires_at, revoked_at, user_agent, ip, acr, amr, display_name
    FROM mokosh_auth.op_sessions
"#;

pub struct PgOpSessionRepository {
    pool: AuthPool,
}

impl PgOpSessionRepository {
    pub fn new(pool: AuthPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl OpSessionRepository for PgOpSessionRepository {
    async fn create(
        &self,
        user_id: UserId,
        tenant_id: TenantId,
        ttl: Duration,
        user_agent: Option<&str>,
        ip: Option<std::net::IpAddr>,
        acr: &str,
        amr: &[String],
    ) -> Result<OpSession, AuthError> {
        // Resume-or-create: if the user already has a session row for
        // this exact user_agent (active OR revoked-from-an-earlier-
        // logout), rotate its sid + expires + acr/amr/ip and clear
        // revoked_at. The display_name and created_at stay so the
        // user-supplied label persists across logout/login cycles.
        // Otherwise insert a fresh row.
        let sid = mokosh_auth_crypto::generate_opaque_token();
        let expires_at = Utc::now() + ttl;
        let ip_net = ip_to_inet(ip);

        let mut tx = self.pool.pg().begin().await.map_err(db_err)?;

        // `IS NOT DISTINCT FROM` makes NULL = NULL work the way we want
        // for unknown UAs (e.g. CLI). FOR UPDATE so a parallel login
        // does not race us into two rows.
        let existing: Option<(uuid::Uuid,)> = sqlx::query_as(
            "SELECT id
             FROM mokosh_auth.op_sessions
             WHERE user_id = $1
               AND user_agent IS NOT DISTINCT FROM $2
             ORDER BY last_active_at DESC
             LIMIT 1
             FOR UPDATE",
        )
        .bind(user_id.0)
        .bind(user_agent)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?;

        let row: OpSessionRow = if let Some((existing_id,)) = existing {
            sqlx::query_as(
                "UPDATE mokosh_auth.op_sessions
                 SET sid = $1,
                     tenant_id = $2,
                     expires_at = $3,
                     last_active_at = NOW(),
                     revoked_at = NULL,
                     ip = $4,
                     acr = $5,
                     amr = $6
                 WHERE id = $7
                 RETURNING id, sid, user_id, tenant_id, created_at, last_active_at,
                           expires_at, revoked_at, user_agent, ip, acr, amr, display_name",
            )
            .bind(&sid)
            .bind(tenant_id.0)
            .bind(expires_at)
            .bind(ip_net)
            .bind(acr)
            .bind(amr)
            .bind(existing_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(db_err)?
        } else {
            sqlx::query_as(
                "INSERT INTO mokosh_auth.op_sessions
                    (sid, user_id, tenant_id, expires_at, user_agent, ip, acr, amr)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                 RETURNING id, sid, user_id, tenant_id, created_at, last_active_at,
                           expires_at, revoked_at, user_agent, ip, acr, amr, display_name",
            )
            .bind(&sid)
            .bind(user_id.0)
            .bind(tenant_id.0)
            .bind(expires_at)
            .bind(user_agent)
            .bind(ip_net)
            .bind(acr)
            .bind(amr)
            .fetch_one(&mut *tx)
            .await
            .map_err(db_err)?
        };

        tx.commit().await.map_err(db_err)?;
        Ok(row.into())
    }

    async fn find_by_sid(&self, sid: &str) -> Result<Option<OpSession>, AuthError> {
        let row: Option<OpSessionRow> = sqlx::query_as(&format!(
            "{SELECT_OP_SESSION} WHERE sid = $1 AND revoked_at IS NULL"
        ))
        .bind(sid)
        .fetch_optional(self.pool.pg())
        .await
        .map_err(db_err)?;
        Ok(row.map(Into::into))
    }

    async fn find_by_id(&self, id: OpSessionId) -> Result<Option<OpSession>, AuthError> {
        let row: Option<OpSessionRow> = sqlx::query_as(&format!(
            "{SELECT_OP_SESSION} WHERE id = $1"
        ))
        .bind(id.0)
        .fetch_optional(self.pool.pg())
        .await
        .map_err(db_err)?;
        Ok(row.map(Into::into))
    }

    async fn list_active_for_user(
        &self,
        user_id: UserId,
        now: DateTime<Utc>,
    ) -> Result<Vec<OpSession>, AuthError> {
        let rows: Vec<OpSessionRow> = sqlx::query_as(&format!(
            "{SELECT_OP_SESSION}
             WHERE user_id = $1
               AND revoked_at IS NULL
               AND expires_at > $2
             ORDER BY last_active_at DESC"
        ))
        .bind(user_id.0)
        .bind(now)
        .fetch_all(self.pool.pg())
        .await
        .map_err(db_err)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn touch(&self, id: OpSessionId, at: DateTime<Utc>) -> Result<(), AuthError> {
        sqlx::query(
            "UPDATE mokosh_auth.op_sessions
             SET last_active_at = $1
             WHERE id = $2 AND revoked_at IS NULL",
        )
        .bind(at)
        .bind(id.0)
        .execute(self.pool.pg())
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn revoke(&self, id: OpSessionId, at: DateTime<Utc>) -> Result<(), AuthError> {
        sqlx::query(
            "UPDATE mokosh_auth.op_sessions
             SET revoked_at = $1
             WHERE id = $2 AND revoked_at IS NULL",
        )
        .bind(at)
        .bind(id.0)
        .execute(self.pool.pg())
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn revoke_others_same_user_agent(
        &self,
        user_id: UserId,
        user_agent: Option<&str>,
        keep_id: OpSessionId,
        at: DateTime<Utc>,
    ) -> Result<u64, AuthError> {
        // Two SQL shapes because COMPARING `user_agent = $2` with NULL
        // is always false; NULL UAs need IS NULL semantics.
        let n = match user_agent {
            Some(ua) => {
                sqlx::query(
                    "UPDATE mokosh_auth.op_sessions
                     SET revoked_at = $1
                     WHERE user_id = $2
                       AND user_agent = $3
                       AND id <> $4
                       AND revoked_at IS NULL",
                )
                .bind(at)
                .bind(user_id.0)
                .bind(ua)
                .bind(keep_id.0)
                .execute(self.pool.pg())
                .await
                .map_err(db_err)?
                .rows_affected()
            }
            None => {
                sqlx::query(
                    "UPDATE mokosh_auth.op_sessions
                     SET revoked_at = $1
                     WHERE user_id = $2
                       AND user_agent IS NULL
                       AND id <> $3
                       AND revoked_at IS NULL",
                )
                .bind(at)
                .bind(user_id.0)
                .bind(keep_id.0)
                .execute(self.pool.pg())
                .await
                .map_err(db_err)?
                .rows_affected()
            }
        };
        Ok(n)
    }

    async fn rename(
        &self,
        id: OpSessionId,
        user_id: UserId,
        display_name: Option<&str>,
    ) -> Result<(), AuthError> {
        // Empty / whitespace-only strings normalize to NULL so the UI
        // can "clear" the label by submitting "".
        let normalized = display_name
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        sqlx::query(
            "UPDATE mokosh_auth.op_sessions
             SET display_name = $1
             WHERE id = $2 AND user_id = $3 AND revoked_at IS NULL",
        )
        .bind(normalized.as_deref())
        .bind(id.0)
        .bind(user_id.0)
        .execute(self.pool.pg())
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn revoke_all_for_user(&self, user_id: UserId) -> Result<Vec<OpSessionId>, AuthError> {
        let rows: Vec<(uuid::Uuid,)> = sqlx::query_as(
            "UPDATE mokosh_auth.op_sessions
             SET revoked_at = NOW()
             WHERE user_id = $1 AND revoked_at IS NULL
             RETURNING id",
        )
        .bind(user_id.0)
        .fetch_all(self.pool.pg())
        .await
        .map_err(db_err)?;
        Ok(rows.into_iter().map(|(id,)| OpSessionId(id)).collect())
    }
}

