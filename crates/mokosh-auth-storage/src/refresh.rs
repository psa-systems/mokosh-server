//! Postgres-backed `RefreshTokenRepository`.
//!
//! `rotate` is the most security-critical query in the entire auth stack.
//! It runs under SERIALIZABLE isolation so that two concurrent calls with
//! the same presented hash cannot both succeed; the loser sees the row
//! already marked `used_at` and triggers family revocation.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mokosh_auth_core::{
    AuthError, NewRefreshToken, NewRefreshTokenFamily, OpSessionId, RefreshFamilyId,
    RefreshTokenRepository, RotatedTokens,
};
use std::collections::BTreeSet;

use crate::conv::{db_err, ip_to_inet};
use crate::pool::AuthPool;

pub struct PgRefreshTokenRepository {
    pool: AuthPool,
}

impl PgRefreshTokenRepository {
    pub fn new(pool: AuthPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RefreshTokenRepository for PgRefreshTokenRepository {
    async fn issue_initial(
        &self,
        family: NewRefreshTokenFamily,
        new_token: NewRefreshToken,
    ) -> Result<RefreshFamilyId, AuthError> {
        let mut tx = self.pool.pg().begin().await.map_err(db_err)?;
        let family_id: uuid::Uuid = sqlx::query_scalar(
            "INSERT INTO mokosh_auth.refresh_token_families
                (client_id, user_id, tenant_id, op_session_id)
             VALUES ($1, $2, $3, $4)
             RETURNING id",
        )
        .bind(family.client_id.0)
        .bind(family.user_id.0)
        .bind(family.tenant_id.0)
        .bind(family.op_session_id.map(|s| s.0))
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err)?;

        sqlx::query(
            "INSERT INTO mokosh_auth.refresh_tokens
                (id, family_id, parent_id, token_hash, client_id, user_id,
                 tenant_id, scope, idle_expires_at, absolute_expires_at,
                 ip, user_agent)
             VALUES ($1, $2, NULL, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(new_token.id.0)
        .bind(family_id)
        .bind(&new_token.token_hash[..])
        .bind(family.client_id.0)
        .bind(family.user_id.0)
        .bind(family.tenant_id.0)
        .bind(&new_token.scope)
        .bind(new_token.idle_expires_at)
        .bind(new_token.absolute_expires_at)
        .bind(ip_to_inet(new_token.ip))
        .bind(&new_token.user_agent)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

        tx.commit().await.map_err(db_err)?;
        Ok(RefreshFamilyId(family_id))
    }

    async fn rotate(
        &self,
        presented_hash: [u8; 32],
        new_token: NewRefreshToken,
        narrowed_scope: &BTreeSet<String>,
    ) -> Result<RotatedTokens, AuthError> {
        // Up to a small number of serialization-failure retries. Postgres
        // returns SQLSTATE 40001 ("could not serialize access") when two
        // concurrent SERIALIZABLE transactions conflict; that is the
        // *correct* outcome (the loser must retry or fail), but we give
        // legitimate retries a small budget before surfacing the error.
        const MAX_ATTEMPTS: u32 = 3;

        let scope_vec: Vec<String> = narrowed_scope.iter().cloned().collect();
        for attempt in 0..MAX_ATTEMPTS {
            match self
                .rotate_once(&presented_hash, &new_token, &scope_vec)
                .await
            {
                Err(AuthError::Storage(msg)) if msg.contains("40001") && attempt + 1 < MAX_ATTEMPTS => {
                    tracing::debug!(attempt, "refresh rotation serialization conflict, retrying");
                    continue;
                }
                other => return other,
            }
        }
        unreachable!("loop returns or continues at most MAX_ATTEMPTS times")
    }

    async fn revoke_by_token_hash(
        &self,
        token_hash: [u8; 32],
        reason: &str,
        at: DateTime<Utc>,
    ) -> Result<Option<OpSessionId>, AuthError> {
        // Look up the family + bound op_session_id in one query. If
        // the token is unknown we still return Ok(None): the caller
        // (the /oauth2/revoke endpoint) must not distinguish hits
        // from misses (RFC 7009).
        let row: Option<(uuid::Uuid, Option<uuid::Uuid>)> = sqlx::query_as(
            "SELECT f.id, f.op_session_id
             FROM mokosh_auth.refresh_tokens rt
             JOIN mokosh_auth.refresh_token_families f ON f.id = rt.family_id
             WHERE rt.token_hash = $1",
        )
        .bind(&token_hash[..])
        .fetch_optional(self.pool.pg())
        .await
        .map_err(db_err)?;

        match row {
            Some((fid, op_sid)) => {
                self.revoke_family(RefreshFamilyId(fid), reason, at).await?;
                Ok(op_sid.map(OpSessionId))
            }
            None => Ok(None),
        }
    }

    async fn revoke_families_for_session(
        &self,
        op_session_id: OpSessionId,
        reason: &str,
        at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        let mut tx = self.pool.pg().begin().await.map_err(db_err)?;
        sqlx::query(
            "UPDATE mokosh_auth.refresh_token_families
             SET revoked_at = $1, revoke_reason = $2
             WHERE op_session_id = $3 AND revoked_at IS NULL",
        )
        .bind(at)
        .bind(reason)
        .bind(op_session_id.0)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
        sqlx::query(
            "UPDATE mokosh_auth.refresh_tokens rt
             SET revoked_at = $1
             FROM mokosh_auth.refresh_token_families f
             WHERE rt.family_id = f.id
               AND f.op_session_id = $2
               AND rt.revoked_at IS NULL",
        )
        .bind(at)
        .bind(op_session_id.0)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        Ok(())
    }

    async fn revoke_family(
        &self,
        family: RefreshFamilyId,
        reason: &str,
        at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        let mut tx = self.pool.pg().begin().await.map_err(db_err)?;
        sqlx::query(
            "UPDATE mokosh_auth.refresh_token_families
             SET revoked_at = $1, revoke_reason = $2
             WHERE id = $3 AND revoked_at IS NULL",
        )
        .bind(at)
        .bind(reason)
        .bind(family.0)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
        sqlx::query(
            "UPDATE mokosh_auth.refresh_tokens
             SET revoked_at = $1
             WHERE family_id = $2 AND revoked_at IS NULL",
        )
        .bind(at)
        .bind(family.0)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        Ok(())
    }
}

impl PgRefreshTokenRepository {
    async fn rotate_once(
        &self,
        presented_hash: &[u8; 32],
        new_token: &NewRefreshToken,
        scope_vec: &[String],
    ) -> Result<RotatedTokens, AuthError> {
        let mut tx = self.pool.pg().begin().await.map_err(db_err)?;
        // SERIALIZABLE: race-free reuse detection. Two concurrent calls
        // with the same `presented_hash` will serialize; the second call
        // sees `used_at IS NOT NULL` and goes down the family-revoke path.
        sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;

        // 1. Lock the presented row.
        #[derive(sqlx::FromRow)]
        struct Row {
            id: uuid::Uuid,
            family_id: uuid::Uuid,
            client_id: uuid::Uuid,
            user_id: uuid::Uuid,
            tenant_id: uuid::Uuid,
            scope: Vec<String>,
            used_at: Option<DateTime<Utc>>,
            revoked_at: Option<DateTime<Utc>>,
            idle_expires_at: DateTime<Utc>,
            absolute_expires_at: DateTime<Utc>,
        }
        let row: Option<Row> = sqlx::query_as(
            "SELECT id, family_id, client_id, user_id, tenant_id, scope,
                    used_at, revoked_at, idle_expires_at, absolute_expires_at
             FROM mokosh_auth.refresh_tokens
             WHERE token_hash = $1
             FOR UPDATE",
        )
        .bind(&presented_hash[..])
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?;

        let row = match row {
            Some(r) => r,
            None => {
                // Unknown token; do not commit any state.
                return Err(AuthError::InvalidGrant("unknown refresh token".into()));
            }
        };

        // 2. Reuse detection. Already-consumed tokens trigger family
        // revocation, then a hard error. The caller (OIDC engine) emits
        // a `RefreshReuseDetected` audit event on this branch.
        if row.used_at.is_some() {
            sqlx::query(
                "UPDATE mokosh_auth.refresh_token_families
                 SET revoked_at = NOW(), revoke_reason = 'reuse_detected'
                 WHERE id = $1 AND revoked_at IS NULL",
            )
            .bind(row.family_id)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
            sqlx::query(
                "UPDATE mokosh_auth.refresh_tokens
                 SET revoked_at = NOW()
                 WHERE family_id = $1 AND revoked_at IS NULL",
            )
            .bind(row.family_id)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
            tx.commit().await.map_err(db_err)?;
            return Err(AuthError::ReuseDetected);
        }

        // 3. Expiry / revocation checks.
        let now = Utc::now();
        if row.revoked_at.is_some()
            || row.idle_expires_at < now
            || row.absolute_expires_at < now
        {
            return Err(AuthError::InvalidGrant("expired refresh token".into()));
        }

        // 4. Resolve effective scope. An empty `scope_vec` means
        // "preserve the prior scope" (RFC 6749 6: scope is optional and
        // MUST default to the value originally granted). A non-empty
        // request must be a subset of the prior scope.
        use std::collections::BTreeSet;
        let prior: BTreeSet<String> = row.scope.iter().cloned().collect();
        let requested: BTreeSet<String> = scope_vec.iter().cloned().collect();
        let effective: Vec<String> = if requested.is_empty() {
            row.scope.clone()
        } else {
            if !requested.is_subset(&prior) {
                return Err(AuthError::InvalidScope);
            }
            requested.into_iter().collect()
        };

        // 5. Mark old token used; insert new sibling within the family.
        sqlx::query("UPDATE mokosh_auth.refresh_tokens SET used_at = NOW() WHERE id = $1")
            .bind(row.id)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;

        sqlx::query(
            "INSERT INTO mokosh_auth.refresh_tokens
                (id, family_id, parent_id, token_hash, client_id, user_id,
                 tenant_id, scope, idle_expires_at, absolute_expires_at,
                 ip, user_agent)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(new_token.id.0)
        .bind(row.family_id)
        .bind(row.id)
        .bind(&new_token.token_hash[..])
        .bind(row.client_id)
        .bind(row.user_id)
        .bind(row.tenant_id)
        .bind(&effective)
        .bind(new_token.idle_expires_at)
        // Absolute expiry is inherited from the family, never extended.
        .bind(row.absolute_expires_at)
        .bind(ip_to_inet(new_token.ip))
        .bind(&new_token.user_agent)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

        tx.commit().await.map_err(db_err)?;

        Ok(RotatedTokens {
            new_token_id: new_token.id,
            family_id: RefreshFamilyId(row.family_id),
            client_id: mokosh_auth_core::ClientId(row.client_id),
            user_id: mokosh_auth_core::UserId(row.user_id),
            tenant_id: mokosh_auth_core::TenantId(row.tenant_id),
            scope: effective,
        })
    }
}
