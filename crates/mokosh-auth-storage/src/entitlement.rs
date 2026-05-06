//! Postgres-backed `EntitlementRepository`. JIT-grant on first authorize.

use async_trait::async_trait;
use mokosh_auth_core::{AuthError, ClientId, EntitlementRepository, TenantId, UserId};
use std::collections::BTreeSet;

use crate::conv::db_err;
use crate::pool::AuthPool;

pub struct PgEntitlementRepository {
    pool: AuthPool,
}

impl PgEntitlementRepository {
    pub fn new(pool: AuthPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl EntitlementRepository for PgEntitlementRepository {
    async fn has(&self, user_id: UserId, client_id: ClientId) -> Result<bool, AuthError> {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (
                 SELECT 1 FROM mokosh_auth.user_application_access
                 WHERE user_id = $1 AND client_id = $2 AND revoked_at IS NULL
             )",
        )
        .bind(user_id.0)
        .bind(client_id.0)
        .fetch_one(self.pool.pg())
        .await
        .map_err(db_err)?;
        Ok(exists)
    }

    async fn grant(
        &self,
        user_id: UserId,
        client_id: ClientId,
        tenant_id: TenantId,
        scopes: &BTreeSet<String>,
    ) -> Result<(), AuthError> {
        let scope_vec: Vec<String> = scopes.iter().cloned().collect();
        // Upsert: re-granting refreshes scopes and clears any previous
        // revoke marker.
        sqlx::query(
            "INSERT INTO mokosh_auth.user_application_access
                (user_id, client_id, tenant_id, granted_scopes)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (user_id, client_id) DO UPDATE
                 SET granted_scopes = EXCLUDED.granted_scopes,
                     granted_at = NOW(),
                     revoked_at = NULL,
                     revoke_reason = NULL",
        )
        .bind(user_id.0)
        .bind(client_id.0)
        .bind(tenant_id.0)
        .bind(&scope_vec)
        .execute(self.pool.pg())
        .await
        .map_err(db_err)?;
        Ok(())
    }
}
