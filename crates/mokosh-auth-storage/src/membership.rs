//! Postgres-backed `MembershipRepository`.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mokosh_auth_core::{
    AuthError, Membership, MembershipRepository, MembershipRole, MembershipStatus, NewMembership,
    TenantId, UserId, UserRole,
};

use crate::conv::db_err;
use crate::pool::AuthPool;

const SELECT_MEMBERSHIP: &str = r#"
    SELECT user_id, tenant_id, role, org_role, status, joined_at
    FROM mokosh_auth.memberships
"#;

pub struct PgMembershipRepository {
    pool: AuthPool,
}

impl PgMembershipRepository {
    pub fn new(pool: AuthPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct MembershipRow {
    user_id: uuid::Uuid,
    tenant_id: uuid::Uuid,
    role: String,
    org_role: String,
    status: String,
    joined_at: DateTime<Utc>,
}

impl TryFrom<MembershipRow> for Membership {
    type Error = AuthError;
    fn try_from(r: MembershipRow) -> Result<Self, Self::Error> {
        Ok(Self {
            user_id: UserId(r.user_id),
            tenant_id: TenantId(r.tenant_id),
            role: UserRole::parse(&r.role)
                .ok_or_else(|| AuthError::Storage(format!("invalid role: {}", r.role)))?,
            org_role: MembershipRole::parse(&r.org_role)
                .ok_or_else(|| AuthError::Storage(format!("invalid org_role: {}", r.org_role)))?,
            status: MembershipStatus::parse(&r.status)
                .ok_or_else(|| AuthError::Storage(format!("invalid status: {}", r.status)))?,
            joined_at: r.joined_at,
        })
    }
}

#[async_trait]
impl MembershipRepository for PgMembershipRepository {
    async fn list_for_user(&self, user_id: UserId) -> Result<Vec<Membership>, AuthError> {
        let rows: Vec<MembershipRow> = sqlx::query_as(&format!(
            "{SELECT_MEMBERSHIP} WHERE user_id = $1 ORDER BY joined_at ASC"
        ))
        .bind(user_id.0)
        .fetch_all(self.pool.pg())
        .await
        .map_err(db_err)?;
        rows.into_iter().map(Membership::try_from).collect()
    }

    async fn list_for_tenant(&self, tenant_id: TenantId) -> Result<Vec<Membership>, AuthError> {
        let rows: Vec<MembershipRow> = sqlx::query_as(&format!(
            "{SELECT_MEMBERSHIP} WHERE tenant_id = $1 ORDER BY joined_at ASC"
        ))
        .bind(tenant_id.0)
        .fetch_all(self.pool.pg())
        .await
        .map_err(db_err)?;
        rows.into_iter().map(Membership::try_from).collect()
    }

    async fn find(
        &self,
        user_id: UserId,
        tenant_id: TenantId,
    ) -> Result<Option<Membership>, AuthError> {
        let row: Option<MembershipRow> = sqlx::query_as(&format!(
            "{SELECT_MEMBERSHIP} WHERE user_id = $1 AND tenant_id = $2"
        ))
        .bind(user_id.0)
        .bind(tenant_id.0)
        .fetch_optional(self.pool.pg())
        .await
        .map_err(db_err)?;
        row.map(Membership::try_from).transpose()
    }

    async fn create(&self, m: NewMembership) -> Result<Membership, AuthError> {
        let row: MembershipRow = sqlx::query_as(
            "INSERT INTO mokosh_auth.memberships
                (user_id, tenant_id, role, org_role, status)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING user_id, tenant_id, role, org_role, status, joined_at",
        )
        .bind(m.user_id.0)
        .bind(m.tenant_id.0)
        .bind(m.role.as_str())
        .bind(m.org_role.as_str())
        .bind(m.status.as_str())
        .fetch_one(self.pool.pg())
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                // (user_id, tenant_id) PK collision: the user is already
                // a member. Caller decides whether this is a soft
                // "already a member" path or a hard error.
                AuthError::Conflict("user is already a member of this tenant".into())
            }
            _ => db_err(e),
        })?;
        Membership::try_from(row)
    }

    async fn change_org_role(
        &self,
        user_id: UserId,
        tenant_id: TenantId,
        org_role: MembershipRole,
    ) -> Result<(), AuthError> {
        let affected = sqlx::query(
            "UPDATE mokosh_auth.memberships
             SET org_role = $1
             WHERE user_id = $2 AND tenant_id = $3",
        )
        .bind(org_role.as_str())
        .bind(user_id.0)
        .bind(tenant_id.0)
        .execute(self.pool.pg())
        .await
        .map_err(db_err)?
        .rows_affected();
        if affected == 0 {
            return Err(AuthError::NotFound);
        }
        Ok(())
    }

    async fn delete(&self, user_id: UserId, tenant_id: TenantId) -> Result<(), AuthError> {
        let affected = sqlx::query(
            "DELETE FROM mokosh_auth.memberships
             WHERE user_id = $1 AND tenant_id = $2",
        )
        .bind(user_id.0)
        .bind(tenant_id.0)
        .execute(self.pool.pg())
        .await
        .map_err(db_err)?
        .rows_affected();
        if affected == 0 {
            return Err(AuthError::NotFound);
        }
        Ok(())
    }

    async fn count_owners_excluding(
        &self,
        tenant_id: TenantId,
        excluded: UserId,
    ) -> Result<u64, AuthError> {
        let (n,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM mokosh_auth.memberships
             WHERE tenant_id = $1 AND org_role = 'owner'
               AND status = 'active' AND user_id <> $2",
        )
        .bind(tenant_id.0)
        .bind(excluded.0)
        .fetch_one(self.pool.pg())
        .await
        .map_err(db_err)?;
        Ok(n.max(0) as u64)
    }

    async fn set_status(
        &self,
        user_id: UserId,
        tenant_id: TenantId,
        status: MembershipStatus,
    ) -> Result<(), AuthError> {
        let affected = sqlx::query(
            "UPDATE mokosh_auth.memberships
             SET status = $1
             WHERE user_id = $2 AND tenant_id = $3",
        )
        .bind(status.as_str())
        .bind(user_id.0)
        .bind(tenant_id.0)
        .execute(self.pool.pg())
        .await
        .map_err(db_err)?
        .rows_affected();
        if affected == 0 {
            return Err(AuthError::NotFound);
        }
        Ok(())
    }

    async fn set_role(
        &self,
        user_id: UserId,
        tenant_id: TenantId,
        role: UserRole,
    ) -> Result<(), AuthError> {
        let affected = sqlx::query(
            "UPDATE mokosh_auth.memberships
             SET role = $1
             WHERE user_id = $2 AND tenant_id = $3",
        )
        .bind(role.as_str())
        .bind(user_id.0)
        .bind(tenant_id.0)
        .execute(self.pool.pg())
        .await
        .map_err(db_err)?
        .rows_affected();
        if affected == 0 {
            return Err(AuthError::NotFound);
        }
        Ok(())
    }

    async fn count_active_admins_in_tenant_excluding(
        &self,
        tenant_id: TenantId,
        excluded: UserId,
    ) -> Result<u64, AuthError> {
        let (n,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM mokosh_auth.memberships
             WHERE tenant_id = $1 AND role = 'admin'
               AND status = 'active' AND user_id <> $2",
        )
        .bind(tenant_id.0)
        .bind(excluded.0)
        .fetch_one(self.pool.pg())
        .await
        .map_err(db_err)?;
        Ok(n.max(0) as u64)
    }
}
