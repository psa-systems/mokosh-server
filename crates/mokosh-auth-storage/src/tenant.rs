//! Postgres-backed `TenantRepository`. Owns the bridge across the
//! `public.tenants` <-> `mokosh_auth.memberships` boundary for the
//! org-management surface (`/v1/orgs/*`).

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mokosh_auth_core::{
    AuthError, MembershipRole, Tenant, TenantId, TenantKind, TenantRepository, UserId, UserRole,
};
use uuid::Uuid;

use crate::conv::db_err;
use crate::pool::AuthPool;

pub struct PgTenantRepository {
    pool: AuthPool,
}

impl PgTenantRepository {
    pub fn new(pool: AuthPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct TenantRow {
    id: Uuid,
    name: String,
    slug: String,
    kind: String,
    created_at: DateTime<Utc>,
}

impl TryFrom<TenantRow> for Tenant {
    type Error = AuthError;
    fn try_from(r: TenantRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: TenantId(r.id),
            name: r.name,
            slug: r.slug,
            kind: TenantKind::parse(&r.kind)
                .ok_or_else(|| AuthError::Storage(format!("invalid tenant kind: {}", r.kind)))?,
            created_at: r.created_at,
        })
    }
}

const SELECT_TENANT: &str = r#"
    SELECT id, name, slug, kind, created_at
    FROM public.tenants
"#;

#[async_trait]
impl TenantRepository for PgTenantRepository {
    async fn find_by_id(&self, id: TenantId) -> Result<Option<Tenant>, AuthError> {
        let row: Option<TenantRow> = sqlx::query_as(&format!("{SELECT_TENANT} WHERE id = $1"))
            .bind(id.0)
            .fetch_optional(self.pool.pg())
            .await
            .map_err(db_err)?;
        row.map(Tenant::try_from).transpose()
    }

    async fn find_by_slug(&self, slug: &str) -> Result<Option<Tenant>, AuthError> {
        let row: Option<TenantRow> = sqlx::query_as(&format!("{SELECT_TENANT} WHERE slug = $1"))
            .bind(slug)
            .fetch_optional(self.pool.pg())
            .await
            .map_err(db_err)?;
        row.map(Tenant::try_from).transpose()
    }

    async fn create_org(
        &self,
        name: &str,
        slug: &str,
        owner_user_id: UserId,
        owner_global_role: UserRole,
    ) -> Result<Tenant, AuthError> {
        let mut tx = self.pool.pg().begin().await.map_err(db_err)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;

        let row: TenantRow = sqlx::query_as(
            "INSERT INTO public.tenants (name, slug, kind, status)
             VALUES ($1, $2, 'org', 'active')
             RETURNING id, name, slug, kind, created_at",
        )
        .bind(name)
        .bind(slug)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                AuthError::Conflict("a tenant with this slug already exists".into())
            }
            _ => db_err(e),
        })?;

        sqlx::query(
            "INSERT INTO mokosh_auth.memberships
                (user_id, tenant_id, role, org_role, status)
             VALUES ($1, $2, $3, $4, 'active')",
        )
        .bind(owner_user_id.0)
        .bind(row.id)
        .bind(owner_global_role.as_str())
        .bind(MembershipRole::Owner.as_str())
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

        tx.commit().await.map_err(db_err)?;
        Tenant::try_from(row)
    }
}
