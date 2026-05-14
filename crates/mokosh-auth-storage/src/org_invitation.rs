//! Postgres-backed `OrgInvitationRepository`. Org-scoped invitations
//! for existing users; see migration
//! `20260514000001_create_org_invitations.sql` and
//! `docs/mokosh-fixes/03-organizations.md`.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mokosh_auth_core::{
    AuthError, MembershipRole, NewOrgInvitation, OrgInvitation, OrgInvitationRepository, TenantId,
    UserId, UserRole,
};
use uuid::Uuid;

use crate::conv::db_err;
use crate::pool::AuthPool;

pub struct PgOrgInvitationRepository {
    pool: AuthPool,
}

impl PgOrgInvitationRepository {
    pub fn new(pool: AuthPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct InvitationRow {
    id: Uuid,
    tenant_id: Uuid,
    email: String,
    org_role: String,
    invited_by: Uuid,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    accepted_at: Option<DateTime<Utc>>,
    accepted_by: Option<Uuid>,
    revoked_at: Option<DateTime<Utc>>,
    revoked_by: Option<Uuid>,
    note: Option<String>,
}

impl TryFrom<InvitationRow> for OrgInvitation {
    type Error = AuthError;
    fn try_from(r: InvitationRow) -> Result<Self, Self::Error> {
        Ok(OrgInvitation {
            id: r.id,
            tenant_id: TenantId(r.tenant_id),
            email: r.email,
            org_role: MembershipRole::parse(&r.org_role).ok_or_else(|| {
                AuthError::Storage(format!("invalid org invitation role: {}", r.org_role))
            })?,
            invited_by: UserId(r.invited_by),
            issued_at: r.issued_at,
            expires_at: r.expires_at,
            accepted_at: r.accepted_at,
            accepted_by: r.accepted_by.map(UserId),
            revoked_at: r.revoked_at,
            revoked_by: r.revoked_by.map(UserId),
            note: r.note,
        })
    }
}

const SELECT_ORG_INVITE: &str = r#"
    SELECT id, tenant_id, email, org_role, invited_by, issued_at, expires_at,
           accepted_at, accepted_by, revoked_at, revoked_by, note
    FROM mokosh_auth.org_invitations
"#;

#[async_trait]
impl OrgInvitationRepository for PgOrgInvitationRepository {
    async fn issue(&self, new: NewOrgInvitation) -> Result<OrgInvitation, AuthError> {
        let token_hash = mokosh_auth_crypto::hash_opaque_token(&new.token);
        let row: InvitationRow = sqlx::query_as(&format!(
            "INSERT INTO mokosh_auth.org_invitations
                (tenant_id, email, org_role, token_hash, invited_by, expires_at, note)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             RETURNING id, tenant_id, email, org_role, invited_by, issued_at, expires_at,
                       accepted_at, accepted_by, revoked_at, revoked_by, note",
        ))
        .bind(new.tenant_id.0)
        .bind(&new.email)
        .bind(new.org_role.as_str())
        .bind(&token_hash[..])
        .bind(new.invited_by.0)
        .bind(new.expires_at)
        .bind(&new.note)
        .fetch_one(self.pool.pg())
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                AuthError::Conflict("an open invite already exists for this email".into())
            }
            _ => db_err(e),
        })?;
        OrgInvitation::try_from(row)
    }

    async fn list_open_for_tenant(
        &self,
        tenant_id: TenantId,
    ) -> Result<Vec<OrgInvitation>, AuthError> {
        let rows: Vec<InvitationRow> = sqlx::query_as(&format!(
            "{SELECT_ORG_INVITE}
             WHERE tenant_id = $1
               AND accepted_at IS NULL AND revoked_at IS NULL
             ORDER BY issued_at DESC"
        ))
        .bind(tenant_id.0)
        .fetch_all(self.pool.pg())
        .await
        .map_err(db_err)?;
        rows.into_iter().map(OrgInvitation::try_from).collect()
    }

    async fn find_by_token_hash(
        &self,
        token_hash: [u8; 32],
    ) -> Result<Option<OrgInvitation>, AuthError> {
        let row: Option<InvitationRow> =
            sqlx::query_as(&format!("{SELECT_ORG_INVITE} WHERE token_hash = $1"))
                .bind(&token_hash[..])
                .fetch_optional(self.pool.pg())
                .await
                .map_err(db_err)?;
        row.map(OrgInvitation::try_from).transpose()
    }

    async fn revoke(&self, id: Uuid, revoked_by: UserId) -> Result<(), AuthError> {
        let affected = sqlx::query(
            "UPDATE mokosh_auth.org_invitations
             SET revoked_at = NOW(), revoked_by = $1
             WHERE id = $2 AND revoked_at IS NULL AND accepted_at IS NULL",
        )
        .bind(revoked_by.0)
        .bind(id)
        .execute(self.pool.pg())
        .await
        .map_err(db_err)?
        .rows_affected();
        if affected == 0 {
            return Err(AuthError::NotFound);
        }
        Ok(())
    }

    async fn accept(
        &self,
        token_hash: [u8; 32],
        accepting_user: UserId,
        accepting_global_role: UserRole,
    ) -> Result<OrgInvitation, AuthError> {
        let mut tx = self.pool.pg().begin().await.map_err(db_err)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;

        #[derive(sqlx::FromRow)]
        struct Locked {
            id: Uuid,
            tenant_id: Uuid,
            email: String,
            org_role: String,
            expires_at: DateTime<Utc>,
            accepted_at: Option<DateTime<Utc>>,
            revoked_at: Option<DateTime<Utc>>,
        }
        let row: Option<Locked> = sqlx::query_as(
            "SELECT id, tenant_id, email, org_role, expires_at, accepted_at, revoked_at
             FROM mokosh_auth.org_invitations
             WHERE token_hash = $1
             FOR UPDATE",
        )
        .bind(&token_hash[..])
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?;
        let row = row.ok_or(AuthError::NotFound)?;

        if row.accepted_at.is_some() {
            return Err(AuthError::Conflict("invite already accepted".into()));
        }
        if row.revoked_at.is_some() {
            return Err(AuthError::InvalidGrant("invite revoked".into()));
        }
        if row.expires_at < Utc::now() {
            return Err(AuthError::InvalidGrant("invite expired".into()));
        }

        let org_role_parsed = MembershipRole::parse(&row.org_role).ok_or_else(|| {
            AuthError::Storage(format!("invalid org invitation role: {}", row.org_role))
        })?;

        sqlx::query(
            "INSERT INTO mokosh_auth.memberships
                (user_id, tenant_id, role, org_role, status)
             VALUES ($1, $2, $3, $4, 'active')",
        )
        .bind(accepting_user.0)
        .bind(row.tenant_id)
        .bind(accepting_global_role.as_str())
        .bind(org_role_parsed.as_str())
        .execute(&mut *tx)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                AuthError::Conflict("user is already a member of this tenant".into())
            }
            _ => db_err(e),
        })?;

        sqlx::query(
            "UPDATE mokosh_auth.org_invitations
             SET accepted_at = NOW(), accepted_by = $1
             WHERE id = $2",
        )
        .bind(accepting_user.0)
        .bind(row.id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

        let final_row: InvitationRow =
            sqlx::query_as(&format!("{SELECT_ORG_INVITE} WHERE id = $1"))
                .bind(row.id)
                .fetch_one(&mut *tx)
                .await
                .map_err(db_err)?;

        tx.commit().await.map_err(db_err)?;
        OrgInvitation::try_from(final_row)
    }
}
