//! Invitations service (PMS-244).

use chrono::{Duration, Utc};
use uuid::Uuid;

use crate::db::Database;
use crate::modules::auth::TenantId;
use crate::utils::error::{AppError, AppResult};
use crate::utils::pagination::PaginationParams;

use super::models::*;

/// How long a pending invite stays valid.
const INVITE_TTL_DAYS: i64 = 14;

#[derive(Clone)]
pub struct InvitationsService {
    db: Database,
}

impl InvitationsService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Create (or refresh) a pending invite for `email` into `tenant_id`.
    /// Re-inviting an email with a live invite updates its role/expiry rather
    /// than erroring (the partial unique index makes that an upsert). Sending
    /// the first invite from a `personal` tenant promotes it to an `org`.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create(
        &self,
        tenant_id: TenantId,
        invited_by: Uuid,
        request: &CreateInvitationRequest,
    ) -> AppResult<InvitationResponse> {
        if !INVITABLE_ROLES.contains(&request.role.as_str()) {
            return Err(AppError::BadRequest(format!(
                "role must be one of {}",
                INVITABLE_ROLES.join(", ")
            )));
        }
        let email = request.email.trim().to_ascii_lowercase();
        let expires_at = Utc::now() + Duration::days(INVITE_TTL_DAYS);

        let mut tx = self.db.pool().begin().await?;

        let invite = sqlx::query_as::<_, InvitationResponse>(
            r#"INSERT INTO tenant_invitations (tenant_id, email, role, invited_by, expires_at)
               VALUES ($1, $2, $3, $4, $5)
               ON CONFLICT (tenant_id, lower(email)) WHERE status = 'pending'
               DO UPDATE SET role = EXCLUDED.role,
                             invited_by = EXCLUDED.invited_by,
                             expires_at = EXCLUDED.expires_at,
                             updated_at = NOW()
               RETURNING id, email, role, status, invited_by, expires_at, created_at"#,
        )
        .bind(tenant_id)
        .bind(&email)
        .bind(&request.role)
        .bind(invited_by)
        .bind(expires_at)
        .fetch_one(&mut *tx)
        .await?;

        // A tenant that starts inviting people is no longer a one-person
        // personal tenant - promote it so it reads as an org everywhere.
        sqlx::query("UPDATE tenants SET kind = 'org', updated_at = NOW() WHERE id = $1 AND kind = 'personal'")
            .bind(tenant_id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(invite)
    }

    /// List the tenant's pending invites, newest first.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_pending(
        &self,
        tenant_id: TenantId,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<InvitationResponse>, u64)> {
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM tenant_invitations WHERE tenant_id = $1 AND status = 'pending'",
        )
        .bind(tenant_id)
        .fetch_one(self.db.pool())
        .await?;

        let rows = sqlx::query_as::<_, InvitationResponse>(
            r#"SELECT id, email, role, status, invited_by, expires_at, created_at
               FROM tenant_invitations
               WHERE tenant_id = $1 AND status = 'pending'
               ORDER BY created_at DESC
               LIMIT $2 OFFSET $3"#,
        )
        .bind(tenant_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(self.db.pool())
        .await?;

        Ok((rows, total as u64))
    }

    /// Revoke a pending invite. 404 if it does not exist in this tenant or is
    /// no longer pending.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn revoke(&self, tenant_id: TenantId, id: Uuid) -> AppResult<()> {
        let res = sqlx::query(
            "UPDATE tenant_invitations SET status = 'revoked', updated_at = NOW()
             WHERE id = $1 AND tenant_id = $2 AND status = 'pending'",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(self.db.pool())
        .await?;
        if res.rows_affected() == 0 {
            return Err(AppError::NotFound("Invitation".to_string()));
        }
        Ok(())
    }
}
