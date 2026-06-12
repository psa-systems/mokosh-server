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
    /// Base URL the invitee follows to accept (the SPA origin). When set, a
    /// `POST /invitations` enqueues an email notification with this link
    /// (PMS-246); when `None` (tests / no SPA configured) no email is sent.
    app_url: Option<String>,
}

impl InvitationsService {
    pub fn new(db: Database) -> Self {
        Self { db, app_url: None }
    }

    /// Set the accept-link base (the SPA origin) so created invites email the
    /// invitee. Acceptance is login-driven: the link points at the Mokosh login,
    /// and the PMS-244 resolution places the invitee on their next sign-in.
    pub fn with_app_url(mut self, app_url: String) -> Self {
        self.app_url = Some(app_url);
        self
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

        // PMS-246: email the invitee. Enqueue a `notifications` email row in the
        // same transaction; the dispatcher worker (with the SMTP mailer) drains
        // it - same path used for password-reset / welcome mail. Acceptance is
        // login-driven, so the link is just the Mokosh login (PMS-244). Skipped
        // when no SPA URL is configured (tests).
        if let Some(app_url) = self.app_url.as_deref() {
            let tenant_name: String = sqlx::query_scalar("SELECT name FROM tenants WHERE id = $1")
                .bind(tenant_id)
                .fetch_one(&mut *tx)
                .await?;
            let subject = format!("You have been invited to {tenant_name} on Mokosh");
            let body = format!(
                "You have been invited to join {tenant_name} on Mokosh as a {role}.\n\n\
                 Sign in to accept the invitation:\n{app_url}\n\n\
                 The invitation expires in {ttl} days. If you did not expect this, you can ignore this email.",
                role = request.role,
                ttl = INVITE_TTL_DAYS,
            );
            sqlx::query(
                "INSERT INTO notifications (tenant_id, channel_type, recipient, subject, body)
                 VALUES ($1, 'email', $2, $3, $4)",
            )
            .bind(tenant_id)
            .bind(&email)
            .bind(&subject)
            .bind(&body)
            .execute(&mut *tx)
            .await?;
        }

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

    /// The newest live (pending, unexpired) invite for `email`, across tenants.
    /// The login path uses this to place an invited user (PMS-244). Most-recent
    /// wins if an email has several pending invites.
    pub async fn newest_pending_for(&self, email: &str) -> AppResult<Option<PendingInvite>> {
        let email = email.trim().to_ascii_lowercase();
        Ok(sqlx::query_as::<_, PendingInvite>(
            r#"SELECT id, tenant_id, role
               FROM tenant_invitations
               WHERE lower(email) = $1 AND status = 'pending' AND expires_at > NOW()
               ORDER BY created_at DESC
               LIMIT 1"#,
        )
        .bind(&email)
        .fetch_optional(self.db.pool())
        .await?)
    }

    /// Mark an invite accepted by `accepted_by`. Best-effort: a no-op if it is
    /// no longer pending (it was revoked or accepted in a concurrent login).
    pub async fn accept(&self, id: Uuid, accepted_by: Uuid) -> AppResult<()> {
        sqlx::query(
            "UPDATE tenant_invitations
             SET status = 'accepted', accepted_at = NOW(), accepted_by = $2, updated_at = NOW()
             WHERE id = $1 AND status = 'pending'",
        )
        .bind(id)
        .bind(accepted_by)
        .execute(self.db.pool())
        .await?;
        Ok(())
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
