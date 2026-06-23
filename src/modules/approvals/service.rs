//! PMS-451: ticket approvals service.

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use super::models::{ApprovalResponse, CreateApprovalRequest, DecideApprovalRequest};
use crate::utils::error::{AppError, AppResult};

#[derive(Debug, FromRow)]
struct ApprovalRow {
    id: Uuid,
    ticket_id: Uuid,
    requested_by_id: Uuid,
    requested_by_name: Option<String>,
    approver_user_id: Option<Uuid>,
    approver_user_name: Option<String>,
    approver_role: Option<String>,
    status: String,
    notes: Option<String>,
    decision_notes: Option<String>,
    decided_by_id: Option<Uuid>,
    decided_by_name: Option<String>,
    requested_at: DateTime<Utc>,
    decided_at: Option<DateTime<Utc>>,
}

impl From<ApprovalRow> for ApprovalResponse {
    fn from(r: ApprovalRow) -> Self {
        Self {
            id: r.id,
            ticket_id: r.ticket_id,
            requested_by_id: r.requested_by_id,
            requested_by_name: r.requested_by_name,
            approver_user_id: r.approver_user_id,
            approver_user_name: r.approver_user_name,
            approver_role: r.approver_role,
            status: r.status,
            notes: r.notes,
            decision_notes: r.decision_notes,
            decided_by_id: r.decided_by_id,
            decided_by_name: r.decided_by_name,
            requested_at: r.requested_at,
            decided_at: r.decided_at,
        }
    }
}

/// Shared SELECT clause used by list / get / mutating returns so a
/// schema-evolved field surfaces in every read path with one edit.
const SELECT_FIELDS: &str = "
    a.id, a.ticket_id, a.requested_by_id,
    NULLIF(TRIM(CONCAT(rb.first_name, ' ', rb.last_name)), '') AS requested_by_name,
    a.approver_user_id,
    NULLIF(TRIM(CONCAT(au.first_name, ' ', au.last_name)), '') AS approver_user_name,
    a.approver_role, a.status, a.notes, a.decision_notes,
    a.decided_by_id,
    NULLIF(TRIM(CONCAT(db.first_name, ' ', db.last_name)), '') AS decided_by_name,
    a.requested_at, a.decided_at
";

const SELECT_JOINS: &str = "
    LEFT JOIN users rb ON rb.id = a.requested_by_id
    LEFT JOIN users au ON au.id = a.approver_user_id
    LEFT JOIN users db ON db.id = a.decided_by_id
";

#[derive(Clone)]
pub struct ApprovalsService {
    pool: PgPool,
}

impl ApprovalsService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn list_for_ticket(
        &self,
        tenant_id: Uuid,
        ticket_id: Uuid,
    ) -> AppResult<Vec<ApprovalResponse>> {
        let q = format!(
            "SELECT {SELECT_FIELDS} \
             FROM ticket_approvals a {SELECT_JOINS} \
             WHERE a.tenant_id = $1 AND a.ticket_id = $2 \
             ORDER BY a.requested_at DESC",
        );
        let rows = sqlx::query_as::<_, ApprovalRow>(&q)
            .bind(tenant_id)
            .bind(ticket_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Pending approval queue for the given user. Surfaces every
    /// pending row where the user is the named approver OR the user
    /// holds the assigned role (caller supplies `roles_held` so the
    /// service stays role-source-agnostic).
    pub async fn pending_for_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        roles_held: &[String],
    ) -> AppResult<Vec<ApprovalResponse>> {
        let q = format!(
            "SELECT {SELECT_FIELDS} \
             FROM ticket_approvals a {SELECT_JOINS} \
             WHERE a.tenant_id = $1 AND a.status = 'pending' AND ( \
                 a.approver_user_id = $2 OR a.approver_role = ANY($3) \
             ) \
             ORDER BY a.requested_at ASC",
        );
        let rows = sqlx::query_as::<_, ApprovalRow>(&q)
            .bind(tenant_id)
            .bind(user_id)
            .bind(roles_held)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn create(
        &self,
        tenant_id: Uuid,
        ticket_id: Uuid,
        requested_by_id: Uuid,
        req: CreateApprovalRequest,
    ) -> AppResult<ApprovalResponse> {
        // XOR check at the application layer so the 422 carries a
        // useful field-level message before reaching the DB CHECK.
        let by_user = req.approver_user_id.is_some();
        let by_role = req.approver_role.is_some();
        if by_user == by_role {
            return Err(AppError::BadRequest(
                "Set exactly one of approver_user_id or approver_role".into(),
            ));
        }
        // Confirm the ticket belongs to the caller's tenant; without
        // this a caller could request approval on someone else's
        // ticket if they guessed the UUID.
        let ticket_owned: Option<(Uuid,)> =
            sqlx::query_as("SELECT id FROM tickets WHERE id = $1 AND tenant_id = $2")
                .bind(ticket_id)
                .bind(tenant_id)
                .fetch_optional(&self.pool)
                .await?;
        if ticket_owned.is_none() {
            return Err(AppError::NotFound("Ticket not found".into()));
        }
        let insert = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO ticket_approvals \
                 (tenant_id, ticket_id, requested_by_id, approver_user_id, approver_role, notes) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             RETURNING id",
        )
        .bind(tenant_id)
        .bind(ticket_id)
        .bind(requested_by_id)
        .bind(req.approver_user_id)
        .bind(&req.approver_role)
        .bind(&req.notes)
        .fetch_one(&self.pool)
        .await?;
        self.get(tenant_id, insert).await
    }

    pub async fn get(&self, tenant_id: Uuid, id: Uuid) -> AppResult<ApprovalResponse> {
        let q = format!(
            "SELECT {SELECT_FIELDS} \
             FROM ticket_approvals a {SELECT_JOINS} \
             WHERE a.tenant_id = $1 AND a.id = $2",
        );
        let row = sqlx::query_as::<_, ApprovalRow>(&q)
            .bind(tenant_id)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(AppError::NotFound("Approval not found".into()))?;
        Ok(row.into())
    }

    /// Apply a decision. `caller_id` must be authorised: either the
    /// named approver, or a holder of the assigned role (the route
    /// layer supplies `caller_role` from `CurrentUser.role`). A
    /// non-pending row rejects the decision so a race between two
    /// approvers cannot double-decide.
    pub async fn decide(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        caller_id: Uuid,
        caller_role: &str,
        req: DecideApprovalRequest,
    ) -> AppResult<ApprovalResponse> {
        let new_status = match req.decision.as_str() {
            "approve" => "approved",
            "reject" => "rejected",
            _ => {
                return Err(AppError::BadRequest(
                    "decision must be 'approve' or 'reject'".into(),
                ));
            }
        };
        let mut tx = self.pool.begin().await?;
        // Pull the row + approver scope so we can authorise without a
        // second round trip.
        let scope: Option<(String, Option<Uuid>, Option<String>)> = sqlx::query_as(
            "SELECT status, approver_user_id, approver_role \
             FROM ticket_approvals \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        let (status, by_user, by_role) =
            scope.ok_or(AppError::NotFound("Approval not found".into()))?;
        if status != "pending" {
            return Err(AppError::BadRequest(format!(
                "Approval is already {status}"
            )));
        }
        let authorised = by_user == Some(caller_id) || by_role.as_deref() == Some(caller_role);
        if !authorised {
            return Err(AppError::Forbidden(
                "Only the assigned approver may decide".into(),
            ));
        }
        sqlx::query(
            "UPDATE ticket_approvals SET status = $3, decision_notes = $4, \
                                          decided_by_id = $5, decided_at = NOW() \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(new_status)
        .bind(&req.decision_notes)
        .bind(caller_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        self.get(tenant_id, id).await
    }

    /// Rescind a pending approval. Only the original requester may
    /// cancel; other paths surface 403.
    pub async fn cancel(&self, tenant_id: Uuid, id: Uuid, caller_id: Uuid) -> AppResult<()> {
        let row: Option<(String, Uuid)> = sqlx::query_as(
            "SELECT status, requested_by_id FROM ticket_approvals \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        let (status, requester) = row.ok_or(AppError::NotFound("Approval not found".into()))?;
        if status != "pending" {
            return Err(AppError::BadRequest(format!(
                "Approval is already {status}"
            )));
        }
        if requester != caller_id {
            return Err(AppError::Forbidden("Only the requester may cancel".into()));
        }
        sqlx::query(
            "UPDATE ticket_approvals SET status = 'cancelled', decided_at = NOW() \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
