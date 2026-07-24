//! PMS-451 phase 1 + PMS-470 phase 2: approvals service.
//!
//! Phase 1 shipped per-ticket sign-off; phase 2 widens the surface to
//! `(target, entity_id)` so change_requests / quotes / time_entries
//! share the same request / decide / cancel machinery. Existing
//! `list_for_ticket` / `create` (ticket-only) call sites stay
//! compile-compatible as thin wrappers over the generic
//! `(target, entity_id)` variants.

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use super::models::{
    ApprovalResponse, ApprovalTarget, CreateApprovalRequest, DecideApprovalRequest,
};
use crate::db::Database;
use crate::utils::error::{AppError, AppResult};

#[derive(Debug, FromRow)]
struct ApprovalRow {
    id: Uuid,
    target: String,
    entity_id: Uuid,
    ticket_id: Option<Uuid>,
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
            target: r.target,
            entity_id: r.entity_id,
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
    a.id, a.target, a.entity_id, a.ticket_id, a.requested_by_id,
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

/// PMS-683: every query runs inside `Database::begin_with_tenant`, which sets
/// the `app.current_tenant` GUC transaction-locally, so `ticket_approvals` and
/// `change_requests` are safe under the fail-closed `tenant_isolation` RLS
/// policy (migration 095).
#[derive(Clone)]
pub struct ApprovalsService {
    db: Database,
}

impl ApprovalsService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// PMS-470/PMS-683: expose the `Database` so the route layer can run its
    /// own tenant-scoped parent-existence checks (against `time_entries`,
    /// `change_requests`, `quotes`) through `begin_with_tenant`, keeping them
    /// GUC-safe now that those tables are RLS-enabled.
    pub fn db(&self) -> &Database {
        &self.db
    }

    /// PMS-470: list approvals for any `(target, entity_id)` parent.
    /// The legacy `list_for_ticket(ticket_id)` is a thin wrapper.
    pub async fn list_for_entity(
        &self,
        tenant_id: Uuid,
        target: ApprovalTarget,
        entity_id: Uuid,
    ) -> AppResult<Vec<ApprovalResponse>> {
        let q = format!(
            "SELECT {SELECT_FIELDS} \
             FROM ticket_approvals a {SELECT_JOINS} \
             WHERE a.tenant_id = $1 AND a.target = $2 AND a.entity_id = $3 \
             ORDER BY a.requested_at DESC",
        );
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows = sqlx::query_as::<_, ApprovalRow>(&q)
            .bind(tenant_id)
            .bind(target.as_str())
            .bind(entity_id)
            .fetch_all(&mut *tx)
            .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Pending approval queue for the given user. PMS-470 widens it
    /// to span every target; the SPA can filter client-side or via a
    /// future `?target=` query param.
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
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows = sqlx::query_as::<_, ApprovalRow>(&q)
            .bind(tenant_id)
            .bind(user_id)
            .bind(roles_held)
            .fetch_all(&mut *tx)
            .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// PMS-470: create an approval against any `(target, entity_id)`.
    /// The route layer enforces parent-entity existence in the
    /// caller's tenant before calling in - this service trusts the
    /// parent and only validates the approver XOR and writes the row.
    /// `legacy_ticket_id` is set ONLY when target is Ticket so the
    /// legacy `ticket_id` column stays populated for phase-1 reads;
    /// for non-ticket targets it lands NULL.
    pub async fn create_for_entity(
        &self,
        tenant_id: Uuid,
        target: ApprovalTarget,
        entity_id: Uuid,
        requested_by_id: Uuid,
        req: CreateApprovalRequest,
    ) -> AppResult<ApprovalResponse> {
        let by_user = req.approver_user_id.is_some();
        let by_role = req.approver_role.is_some();
        if by_user == by_role {
            return Err(AppError::BadRequest(
                "Set exactly one of approver_user_id or approver_role".into(),
            ));
        }
        let legacy_ticket_id: Option<Uuid> = match target {
            ApprovalTarget::Ticket => Some(entity_id),
            _ => None,
        };
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let insert = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO ticket_approvals \
                 (tenant_id, target, entity_id, ticket_id, requested_by_id, \
                  approver_user_id, approver_role, notes) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             RETURNING id",
        )
        .bind(tenant_id)
        .bind(target.as_str())
        .bind(entity_id)
        .bind(legacy_ticket_id)
        .bind(requested_by_id)
        .bind(req.approver_user_id)
        .bind(&req.approver_role)
        .bind(&req.notes)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        self.get(tenant_id, insert).await
    }

    pub async fn get(&self, tenant_id: Uuid, id: Uuid) -> AppResult<ApprovalResponse> {
        let q = format!(
            "SELECT {SELECT_FIELDS} \
             FROM ticket_approvals a {SELECT_JOINS} \
             WHERE a.tenant_id = $1 AND a.id = $2",
        );
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row = sqlx::query_as::<_, ApprovalRow>(&q)
            .bind(tenant_id)
            .bind(id)
            .fetch_optional(&mut *tx)
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
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
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
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: Option<(String, Uuid)> = sqlx::query_as(
            "SELECT status, requested_by_id FROM ticket_approvals \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
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
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    // ----------------------------------------------------------------
    // Phase-1 wrappers: keep the existing ticket-only signatures
    // compile-compatible so consumers that only know about tickets do
    // not have to rewrite. New code should call the polymorphic
    // `_for_entity` variants directly.
    // ----------------------------------------------------------------

    pub async fn list_for_ticket(
        &self,
        tenant_id: Uuid,
        ticket_id: Uuid,
    ) -> AppResult<Vec<ApprovalResponse>> {
        self.list_for_entity(tenant_id, ApprovalTarget::Ticket, ticket_id)
            .await
    }

    /// PMS-470: phase-1 ticket-only create wrapper. Confirms the
    /// ticket exists in the caller's tenant (mirrors the pre-phase-2
    /// guard) before delegating to the generic
    /// `create_for_entity(Ticket, ticket_id)`.
    pub async fn create(
        &self,
        tenant_id: Uuid,
        ticket_id: Uuid,
        requested_by_id: Uuid,
        req: CreateApprovalRequest,
    ) -> AppResult<ApprovalResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let ticket_owned: Option<(Uuid,)> =
            sqlx::query_as("SELECT id FROM tickets WHERE id = $1 AND tenant_id = $2")
                .bind(ticket_id)
                .bind(tenant_id)
                .fetch_optional(&mut *tx)
                .await?;
        drop(tx);
        if ticket_owned.is_none() {
            return Err(AppError::NotFound("Ticket not found".into()));
        }
        self.create_for_entity(
            tenant_id,
            ApprovalTarget::Ticket,
            ticket_id,
            requested_by_id,
            req,
        )
        .await
    }
}
