//! `PortalRoleService`: CRUD for the `portal_roles` table (prompt 007).
//!
//! Every query filters explicitly on `tenant_id` in addition to the
//! table-level RLS policy (migration 139). The service runs on the
//! privileged migrator pool because RLS is fail-closed and the audit
//! row for a mutation lives in a table without an
//! `app.current_tenant` GUC of its own; the belt-and-braces WHERE
//! keeps cross-tenant reads impossible even if the GUC drifts.

use uuid::Uuid;

use crate::db::Database;
use crate::modules::audit::{audit_write, AuditAction, AuditCtx};
use crate::modules::auth::TenantId;
use crate::modules::contact_portal::capabilities::validate_capabilities;
use crate::utils::error::{AppError, AppResult};

use super::capability_labels;
use super::models::*;

#[derive(Clone)]
pub struct PortalRoleService {
    db: Database,
}

impl PortalRoleService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    pub async fn list_roles(&self, tenant_id: TenantId) -> AppResult<Vec<PortalRoleSummary>> {
        let rows: Vec<(Uuid, String, Vec<String>, bool)> = sqlx::query_as(
            "SELECT id, name, capabilities, is_builtin FROM portal_roles \
             WHERE tenant_id = $1 ORDER BY is_builtin DESC, name",
        )
        .bind(*tenant_id)
        .fetch_all(self.db.migrator_pool())
        .await?;
        Ok(rows
            .into_iter()
            .map(|(id, name, capabilities, is_builtin)| PortalRoleSummary {
                id,
                name,
                capabilities,
                is_builtin,
            })
            .collect())
    }

    pub async fn get_role(&self, tenant_id: TenantId, role_id: Uuid) -> AppResult<PortalRole> {
        let row: Option<(
            Uuid,
            Uuid,
            String,
            Vec<String>,
            bool,
            chrono::DateTime<chrono::Utc>,
            chrono::DateTime<chrono::Utc>,
        )> = sqlx::query_as(
            "SELECT id, tenant_id, name, capabilities, is_builtin, created_at, updated_at \
             FROM portal_roles WHERE tenant_id = $1 AND id = $2",
        )
        .bind(*tenant_id)
        .bind(role_id)
        .fetch_optional(self.db.migrator_pool())
        .await?;
        let (id, tid, name, capabilities, is_builtin, created_at, updated_at) =
            row.ok_or_else(|| AppError::NotFound("Portal role".to_string()))?;
        Ok(PortalRole {
            id,
            tenant_id: tid,
            name,
            capabilities,
            is_builtin,
            created_at,
            updated_at,
        })
    }

    pub async fn create_role(
        &self,
        tenant_id: TenantId,
        name: String,
        capabilities: Vec<String>,
        ctx: &AuditCtx,
    ) -> AppResult<PortalRole> {
        let name = name.trim().to_string();
        if name.is_empty() || name.chars().count() > 64 {
            return Err(AppError::BadRequest(
                "Role name must be between 1 and 64 characters".to_string(),
            ));
        }
        if let Err(bad) = validate_capabilities(&capabilities) {
            return Err(AppError::BadRequest(format!("Unknown capability: {bad}")));
        }

        // Case-insensitive uniqueness check + INSERT in one transaction
        // so a concurrent create loses the race on the 23505 backstop
        // instead of both landing.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let taken: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM portal_roles \
             WHERE tenant_id = $1 AND LOWER(name) = LOWER($2))",
        )
        .bind(*tenant_id)
        .bind(&name)
        .fetch_one(&mut *tx)
        .await?;
        if taken {
            return Err(AppError::Conflict(
                "A role with that name already exists".to_string(),
            ));
        }

        let role_id = Uuid::new_v4();
        if let Err(e) = sqlx::query(
            "INSERT INTO portal_roles (id, tenant_id, name, capabilities, is_builtin) \
             VALUES ($1, $2, $3, $4, FALSE)",
        )
        .bind(role_id)
        .bind(*tenant_id)
        .bind(&name)
        .bind(&capabilities)
        .execute(&mut *tx)
        .await
        {
            if e.as_database_error().and_then(|d| d.code()).as_deref() == Some("23505") {
                return Err(AppError::Conflict(
                    "A role with that name already exists".to_string(),
                ));
            }
            return Err(e.into());
        }

        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(r) FROM portal_roles r WHERE tenant_id = $1 AND id = $2",
        )
        .bind(*tenant_id)
        .bind(role_id)
        .fetch_optional(&mut *tx)
        .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Create,
            "portal_roles",
            Some(role_id),
            None,
            after,
        )
        .await?;
        tx.commit().await?;

        self.get_role(tenant_id, role_id).await
    }

    pub async fn update_role(
        &self,
        tenant_id: TenantId,
        role_id: Uuid,
        name: Option<String>,
        capabilities: Option<Vec<String>>,
        ctx: &AuditCtx,
    ) -> AppResult<PortalRole> {
        let existing = self.get_role(tenant_id, role_id).await?;

        if let Some(ref new_name) = name {
            let trimmed = new_name.trim();
            if trimmed.is_empty() || trimmed.chars().count() > 64 {
                return Err(AppError::BadRequest(
                    "Role name must be between 1 and 64 characters".to_string(),
                ));
            }
        }
        if let Some(ref caps) = capabilities {
            if caps.is_empty() {
                return Err(AppError::BadRequest(
                    "A role must carry at least one capability".to_string(),
                ));
            }
            if let Err(bad) = validate_capabilities(caps) {
                return Err(AppError::BadRequest(format!("Unknown capability: {bad}")));
            }
            if existing.is_builtin {
                return Err(AppError::BadRequest(
                    "Cannot modify capabilities of a built-in role".to_string(),
                ));
            }
        }

        let new_name = name.map(|n| n.trim().to_string());

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;

        if let Some(ref n) = new_name {
            let taken: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM portal_roles \
                 WHERE tenant_id = $1 AND id <> $2 AND LOWER(name) = LOWER($3))",
            )
            .bind(*tenant_id)
            .bind(role_id)
            .bind(n)
            .fetch_one(&mut *tx)
            .await?;
            if taken {
                return Err(AppError::Conflict(
                    "A role with that name already exists".to_string(),
                ));
            }
        }

        let before: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(r) FROM portal_roles r WHERE tenant_id = $1 AND id = $2",
        )
        .bind(*tenant_id)
        .bind(role_id)
        .fetch_optional(&mut *tx)
        .await?;

        if let Some(ref n) = new_name {
            if let Err(e) = sqlx::query(
                "UPDATE portal_roles SET name = $3, updated_at = NOW() \
                 WHERE tenant_id = $1 AND id = $2",
            )
            .bind(*tenant_id)
            .bind(role_id)
            .bind(n)
            .execute(&mut *tx)
            .await
            {
                if e.as_database_error().and_then(|d| d.code()).as_deref() == Some("23505") {
                    return Err(AppError::Conflict(
                        "A role with that name already exists".to_string(),
                    ));
                }
                return Err(e.into());
            }
        }
        if let Some(ref caps) = capabilities {
            sqlx::query(
                "UPDATE portal_roles SET capabilities = $3, updated_at = NOW() \
                 WHERE tenant_id = $1 AND id = $2",
            )
            .bind(*tenant_id)
            .bind(role_id)
            .bind(caps)
            .execute(&mut *tx)
            .await?;
        }

        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(r) FROM portal_roles r WHERE tenant_id = $1 AND id = $2",
        )
        .bind(*tenant_id)
        .bind(role_id)
        .fetch_optional(&mut *tx)
        .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Update,
            "portal_roles",
            Some(role_id),
            before,
            after,
        )
        .await?;
        tx.commit().await?;

        self.get_role(tenant_id, role_id).await
    }

    pub async fn delete_role(
        &self,
        tenant_id: TenantId,
        role_id: Uuid,
        ctx: &AuditCtx,
    ) -> AppResult<()> {
        let existing = self.get_role(tenant_id, role_id).await?;
        if existing.is_builtin {
            return Err(AppError::BadRequest(
                "Built-in roles cannot be deleted".to_string(),
            ));
        }

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let assignment_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM contact_role_assignments \
             WHERE tenant_id = $1 AND role_id = $2",
        )
        .bind(*tenant_id)
        .bind(role_id)
        .fetch_one(&mut *tx)
        .await?;
        if assignment_count > 0 {
            return Err(AppError::Conflict(format!(
                "{assignment_count} contacts hold this role; remove those assignments first"
            )));
        }

        let before: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(r) FROM portal_roles r WHERE tenant_id = $1 AND id = $2",
        )
        .bind(*tenant_id)
        .bind(role_id)
        .fetch_optional(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM portal_roles WHERE tenant_id = $1 AND id = $2")
            .bind(*tenant_id)
            .bind(role_id)
            .execute(&mut *tx)
            .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Delete,
            "portal_roles",
            Some(role_id),
            before,
            None,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub fn capability_labels(&self) -> ListCapabilitiesResponse {
        ListCapabilitiesResponse {
            capabilities: capability_labels::descriptors(),
        }
    }

    /// mokosh-contact-login prompt 008: DB-load the effective capability set
    /// for a portal contact. Shared shape with
    /// [`crate::modules::auth::caller_context::load_contact_capabilities`];
    /// this thin wrapper lets the service layer reach for a
    /// `PortalRoleService` handle without dragging `Database` around
    /// separately. Both call sites resolve capabilities from
    /// `portal_roles` per request (fresh reads, no JWT caps trust) so a
    /// revoke lands on the very next request.
    pub async fn load_contact_capabilities(
        &self,
        tenant_id: TenantId,
        contact_id: Uuid,
    ) -> AppResult<Vec<String>> {
        crate::modules::auth::caller_context::load_contact_capabilities(
            &self.db, *tenant_id, contact_id,
        )
        .await
    }
}
