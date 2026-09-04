//! `PortalRoleService`: CRUD for the `portal_roles` table (prompt 007).
//!
//! Every query filters explicitly on `tenant_id` in addition to the
//! table-level RLS policy (migration 139). The service runs on the
//! privileged migrator pool because RLS is fail-closed and the audit
//! row for a mutation lives in a table without an
//! `app.current_tenant` GUC of its own; the belt-and-braces WHERE
//! keeps cross-tenant reads impossible even if the GUC drifts.
//!
//! PMS-929 (prompt 012): a portal role can now be tenant-wide
//! (`company_id IS NULL`, existing shape) or scoped to a single Company
//! (`company_id = <uuid>`). The list surface takes `Option<Uuid>`:
//! `None` returns tenant-wide only (Settings > Contact Roles view), and
//! `Some(cid)` returns the union of tenant-wide plus that Company's
//! scoped roles (Company detail page + the ContactPortalCard picker).
//! Uniqueness is enforced by the two partial indexes migration 148
//! carries, so a same-name tenant-wide and a same-name Company-scoped
//! role coexist and each Company independently owns its own name-space.

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

    /// mokosh-contact-login prompt 012 (PMS-929): list the portal roles
    /// visible to a given caller scope. `company_id = None` returns
    /// tenant-wide roles only (the Settings > Contact Roles view);
    /// `company_id = Some(cid)` returns the union of tenant-wide roles
    /// plus the Company-scoped roles owned by that Company (the Company
    /// detail page + the ContactPortalCard picker union).
    ///
    /// Ordering: built-ins first (they are always tenant-wide), then
    /// tenant-wide customs, then Company-scoped rows, name-alphabetical
    /// inside each band. The `company_id NULLS FIRST` clause is a no-op
    /// when `company_id = None` but keeps the shape symmetrical for the
    /// Some branch.
    pub async fn list_roles(
        &self,
        tenant_id: TenantId,
        company_id: Option<Uuid>,
    ) -> AppResult<Vec<PortalRoleSummary>> {
        // MAPPS-635 E: mirror the LATERAL subquery that `contacts`
        // service uses so this alternate listing path (the
        // `portal_role_routes` at `/api/v1/portal-roles`) also carries
        // the per-role contacts_count for the Settings > Contact
        // Roles table.
        // Merge cleanup: box the large variant in a follow-up (out of scope for the route-overlap fix)
        #[allow(clippy::type_complexity)]
        let rows: Vec<(Uuid, String, Vec<String>, bool, Option<Uuid>, i64)> = match company_id {
            None => {
                sqlx::query_as(
                    "SELECT pr.id, pr.name, pr.capabilities, pr.is_builtin, pr.company_id, \
                            COALESCE((SELECT COUNT(*) FROM contact_role_assignments cra \
                                      WHERE cra.tenant_id = pr.tenant_id AND cra.role_id = pr.id), 0) \
                     FROM portal_roles pr \
                     WHERE pr.tenant_id = $1 AND pr.company_id IS NULL \
                     ORDER BY pr.is_builtin DESC, pr.name",
                )
                .bind(*tenant_id)
                .fetch_all(self.db.migrator_pool())
                .await?
            }
            Some(cid) => {
                sqlx::query_as(
                    "SELECT pr.id, pr.name, pr.capabilities, pr.is_builtin, pr.company_id, \
                            COALESCE((SELECT COUNT(*) FROM contact_role_assignments cra \
                                      WHERE cra.tenant_id = pr.tenant_id AND cra.role_id = pr.id), 0) \
                     FROM portal_roles pr \
                     WHERE pr.tenant_id = $1 AND (pr.company_id IS NULL OR pr.company_id = $2) \
                     ORDER BY pr.is_builtin DESC, pr.company_id NULLS FIRST, pr.name",
                )
                .bind(*tenant_id)
                .bind(cid)
                .fetch_all(self.db.migrator_pool())
                .await?
            }
        };
        Ok(rows
            .into_iter()
            .map(
                |(id, name, capabilities, is_builtin, company_id, contacts_count)| {
                    PortalRoleSummary {
                        id,
                        name,
                        capabilities,
                        is_builtin,
                        company_id,
                        contacts_count,
                    }
                },
            )
            .collect())
    }

    pub async fn get_role(&self, tenant_id: TenantId, role_id: Uuid) -> AppResult<PortalRole> {
        // Merge cleanup: box the large variant in a follow-up (out of scope for the route-overlap fix)
        #[allow(clippy::type_complexity)]
        let row: Option<(
            Uuid,
            Uuid,
            Option<Uuid>,
            String,
            Vec<String>,
            bool,
            chrono::DateTime<chrono::Utc>,
            chrono::DateTime<chrono::Utc>,
        )> = sqlx::query_as(
            "SELECT id, tenant_id, company_id, name, capabilities, is_builtin, created_at, updated_at \
             FROM portal_roles WHERE tenant_id = $1 AND id = $2",
        )
        .bind(*tenant_id)
        .bind(role_id)
        .fetch_optional(self.db.migrator_pool())
        .await?;
        let (id, tid, company_id, name, capabilities, is_builtin, created_at, updated_at) =
            row.ok_or_else(|| AppError::NotFound("Portal role".to_string()))?;
        Ok(PortalRole {
            id,
            tenant_id: tid,
            company_id,
            name,
            capabilities,
            is_builtin,
            created_at,
            updated_at,
        })
    }

    /// mokosh-contact-login prompt 012 (PMS-929): create a portal role.
    /// `company_id = None` mints a tenant-wide role (Settings > Contact
    /// Roles surface, existing shape); `company_id = Some(cid)` mints a
    /// role scoped to that Company (Company detail page). A scoped
    /// create verifies the Company belongs to this tenant first so a
    /// foreign or fabricated id returns 404 rather than 500 on the FK
    /// insert. Uniqueness collision (case-insensitive, within the same
    /// scope) surfaces as 409 with a scope-agnostic message so the
    /// caller cannot infer whether a same-name tenant-wide role exists.
    pub async fn create_role(
        &self,
        tenant_id: TenantId,
        company_id: Option<Uuid>,
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

        // Company-scoped: verify the Company belongs to this tenant
        // BEFORE opening the tenant-bound tx so a foreign or fabricated
        // company_id returns a clear 404 instead of a FK 500. Read runs
        // on the migrator pool with an explicit tenant filter (belt +
        // braces vs the fail-closed RLS policy).
        if let Some(cid) = company_id {
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM companies WHERE id = $1 AND tenant_id = $2)",
            )
            .bind(cid)
            .bind(*tenant_id)
            .fetch_one(self.db.migrator_pool())
            .await?;
            if !exists {
                return Err(AppError::NotFound("Company".to_string()));
            }
        }

        // Case-insensitive uniqueness check + INSERT in one transaction
        // so a concurrent create loses the race on the 23505 backstop
        // instead of both landing. Query shape matches the pair of
        // partial indexes migration 148 carries: a tenant-wide check
        // when company_id IS NULL, a per-Company check otherwise.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let taken: bool = match company_id {
            None => {
                sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM portal_roles \
                 WHERE tenant_id = $1 AND company_id IS NULL \
                 AND LOWER(name) = LOWER($2))",
                )
                .bind(*tenant_id)
                .bind(&name)
                .fetch_one(&mut *tx)
                .await?
            }
            Some(cid) => {
                sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM portal_roles \
                 WHERE tenant_id = $1 AND company_id = $2 \
                 AND LOWER(name) = LOWER($3))",
                )
                .bind(*tenant_id)
                .bind(cid)
                .bind(&name)
                .fetch_one(&mut *tx)
                .await?
            }
        };
        if taken {
            return Err(AppError::Conflict(
                "A role with that name already exists in this scope".to_string(),
            ));
        }

        let role_id = Uuid::new_v4();
        if let Err(e) = sqlx::query(
            "INSERT INTO portal_roles (id, tenant_id, company_id, name, capabilities, is_builtin) \
             VALUES ($1, $2, $3, $4, $5, FALSE)",
        )
        .bind(role_id)
        .bind(*tenant_id)
        .bind(company_id)
        .bind(&name)
        .bind(&capabilities)
        .execute(&mut *tx)
        .await
        {
            if e.as_database_error().and_then(|d| d.code()).as_deref() == Some("23505") {
                return Err(AppError::Conflict(
                    "A role with that name already exists in this scope".to_string(),
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

    /// mokosh-contact-login prompt 012 (PMS-929): update a portal role.
    /// Never touches `company_id` (scope is immutable; recreate to
    /// switch scope). A request body carrying `company_id` at the DTO
    /// layer is silently dropped there; this method never accepts a
    /// scope input, so a defensive caller reaching for it cannot rewire
    /// scope through the service either.
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
            // Scope-aware uniqueness probe: a rename inside the same
            // scope collides against sibling rows in the same scope
            // only. `existing.company_id` determines which partial
            // index the rename lands in.
            let taken: bool = match existing.company_id {
                None => {
                    sqlx::query_scalar(
                        "SELECT EXISTS(SELECT 1 FROM portal_roles \
                     WHERE tenant_id = $1 AND id <> $2 AND company_id IS NULL \
                     AND LOWER(name) = LOWER($3))",
                    )
                    .bind(*tenant_id)
                    .bind(role_id)
                    .bind(n)
                    .fetch_one(&mut *tx)
                    .await?
                }
                Some(cid) => {
                    sqlx::query_scalar(
                        "SELECT EXISTS(SELECT 1 FROM portal_roles \
                     WHERE tenant_id = $1 AND id <> $2 AND company_id = $3 \
                     AND LOWER(name) = LOWER($4))",
                    )
                    .bind(*tenant_id)
                    .bind(role_id)
                    .bind(cid)
                    .bind(n)
                    .fetch_one(&mut *tx)
                    .await?
                }
            };
            if taken {
                return Err(AppError::Conflict(
                    "A role with that name already exists in this scope".to_string(),
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
                        "A role with that name already exists in this scope".to_string(),
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
