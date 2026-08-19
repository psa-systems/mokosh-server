//! Teams service (PMS-791 / MAPPS-461).
//!
//! Team CRUD + membership on top of the pre-existing `teams` and
//! `team_members` tables (migration 003_auth.sql, unused until this
//! ticket). Migrations 126 + 127 add the case-insensitive name uniqueness
//! index and the `updated_at` column + trigger.
//!
//! Security-critical checks — every one has a named test in
//! `tests/teams.rs`:
//!
//! - Cross-tenant `user_id` in `add_member` rejected (F1).
//! - Cross-tenant `manager_id` in create / update rejected (F2).
//! - `soft_delete_team` is soft only; hard delete would FK-violate on
//!   `tickets.team_id` (NO ACTION) per the cascade audit in
//!   docs/mokosh-orgs/01-data-model.md.
//! - `team_members.role = 'leader'` is a display / notification hint and
//!   grants NO additional authorization (F4). This is enforced by the
//!   route layer: every write is `RequireAdmin`, never `RequireAuth +
//!   is-leader`.
//! - `list_members` filters `WHERE users.deleted_at IS NULL` so
//!   soft-deleted user tombstones do not leak (F13).
//! - Every write calls `audit_write` in the same transaction (F10).
//! - `update_team` uses a dynamic UPDATE with bind parameters only, never
//!   string concatenation, to close the SQL-injection surface (F6).

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::db::Database;
use crate::modules::audit::{audit_write, AuditAction, AuditCtx};
use crate::modules::auth::TenantId;
use crate::utils::error::{AppError, AppResult};

use super::models::*;

/// `^#[0-9A-Fa-f]{6}$` — enforced at the service layer rather than as a
/// `validator` regex derive so mokosh-types does not need a `regex`
/// dependency (see security review F5).
fn validate_hex_color(color: &str) -> AppResult<()> {
    if color.len() != 7 {
        return Err(AppError::validation_field(
            "color",
            "must be a 7-character hex color like #6366F1",
        ));
    }
    let bytes = color.as_bytes();
    if bytes[0] != b'#' {
        return Err(AppError::validation_field(
            "color",
            "must start with '#' (e.g. #6366F1)",
        ));
    }
    if !bytes[1..].iter().all(|b| b.is_ascii_hexdigit()) {
        return Err(AppError::validation_field(
            "color",
            "must be hex digits after the '#' (e.g. #6366F1)",
        ));
    }
    Ok(())
}

/// `role` on `team_members` is `"leader"` or `"member"`. Anything else is
/// a 400 with a `field: "role"` hint.
fn validate_team_member_role(role: &str) -> AppResult<()> {
    if role == "leader" || role == "member" {
        Ok(())
    } else {
        Err(AppError::validation_field(
            "role",
            "must be 'leader' or 'member'",
        ))
    }
}

/// Filters for [`TeamsService::list_teams`]. `include_inactive = true` +
/// `only_inactive = false` returns everything.
#[derive(Debug, Clone, Copy, Default)]
pub struct TeamListFilters {
    pub include_inactive: bool,
    pub only_inactive: bool,
    pub manager_id: Option<Uuid>,
}

#[derive(Clone)]
pub struct TeamsService {
    db: Database,
}

impl TeamsService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    // ------------------------------------------------------------------
    // WRITE
    // ------------------------------------------------------------------

    /// Create a team owned by `tenant_id`.
    ///
    /// Guards:
    /// - `color` (if present) matches `^#[0-9A-Fa-f]{6}$` (F5).
    /// - `manager_id` (if present) is a user in the SAME tenant (F2).
    /// - `name` does not collide with another ACTIVE team's name
    ///   (case-insensitive) within the tenant (409). The DB unique index
    ///   `teams_name_ci_unique_idx` from migration 126 is the ultimate
    ///   guard; this probe surfaces a nicer error.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_team(
        &self,
        tenant_id: TenantId,
        request: &CreateTeamRequest,
        ctx: &AuditCtx,
    ) -> AppResult<Team> {
        if let Some(color) = request.color.as_deref() {
            validate_hex_color(color)?;
        }
        if let Some(mgr_id) = request.manager_id {
            self.assert_user_in_tenant(*tenant_id, mgr_id, "manager_id").await?;
        }
        self.assert_name_unique(*tenant_id, &request.name, None).await?;

        let team_id = Uuid::new_v4();
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            r#"
            INSERT INTO teams (id, tenant_id, name, description, manager_id, color, is_active)
            VALUES ($1, $2, $3, $4, $5, $6, TRUE)
            "#,
        )
        .bind(team_id)
        .bind(*tenant_id)
        .bind(&request.name)
        .bind(request.description.as_deref())
        .bind(request.manager_id)
        .bind(request.color.as_deref())
        .execute(&mut *tx)
        .await?;

        let after: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT to_jsonb(t) FROM teams t WHERE id = $1")
                .bind(team_id)
                .fetch_optional(&mut *tx)
                .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Create,
            "teams",
            Some(team_id),
            None,
            after,
        )
        .await?;
        tx.commit().await?;

        self.get_team(tenant_id, team_id).await
    }

    /// Partial update. Every field optional; omitted fields unchanged.
    /// Uniqueness re-check on `name` scopes to `id != $team_id` so a
    /// self-rename with a case flip is idempotent, not a collision.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, team_id = %team_id))]
    pub async fn update_team(
        &self,
        tenant_id: TenantId,
        team_id: Uuid,
        request: &UpdateTeamRequest,
        ctx: &AuditCtx,
    ) -> AppResult<Team> {
        if let Some(color) = request.color.as_deref() {
            validate_hex_color(color)?;
        }
        if let Some(mgr_id) = request.manager_id {
            self.assert_user_in_tenant(*tenant_id, mgr_id, "manager_id").await?;
        }
        if let Some(new_name) = request.name.as_deref() {
            self.assert_name_unique(*tenant_id, new_name, Some(team_id))
                .await?;
        }

        // Dynamic UPDATE. `param_idx` starts at 3 because $1 = tenant_id
        // and $2 = team_id in the WHERE clause. Bind params only, never
        // string concatenation (F6 pin).
        let mut query = String::from("UPDATE teams SET updated_at = NOW()");
        let mut param_idx = 3;
        if request.name.is_some() {
            query.push_str(&format!(", name = ${}", param_idx));
            param_idx += 1;
        }
        if request.description.is_some() {
            query.push_str(&format!(", description = ${}", param_idx));
            param_idx += 1;
        }
        if request.manager_id.is_some() {
            query.push_str(&format!(", manager_id = ${}", param_idx));
            param_idx += 1;
        }
        if request.color.is_some() {
            query.push_str(&format!(", color = ${}", param_idx));
            param_idx += 1;
        }
        if request.is_active.is_some() {
            query.push_str(&format!(", is_active = ${}", param_idx));
            #[allow(unused_assignments)]
            {
                param_idx += 1;
            }
        }
        query.push_str(" WHERE tenant_id = $1 AND id = $2");

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let before: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM teams t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(*tenant_id)
        .bind(team_id)
        .fetch_optional(&mut *tx)
        .await?;
        if before.is_none() {
            return Err(AppError::NotFound("Team".to_string()));
        }

        let mut q = sqlx::query(&query).bind(*tenant_id).bind(team_id);
        if let Some(ref n) = request.name {
            q = q.bind(n);
        }
        if let Some(ref d) = request.description {
            q = q.bind(d);
        }
        if let Some(m) = request.manager_id {
            q = q.bind(m);
        }
        if let Some(ref c) = request.color {
            q = q.bind(c);
        }
        if let Some(a) = request.is_active {
            q = q.bind(a);
        }
        q.execute(&mut *tx).await?;

        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM teams t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(*tenant_id)
        .bind(team_id)
        .fetch_optional(&mut *tx)
        .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Update,
            "teams",
            Some(team_id),
            before,
            after,
        )
        .await?;
        tx.commit().await?;

        self.get_team(tenant_id, team_id).await
    }

    /// Soft delete: sets `is_active = false`. Hard delete would FK-violate
    /// on `tickets.team_id` / `appointments.team_id` (NO ACTION) so the
    /// service does not offer a hard-delete path at all.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, team_id = %team_id))]
    pub async fn soft_delete_team(
        &self,
        tenant_id: TenantId,
        team_id: Uuid,
        ctx: &AuditCtx,
    ) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let before: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM teams t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(*tenant_id)
        .bind(team_id)
        .fetch_optional(&mut *tx)
        .await?;
        if before.is_none() {
            return Err(AppError::NotFound("Team".to_string()));
        }

        sqlx::query(
            "UPDATE teams SET is_active = FALSE, updated_at = NOW() \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(*tenant_id)
        .bind(team_id)
        .execute(&mut *tx)
        .await?;

        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM teams t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(*tenant_id)
        .bind(team_id)
        .fetch_optional(&mut *tx)
        .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Update,
            "teams",
            Some(team_id),
            before,
            after,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // READ
    // ------------------------------------------------------------------

    /// Read one team from the caller's tenant. RLS + the explicit
    /// `tenant_id` predicate keep other tenants' teams unreachable.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, team_id = %team_id))]
    pub async fn get_team(&self, tenant_id: TenantId, team_id: Uuid) -> AppResult<Team> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: Option<TeamRow> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, name, description, manager_id, color,
                   is_active, created_at, updated_at
            FROM teams
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(*tenant_id)
        .bind(team_id)
        .fetch_optional(&mut *tx)
        .await?;
        row.map(Into::into)
            .ok_or_else(|| AppError::NotFound("Team".to_string()))
    }

    /// Team + members envelope for `?include=members`.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, team_id = %team_id))]
    pub async fn get_team_with_members(
        &self,
        tenant_id: TenantId,
        team_id: Uuid,
    ) -> AppResult<TeamWithMembers> {
        let team = self.get_team(tenant_id, team_id).await?;
        let members = self.list_members(tenant_id, team_id).await?;
        Ok(TeamWithMembers { team, members })
    }

    /// Enumerate teams in the tenant. Active-only by default; filters
    /// let the caller include or exclude the archived ones.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_teams(
        &self,
        tenant_id: TenantId,
        filters: TeamListFilters,
    ) -> AppResult<Vec<Team>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        // Compose the WHERE clause with bound parameters only.
        let mut query = String::from(
            "SELECT id, tenant_id, name, description, manager_id, color, \
                    is_active, created_at, updated_at \
             FROM teams WHERE tenant_id = $1",
        );
        let mut idx = 2;
        if filters.only_inactive {
            query.push_str(" AND is_active = FALSE");
        } else if !filters.include_inactive {
            query.push_str(" AND is_active = TRUE");
        }
        if filters.manager_id.is_some() {
            query.push_str(&format!(" AND manager_id = ${}", idx));
            idx += 1;
        }
        query.push_str(" ORDER BY name");
        let _ = idx;

        let mut q = sqlx::query_as::<_, TeamRow>(&query).bind(*tenant_id);
        if let Some(mgr) = filters.manager_id {
            q = q.bind(mgr);
        }
        let rows = q.fetch_all(&mut *tx).await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Member roster for a team, joined to `users` so the client gets
    /// human-readable fields in one round-trip. Soft-deleted users are
    /// filtered out (F13).
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, team_id = %team_id))]
    pub async fn list_members(
        &self,
        tenant_id: TenantId,
        team_id: Uuid,
    ) -> AppResult<Vec<TeamMemberWithUser>> {
        // Ensure the team exists in this tenant before returning members;
        // otherwise a caller could probe team_id -> member_count.
        let team_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM teams WHERE tenant_id = $1 AND id = $2)",
        )
        .bind(*tenant_id)
        .bind(team_id)
        .fetch_one(self.db.pool())
        .await?;
        if !team_exists {
            return Err(AppError::NotFound("Team".to_string()));
        }

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows: Vec<TeamMemberJoinRow> = sqlx::query_as(
            r#"
            SELECT tm.user_id, u.email, u.first_name, u.last_name, u.avatar_url,
                   tm.role, tm.joined_at
            FROM team_members tm
            JOIN users u ON u.id = tm.user_id AND u.tenant_id = tm.tenant_id
            WHERE tm.tenant_id = $1 AND tm.team_id = $2
              AND u.deleted_at IS NULL
            ORDER BY u.last_name, u.first_name
            "#,
        )
        .bind(*tenant_id)
        .bind(team_id)
        .fetch_all(&mut *tx)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// The teams the given user belongs to inside this tenant. Feeds the
    /// SPA's "My teams" filter (phase 4) and the current-user session's
    /// team snapshot on session bootstrap.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, user_id = %user_id))]
    pub async fn list_teams_for_user(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
    ) -> AppResult<Vec<Team>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows: Vec<TeamRow> = sqlx::query_as(
            r#"
            SELECT t.id, t.tenant_id, t.name, t.description, t.manager_id,
                   t.color, t.is_active, t.created_at, t.updated_at
            FROM teams t
            JOIN team_members tm
              ON tm.team_id = t.id AND tm.tenant_id = t.tenant_id
            WHERE t.tenant_id = $1 AND tm.user_id = $2 AND t.is_active = TRUE
            ORDER BY t.name
            "#,
        )
        .bind(*tenant_id)
        .bind(user_id)
        .fetch_all(&mut *tx)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    // ------------------------------------------------------------------
    // MEMBERS
    // ------------------------------------------------------------------

    /// Add a member. `user_id` must be a user in the SAME tenant (F1).
    /// PK on `(tenant_id, team_id, user_id)` guarantees uniqueness; a
    /// concurrent duplicate INSERT surfaces as 409 via `map_pg_error`.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, team_id = %team_id))]
    pub async fn add_member(
        &self,
        tenant_id: TenantId,
        team_id: Uuid,
        request: &AddTeamMemberRequest,
        ctx: &AuditCtx,
    ) -> AppResult<TeamMember> {
        let role = request.role.as_deref().unwrap_or("member");
        validate_team_member_role(role)?;
        self.assert_user_in_tenant(*tenant_id, request.user_id, "user_id")
            .await?;

        // Team-in-tenant check surfaces a nicer 404 than the FK violation.
        let team_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM teams WHERE tenant_id = $1 AND id = $2)",
        )
        .bind(*tenant_id)
        .bind(team_id)
        .fetch_one(self.db.pool())
        .await?;
        if !team_exists {
            return Err(AppError::NotFound("Team".to_string()));
        }

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let insert = sqlx::query(
            r#"
            INSERT INTO team_members (tenant_id, team_id, user_id, role, joined_at)
            VALUES ($1, $2, $3, $4, NOW())
            "#,
        )
        .bind(*tenant_id)
        .bind(team_id)
        .bind(request.user_id)
        .bind(role)
        .execute(&mut *tx)
        .await;

        match insert {
            Ok(_) => {}
            Err(sqlx::Error::Database(dbe)) if dbe.code().as_deref() == Some("23505") => {
                return Err(AppError::conflict("User is already a member of this team"));
            }
            Err(e) => return Err(e.into()),
        }

        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(tm) FROM team_members tm \
             WHERE tenant_id = $1 AND team_id = $2 AND user_id = $3",
        )
        .bind(*tenant_id)
        .bind(team_id)
        .bind(request.user_id)
        .fetch_optional(&mut *tx)
        .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Create,
            "team_members",
            Some(request.user_id),
            None,
            after,
        )
        .await?;
        tx.commit().await?;

        Ok(TeamMember {
            tenant_id: *tenant_id,
            team_id,
            user_id: request.user_id,
            role: role.to_string(),
            joined_at: Utc::now(),
        })
    }

    /// Change a member's role. 404 if the membership does not exist.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, team_id = %team_id, user_id = %user_id))]
    pub async fn update_member_role(
        &self,
        tenant_id: TenantId,
        team_id: Uuid,
        user_id: Uuid,
        request: &UpdateTeamMemberRoleRequest,
        ctx: &AuditCtx,
    ) -> AppResult<TeamMember> {
        validate_team_member_role(&request.role)?;

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let before: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(tm) FROM team_members tm \
             WHERE tenant_id = $1 AND team_id = $2 AND user_id = $3",
        )
        .bind(*tenant_id)
        .bind(team_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;
        if before.is_none() {
            return Err(AppError::NotFound("Team member".to_string()));
        }

        sqlx::query(
            "UPDATE team_members SET role = $4 \
             WHERE tenant_id = $1 AND team_id = $2 AND user_id = $3",
        )
        .bind(*tenant_id)
        .bind(team_id)
        .bind(user_id)
        .bind(&request.role)
        .execute(&mut *tx)
        .await?;

        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(tm) FROM team_members tm \
             WHERE tenant_id = $1 AND team_id = $2 AND user_id = $3",
        )
        .bind(*tenant_id)
        .bind(team_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Update,
            "team_members",
            Some(user_id),
            before,
            after,
        )
        .await?;
        tx.commit().await?;

        let row: TeamMemberRow = sqlx::query_as(
            "SELECT tenant_id, team_id, user_id, role, joined_at \
             FROM team_members WHERE tenant_id = $1 AND team_id = $2 AND user_id = $3",
        )
        .bind(*tenant_id)
        .bind(team_id)
        .bind(user_id)
        .fetch_one(self.db.pool())
        .await?;
        Ok(row.into())
    }

    /// Remove a member. Idempotent: no row is a no-op that returns Ok, so
    /// the DELETE endpoint stays 204 even on a stale second click.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, team_id = %team_id, user_id = %user_id))]
    pub async fn remove_member(
        &self,
        tenant_id: TenantId,
        team_id: Uuid,
        user_id: Uuid,
        ctx: &AuditCtx,
    ) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let before: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(tm) FROM team_members tm \
             WHERE tenant_id = $1 AND team_id = $2 AND user_id = $3",
        )
        .bind(*tenant_id)
        .bind(team_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;
        // Idempotent short-circuit: no membership = nothing to do.
        if before.is_none() {
            tx.commit().await?;
            return Ok(());
        }

        sqlx::query(
            "DELETE FROM team_members \
             WHERE tenant_id = $1 AND team_id = $2 AND user_id = $3",
        )
        .bind(*tenant_id)
        .bind(team_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Delete,
            "team_members",
            Some(user_id),
            before,
            None,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// F1 / F2: reject a `user_id` (or `manager_id`) that does not belong
    /// to the current tenant. Runs on the migrator pool because the
    /// caller is not yet placed in the target user's tenant (they are
    /// resolving an incoming ID, which by definition is not yet checked).
    /// Error message is deliberately generic so an attacker cannot
    /// enumerate user existence across tenants.
    async fn assert_user_in_tenant(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        field: &'static str,
    ) -> AppResult<()> {
        let same_tenant: Option<bool> = sqlx::query_scalar(
            "SELECT (tenant_id = $2) FROM users WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_optional(self.db.migrator_pool())
        .await?;
        match same_tenant {
            Some(true) => Ok(()),
            _ => Err(AppError::validation_field(
                field,
                "user not found in this tenant",
            )),
        }
    }

    /// Case-insensitive name uniqueness probe scoped to ACTIVE teams
    /// (mirrors the partial index in migration 126). Pass `Some(id)` on
    /// the update path so a self-rename with a case flip does not
    /// self-collide.
    async fn assert_name_unique(
        &self,
        tenant_id: Uuid,
        name: &str,
        exclude_id: Option<Uuid>,
    ) -> AppResult<()> {
        let collision: bool = match exclude_id {
            Some(id) => {
                sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM teams \
                     WHERE tenant_id = $1 AND LOWER(name) = LOWER($2) \
                     AND is_active AND id != $3)",
                )
                .bind(tenant_id)
                .bind(name)
                .bind(id)
                .fetch_one(self.db.migrator_pool())
                .await?
            }
            None => {
                sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM teams \
                     WHERE tenant_id = $1 AND LOWER(name) = LOWER($2) AND is_active)",
                )
                .bind(tenant_id)
                .bind(name)
                .fetch_one(self.db.migrator_pool())
                .await?
            }
        };
        if collision {
            Err(AppError::conflict("A team with this name already exists"))
        } else {
            Ok(())
        }
    }
}

// ----------------------------------------------------------------------
// sqlx row shims (thin structs so the SELECTs pick up the columns without
// needing derives on the public DTO types)
// ----------------------------------------------------------------------

#[derive(sqlx::FromRow)]
struct TeamRow {
    id: Uuid,
    tenant_id: Uuid,
    name: String,
    description: Option<String>,
    manager_id: Option<Uuid>,
    color: Option<String>,
    is_active: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<TeamRow> for Team {
    fn from(r: TeamRow) -> Self {
        Self {
            id: r.id,
            tenant_id: r.tenant_id,
            name: r.name,
            description: r.description,
            manager_id: r.manager_id,
            color: r.color,
            is_active: r.is_active,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct TeamMemberRow {
    tenant_id: Uuid,
    team_id: Uuid,
    user_id: Uuid,
    role: String,
    joined_at: DateTime<Utc>,
}

impl From<TeamMemberRow> for TeamMember {
    fn from(r: TeamMemberRow) -> Self {
        Self {
            tenant_id: r.tenant_id,
            team_id: r.team_id,
            user_id: r.user_id,
            role: r.role,
            joined_at: r.joined_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct TeamMemberJoinRow {
    user_id: Uuid,
    email: String,
    first_name: String,
    last_name: String,
    avatar_url: Option<String>,
    role: String,
    joined_at: DateTime<Utc>,
}

impl From<TeamMemberJoinRow> for TeamMemberWithUser {
    fn from(r: TeamMemberJoinRow) -> Self {
        Self {
            user_id: r.user_id,
            email: r.email,
            first_name: r.first_name,
            last_name: r.last_name,
            avatar_url: r.avatar_url,
            role: r.role,
            joined_at: r.joined_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_hex_color_accepts_seven_char_hex() {
        assert!(validate_hex_color("#6366F1").is_ok());
        assert!(validate_hex_color("#000000").is_ok());
        assert!(validate_hex_color("#ffffff").is_ok());
    }

    #[test]
    fn validate_hex_color_rejects_short_hex() {
        assert!(validate_hex_color("#f00").is_err());
    }

    #[test]
    fn validate_hex_color_rejects_missing_hash() {
        assert!(validate_hex_color("ff0000").is_err());
    }

    #[test]
    fn validate_hex_color_rejects_javascript_uri() {
        assert!(validate_hex_color("javascript:alert(1)").is_err());
    }

    #[test]
    fn validate_hex_color_rejects_eight_char_hex_with_alpha() {
        assert!(validate_hex_color("#ff0000ff").is_err());
    }

    #[test]
    fn validate_team_member_role_accepts_only_leader_or_member() {
        assert!(validate_team_member_role("leader").is_ok());
        assert!(validate_team_member_role("member").is_ok());
        assert!(validate_team_member_role("admin").is_err());
        assert!(validate_team_member_role("Leader").is_err());
        assert!(validate_team_member_role("").is_err());
    }
}
