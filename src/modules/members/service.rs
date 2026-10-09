//! Members list service: the merge of native `users` rows and cross-account
//! grantees from `mokosh_bunyip_grants`, batched and paginated server-side.
//!
//! A placed grantee shows up twice in the raw data (one `users` row from
//! BUNYIP-674 JIT placement, one grant row) and is collapsed to one
//! `MemberRow::User` with `placed_by_grant_id = Some(_)` so the SPA renders
//! "Guest" beside the name without a second lookup. A grant with no matching
//! users row stays an `UnplacedGuest` ("awaiting first sign-in"). Both kinds
//! are sorted together by (last_name, first_name, email) and paginated as one
//! set.
//!
//! The design (MAPPS-877) sketches a SaaS fan-out to a bunyip directory that
//! returns the authoritative grant list; this phase 1 implements the
//! standalone-mode shape only, reading `mokosh_bunyip_grants` directly, which
//! the design's "Standalone mode" paragraph explicitly allows: "reads
//! directly from `mokosh_bunyip_grants` in this tenant instead of calling
//! bunyip; still sets `bunyip_reachable = true` because it never left the
//! process." Future phases wire the SaaS fan-out when the bunyip-side
//! directory lands.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use serde::Deserialize;
use sqlx::{QueryBuilder, Row};
use uuid::Uuid;
use validator::Validate;

use crate::db::Database;
use crate::modules::auth::TenantId;
use crate::utils::error::{AppError, AppResult};
use crate::utils::pagination::PaginationParams;

use mokosh_types::members::{MemberRow, MembersResponse, TeamChip};

/// The three literals `kind` accepts. `everyone` is the default (both
/// kinds); `user` hides `UnplacedGuest`; `guest` hides any `User` row
/// without `placed_by_grant_id`, so the "Guests" filter shows placed
/// guests AND unplaced guests, matching how the SPA renders them.
const ALLOWED_KINDS: &[&str] = &["user", "guest", "everyone"];

/// The role vocab, matching the PMS-1162 projection. Accepted on both the
/// users side (via the enum round-trip) and the grants side (as a string
/// equality on `role`).
const ALLOWED_ROLES: &[&str] = &[
    "super_admin",
    "admin",
    "manager",
    "technician",
    "dispatcher",
    "sales",
    "finance",
    "read_only",
];

/// Members list filter. Validated at the route boundary; `kind` and `role`
/// are enumerated so a typo is a 422 at the API rather than a silent
/// empty-list.
#[derive(Debug, Clone, Default, Deserialize, Validate)]
pub struct MembersFilter {
    /// Case-insensitive substring over email + first_name + last_name.
    /// Capped at 200 chars so the ILIKE plan stays bounded, matching the
    /// shape `ListUsersFilter::q` carries.
    #[validate(length(max = 200))]
    pub q: Option<String>,
    /// Effective role: for a `User` row that is a placed grantee the role
    /// comes from the grant (not the users row), so filtering by role on
    /// the merged set means filtering on whichever side carries it.
    pub role: Option<String>,
    /// `user` | `guest` | `everyone`. `None` is `everyone`.
    pub kind: Option<String>,
    /// Narrows to users on a given team. Unplaced guests have no users
    /// row to join and are excluded when this is set.
    pub team_id: Option<Uuid>,
}

impl MembersFilter {
    /// Reject bad enum literals before the service runs any query. Called
    /// from the route handler so the API answers 422 on the typo rather
    /// than returning an empty list.
    pub fn validate_enums(&self) -> AppResult<()> {
        if let Some(kind) = self.kind.as_deref() {
            if !ALLOWED_KINDS.contains(&kind) {
                return Err(AppError::validation_field(
                    "kind",
                    "kind must be one of user, guest, everyone",
                ));
            }
        }
        if let Some(role) = self.role.as_deref() {
            if !ALLOWED_ROLES.contains(&role) {
                return Err(AppError::validation_field(
                    "role",
                    "role is not in the allowed set",
                ));
            }
        }
        Ok(())
    }
}

/// The service: holds a `Database` handle. No subservice injection today
/// because the standalone-mode implementation reads `users` + grants +
/// teams through its own queries; the SaaS fan-out that composes an
/// upstream directory handle lands in a later phase.
#[derive(Clone)]
pub struct MembersService {
    pub db: Database,
}

impl MembersService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Wrap in `Arc` for the router state.
    pub fn arc(db: Database) -> Arc<Self> {
        Arc::new(Self::new(db))
    }

    /// Build the merged members page.
    ///
    /// The merge is deterministic: all native users first, placed grantees
    /// decorated with their grant id, remaining grants emitted as unplaced
    /// guests, sort the whole set by (last_name, first_name, email) with a
    /// stable id tie-break, then paginate the sorted set. `kind` /
    /// `team_id` filters narrow the raw set before pagination so `total`
    /// reflects the filtered set, not the pre-filter one.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list(
        &self,
        tenant_id: TenantId,
        filter: &MembersFilter,
        pagination: &PaginationParams,
    ) -> AppResult<MembersResponse> {
        let kind = filter.kind.as_deref().unwrap_or("everyone");

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;

        // Tenant slug is the join key for `mokosh_bunyip_grants`, which is
        // keyed by text (`mokosh_account_id`) rather than tenant UUID.
        let tenant_slug: String = sqlx::query_scalar("SELECT slug FROM tenants WHERE id = $1")
            .bind(*tenant_id)
            .fetch_one(&mut *tx)
            .await?;

        // --- native users -----------------------------------------------
        // MAPPS-562: the auto-provisioned `system+<slug>@mokosh.local`
        // attribution user exists only to satisfy FKs on tickets etc.;
        // hide it here the same way `list_users` does.
        let mut users_qb: QueryBuilder<sqlx::Postgres> = QueryBuilder::new(
            "SELECT id, email, first_name, last_name, role, status, \
                    last_login_at, bunyip_user_id \
             FROM users \
             WHERE tenant_id = ",
        );
        users_qb.push_bind(*tenant_id);
        users_qb.push(
            " AND email NOT LIKE 'system+%@mokosh.local' \
              AND deleted_at IS NULL",
        );
        if let Some(q) = filter.q.as_deref().filter(|q| !q.is_empty()) {
            let pattern = format!("%{}%", q);
            users_qb.push(" AND (email ILIKE ");
            users_qb.push_bind(pattern.clone());
            users_qb.push(" OR first_name ILIKE ");
            users_qb.push_bind(pattern.clone());
            users_qb.push(" OR last_name ILIKE ");
            users_qb.push_bind(pattern);
            users_qb.push(")");
        }
        if let Some(role) = filter.role.as_deref() {
            users_qb.push(" AND role = ");
            users_qb.push_bind(role.to_string());
        }
        let mut user_rows: Vec<UserScan> = users_qb
            .build_query_as::<UserScan>()
            .fetch_all(&mut *tx)
            .await?;

        // `team_id` filter: narrow users to those on the team. Unplaced
        // guests cannot be on a team (no users row to join) so this also
        // suppresses the grant branch.
        let team_filter_active = filter.team_id.is_some();
        if let Some(team_id) = filter.team_id {
            let members: Vec<Uuid> = sqlx::query_scalar(
                "SELECT user_id FROM team_members \
                 WHERE tenant_id = $1 AND team_id = $2",
            )
            .bind(*tenant_id)
            .bind(team_id)
            .fetch_all(&mut *tx)
            .await?;
            let allowed: HashSet<Uuid> = members.into_iter().collect();
            user_rows.retain(|u| allowed.contains(&u.id));
        }

        // --- active grants targeting this tenant -----------------------
        // SAFETY (PMS-285): `mokosh_bunyip_grants` is an RLS-exempt
        // cross-tenant table (see `mokosh_bunyip_grants.rs` module doc).
        // Scoping by `mokosh_account_id = tenant.slug` reads only this
        // tenant's grants; the slug is bound from the tenant we already
        // resolved under this tenant_id, so no other tenant's grants can
        // be returned. Reads on `self.db.migrator_pool()` because the RLS
        // app pool would see zero rows (table has no `tenant_id`).
        let mut grants: Vec<GrantScan> = if team_filter_active {
            Vec::new()
        } else {
            let mut grants_qb: QueryBuilder<sqlx::Postgres> = QueryBuilder::new(
                "SELECT id, grantee_bunyip_user_id, role, granted_at \
                 FROM mokosh_bunyip_grants \
                 WHERE revoked_at IS NULL AND mokosh_account_id = ",
            );
            grants_qb.push_bind(tenant_slug.clone());
            if let Some(role) = filter.role.as_deref() {
                grants_qb.push(" AND role = ");
                grants_qb.push_bind(role.to_string());
            }
            grants_qb
                .build_query_as::<GrantScan>()
                .fetch_all(self.db.migrator_pool())
                .await?
        };

        // --- pair grants with users via bunyip_user_id -----------------
        let mut users_by_bunyip: HashMap<Uuid, Uuid> = HashMap::new();
        for u in &user_rows {
            users_by_bunyip.insert(u.bunyip_user_id, u.id);
        }
        let mut placed_grant_by_user: HashMap<Uuid, (String, String)> = HashMap::new();
        grants.retain(|g| {
            if let Some(user_id) = users_by_bunyip.get(&g.grantee_bunyip_user_id) {
                placed_grant_by_user.insert(
                    *user_id,
                    (g.id.to_string(), g.role.clone().unwrap_or_default()),
                );
                false
            } else {
                true
            }
        });

        // --- team chips, batched for the users we are about to return --
        let page_user_ids: Vec<Uuid> = user_rows.iter().map(|u| u.id).collect();
        let mut team_chips: HashMap<Uuid, Vec<TeamChip>> = HashMap::new();
        if !page_user_ids.is_empty() {
            let rows = sqlx::query(
                "SELECT tm.user_id, t.id AS team_id, t.name, t.color \
                 FROM team_members tm \
                 JOIN teams t ON t.id = tm.team_id \
                 WHERE tm.user_id = ANY($1) \
                   AND t.tenant_id = $2 \
                   AND t.is_active = TRUE",
            )
            .bind(&page_user_ids)
            .bind(*tenant_id)
            .fetch_all(&mut *tx)
            .await?;
            for row in rows {
                let user_id: Uuid = row.get("user_id");
                let chip = TeamChip {
                    team_id: row.get("team_id"),
                    team_name: row.get("name"),
                    color: row.get("color"),
                };
                team_chips.entry(user_id).or_default().push(chip);
            }
        }

        tx.commit().await?;

        // --- compose the merged set ------------------------------------
        let mut rows: Vec<MemberRow> = Vec::with_capacity(user_rows.len() + grants.len());
        for u in user_rows {
            let placed = placed_grant_by_user.get(&u.id).cloned();
            rows.push(MemberRow::User {
                user_id: u.id,
                email: u.email,
                first_name: u.first_name,
                last_name: u.last_name,
                role: placed.as_ref().map(|(_, r)| r.clone()).unwrap_or(u.role),
                status: u.status,
                last_login_at: u.last_login_at,
                team_memberships: team_chips.remove(&u.id).unwrap_or_default(),
                placed_by_grant_id: placed.map(|(id, _)| id),
            });
        }
        for g in grants {
            rows.push(MemberRow::UnplacedGuest {
                grant_id: g.id.to_string(),
                grantee_email: None,
                grantee_name: None,
                role: g.role.unwrap_or_default(),
                granted_at: g.granted_at,
            });
        }

        // --- kind filter ----------------------------------------------
        match kind {
            "user" => rows.retain(|r| {
                matches!(
                    r,
                    MemberRow::User {
                        placed_by_grant_id: None,
                        ..
                    }
                )
            }),
            "guest" => rows.retain(|r| {
                matches!(
                    r,
                    MemberRow::User {
                        placed_by_grant_id: Some(_),
                        ..
                    } | MemberRow::UnplacedGuest { .. }
                )
            }),
            _ => {}
        }

        // --- sort + paginate -------------------------------------------
        rows.sort_by_key(sort_key);

        let total = rows.len() as u64;
        let per_page = pagination.limit();
        let page = pagination.page;
        let offset = pagination.offset() as usize;
        let limit = pagination.limit() as usize;
        let page_rows: Vec<MemberRow> = rows.into_iter().skip(offset).take(limit).collect();

        Ok(MembersResponse {
            rows: page_rows,
            total,
            page,
            per_page,
            bunyip_reachable: true,
        })
    }
}

/// (last_name, first_name, email, id) for a stable deterministic sort
/// across kinds. `UnplacedGuest` uses the grantee_name (split on the first
/// space) when present, else the email; falling back to the grant id when
/// everything is absent so the order is still stable.
fn sort_key(row: &MemberRow) -> (String, String, String, String) {
    match row {
        MemberRow::User {
            last_name,
            first_name,
            email,
            user_id,
            ..
        } => (
            last_name.to_lowercase(),
            first_name.to_lowercase(),
            email.to_lowercase(),
            user_id.to_string(),
        ),
        MemberRow::UnplacedGuest {
            grantee_name,
            grantee_email,
            grant_id,
            ..
        } => {
            let name = grantee_name.clone().unwrap_or_default();
            let (first, last) = match name.split_once(' ') {
                Some((f, l)) => (f.to_string(), l.to_string()),
                None => (name.clone(), String::new()),
            };
            let email = grantee_email.clone().unwrap_or_default();
            (
                last.to_lowercase(),
                first.to_lowercase(),
                email.to_lowercase(),
                grant_id.clone(),
            )
        }
    }
}

#[derive(sqlx::FromRow)]
struct UserScan {
    id: Uuid,
    email: String,
    first_name: String,
    last_name: String,
    role: String,
    status: String,
    last_login_at: Option<chrono::DateTime<chrono::Utc>>,
    bunyip_user_id: Uuid,
}

#[derive(sqlx::FromRow)]
struct GrantScan {
    id: Uuid,
    grantee_bunyip_user_id: Uuid,
    role: Option<String>,
    granted_at: Option<chrono::DateTime<chrono::Utc>>,
}
