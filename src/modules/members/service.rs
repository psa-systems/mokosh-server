//! MAPPS-877: unified members reader.
//!
//! One `list` method that returns natives + placed guests + unplaced
//! guests as one ordered, paginated, filterable list. Fans out to:
//!
//! - `users` in the caller's tenant (`bunyip_user_id` projected so a
//!   placed guest can be joined against the grant fan-out below).
//! - `BunyipUserDirectory::list_owner_grants(caller.id)` for the
//!   owner outbox in SaaS mode. Standalone mode reads the
//!   `mokosh_bunyip_grants` mirror directly.
//!
//! A grant that matches a `users` row (on `bunyip_user_id`) decorates
//! that row with `placed_by_grant_id`. Grants without a match emit
//! `UnplacedGuest` rows. Sort is name-first (last_name, first_name,
//! email) across both kinds, tie-broken on id so pagination is
//! deterministic.

use std::sync::Arc;

use serde::Deserialize;
use sqlx::Row;
use uuid::Uuid;

use crate::db::Database;
use crate::modules::auth::bunyip_directory::{BunyipUserDirectory, OwnerGrantView};
use crate::utils::error::{AppError, AppResult};
use crate::utils::pagination::PaginationParams;
use mokosh_types::members::{MemberRow, MembersResponse, TeamChip};

/// Query-string filters accepted by `GET /api/v1/members`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct MembersFilter {
    /// Case-insensitive substring across email + first_name +
    /// last_name (users) + grantee_email + grantee_name (guests).
    #[serde(default)]
    pub q: Option<String>,
    /// PMS-1162 role vocab. Filters the effective role (users.role
    /// on natives; grant.role on unplaced guests). Placed guests
    /// filter on their grant role; a users row that a grant name
    /// placed here reads `users.role` because PMS-1162 keeps that
    /// column reconciled.
    #[serde(default)]
    pub role: Option<String>,
    /// `user`, `guest`, or `everyone` (default). `user` hides
    /// `UnplacedGuest` rows; `guest` hides plain natives AND
    /// placed-guest natives (a placed guest is a user for the
    /// purpose of `kind`, distinguishable on `placed_by_grant_id`).
    #[serde(default)]
    pub kind: Option<String>,
    /// Restricts to members of a specific team. Natives only; a
    /// guest without a users row has no team memberships to filter
    /// against, so specifying `team_id` and `kind=guest` returns
    /// nothing.
    #[serde(default)]
    pub team_id: Option<Uuid>,
}

impl MembersFilter {
    fn valid(&self) -> AppResult<()> {
        if let Some(kind) = self.kind.as_deref() {
            if !matches!(kind, "user" | "guest" | "everyone") {
                return Err(AppError::validation_field(
                    "kind",
                    "expected one of user | guest | everyone".to_string(),
                ));
            }
        }
        if let Some(role) = self.role.as_deref() {
            if !matches!(
                role,
                "super_admin" | "admin" | "manager" | "technician" | "finance" | "read_only"
            ) {
                return Err(AppError::validation_field(
                    "role",
                    "expected one of super_admin | admin | manager | technician | finance | read_only"
                        .to_string(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct MembersService {
    db: Arc<Database>,
    /// `Some` in SaaS mode; `None` in standalone (mirror is
    /// authoritative and we read it directly).
    bunyip_directory: Option<Arc<BunyipUserDirectory>>,
}

impl MembersService {
    pub fn new(db: Arc<Database>, bunyip_directory: Option<Arc<BunyipUserDirectory>>) -> Self {
        Self {
            db,
            bunyip_directory,
        }
    }

    pub async fn list(
        &self,
        tenant_id: Uuid,
        caller_bunyip_user_id: Uuid,
        filter: &MembersFilter,
        pagination: &PaginationParams,
    ) -> AppResult<MembersResponse> {
        filter.valid()?;

        // 1. Native users. `bunyip_user_id` is projected so we can
        //    match placed guests against the grant fan-out below.
        //    `deleted_at IS NULL` filters out tombstoned rows (a
        //    guest whose owner revoked their grant leaves the users
        //    row soft-deleted; the mokosh people list should not
        //    show the ghost). The system attribution row (MAPPS-562)
        //    is hidden by the email pattern.
        //
        //    SAFETY (PMS-285): tenant_id is bound to the caller's
        //    authenticated tenant and appears in the WHERE clause.
        //    The RLS-covered app pool would fail-closed to zero rows
        //    without a tx setting the GUC; we use `begin_with_tenant`
        //    below to satisfy the policy.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;

        let mut users_query = String::from(
            "SELECT id, bunyip_user_id, email, first_name, last_name, role::text AS role, \
                    status::text AS status, last_login_at \
             FROM users \
             WHERE tenant_id = $1 \
               AND deleted_at IS NULL \
               AND email NOT LIKE 'system+%@mokosh.local'",
        );
        let mut idx: i32 = 2;
        if let Some(_needle) = filter.q.as_deref() {
            users_query.push_str(&format!(
                " AND (email ILIKE ${idx} OR first_name ILIKE ${idx} OR last_name ILIKE ${idx})",
                idx = idx
            ));
            idx += 1;
        }
        if filter.role.is_some() {
            users_query.push_str(&format!(" AND role::text = ${idx}"));
            idx += 1;
        }
        if let Some(_team_id) = filter.team_id {
            users_query.push_str(&format!(
                " AND EXISTS (SELECT 1 FROM team_members tm \
                                WHERE tm.tenant_id = $1 \
                                  AND tm.team_id = ${idx} \
                                  AND tm.user_id = users.id)"
            ));
            idx += 1;
        }
        let _ = idx;
        users_query.push_str(" ORDER BY last_name, first_name, email, id");

        let mut q = sqlx::query(&users_query).bind(tenant_id);
        if let Some(needle) = filter.q.as_deref() {
            q = q.bind(format!("%{}%", needle));
        }
        if let Some(role) = filter.role.as_deref() {
            q = q.bind(role.to_string());
        }
        if let Some(team_id) = filter.team_id {
            q = q.bind(team_id);
        }
        let user_rows = q.fetch_all(&mut *tx).await?;

        let mut users: Vec<UserPreRow> = user_rows
            .into_iter()
            .map(|r| UserPreRow {
                id: r.get::<Uuid, _>("id"),
                bunyip_user_id: r
                    .try_get::<Option<Uuid>, _>("bunyip_user_id")
                    .ok()
                    .flatten(),
                email: r.get::<String, _>("email"),
                first_name: r.get::<String, _>("first_name"),
                last_name: r.get::<String, _>("last_name"),
                role: r.get::<String, _>("role"),
                status: r.get::<String, _>("status"),
                last_login_at: r
                    .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("last_login_at")
                    .ok()
                    .flatten(),
                placed_by_grant_id: None,
                team_memberships: Vec::new(),
            })
            .collect();

        // 2. Grants fan-out. SaaS -> bunyip; standalone -> mirror.
        //    A transport failure in SaaS mode logs a warning, sets
        //    `bunyip_reachable = false` on the response, and
        //    proceeds with an empty grants list; the natives are
        //    still visible and the SPA can prompt a retry. A false
        //    empty on this page would let an owner believe access
        //    they revoked is gone when it is still active - hence
        //    the flag.
        //
        // SAFETY (PMS-285): the standalone-mode branch below reads
        // `mokosh_bunyip_grants` on the migrator pool because that
        // table has no RLS policy (migration 220 does not enable it)
        // and its rows are scoped by `owner_bunyip_user_id` in the
        // WHERE, which is the caller's authenticated id. The sibling
        // `owner_grants_routes::active_for_owner` reads the same
        // table with the same filter for the same reason.
        let (grants, bunyip_reachable) = self
            .load_grants(caller_bunyip_user_id, self.db.migrator_pool())
            .await;

        // 3. Match grants against the users list. A hit sets
        //    `placed_by_grant_id` and drops the grant from the
        //    pending-guest set. Remaining grants emit UnplacedGuest.
        let mut unplaced: Vec<UnplacedPreRow> = Vec::new();
        for grant in grants {
            let matched = users
                .iter_mut()
                .find(|u| u.bunyip_user_id == Some(grant.grantee_bunyip_user_id));
            match matched {
                Some(u) => {
                    u.placed_by_grant_id = Some(grant.grant_id);
                    // A placed guest's effective role IS the grant
                    // role. `users.role` is a PMS-1162 projection of
                    // it, but reading it directly here keeps the two
                    // reconciled at fetch time as well.
                    u.role = grant.role;
                }
                None => {
                    unplaced.push(UnplacedPreRow {
                        grant_id: grant.grant_id,
                        grantee_email: grant.grantee_email,
                        grantee_name: grant.grantee_name,
                        role: grant.role,
                        granted_at: Some(grant.granted_at),
                    });
                }
            }
        }

        // 4. Team chips for placed / native rows. One batched SELECT
        //    over the users page's ids. Zero-team users skip.
        if !users.is_empty() {
            let user_ids: Vec<Uuid> = users.iter().map(|u| u.id).collect();
            let team_rows: Vec<(Uuid, Uuid, String, Option<String>)> = sqlx::query_as(
                "SELECT tm.user_id, t.id, t.name, t.color \
                 FROM team_members tm \
                 JOIN teams t ON t.id = tm.team_id AND t.tenant_id = tm.tenant_id \
                 WHERE tm.tenant_id = $1 AND tm.user_id = ANY($2) AND t.is_active = TRUE \
                 ORDER BY t.name",
            )
            .bind(tenant_id)
            .bind(&user_ids)
            .fetch_all(&mut *tx)
            .await?;
            for (user_id, team_id, team_name, color) in team_rows {
                if let Some(u) = users.iter_mut().find(|u| u.id == user_id) {
                    u.team_memberships.push(TeamChip {
                        team_id,
                        team_name,
                        color,
                    });
                }
            }
        }

        drop(tx);

        // 5. `kind` filter runs AFTER placed-guest decoration
        //    because kind=`guest` needs to see both placed guests
        //    (users with `placed_by_grant_id`) AND unplaced guests,
        //    while `kind=user` needs to see the natives (users
        //    without `placed_by_grant_id`).
        let kind = filter.kind.as_deref().unwrap_or("everyone");
        users.retain(|u| match kind {
            "user" => u.placed_by_grant_id.is_none(),
            "guest" => u.placed_by_grant_id.is_some(),
            _ => true,
        });
        if kind == "user" {
            unplaced.clear();
        }
        if filter.team_id.is_some() {
            // team_id was already applied to users; guests have no
            // users row so they must be dropped entirely.
            unplaced.clear();
        }

        // Optional: filter guests by q (users were filtered in-DB;
        // guests came from a fan-out that ignores mokosh's filters).
        if let Some(needle) = filter.q.as_deref() {
            let needle_lc = needle.to_ascii_lowercase();
            unplaced.retain(|g| {
                let email_hit = g
                    .grantee_email
                    .as_deref()
                    .map(|s| s.to_ascii_lowercase().contains(&needle_lc))
                    .unwrap_or(false);
                let name_hit = g
                    .grantee_name
                    .as_deref()
                    .map(|s| s.to_ascii_lowercase().contains(&needle_lc))
                    .unwrap_or(false);
                email_hit || name_hit
            });
        }
        if let Some(role) = filter.role.as_deref() {
            unplaced.retain(|g| g.role == role);
        }

        // 6. Merge and sort by name, tie-break on id.
        let mut all: Vec<MemberRow> = Vec::with_capacity(users.len() + unplaced.len());
        for u in users {
            all.push(MemberRow::User {
                user_id: u.id,
                email: u.email,
                first_name: u.first_name,
                last_name: u.last_name,
                role: u.role,
                status: u.status,
                last_login_at: u.last_login_at,
                team_memberships: u.team_memberships,
                placed_by_grant_id: u.placed_by_grant_id,
            });
        }
        for g in unplaced {
            all.push(MemberRow::UnplacedGuest {
                grant_id: g.grant_id,
                grantee_email: g.grantee_email,
                grantee_name: g.grantee_name,
                role: g.role,
                granted_at: g.granted_at,
            });
        }
        all.sort_by_key(sort_key);

        // 7. Paginate the merged set. Server-side rather than
        //    client-side because a client cannot compute a correct
        //    total across a merged fan-out without over-fetching.
        let total = all.len() as u64;
        let per_page = pagination.per_page();
        let page = pagination.page.max(1);
        let start = ((page - 1) * per_page) as usize;
        let end = (start + per_page as usize).min(all.len());
        let rows: Vec<MemberRow> = if start >= all.len() {
            Vec::new()
        } else {
            all.drain(start..end).collect()
        };

        Ok(MembersResponse {
            rows,
            total,
            page,
            per_page,
            bunyip_reachable,
        })
    }

    async fn load_grants(
        &self,
        caller_bunyip_user_id: Uuid,
        migrator_pool: &sqlx::PgPool,
    ) -> (Vec<OwnerGrantView>, bool) {
        if let Some(directory) = self.bunyip_directory.as_ref() {
            match directory.list_owner_grants(caller_bunyip_user_id).await {
                Ok(rows) => (rows, true),
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        owner = %caller_bunyip_user_id,
                        "MAPPS-877 members: bunyip grant fan-out failed; \
                         falling back to native-only list"
                    );
                    (Vec::new(), false)
                }
            }
        } else {
            // Standalone: read the mirror directly. Same shape the
            // owner-outbox route uses, minus the `grantee_name`
            // column bunyip's join provides in SaaS mode.
            let rows = sqlx::query(
                "SELECT bunyip_grant_id, grantee_bunyip_user_id, mokosh_account_id, \
                        grantee_email, role, granted_at \
                 FROM mokosh_bunyip_grants \
                 WHERE owner_bunyip_user_id = $1 \
                   AND revoked_at IS NULL \
                   AND role IS NOT NULL \
                 ORDER BY granted_at ASC",
            )
            .bind(caller_bunyip_user_id)
            .fetch_all(migrator_pool)
            .await;

            let rows = match rows {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        owner = %caller_bunyip_user_id,
                        "MAPPS-877 members: standalone mirror read failed"
                    );
                    return (Vec::new(), true);
                }
            };
            let out: Vec<OwnerGrantView> = rows
                .into_iter()
                .map(|row| OwnerGrantView {
                    grant_id: row.get::<Uuid, _>("bunyip_grant_id"),
                    grantee_bunyip_user_id: row.get::<Uuid, _>("grantee_bunyip_user_id"),
                    mokosh_account_id: row.get::<String, _>("mokosh_account_id"),
                    role: row.get::<String, _>("role"),
                    granted_at: row.get::<chrono::DateTime<chrono::Utc>, _>("granted_at"),
                    grantee_email: row
                        .try_get::<Option<String>, _>("grantee_email")
                        .ok()
                        .flatten(),
                    grantee_name: None,
                })
                .collect();
            (out, true)
        }
    }
}

/// Intermediate shape while the service is building rows. Split from
/// the wire `MemberRow` so the merge code can mutate one row's role
/// and `placed_by_grant_id` without wrapping and unwrapping the enum.
struct UserPreRow {
    id: Uuid,
    bunyip_user_id: Option<Uuid>,
    email: String,
    first_name: String,
    last_name: String,
    role: String,
    status: String,
    last_login_at: Option<chrono::DateTime<chrono::Utc>>,
    placed_by_grant_id: Option<Uuid>,
    team_memberships: Vec<TeamChip>,
}

struct UnplacedPreRow {
    grant_id: Uuid,
    grantee_email: Option<String>,
    grantee_name: Option<String>,
    role: String,
    granted_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// (last, first, email, id) so the sort is deterministic across kinds.
/// Guests without a name fall back to their email; guests without an
/// email use the grant id so nothing sorts on an empty string.
fn sort_key(row: &MemberRow) -> (String, String, String, String) {
    match row {
        MemberRow::User {
            user_id,
            email,
            first_name,
            last_name,
            ..
        } => (
            last_name.to_ascii_lowercase(),
            first_name.to_ascii_lowercase(),
            email.to_ascii_lowercase(),
            user_id.to_string(),
        ),
        MemberRow::UnplacedGuest {
            grant_id,
            grantee_email,
            grantee_name,
            ..
        } => {
            let (last, first) = match grantee_name.as_deref() {
                Some(full) => {
                    let mut parts = full.split_whitespace();
                    let first = parts.next().unwrap_or("").to_string();
                    let last = parts.last().unwrap_or("").to_string();
                    (last, first)
                }
                None => (String::new(), String::new()),
            };
            (
                last.to_ascii_lowercase(),
                first.to_ascii_lowercase(),
                grantee_email
                    .as_deref()
                    .unwrap_or_default()
                    .to_ascii_lowercase(),
                grant_id.to_string(),
            )
        }
    }
}
