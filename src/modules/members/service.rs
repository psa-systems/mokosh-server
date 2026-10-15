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

use std::collections::HashMap;
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
    /// The merge, sort and pagination all happen in one `UNION ALL` query
    /// over native `users` rows (with `placed_by_grant_id` resolved via a
    /// `LEFT JOIN` on `mokosh_bunyip_grants`) and unplaced-grant rows (a
    /// grant with no matching `bunyip_user_id` in `users`), ordered by
    /// `(last_name, first_name, email, id)` with `LIMIT`/`OFFSET` pushed
    /// down. `total` is a second query over the same `UNION ALL` wrapped in
    /// `COUNT(*)`, matching the count-then-page convention `list_assets`
    /// uses. `kind` / `team_id` narrow which arms run and what they select
    /// so `total` reflects the filtered set, not the pre-filter one.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list(
        &self,
        tenant_id: TenantId,
        filter: &MembersFilter,
        pagination: &PaginationParams,
    ) -> AppResult<MembersResponse> {
        let kind = filter.kind.as_deref().unwrap_or("everyone");
        let team_filter_active = filter.team_id.is_some();

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;

        // Tenant slug is the join key for `mokosh_bunyip_grants`, which is
        // keyed by text (`mokosh_account_id`) rather than tenant UUID.
        let tenant_slug: String = sqlx::query_scalar("SELECT slug FROM tenants WHERE id = $1")
            .bind(*tenant_id)
            .fetch_one(&mut *tx)
            .await?;

        // SAFETY (PMS-285): the combined query below UNIONs native `users`
        // rows with `mokosh_bunyip_grants` rows, a cross-tenant table with
        // no `tenant_id` column (see its module doc), so the two arms
        // cannot share one `app.current_tenant` GUC the way a single-table
        // read would. It runs on `self.db.migrator_pool()`, the same
        // BYPASSRLS accessor the pre-existing grants read already used,
        // with tenant scoping enforced explicitly: the users arm filters
        // `u.tenant_id = $1` and the grants arm filters
        // `mokosh_account_id = <this tenant's slug>`, both bound from the
        // `tenant_id` this handler was gated on, so no other tenant's rows
        // can surface.
        let total: i64 = {
            let mut count_qb: QueryBuilder<sqlx::Postgres> =
                QueryBuilder::new("SELECT COUNT(*) FROM (");
            push_union(
                &mut count_qb,
                *tenant_id,
                &tenant_slug,
                filter,
                kind,
                team_filter_active,
            );
            count_qb.push(") members_union");
            count_qb
                .build_query_scalar()
                .fetch_one(self.db.migrator_pool())
                .await?
        };

        let per_page = pagination.limit();
        let page = pagination.page;

        let mut page_qb: QueryBuilder<sqlx::Postgres> = QueryBuilder::new(
            "SELECT kind, user_id, email, first_name, last_name, role, status, \
                    last_login_at, grant_id, grantee_email, grantee_name, granted_at \
             FROM (",
        );
        push_union(
            &mut page_qb,
            *tenant_id,
            &tenant_slug,
            filter,
            kind,
            team_filter_active,
        );
        page_qb.push(
            ") members_union \
             ORDER BY sort_last, sort_first, sort_email, sort_id \
             LIMIT ",
        );
        page_qb.push_bind(pagination.limit() as i64);
        page_qb.push(" OFFSET ");
        page_qb.push_bind(pagination.offset() as i64);

        let merged_rows: Vec<MergedRow> = page_qb
            .build_query_as::<MergedRow>()
            .fetch_all(self.db.migrator_pool())
            .await?;

        // --- team chips, batched for exactly the returned page ----------
        let page_user_ids: Vec<Uuid> = merged_rows
            .iter()
            .filter(|r| r.kind == "user")
            .filter_map(|r| r.user_id)
            .collect();
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

        // --- compose the page -------------------------------------------
        let page_rows: Vec<MemberRow> = merged_rows
            .into_iter()
            .map(|r| match r.kind.as_str() {
                "user" => {
                    let user_id = r.user_id.expect("user arm always carries user_id");
                    MemberRow::User {
                        user_id,
                        email: r.email.unwrap_or_default(),
                        first_name: r.first_name.unwrap_or_default(),
                        last_name: r.last_name.unwrap_or_default(),
                        role: r.role.unwrap_or_default(),
                        status: r.status.unwrap_or_default(),
                        last_login_at: r.last_login_at,
                        team_memberships: team_chips.remove(&user_id).unwrap_or_default(),
                        placed_by_grant_id: r.grant_id.map(|id| id.to_string()),
                    }
                }
                _ => MemberRow::UnplacedGuest {
                    grant_id: r.grant_id.map(|id| id.to_string()).unwrap_or_default(),
                    grantee_email: r.grantee_email,
                    grantee_name: r.grantee_name,
                    role: r.role.unwrap_or_default(),
                    granted_at: r.granted_at,
                },
            })
            .collect();

        Ok(MembersResponse {
            rows: page_rows,
            total: total as u64,
            page,
            per_page,
            bunyip_reachable: true,
        })
    }
}

/// Push `(arm_a) UNION ALL (arm_b)` (or just `arm_a` when `kind`/`team_id`
/// suppress the grants arm) onto `qb`. Shared by the count query and the
/// page query so the two see the exact same filtered, unioned row set.
///
/// `arm_a` is every native `users` row (MAPPS-562's `system+...@mokosh.local`
/// attribution user and soft-deleted rows excluded), `LEFT JOIN`ed to its
/// active grant (if any) via `bunyip_user_id`; `grant_id IS NOT NULL` on
/// that join is exactly `placed_by_grant_id = Some(_)`. `arm_b` is every
/// active grant with no matching `users` row (`NOT EXISTS`), i.e. the
/// `UnplacedGuest`s. `team_id` narrows `arm_a` to that team's members and
/// drops `arm_b` entirely (an unplaced guest has no `users` row to join a
/// team through, matching the pre-SQL-pushdown behaviour). `kind = "user"`
/// drops `arm_b`; `kind = "guest"` restricts `arm_a` to placed rows only.
/// Both arms expose `sort_last`/`sort_first`/`sort_email`/`sort_id` so the
/// caller can `ORDER BY` the union without re-deriving the sort key in Rust.
fn push_union(
    qb: &mut QueryBuilder<'_, sqlx::Postgres>,
    tenant_id: Uuid,
    tenant_slug: &str,
    filter: &MembersFilter,
    kind: &str,
    team_filter_active: bool,
) {
    qb.push(
        "SELECT 'user' AS kind, u.id AS user_id, u.email, u.first_name, u.last_name, \
                u.role AS role, u.status, u.last_login_at, g.id AS grant_id, \
                NULL::text AS grantee_email, NULL::text AS grantee_name, \
                NULL::timestamptz AS granted_at, \
                lower(u.last_name) AS sort_last, lower(u.first_name) AS sort_first, \
                lower(u.email) AS sort_email, u.id::text AS sort_id \
         FROM users u \
         LEFT JOIN mokosh_bunyip_grants g \
           ON g.grantee_bunyip_user_id = u.bunyip_user_id \
          AND g.revoked_at IS NULL \
          AND g.mokosh_account_id = ",
    );
    qb.push_bind(tenant_slug.to_string());
    qb.push(" WHERE u.tenant_id = ");
    qb.push_bind(tenant_id);
    qb.push(
        " AND u.email NOT LIKE 'system+%@mokosh.local' \
          AND u.deleted_at IS NULL",
    );
    if let Some(q) = filter.q.as_deref().filter(|q| !q.is_empty()) {
        let pattern = format!("%{}%", q);
        qb.push(" AND (u.email ILIKE ");
        qb.push_bind(pattern.clone());
        qb.push(" OR u.first_name ILIKE ");
        qb.push_bind(pattern.clone());
        qb.push(" OR u.last_name ILIKE ");
        qb.push_bind(pattern);
        qb.push(")");
    }
    if let Some(role) = filter.role.as_deref() {
        qb.push(" AND u.role = ");
        qb.push_bind(role.to_string());
    }
    if let Some(team_id) = filter.team_id {
        qb.push(
            " AND EXISTS (SELECT 1 FROM team_members tm \
                           WHERE tm.tenant_id = u.tenant_id \
                             AND tm.team_id = ",
        );
        qb.push_bind(team_id);
        qb.push(" AND tm.user_id = u.id)");
    }
    match kind {
        // A placed guest is a `User` row AND has a grant, so "user" (plain
        // native users only) excludes it the same as the pre-pushdown
        // `retain(|r| matches!(r, MemberRow::User { placed_by_grant_id:
        // None, .. }))` did.
        "user" => qb.push(" AND g.id IS NULL"),
        "guest" => qb.push(" AND g.id IS NOT NULL"),
        _ => qb,
    };

    // Unplaced guests have no `users` row to join a team through, so a
    // `team_id` filter excludes them outright, the same as the pre-pushdown
    // behaviour (grants branch skipped entirely when the filter is active).
    // `kind = "user"` hides UnplacedGuest explicitly.
    if !team_filter_active && kind != "user" {
        qb.push(
            " UNION ALL \
              SELECT 'unplaced_guest' AS kind, NULL::uuid AS user_id, NULL::text AS email, \
                     NULL::text AS first_name, NULL::text AS last_name, g.role AS role, \
                     NULL::text AS status, NULL::timestamptz AS last_login_at, \
                     g.id AS grant_id, g.grantee_email, NULL::text AS grantee_name, \
                     g.granted_at, \
                     '' AS sort_last, '' AS sort_first, \
                     lower(coalesce(g.grantee_email, '')) AS sort_email, \
                     g.id::text AS sort_id \
              FROM mokosh_bunyip_grants g \
              WHERE g.revoked_at IS NULL AND g.mokosh_account_id = ",
        );
        qb.push_bind(tenant_slug.to_string());
        qb.push(
            " AND NOT EXISTS ( \
                   SELECT 1 FROM users u2 \
                    WHERE u2.bunyip_user_id = g.grantee_bunyip_user_id \
                      AND u2.tenant_id = ",
        );
        qb.push_bind(tenant_id);
        qb.push(")");
        if let Some(role) = filter.role.as_deref() {
            qb.push(" AND g.role = ");
            qb.push_bind(role.to_string());
        }
    }
}

/// One row of the `UNION ALL` built by [`push_union`]. `kind` is `"user"`
/// or `"unplaced_guest"`; the `sort_*` columns exist only to be `ORDER BY`ed
/// in SQL and are not decoded into [`MemberRow`].
#[derive(sqlx::FromRow)]
struct MergedRow {
    kind: String,
    user_id: Option<Uuid>,
    email: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
    role: Option<String>,
    status: Option<String>,
    last_login_at: Option<chrono::DateTime<chrono::Utc>>,
    grant_id: Option<Uuid>,
    grantee_email: Option<String>,
    grantee_name: Option<String>,
    granted_at: Option<chrono::DateTime<chrono::Utc>>,
}
