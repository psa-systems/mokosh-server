//! MAPPS-475 (MAPPS-474 phase 1): read helpers for `identities` and
//! `tenant_memberships`.
//!
//! Phase 1 does NOT wire these into any handler; the auth service still
//! reads from `users`. Phase 2 will call [`IdentityRepo::find_by_email`]
//! from the new `GET /api/v1/auth/memberships` endpoint, and phase 3 will
//! call it from the refactored login handler.
//!
//! Both tables are cross-tenant lookup tables, so every read here runs on
//! the BYPASSRLS migrator pool with no `app.current_tenant` GUC. That is a
//! requirement, not a convenience: PMS-1040 audited every call site below,
//! confirmed all of them pass `db().migrator_pool()`, and on that basis
//! migration 195 gave `tenant_memberships` the fail-closed
//! `tenant_isolation` policy as a backstop. A caller that hands one of
//! these functions the bare NOBYPASSRLS `db().pool()` now reads zero
//! membership rows. `identities` has no `tenant_id` to scope to and stays
//! exempt, named in `TENANTLESS_WITHOUT_RLS` (`tests/rls_coverage.rs`).
//! Migration `157_identities_and_memberships.sql` created both tables; its
//! header's "neither table is RLS-enabled" predates 191.

use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct IdentityRow {
    pub id: Uuid,
    pub email: String,
    pub password_hash: Option<String>,
    pub first_name: String,
    pub last_name: String,
    pub phone: Option<String>,
    pub mobile: Option<String>,
    pub avatar_url: Option<String>,
    pub timezone: String,
    pub locale: String,
    pub email_verified_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_login_at: Option<chrono::DateTime<chrono::Utc>>,
    pub mfa_enabled: bool,
    pub mfa_secret: Option<String>,
    pub notification_preferences: serde_json::Value,
    pub settings: serde_json::Value,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    /// MAPPS-497 item 4 (PMS-502 identity extension): the highest TOTP
    /// step this identity has burned via the identity-first login path.
    /// Non-null with default 0 so a fresh identity accepts any positive
    /// step. Written by `IdentityRepo::record_identity_mfa_success` as a
    /// compare-and-set; a subsequent same-step attempt is a replay.
    #[sqlx(default)]
    pub mfa_last_totp_step: i64,
}

pub struct IdentityRepo;

impl IdentityRepo {
    pub async fn find_by_email(
        pool: &PgPool,
        email: &str,
    ) -> Result<Option<IdentityRow>, sqlx::Error> {
        sqlx::query_as::<_, IdentityRow>(
            r#"
            SELECT id, email, password_hash, first_name, last_name, phone, mobile,
                   avatar_url, timezone, locale, email_verified_at, last_login_at,
                   mfa_enabled, mfa_secret, notification_preferences, settings,
                   status, created_at, updated_at, mfa_last_totp_step
            FROM identities
            WHERE lower(email) = lower($1)
            "#,
        )
        .bind(email)
        .fetch_optional(pool)
        .await
    }

    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<IdentityRow>, sqlx::Error> {
        sqlx::query_as::<_, IdentityRow>(
            r#"
            SELECT id, email, password_hash, first_name, last_name, phone, mobile,
                   avatar_url, timezone, locale, email_verified_at, last_login_at,
                   mfa_enabled, mfa_secret, notification_preferences, settings,
                   status, created_at, updated_at, mfa_last_totp_step
            FROM identities
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct MembershipRow {
    pub id: Uuid,
    pub identity_id: Uuid,
    pub tenant_id: Uuid,
    pub role: String,
    pub title: Option<String>,
    pub status: String,
    pub joined_at: chrono::DateTime<chrono::Utc>,
    pub last_active_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

pub struct MembershipRepo;

/// PMS-1208 finding 11: a grant-arm row from
/// [`MembershipRepo::list_views_for_identity`]. A struct rather than
/// a tuple so a reordered SELECT does not silently bind the wrong value
/// to the wrong field (sqlx's `FromRow` matches on column NAME, not
/// position) and clippy's `type_complexity` stays off the function.
#[derive(sqlx::FromRow)]
struct GrantArmRow {
    id: Uuid,
    /// Nullable per migration 225: a row written by a pre-BUNYIP-674-
    /// webhook test seed, or any pre-PMS-1393 record, has `NULL` here.
    bunyip_grant_id: Option<Uuid>,
    tenant_id: Uuid,
    name: String,
    slug: String,
    kind: String,
    role: String,
}

/// Owner-arm row (identity's own memberships via `tenant_memberships`).
/// Same reasoning as [`GrantArmRow`] about named columns and clippy.
#[derive(sqlx::FromRow)]
struct OwnerArmRow {
    tenant_id: Uuid,
    name: String,
    slug: String,
    kind: String,
    role: String,
    status: String,
}

impl MembershipRepo {
    /// Every active membership for an identity, ordered by joined_at so
    /// the picker in phase 3 renders "your longest-standing tenant first".
    pub async fn list_active_for_identity(
        pool: &PgPool,
        identity_id: Uuid,
    ) -> Result<Vec<MembershipRow>, sqlx::Error> {
        sqlx::query_as::<_, MembershipRow>(
            r#"
            SELECT id, identity_id, tenant_id, role, title, status,
                   joined_at, last_active_at, created_at, updated_at
            FROM tenant_memberships
            WHERE identity_id = $1 AND status = 'active'
            ORDER BY joined_at ASC
            "#,
        )
        .bind(identity_id)
        .fetch_all(pool)
        .await
    }

    pub async fn find(
        pool: &PgPool,
        identity_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<Option<MembershipRow>, sqlx::Error> {
        sqlx::query_as::<_, MembershipRow>(
            r#"
            SELECT id, identity_id, tenant_id, role, title, status,
                   joined_at, last_active_at, created_at, updated_at
            FROM tenant_memberships
            WHERE identity_id = $1 AND tenant_id = $2
            "#,
        )
        .bind(identity_id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// MAPPS-491: resolve `tenant_memberships.id` from an email + tenant
    /// pair. Used as the fallback for legacy tokens minted before phase 2
    /// (no `mid` claim) and in `generate_tokens` at mint time.
    pub async fn find_id_by_email_and_tenant(
        pool: &PgPool,
        email: &str,
        tenant_id: Uuid,
    ) -> Result<Option<Uuid>, sqlx::Error> {
        sqlx::query_scalar::<_, Uuid>(
            r#"
            SELECT tm.id
            FROM tenant_memberships tm
            JOIN identities i ON i.id = tm.identity_id
            WHERE lower(i.email) = lower($1) AND tm.tenant_id = $2
            "#,
        )
        .bind(email)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// MAPPS-491: list every active membership for an identity joined
    /// against `tenants` so callers get a wire-ready `MembershipView`
    /// (tenant name/slug/kind included) in one round trip. Ordered by
    /// `joined_at` so the phase-3 picker leads with the identity's
    /// longest-standing tenant.
    ///
    /// PMS-1393: each row also carries the live `mokosh_bunyip_grants` id when
    /// the seat came from a grant, because that id is what makes
    /// `DELETE /api/v1/my-grants/{id}` callable and nothing else on the wire
    /// held it. Three things about the join are deliberate.
    ///
    /// It goes through `users` rather than `identities`, because the Bunyip sub
    /// lives on `users.bunyip_user_id` (migration 226) and `identities` has no
    /// such column; the placement row for the seat's own tenant is the one that
    /// answers, which is also the row `grantee_leave` tombstones.
    ///
    /// It matches `mokosh_account_id` against `tenants.slug`, because that
    /// column holds a SLUG and not a tenant id (migration 225's own comment says
    /// so: Bunyip has no local tenant knowledge). A join written against
    /// `t.id::text` would compile, return nothing, and read as "no grants
    /// anywhere".
    ///
    /// It requires `revoked_at IS NULL`, so a revoked grant yields `None` rather
    /// than an id. That is what stops a client offering Leave on a seat whose
    /// grant is already gone, where the endpoint would answer 204 for a revoke
    /// that happened days ago.
    ///
    /// Reads `users` and `mokosh_bunyip_grants` across tenants, which is what
    /// the existing `tenant_memberships` read here already does: both callers
    /// hand this the migrator pool because the whole point is the seats an
    /// identity holds OUTSIDE the currently scoped tenant.
    pub async fn list_views_for_identity(
        pool: &PgPool,
        identity_id: Uuid,
        active_tenant_id: Option<Uuid>,
    ) -> Result<Vec<mokosh_types::auth::MembershipView>, sqlx::Error> {
        // PMS-1208 finding 11: grant rows are collected FIRST, and
        // tenant_memberships rows for the same tenant are skipped.
        //
        // Why the order matters. Migration 157's
        // `users_sync_to_identity` trigger fires on every `users`
        // INSERT/UPDATE and materialises a matching
        // `tenant_memberships` row (identity_id, tenant_id, role) via
        // an ON CONFLICT upsert. `AuthService::place_grantee_user`
        // INSERTs a `users` row for the JIT-placed grantee, and that
        // trigger writes a tenant_memberships row for the grantee's
        // identity in the granted tenant. Without this reorder the
        // memberships list carried the trigger-produced row from the
        // owner arm, `mokosh_bunyip_grant_id` came back None, the SPA
        // switcher rendered "Member" instead of "Shared with you",
        // and its `switch_to` fell to `POST /auth/switch-tenant/{id}`
        // (the own-tenant path) which minted a legacy HS256 session.
        //
        // Collecting grants first + skipping owner-arm dupes gives
        // the grantee's tenant its authoritative designation (the
        // grant's role, `mokosh_bunyip_grant_id: Some(...)`,
        // `bunyip_grant_id: Some(...)`) and keeps the SPA on the
        // bunyip mint path. An owner who happens to grant themselves
        // their OWN tenant surfaces as "Shared with you" for that
        // owner, which is unusual but not wrong (the grant IS what
        // put a row here) and does not affect their real access,
        // which the owner path resolves separately.
        // `bunyip_grant_id` is nullable per migration 225: a row written
        // by a pre-BUNYIP-674-webhook test seed, or any pre-PMS-1393
        // record, has `NULL` there. Keep the type Option so sqlx can
        // decode either case; the switcher's bunyip-mint path hides
        // the "Switch" affordance when the id is None, consistent with
        // how it reads a revoked grant.
        let grant_rows: Vec<GrantArmRow> = sqlx::query_as(
            r#"
            SELECT g.id, g.bunyip_grant_id, t.id AS tenant_id, t.name, t.slug, t.kind, g.role
            FROM mokosh_bunyip_grants g
            JOIN tenants t ON t.slug = g.mokosh_account_id
            WHERE g.revoked_at IS NULL
              AND g.role IS NOT NULL
              AND (
                  g.grantee_bunyip_user_id IN (
                      SELECT DISTINCT u.bunyip_user_id
                      FROM users u
                      JOIN identities i ON lower(i.email) = lower(u.email)
                      WHERE i.id = $1
                        AND u.bunyip_user_id IS NOT NULL
                        AND u.deleted_at IS NULL
                  )
                  OR (
                      g.grantee_email IS NOT NULL
                      AND EXISTS (
                          SELECT 1 FROM identities i
                          WHERE i.id = $1
                            AND lower(i.email) = lower(g.grantee_email)
                      )
                  )
              )
            ORDER BY g.granted_at ASC
            "#,
        )
        .bind(identity_id)
        .fetch_all(pool)
        .await
        .unwrap_or_default();

        let mut views: Vec<mokosh_types::auth::MembershipView> = grant_rows
            .into_iter()
            .map(|r| mokosh_types::auth::MembershipView {
                is_active: Some(r.tenant_id) == active_tenant_id,
                tenant_id: r.tenant_id,
                tenant_name: r.name,
                tenant_slug: r.slug,
                tenant_kind: r.kind,
                role: r.role,
                status: "active".to_string(),
                // PMS-1210: mokosh mirror id, used by DELETE
                // `/api/v1/my-grants/{id}` (mokosh's own row).
                mokosh_bunyip_grant_id: Some(r.id),
                // PMS-1208 finding 4: bunyip source-of-truth id, used by
                // the SPA's tenant switcher to mint a grant-scoped at+jwt
                // at bunyip's `POST /v1/grants/{id}/access-token`. Already
                // `Option` on the SELECT because the mirror column is
                // nullable (see migration 225); a pre-webhook or hand-
                // seeded row forwards `None`, which the SPA reads as "no
                // bunyip mint path for this seat".
                bunyip_grant_id: r.bunyip_grant_id,
            })
            .collect();

        let owner_rows: Vec<OwnerArmRow> = sqlx::query_as(
            r#"
            SELECT tm.tenant_id, t.name, t.slug, t.kind, tm.role, tm.status
            FROM tenant_memberships tm
            JOIN tenants t ON t.id = tm.tenant_id
            WHERE tm.identity_id = $1 AND tm.status = 'active'
            ORDER BY tm.joined_at ASC
            "#,
        )
        .bind(identity_id)
        .fetch_all(pool)
        .await?;

        for r in owner_rows {
            // A tenant already claimed by the grants arm keeps its
            // grant designation. See the head-of-function comment.
            if views.iter().any(|v| v.tenant_id == r.tenant_id) {
                continue;
            }
            views.push(mokosh_types::auth::MembershipView {
                is_active: Some(r.tenant_id) == active_tenant_id,
                tenant_id: r.tenant_id,
                tenant_name: r.name,
                tenant_slug: r.slug,
                tenant_kind: r.kind,
                role: r.role,
                status: r.status,
                mokosh_bunyip_grant_id: None,
                bunyip_grant_id: None,
            });
        }

        Ok(views)
    }
}

impl IdentityRepo {
    /// MAPPS-491: resolve `identities.id` from an email. Convenience
    /// used by the middleware to enrich `AuthState` with `identity_id`
    /// when only the user row is in scope.
    pub async fn find_id_by_email(pool: &PgPool, email: &str) -> Result<Option<Uuid>, sqlx::Error> {
        sqlx::query_scalar::<_, Uuid>(r#"SELECT id FROM identities WHERE lower(email) = lower($1)"#)
            .bind(email)
            .fetch_optional(pool)
            .await
    }

    /// MAPPS-497 item 4 (PMS-502 identity extension): burn the
    /// just-accepted TOTP step on the identity plane. Compare-and-set:
    /// only advances the watermark when the new step is strictly
    /// greater than the last one. Returns `true` on advance, `false`
    /// on replay (0 rows affected). Called from
    /// `authenticate_identity_first` on TOTP success; the caller must
    /// fail closed on `false`.
    pub async fn record_identity_mfa_success(
        pool: &PgPool,
        identity_id: Uuid,
        used_step: i64,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            UPDATE identities
            SET mfa_last_totp_step = $1, updated_at = NOW()
            WHERE id = $2 AND mfa_last_totp_step < $1
            "#,
        )
        .bind(used_step)
        .bind(identity_id)
        .execute(pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }
}
