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
    /// PMS-1210 addition: also UNIONs in every active row from
    /// `mokosh_bunyip_grants` where the caller is the grantee, so
    /// the client's switcher renders "shared with you" tenants
    /// beside the caller's own. The grant rows carry
    /// `mokosh_bunyip_grant_id = Some(grant.id)`; the identity's
    /// own rows carry `None`, which is what the Leave affordance
    /// keys on. The bunyip sub is resolved from the identity's
    /// linked `users` row: BUNYIP-674 option B seeds `bunyip_user_id`
    /// on JIT provisioning, so a granted user has a non-NULL value
    /// there. A caller with no linked `users.bunyip_user_id`
    /// (legacy identity, or the mocks in the unit-test rig) reads
    /// zero grant rows and the shape reduces to what MAPPS-491
    /// shipped.
    pub async fn list_views_for_identity(
        pool: &PgPool,
        identity_id: Uuid,
        active_tenant_id: Option<Uuid>,
    ) -> Result<Vec<mokosh_types::auth::MembershipView>, sqlx::Error> {
        let rows: Vec<(Uuid, String, String, String, String, String)> = sqlx::query_as(
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

        let mut views: Vec<mokosh_types::auth::MembershipView> = rows
            .into_iter()
            .map(
                |(tenant_id, name, slug, kind, role, status)| mokosh_types::auth::MembershipView {
                    is_active: Some(tenant_id) == active_tenant_id,
                    tenant_id,
                    tenant_name: name,
                    tenant_slug: slug,
                    tenant_kind: kind,
                    role,
                    status,
                    mokosh_bunyip_grant_id: None,
                    bunyip_grant_id: None,
                },
            )
            .collect();

        // PMS-1210: append grant-based memberships. A single UNION-
        // like query joining identities.email/user_id to users
        // would be cleaner, but `identities` and `users` are on
        // separate identity/tenant axes, and the reliable link is
        // through the identity's email address hitting a users row
        // that carries a bunyip_user_id. The subquery below reads
        // every DISTINCT bunyip_user_id linked to this identity by
        // email (case-insensitive, matching how the JIT provisioner
        // seeds the row).
        //
        // PMS-1208 finding 3: the second identity axis is
        // `g.grantee_email`. Standalone-mode grantees have no
        // `users.bunyip_user_id` (there is no Bunyip identity plane),
        // and the sub-based subquery above never matches for them, so
        // grants they accepted stayed invisible to the switcher.
        // Migration 224 added `mokosh_bunyip_grants.grantee_email`
        // populated at accept time; matching it against the identity's
        // email (case-insensitively, matching the identity/users
        // email join shape) makes those grants visible without paying
        // anything in SaaS mode where both axes match the same row.
        let grant_rows: Vec<(Uuid, Uuid, Uuid, String, String, String, String)> = sqlx::query_as(
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

        for (grant_id, bunyip_grant_id, tenant_id, name, slug, kind, role) in grant_rows {
            // De-dupe against the identity's own tenant_memberships
            // list: an owner who ALSO grants themselves would not
            // appear twice.
            if views.iter().any(|v| v.tenant_id == tenant_id) {
                continue;
            }
            views.push(mokosh_types::auth::MembershipView {
                is_active: Some(tenant_id) == active_tenant_id,
                tenant_id,
                tenant_name: name,
                tenant_slug: slug,
                tenant_kind: kind,
                role,
                status: "active".to_string(),
                // PMS-1210: mokosh mirror id, used by
                // DELETE `/api/v1/my-grants/{id}` (mokosh's own row).
                mokosh_bunyip_grant_id: Some(grant_id),
                // PMS-1208 finding 4: bunyip source-of-truth id, used
                // by the SPA's tenant switcher to mint a grant-scoped
                // at+jwt at bunyip's `POST /v1/grants/{id}/access-token`
                // (bunyip's own row). Not the same id as
                // `mokosh_bunyip_grant_id` above: mokosh assigns the
                // mirror its own `id` on receive, and stores bunyip's
                // side-of-truth id verbatim as `bunyip_grant_id`.
                // Sending mokosh's mirror id to bunyip 404s because
                // bunyip's table has never seen that UUID.
                bunyip_grant_id: Some(bunyip_grant_id),
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
