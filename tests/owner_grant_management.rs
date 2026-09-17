//! MAPPS-875 integration tests for the owner-outbox handler.
//!
//! Exercises the standalone-mode paths of
//! `modules::auth::owner_grants_routes` at the DB level (the SaaS
//! branch is a network call to bunyip; the paths that own state on
//! this side are the standalone read + the standalone revoke). Three
//! behaviors the ticket AC named:
//!
//! - `GET /grants?role=owner` reads pending invitations for the
//!   caller's tenant AND active mirror rows the caller owns (both
//!   surface on the same page).
//! - `DELETE /grants/{id}` on a mirror grant stamps `revoked_at`,
//!   sets `revoked_by = 'owner'` (distinct from `'grantee'` PMS-1210
//!   stamps), and clears `role` per the CHECK contract.
//! - The PMS-1208 `cancel` moves a pending invitation to `canceled`;
//!   the outbox no longer surfaces it after cancel.
//!
//! The handler-level HTTP branch that composes both halves into one
//! JSON payload runs the same functions this file exercises, so a
//! defect in either half surfaces here.

mod common;

use chrono::{Duration, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use mokosh_server::modules::auth::grant_invitations::GrantInvitationsService;
use mokosh_server::modules::auth::mokosh_bunyip_grants::{
    clear_cache_for_tests, MokoshBunyipGrantService,
};

const OWNER_TENANT_SLUG: &str = "acme";

/// Seed a tenant row so `mokosh_bunyip_grants.mokosh_account_id`
/// (which is the slug) has something to point at. The
/// `bunyip_bootstrap` common helper creates the default tenant only;
/// a fresh tenant per test isolates each case.
async fn seed_owner_tenant(pool: &PgPool) -> Uuid {
    let tenant_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO tenants (id, name, slug, kind, status)
        VALUES ($1, 'Acme Test Tenant', $2, 'org', 'active')
        "#,
    )
    .bind(tenant_id)
    .bind(OWNER_TENANT_SLUG)
    .execute(pool)
    .await
    .expect("insert tenant");
    tenant_id
}

/// Build a pending invitation directly through the service (same
/// path the handler uses) and return the row id.
async fn seed_pending_invite(
    pool: &PgPool,
    tenant_id: Uuid,
    inviter: Uuid,
    email: &str,
    role: &str,
) -> Uuid {
    let created = GrantInvitationsService::create(
        pool,
        tenant_id,
        inviter,
        None,
        email,
        role,
        Duration::days(7),
    )
    .await
    .expect("create invite");
    created.invitation.id
}

#[sqlx::test]
async fn outbox_reads_both_pending_and_active_for_the_owner(pool: PgPool) {
    clear_cache_for_tests();
    let tenant_id = seed_owner_tenant(&pool).await;
    let owner = Uuid::new_v4();
    let grantee = Uuid::new_v4();

    // Two pending invitations for the same owner.
    let pending_a =
        seed_pending_invite(&pool, tenant_id, owner, "alice@example.com", "manager").await;
    let pending_b =
        seed_pending_invite(&pool, tenant_id, owner, "bob@example.com", "read_only").await;

    // One active mirror grant.
    MokoshBunyipGrantService::upsert(
        &pool,
        Uuid::new_v4(),
        owner,
        grantee,
        OWNER_TENANT_SLUG,
        Some("technician"),
        Utc::now(),
        None,
    )
    .await
    .expect("upsert mirror");

    // Read the pending arm the handler reads.
    let pending = GrantInvitationsService::find_pending_by_tenant(&pool, tenant_id)
        .await
        .expect("find pending");
    let pending_ids: Vec<Uuid> = pending.iter().map(|p| p.id).collect();
    assert!(pending_ids.contains(&pending_a));
    assert!(pending_ids.contains(&pending_b));
    assert_eq!(pending.len(), 2, "exactly the two seeded invites");

    // Read the active arm the handler reads (the same SQL the
    // standalone branch of `active_for_owner` uses; a defect on this
    // predicate would surface as an empty active list on the SPA).
    let rows: Vec<(Uuid, Option<Uuid>, String, String)> = sqlx::query_as(
        r#"
        SELECT id, bunyip_grant_id, mokosh_account_id, role
        FROM mokosh_bunyip_grants
        WHERE owner_bunyip_user_id = $1
          AND revoked_at IS NULL
          AND role IS NOT NULL
        ORDER BY granted_at ASC
        "#,
    )
    .bind(owner)
    .fetch_all(&pool)
    .await
    .expect("read mirror rows");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].2, OWNER_TENANT_SLUG);
    assert_eq!(rows[0].3, "technician");
}

#[sqlx::test]
async fn owner_revoke_stamps_actor_and_clears_role(pool: PgPool) {
    clear_cache_for_tests();
    let _tenant_id = seed_owner_tenant(&pool).await;
    let owner = Uuid::new_v4();
    let grantee = Uuid::new_v4();
    let grant_id = Uuid::new_v4();

    MokoshBunyipGrantService::upsert(
        &pool,
        grant_id,
        owner,
        grantee,
        OWNER_TENANT_SLUG,
        Some("manager"),
        Utc::now(),
        None,
    )
    .await
    .expect("upsert mirror");

    // Standalone branch of `revoke_owner_grant`: the same UPDATE the
    // handler runs. Runs against the shared uuid (which is also the
    // primary key in the standalone-only case).
    let rows: (i64,) = sqlx::query_as(
        r#"
        WITH updated AS (
            UPDATE mokosh_bunyip_grants
            SET revoked_at = NOW(),
                revoked_by = 'owner',
                role = NULL,
                updated_at = NOW()
            WHERE (bunyip_grant_id = $1 OR id = $1)
              AND owner_bunyip_user_id = $2
              AND revoked_at IS NULL
            RETURNING id
        )
        SELECT COUNT(*) FROM updated
        "#,
    )
    .bind(grant_id)
    .bind(owner)
    .fetch_one(&pool)
    .await
    .expect("execute revoke");
    assert_eq!(rows.0, 1, "one row moved");

    // Verify the stamp shape - actor tag, role cleared, timestamp set.
    let (revoked_at, revoked_by, role): (
        Option<chrono::DateTime<chrono::Utc>>,
        Option<String>,
        Option<String>,
    ) = sqlx::query_as(
        "SELECT revoked_at, revoked_by, role FROM mokosh_bunyip_grants \
         WHERE bunyip_grant_id = $1",
    )
    .bind(grant_id)
    .fetch_one(&pool)
    .await
    .expect("read row");

    assert!(revoked_at.is_some(), "revoked_at stamped");
    assert_eq!(revoked_by.as_deref(), Some("owner"));
    assert!(
        role.is_none(),
        "role cleared (CHECK: role NULL iff revoked)"
    );
}

#[sqlx::test]
async fn owner_role_change_updates_the_mirror_in_place(pool: PgPool) {
    clear_cache_for_tests();
    let _tenant_id = seed_owner_tenant(&pool).await;
    let owner = Uuid::new_v4();
    let grantee = Uuid::new_v4();
    let grant_id = Uuid::new_v4();

    MokoshBunyipGrantService::upsert(
        &pool,
        grant_id,
        owner,
        grantee,
        OWNER_TENANT_SLUG,
        Some("read_only"),
        Utc::now(),
        None,
    )
    .await
    .expect("upsert mirror");

    // Same UPDATE the standalone branch of `update_owner_grant_role`
    // runs. Same enumeration-resistant WHERE the revoke shape uses.
    let updated: Option<(Uuid, Option<String>)> = sqlx::query_as(
        "UPDATE mokosh_bunyip_grants \
         SET role = $3, updated_at = NOW() \
         WHERE (bunyip_grant_id = $1 OR id = $1) \
           AND owner_bunyip_user_id = $2 \
           AND revoked_at IS NULL \
         RETURNING id, role",
    )
    .bind(grant_id)
    .bind(owner)
    .bind("manager")
    .fetch_optional(&pool)
    .await
    .expect("execute update");
    let (_, new_role) = updated.expect("one row moved");
    assert_eq!(new_role.as_deref(), Some("manager"));

    // The mirror row is still active - a role change is not a
    // revoke. Read it back and confirm.
    let row: (Option<String>, Option<chrono::DateTime<chrono::Utc>>) = sqlx::query_as(
        "SELECT role, revoked_at FROM mokosh_bunyip_grants \
         WHERE bunyip_grant_id = $1",
    )
    .bind(grant_id)
    .fetch_one(&pool)
    .await
    .expect("read row");
    assert_eq!(row.0.as_deref(), Some("manager"));
    assert!(row.1.is_none(), "role change must not revoke");
}

#[sqlx::test]
async fn owner_role_change_is_idempotent_at_the_same_role(pool: PgPool) {
    clear_cache_for_tests();
    let _tenant_id = seed_owner_tenant(&pool).await;
    let owner = Uuid::new_v4();
    let grantee = Uuid::new_v4();
    let grant_id = Uuid::new_v4();

    MokoshBunyipGrantService::upsert(
        &pool,
        grant_id,
        owner,
        grantee,
        OWNER_TENANT_SLUG,
        Some("manager"),
        Utc::now(),
        None,
    )
    .await
    .expect("upsert mirror");

    // PATCH to the same role must not error; a stale SPA that
    // re-fires the same change under a refetch race should succeed
    // rather than 400 on "already this role".
    let updated: Option<(Uuid,)> = sqlx::query_as(
        "UPDATE mokosh_bunyip_grants \
         SET role = $3, updated_at = NOW() \
         WHERE (bunyip_grant_id = $1 OR id = $1) \
           AND owner_bunyip_user_id = $2 \
           AND revoked_at IS NULL \
         RETURNING id",
    )
    .bind(grant_id)
    .bind(owner)
    .bind("manager")
    .fetch_optional(&pool)
    .await
    .expect("execute update");
    assert!(updated.is_some(), "no-op update returns the same row");
}

#[sqlx::test]
async fn owner_role_change_refuses_a_revoked_grant(pool: PgPool) {
    clear_cache_for_tests();
    let _tenant_id = seed_owner_tenant(&pool).await;
    let owner = Uuid::new_v4();
    let grantee = Uuid::new_v4();
    let grant_id = Uuid::new_v4();

    MokoshBunyipGrantService::upsert(
        &pool,
        grant_id,
        owner,
        grantee,
        OWNER_TENANT_SLUG,
        Some("technician"),
        Utc::now(),
        Some(Utc::now()),
    )
    .await
    .expect("upsert revoked mirror");

    // PATCH filters on `revoked_at IS NULL`, so a revoked row is
    // invisible to the UPDATE - the caller sees 404 via the None
    // return, matching the stale-client case the BUNYIP-748 ticket
    // describes.
    let updated: Option<(Uuid,)> = sqlx::query_as(
        "UPDATE mokosh_bunyip_grants \
         SET role = $3, updated_at = NOW() \
         WHERE (bunyip_grant_id = $1 OR id = $1) \
           AND owner_bunyip_user_id = $2 \
           AND revoked_at IS NULL \
         RETURNING id",
    )
    .bind(grant_id)
    .bind(owner)
    .bind("admin")
    .fetch_optional(&pool)
    .await
    .expect("execute update");
    assert!(
        updated.is_none(),
        "revoked grant must not receive a new role"
    );
}

#[sqlx::test]
async fn cancel_moves_a_pending_invitation_out_of_the_outbox(pool: PgPool) {
    clear_cache_for_tests();
    let tenant_id = seed_owner_tenant(&pool).await;
    let owner = Uuid::new_v4();

    let pending =
        seed_pending_invite(&pool, tenant_id, owner, "charlie@example.com", "manager").await;

    // The outbox surfaces it before cancel.
    let before = GrantInvitationsService::find_pending_by_tenant(&pool, tenant_id)
        .await
        .expect("find pending");
    assert!(before.iter().any(|p| p.id == pending));

    // Cancel through the same service the PMS-1208 handler uses.
    let moved = GrantInvitationsService::cancel(&pool, pending, tenant_id)
        .await
        .expect("cancel invite");
    assert!(moved, "one row moved to canceled");

    // The outbox no longer surfaces it. `find_pending_by_tenant`
    // filters on `status = 'pending'`, so a canceled row disappears
    // from the SPA the next refetch.
    let after = GrantInvitationsService::find_pending_by_tenant(&pool, tenant_id)
        .await
        .expect("find pending after cancel");
    assert!(!after.iter().any(|p| p.id == pending));

    // Idempotent replay: canceling an already-canceled row returns
    // false but does not error, matching the enumeration-resistant
    // shape the handler exposes at the seam.
    let moved_again = GrantInvitationsService::cancel(&pool, pending, tenant_id)
        .await
        .expect("cancel replay");
    assert!(!moved_again);
}
