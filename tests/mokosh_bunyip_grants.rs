//! BUNYIP-674 integration tests for the `mokosh_bunyip_grants` mirror
//! and the `mokosh_grant_changed` webhook receiver.
//!
//! Exercises the DB shape directly (via
//! `MokoshBunyipGrantService::upsert` / `is_grant_active`), which is
//! the same code path the webhook receiver runs against a verified
//! payload. HMAC verification is unit-tested inside `bunyip_webhook.rs`
//! and does not need a full HTTP boot here.

mod common;

use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use mokosh_server::modules::auth::mokosh_bunyip_grants::{
    clear_cache_for_tests, map_grant_role, MokoshBunyipGrantService,
};
use mokosh_types::auth::UserRole;

fn triple() -> (Uuid, Uuid, Uuid, &'static str) {
    (
        Uuid::new_v4(), // bunyip_grant_id
        Uuid::new_v4(), // owner
        Uuid::new_v4(), // grantee
        "acme",         // mokosh_account_id
    )
}

#[sqlx::test]
async fn upsert_granted_then_is_grant_active_returns_true(pool: PgPool) {
    clear_cache_for_tests();
    let (grant_id, owner, grantee, account) = triple();
    let now = Utc::now();

    MokoshBunyipGrantService::upsert(
        &pool,
        grant_id,
        owner,
        grantee,
        account,
        Some("manager"),
        now,
        None,
    )
    .await
    .expect("upsert granted");

    assert!(
        MokoshBunyipGrantService::is_grant_active(&pool, grantee, account)
            .await
            .expect("is_grant_active")
    );
}

#[sqlx::test]
async fn upsert_revoked_is_seen_as_inactive(pool: PgPool) {
    clear_cache_for_tests();
    let (grant_id, owner, grantee, account) = triple();
    let now = Utc::now();

    // First, a granted event.
    MokoshBunyipGrantService::upsert(
        &pool,
        grant_id,
        owner,
        grantee,
        account,
        Some("admin"),
        now,
        None,
    )
    .await
    .expect("granted");
    assert!(
        MokoshBunyipGrantService::is_grant_active(&pool, grantee, account)
            .await
            .unwrap()
    );

    // Then a revoked event. The cache invalidation on write is what
    // makes the very next read see the change without waiting for the
    // 30s TTL. The revoke's `at` must be STRICTLY newer than the grant's
    // stored `event_at` for the upsert to apply (migration 236); reusing
    // `now` would leave the row granted.
    let later = now + chrono::Duration::seconds(1);
    MokoshBunyipGrantService::upsert(
        &pool,
        grant_id,
        owner,
        grantee,
        account,
        None,
        later,
        Some(later),
    )
    .await
    .expect("revoked");
    assert!(
        !MokoshBunyipGrantService::is_grant_active(&pool, grantee, account)
            .await
            .unwrap()
    );
}

#[sqlx::test]
async fn is_grant_active_for_an_unknown_triple_is_false(pool: PgPool) {
    clear_cache_for_tests();
    // No upsert - the caller has never had a grant to this account.
    let unknown_grantee = Uuid::new_v4();
    assert!(
        !MokoshBunyipGrantService::is_grant_active(&pool, unknown_grantee, "acme")
            .await
            .unwrap()
    );
}

#[sqlx::test]
async fn a_revoked_row_can_be_reinstated_by_a_later_granted_event(pool: PgPool) {
    clear_cache_for_tests();
    let (grant_id, owner, grantee, account) = triple();
    let now = Utc::now();

    MokoshBunyipGrantService::upsert(
        &pool,
        grant_id,
        owner,
        grantee,
        account,
        Some("manager"),
        now,
        None,
    )
    .await
    .unwrap();
    let revoked_at = now + chrono::Duration::seconds(1);
    MokoshBunyipGrantService::upsert(
        &pool,
        grant_id,
        owner,
        grantee,
        account,
        None,
        revoked_at,
        Some(revoked_at),
    )
    .await
    .unwrap();
    assert!(
        !MokoshBunyipGrantService::is_grant_active(&pool, grantee, account)
            .await
            .unwrap()
    );

    // A `granted` event AFTER the revoked one is Bunyip saying the
    // grant is live again (a revoke-then-regrant on Bunyip mints a new
    // bunyip_grant_id but keeps the same triple). The mirror follows.
    // Newer than `revoked_at` (migration 236's strictly-newer guard).
    let new_grant_id = Uuid::new_v4();
    MokoshBunyipGrantService::upsert(
        &pool,
        new_grant_id,
        owner,
        grantee,
        account,
        Some("read_only"),
        revoked_at + chrono::Duration::seconds(1),
        None,
    )
    .await
    .unwrap();
    assert!(
        MokoshBunyipGrantService::is_grant_active(&pool, grantee, account)
            .await
            .unwrap()
    );
}

#[sqlx::test]
async fn a_duplicate_granted_event_is_idempotent(pool: PgPool) {
    clear_cache_for_tests();
    let (grant_id, owner, grantee, account) = triple();
    let now = Utc::now();

    // First delivery.
    MokoshBunyipGrantService::upsert(
        &pool,
        grant_id,
        owner,
        grantee,
        account,
        Some("technician"),
        now,
        None,
    )
    .await
    .unwrap();
    // A retried delivery of the same event carries the same body; the
    // upsert-on-triple keeps ONE row.
    MokoshBunyipGrantService::upsert(
        &pool,
        grant_id,
        owner,
        grantee,
        account,
        Some("technician"),
        now,
        None,
    )
    .await
    .unwrap();

    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM mokosh_bunyip_grants \
         WHERE grantee_bunyip_user_id = $1 AND mokosh_account_id = $2",
    )
    .bind(grantee)
    .bind(account)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count.0, 1);
    assert!(
        MokoshBunyipGrantService::is_grant_active(&pool, grantee, account)
            .await
            .unwrap()
    );
}

/// A `revoked` event for a triple the mirror never saw the `granted`
/// for still lands the row in the revoked state (the receiver's
/// no-op-on-unknown contract). The parent BUNYIP-674 ticket names this
/// as the "race where mokosh missed the granted webhook still lands
/// in the correct state" case.
#[sqlx::test]
async fn a_revoked_event_for_an_unknown_triple_lands_the_revoked_row(pool: PgPool) {
    clear_cache_for_tests();
    let (grant_id, owner, grantee, account) = triple();
    let now = Utc::now();

    MokoshBunyipGrantService::upsert(
        &pool,
        grant_id,
        owner,
        grantee,
        account,
        None,
        now,
        Some(now),
    )
    .await
    .expect("revoked on unknown triple");

    let (revoked_at,): (Option<chrono::DateTime<chrono::Utc>>,) = sqlx::query_as(
        "SELECT revoked_at FROM mokosh_bunyip_grants \
         WHERE grantee_bunyip_user_id = $1 AND mokosh_account_id = $2",
    )
    .bind(grantee)
    .bind(account)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(revoked_at.is_some());
    assert!(
        !MokoshBunyipGrantService::is_grant_active(&pool, grantee, account)
            .await
            .unwrap()
    );
}

use mokosh_server::modules::auth::oidc_rs::AtClaims;
use mokosh_server::modules::auth::AuthService;
use mokosh_server::Database;

fn claims_with_grant(sub: Uuid, mokosh_account_id: Option<&str>) -> AtClaims {
    AtClaims {
        iss: "https://bunyip.test".into(),
        sub: sub.to_string(),
        aud: "https://api.mokosh.test".into(),
        client_id: "mokosh".into(),
        scope: "openid".into(),
        exp: 0,
        iat: 0,
        bunyip_role: Some("subscriber".to_string()),
        mokosh_grant_id: mokosh_account_id.map(|_| Uuid::new_v4().to_string()),
        mokosh_grant_role: mokosh_account_id.map(|_| "manager".to_string()),
        mokosh_grant_account_id: mokosh_account_id.map(str::to_string),
    }
}

/// BUNYIP-674 end-to-end: a token without a grant claim passes the gate
/// with no DB touch; a token with an active grant passes; a token whose
/// grant is revoked is refused with Forbidden.
#[sqlx::test]
async fn ensure_grant_still_active_if_claimed_gates_on_the_mirror(pool: PgPool) {
    clear_cache_for_tests();
    let auth = AuthService::new(Database::from_pool(pool.clone()), "test-secret".into());

    let grantee = Uuid::new_v4();
    let account = "acme";

    // No grant claim: always Ok.
    auth.ensure_grant_still_active_if_claimed(&claims_with_grant(grantee, None))
        .await
        .expect("no grant claim => pass");

    // Grant claim but no matching mirror row: Forbidden.
    let err = auth
        .ensure_grant_still_active_if_claimed(&claims_with_grant(grantee, Some(account)))
        .await
        .expect_err("no mirror row => Forbidden");
    assert!(
        matches!(err, mokosh_server::utils::error::AppError::Forbidden(_)),
        "expected Forbidden, got {err:?}"
    );

    // Now seed an active grant on the mirror.
    let now = Utc::now();
    MokoshBunyipGrantService::upsert(
        &pool,
        Uuid::new_v4(), // bunyip_grant_id
        Uuid::new_v4(), // owner
        grantee,
        account,
        Some("manager"),
        now,
        None,
    )
    .await
    .expect("upsert active grant");

    auth.ensure_grant_still_active_if_claimed(&claims_with_grant(grantee, Some(account)))
        .await
        .expect("active grant => pass");

    // Revoke it and the same claim now fails. `at` must be strictly newer
    // than the row's stored `event_at` (migration 236).
    let revoked_at = now + chrono::Duration::seconds(1);
    MokoshBunyipGrantService::upsert(
        &pool,
        Uuid::new_v4(),
        Uuid::new_v4(),
        grantee,
        account,
        None,
        revoked_at,
        Some(revoked_at),
    )
    .await
    .expect("revoke grant");
    let err = auth
        .ensure_grant_still_active_if_claimed(&claims_with_grant(grantee, Some(account)))
        .await
        .expect_err("revoked grant => Forbidden");
    assert!(matches!(
        err,
        mokosh_server::utils::error::AppError::Forbidden(_)
    ));
}

/// BUNYIP-674 option B, phase 1: the new (bunyip_user_id, tenant_id)
/// resolver finds a placement row keyed on the caller's Bunyip sub in
/// a specific tenant. Two owner rows for the SAME bunyip sub in two
/// different tenants (the shape a grantee turns into) are both
/// resolvable, and each returns the row from its own tenant.
#[sqlx::test]
async fn find_bunyip_principal_in_tenant_returns_the_row_for_that_tenant(pool: PgPool) {
    let auth = AuthService::new(Database::from_pool(pool.clone()), "test-secret".into());

    // Two tenants, seeded here rather than through the app helpers so
    // this file stays free of the process-global `tracing` subscriber
    // `common` installs (`bunyip_query_budget` documents the reason).
    let tenant_a = Uuid::new_v4();
    let tenant_b = Uuid::new_v4();
    for (id, name, slug) in [
        (tenant_a, "TenantA", "tenant-a"),
        (tenant_b, "TenantB", "tenant-b"),
    ] {
        sqlx::query("INSERT INTO tenants (id, name, slug, status, kind) VALUES ($1, $2, $3, 'active', 'org')")
            .bind(id)
            .bind(name)
            .bind(slug)
            .execute(&pool)
            .await
            .expect("seed tenant");
    }

    // ONE bunyip sub, TWO placement rows (a's owner + b's grantee).
    // Each row gets a distinct `users.id` so the FKs elsewhere in the
    // schema still distinguish them; both point at the same
    // `bunyip_user_id` so the resolver can find either by
    // (sub, tenant_id). This is the shape option B lands.
    let bunyip_sub = Uuid::new_v4();
    let user_in_a = Uuid::new_v4();
    let user_in_b = Uuid::new_v4();
    for (uid, tid, role, email) in [
        (user_in_a, tenant_a, "admin", "shared@example.com"),
        (user_in_b, tenant_b, "manager", "shared@example.com"),
    ] {
        sqlx::query(
            "INSERT INTO users (id, tenant_id, email, first_name, last_name, role, \
             status, email_verified_at, bunyip_user_id) \
             VALUES ($1, $2, $3, 'Shared', 'User', $4, 'active', NOW(), $5)",
        )
        .bind(uid)
        .bind(tid)
        .bind(email)
        .bind(role)
        .bind(bunyip_sub)
        .execute(&pool)
        .await
        .expect("seed placement row");
    }

    let in_a = auth
        .find_bunyip_principal_in_tenant(bunyip_sub, tenant_a)
        .await
        .expect("resolve in tenant A")
        .expect("row present in A");
    assert_eq!(in_a.user.id, user_in_a);
    assert_eq!(in_a.user.tenant_id, tenant_a);
    assert_eq!(in_a.placement.1, "admin");

    let in_b = auth
        .find_bunyip_principal_in_tenant(bunyip_sub, tenant_b)
        .await
        .expect("resolve in tenant B")
        .expect("row present in B");
    assert_eq!(in_b.user.id, user_in_b);
    assert_eq!(in_b.user.tenant_id, tenant_b);
    assert_eq!(in_b.placement.1, "manager");

    // A tenant the sub is not placed in returns None (the grant path
    // then knows to JIT-provision or refuse, depending on whether the
    // mirror has an active grant).
    let unknown_tenant = Uuid::new_v4();
    let absent = auth
        .find_bunyip_principal_in_tenant(bunyip_sub, unknown_tenant)
        .await
        .expect("resolve in a tenant with no placement");
    assert!(absent.is_none());
}

/// BUNYIP-674 option B phase 2: the vocab mapper carries the whole
/// PMS-1162 role set onto Mokosh's [`UserRole`]. Not every mapping is
/// a bijection - `read_only` is deliberately mapped to Technician for
/// now (mokosh has no first-class read-only tier) - so this pins the
/// intended shape so the fallback is a deliberate act.
#[test]
fn map_grant_role_covers_the_pms_1162_vocabulary() {
    assert_eq!(map_grant_role("admin"), Some(UserRole::Admin));
    assert_eq!(map_grant_role("manager"), Some(UserRole::Manager));
    assert_eq!(map_grant_role("technician"), Some(UserRole::Technician));
    assert_eq!(map_grant_role("finance"), Some(UserRole::Finance));
    // Intentional over-privilege: read_only lands as Technician until
    // a first-class read-only tier ships. The comment on the mapper
    // spells this out; this assertion is the pin that would fail if a
    // future edit collapsed the arm and the fallback silently became
    // Admin or Manager.
    assert_eq!(map_grant_role("read_only"), Some(UserRole::Technician));
    // Anything outside the vocab returns None so the middleware
    // refuses the request rather than picking a fallback role for the
    // caller.
    assert_eq!(map_grant_role(""), None);
    assert_eq!(map_grant_role("owner"), None);
    assert_eq!(map_grant_role("ADMIN"), None);
    assert_eq!(map_grant_role("super_admin"), None);
}

/// BUNYIP-674 option B phase 2: `active_grant_role` returns the role
/// on an active row and `None` on a revoked one, drawing off the
/// same 30s cache `is_grant_active` populates so the request-path
/// pair of reads pays for ONE database round-trip.
#[sqlx::test]
async fn active_grant_role_reads_through_the_shared_cache(pool: PgPool) {
    clear_cache_for_tests();
    let (grant_id, owner, grantee, account) = triple();
    let now = Utc::now();

    // No row → no role.
    assert_eq!(
        MokoshBunyipGrantService::active_grant_role(&pool, grantee, account)
            .await
            .unwrap(),
        None
    );

    // Granted at manager → the role is what the request path reads.
    MokoshBunyipGrantService::upsert(
        &pool,
        grant_id,
        owner,
        grantee,
        account,
        Some("manager"),
        now,
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        MokoshBunyipGrantService::active_grant_role(&pool, grantee, account)
            .await
            .unwrap(),
        Some("manager".to_string())
    );

    // Revoked → the role goes away with the activeness. `at` must be
    // strictly newer than the row's stored `event_at` (migration 236).
    let revoked_at = now + chrono::Duration::seconds(1);
    MokoshBunyipGrantService::upsert(
        &pool,
        grant_id,
        owner,
        grantee,
        account,
        None,
        revoked_at,
        Some(revoked_at),
    )
    .await
    .unwrap();
    assert_eq!(
        MokoshBunyipGrantService::active_grant_role(&pool, grantee, account)
            .await
            .unwrap(),
        None
    );
}

/// BUNYIP-674 option B phase 2: JIT-provisioning a grantee places the
/// row at the grant's role in the target tenant. A duplicate call
/// (the same sub + tenant) upserts on the partial UNIQUE index and
/// keeps ONE row.
#[sqlx::test]
async fn place_grantee_user_jits_the_row_and_is_idempotent(pool: PgPool) {
    let auth = AuthService::new(Database::from_pool(pool.clone()), "test-secret".into());
    let tenant_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, status, kind) \
         VALUES ($1, 'Acme', 'acme', 'active', 'org')",
    )
    .bind(tenant_id)
    .execute(&pool)
    .await
    .unwrap();

    let sub = Uuid::new_v4();
    let placed = auth
        .place_grantee_user(
            sub,
            tenant_id,
            UserRole::Manager,
            "grantee@example.com",
            Some("Guest"),
            Some("Person"),
            true,
        )
        .await
        .expect("first JIT");
    assert_eq!(placed.tenant_id, tenant_id);
    assert_eq!(placed.role, UserRole::Manager);
    assert_eq!(placed.email, "grantee@example.com");
    // The row's `id` is FRESH, NOT the bunyip sub: that decoupling is
    // what lets the same sub occupy their own tenant AND this granted
    // tenant at the same time.
    assert_ne!(placed.id, sub);

    // A second call for the same triple keeps the row and can change
    // the role on the fly (the receiver-driven re-grant with a
    // different role runs through this exact path on next request).
    let re_placed = auth
        .place_grantee_user(
            sub,
            tenant_id,
            UserRole::Finance,
            "grantee@example.com",
            None,
            None,
            true,
        )
        .await
        .expect("re-place with a new role");
    assert_eq!(
        re_placed.id, placed.id,
        "same id, upserted through the UNIQUE"
    );
    assert_eq!(re_placed.role, UserRole::Finance);

    let count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM users WHERE bunyip_user_id = $1 AND tenant_id = $2")
            .bind(sub)
            .bind(tenant_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count.0, 1);
}

/// BUNYIP-674 option B phase 3: `tombstone_grantee_placement` sets
/// `deleted_at` on the row so `find_bunyip_principal_in_tenant` stops
/// seeing it. A follow-up `place_grantee_user` on the same triple
/// clears the tombstone (the re-grant heals the revoke).
#[sqlx::test]
async fn tombstone_then_reinstate_via_place_grantee_user(pool: PgPool) {
    let auth = AuthService::new(Database::from_pool(pool.clone()), "test-secret".into());
    let tenant_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, status, kind) \
         VALUES ($1, 'Acme', 'acme', 'active', 'org')",
    )
    .bind(tenant_id)
    .execute(&pool)
    .await
    .unwrap();

    let sub = Uuid::new_v4();
    let placed = auth
        .place_grantee_user(
            sub,
            tenant_id,
            UserRole::Manager,
            "g@example.com",
            Some("G"),
            Some("P"),
            true,
        )
        .await
        .unwrap();

    // Revoke: tombstone.
    auth.tombstone_grantee_placement(sub, tenant_id)
        .await
        .unwrap();
    assert!(
        auth.find_bunyip_principal_in_tenant(sub, tenant_id)
            .await
            .unwrap()
            .is_none(),
        "tombstoned row is invisible to the resolver"
    );

    // Idempotent second tombstone.
    auth.tombstone_grantee_placement(sub, tenant_id)
        .await
        .unwrap();

    // Re-grant lands the same row back live and the resolver finds
    // it again (same `users.id`, so any FK on the row from an
    // audit trail or ticket assignment is preserved).
    let reinstated = auth
        .place_grantee_user(
            sub,
            tenant_id,
            UserRole::Admin,
            "g@example.com",
            None,
            None,
            true,
        )
        .await
        .unwrap();
    assert_eq!(reinstated.id, placed.id);
    assert_eq!(reinstated.role, UserRole::Admin);
    let after = auth
        .find_bunyip_principal_in_tenant(sub, tenant_id)
        .await
        .unwrap()
        .expect("reinstated row visible again");
    assert_eq!(after.user.id, placed.id);
    assert_eq!(after.placement.1, "admin");
}

/// Migration 221's backfill invariant: an OWNER row inserted with only
/// `id` (as every pre-BUNYIP-674 code path does) is not visible to the
/// new resolver, because bunyip_user_id is NULL on it. This pins that
/// the fallback belongs at the CALLER (a request-time resolver runs
/// the new lookup first and falls back to `find_bunyip_principal` for
/// pre-migration rows) rather than being welded into the query with
/// COALESCE, which would make it impossible to tell "same sub, other
/// tenant" apart from "unmirrored row".
#[sqlx::test]
async fn a_row_with_no_bunyip_user_id_is_invisible_to_the_new_resolver(pool: PgPool) {
    let auth = AuthService::new(Database::from_pool(pool.clone()), "test-secret".into());
    let tenant_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, status, kind) VALUES ($1, 'T', 't', 'active', 'org')",
    )
    .bind(tenant_id)
    .execute(&pool)
    .await
    .unwrap();

    // Pre-BUNYIP-674 shape: id = sub, bunyip_user_id defaulted to NULL.
    let sub = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, tenant_id, email, first_name, last_name, role, \
         status, email_verified_at) \
         VALUES ($1, $2, 'legacy@example.com', 'L', 'U', 'admin', 'active', NOW())",
    )
    .bind(sub)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .unwrap();

    let via_new = auth
        .find_bunyip_principal_in_tenant(sub, tenant_id)
        .await
        .expect("query runs");
    assert!(
        via_new.is_none(),
        "the new resolver refuses a NULL-mirror row so the caller can decide \
         to backfill or fall back to find_bunyip_principal"
    );

    // The old resolver still finds it by id.
    let via_old = auth
        .find_bunyip_principal(sub)
        .await
        .expect("query runs")
        .expect("legacy row is still resolvable by id");
    assert_eq!(via_old.user.id, sub);
}

/// PMS-1295: a `granted` event older than the stored revoked row leaves
/// it revoked, and a re-delivery of the same event changes nothing.
#[sqlx::test]
async fn a_stale_granted_event_never_reinstates_and_a_duplicate_is_a_no_op(pool: PgPool) {
    clear_cache_for_tests();
    let (grant_id, owner, grantee, account) = triple();
    let t1 = Utc::now() - chrono::Duration::minutes(10);
    let t2 = t1 + chrono::Duration::minutes(5);

    let applied = MokoshBunyipGrantService::upsert(
        &pool,
        grant_id,
        owner,
        grantee,
        account,
        None,
        t2,
        Some(t2),
    )
    .await
    .unwrap();
    assert!(applied);

    let stale = MokoshBunyipGrantService::upsert(
        &pool,
        grant_id,
        owner,
        grantee,
        account,
        Some("admin"),
        t1,
        None,
    )
    .await
    .unwrap();
    assert!(!stale);
    assert!(
        !MokoshBunyipGrantService::is_grant_active(&pool, grantee, account)
            .await
            .unwrap()
    );

    let before: (chrono::DateTime<Utc>,) = sqlx::query_as(
        "SELECT updated_at FROM mokosh_bunyip_grants WHERE grantee_bunyip_user_id = $1",
    )
    .bind(grantee)
    .fetch_one(&pool)
    .await
    .unwrap();
    let dup = MokoshBunyipGrantService::upsert(
        &pool,
        grant_id,
        owner,
        grantee,
        account,
        None,
        t2,
        Some(t2),
    )
    .await
    .unwrap();
    assert!(!dup);
    let after: (chrono::DateTime<Utc>,) = sqlx::query_as(
        "SELECT updated_at FROM mokosh_bunyip_grants WHERE grantee_bunyip_user_id = $1",
    )
    .bind(grantee)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(before.0, after.0);
}
