//! MAPPS-475 (MAPPS-474 phase 1): backfill + dual-write trigger coverage
//! for `identities` and `tenant_memberships`.
//!
//! Phase 1 is scaffolding: the two tables exist, are populated from every
//! legacy `users` write via trigger, and read helpers in
//! `mokosh_server::db::identity` compile. No handler consumes them yet
//! (phase 2 wires `/auth/memberships`); these tests prove the plumbing.

mod common;

use sqlx::PgPool;
use uuid::Uuid;

use mokosh_server::db::identity::{IdentityRepo, MembershipRepo};

async fn insert_user(
    pool: &PgPool,
    tenant_id: Uuid,
    email: &str,
    role: &str,
    status: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO users (
            id, tenant_id, email, password_hash,
            first_name, last_name, role, status
        )
        VALUES ($1, $2, $3, 'hash', 'First', 'Last', $4, $5)
        "#,
    )
    .bind(id)
    .bind(tenant_id)
    .bind(email)
    .bind(role)
    .bind(status)
    .execute(pool)
    .await
    .expect("insert users row");
    id
}

async fn insert_tenant(pool: &PgPool, name: &str, slug: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO tenants (id, name, slug, kind, status)
        VALUES ($1, $2, $3, 'org', 'active')
        "#,
    )
    .bind(id)
    .bind(name)
    .bind(slug)
    .execute(pool)
    .await
    .expect("insert tenants row");
    id
}

#[sqlx::test]
async fn seed_admin_is_backfilled_into_identity_and_membership(pool: PgPool) {
    let (admin_id, admin_email, _password) = common::seed_admin(&pool).await;

    let identity = IdentityRepo::find_by_email(&pool, &admin_email)
        .await
        .expect("find identity")
        .expect("identity exists");
    assert_eq!(identity.id, admin_id);
    assert_eq!(identity.email.to_lowercase(), admin_email.to_lowercase());
    assert_eq!(identity.status, "active");

    let memberships = MembershipRepo::list_active_for_identity(&pool, identity.id)
        .await
        .expect("list memberships");
    assert_eq!(memberships.len(), 1);
    assert_eq!(memberships[0].tenant_id, common::DEFAULT_TENANT_ID);
    assert_eq!(memberships[0].role, "super_admin");
}

#[sqlx::test]
async fn insert_new_users_row_creates_identity_and_membership(pool: PgPool) {
    let tenant = insert_tenant(&pool, "Acme Co", "acme").await;
    let user_id = insert_user(&pool, tenant, "new@example.com", "admin", "active").await;

    let identity = IdentityRepo::find_by_email(&pool, "new@example.com")
        .await
        .expect("find identity")
        .expect("identity exists");
    assert_eq!(identity.id, user_id);
    assert_eq!(identity.email, "new@example.com");

    let membership = MembershipRepo::find(&pool, identity.id, tenant)
        .await
        .expect("find membership")
        .expect("membership exists");
    assert_eq!(membership.role, "admin");
    assert_eq!(membership.status, "active");
}

#[sqlx::test]
async fn insert_users_row_with_existing_email_reuses_identity(pool: PgPool) {
    // Same human, two tenants: one identity, two memberships.
    let tenant_a = insert_tenant(&pool, "Alpha Co", "alpha").await;
    let tenant_b = insert_tenant(&pool, "Beta Co", "beta").await;

    let user_a = insert_user(&pool, tenant_a, "same@example.com", "admin", "active").await;
    let user_b = insert_user(&pool, tenant_b, "SAME@example.com", "technician", "active").await;

    let identity = IdentityRepo::find_by_email(&pool, "same@example.com")
        .await
        .expect("find identity")
        .expect("identity exists");
    // First insert wins the identity id (before the second users row exists).
    assert_eq!(identity.id, user_a);
    assert_ne!(identity.id, user_b);

    let memberships = MembershipRepo::list_active_for_identity(&pool, identity.id)
        .await
        .expect("list memberships");
    let tenant_ids: Vec<Uuid> = memberships.iter().map(|m| m.tenant_id).collect();
    assert_eq!(memberships.len(), 2);
    assert!(tenant_ids.contains(&tenant_a));
    assert!(tenant_ids.contains(&tenant_b));

    let role_a = memberships
        .iter()
        .find(|m| m.tenant_id == tenant_a)
        .unwrap()
        .role
        .as_str();
    let role_b = memberships
        .iter()
        .find(|m| m.tenant_id == tenant_b)
        .unwrap()
        .role
        .as_str();
    assert_eq!(role_a, "admin");
    assert_eq!(role_b, "technician");
}

#[sqlx::test]
async fn update_users_role_propagates_to_membership(pool: PgPool) {
    let tenant = insert_tenant(&pool, "Gamma Co", "gamma").await;
    let user_id = insert_user(&pool, tenant, "role@example.com", "technician", "active").await;

    sqlx::query("UPDATE users SET role = 'manager' WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("update role");

    let identity = IdentityRepo::find_by_email(&pool, "role@example.com")
        .await
        .expect("find")
        .expect("exists");
    let membership = MembershipRepo::find(&pool, identity.id, tenant)
        .await
        .expect("find")
        .expect("exists");
    assert_eq!(membership.role, "manager");
}

#[sqlx::test]
async fn update_users_status_propagates_to_membership(pool: PgPool) {
    let tenant = insert_tenant(&pool, "Delta Co", "delta").await;
    let user_id = insert_user(&pool, tenant, "status@example.com", "technician", "active").await;

    sqlx::query("UPDATE users SET status = 'inactive' WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("update status");

    let identity = IdentityRepo::find_by_email(&pool, "status@example.com")
        .await
        .expect("find")
        .expect("exists");
    let membership = MembershipRepo::find(&pool, identity.id, tenant)
        .await
        .expect("find")
        .expect("exists");
    assert_eq!(membership.status, "inactive");
}

// MAPPS-551 (rewrite of the pre-551 mirror pin): a UPDATE users
// password_hash write must NOT propagate to identities. The MAPPS-498
// mirror still fires for every OTHER per-human column (see
// `update_identity_propagates_to_users` below), but password_hash is
// authoritative per-tenant on `users`. Two portals sharing an email
// hold independent passwords, forever, and a change on one row must
// not overwrite the identity's hash (which would then re-mirror to
// every other users row at that email via the reverse trigger).
#[sqlx::test]
async fn update_users_password_hash_does_not_propagate_to_identity(pool: PgPool) {
    let tenant = insert_tenant(&pool, "Epsilon Co", "epsilon").await;
    let user_id = insert_user(&pool, tenant, "pw@example.com", "technician", "active").await;

    // Read the identity's password_hash as it was seeded by the
    // users INSERT (identity's INSERT branch still copies
    // password_hash on first-seen email; that seed is intentional
    // per migration 135's inline comment).
    let identity_hash_before: Option<String> =
        sqlx::query_scalar("SELECT password_hash FROM identities WHERE id = $1")
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .expect("read identity hash before");

    sqlx::query("UPDATE users SET password_hash = 'new-hash-post-551' WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("update pw");

    let identity_after = IdentityRepo::find_by_id(&pool, user_id)
        .await
        .expect("find")
        .expect("exists");
    assert_eq!(
        identity_after.password_hash, identity_hash_before,
        "MAPPS-551: users password_hash UPDATE must NOT touch identities.password_hash"
    );
    // And the users row DID change (sanity check we actually ran the
    // update).
    let users_hash_after: Option<String> =
        sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .expect("read users hash after");
    assert_eq!(users_hash_after.as_deref(), Some("new-hash-post-551"));
}

/// PMS-1120: a write to `identities` does NOT reach `users`.
///
/// MAPPS-498 installed that direction and this test pinned it. It was half of
/// a lock-order cycle (`tests/identity_mirror_lock_order.rs` has the shape),
/// and the fan-out it promised never worked outside a superuser test anyway:
/// the trigger carried no `SECURITY DEFINER`, so its `UPDATE users` ran under
/// the caller's tenant GUC and RLS filtered it to one tenant. PMS-1223 found
/// the same gap for `mfa_enabled` and stopped relying on the mirror; this
/// removes the direction rather than leaving a half-working one.
///
/// So the rule is now one way: `users` is where a human's profile is written
/// and it flows to `identities`. A write that must reach both planes writes
/// both, `users` first, which is what `write_mfa_secret` and
/// `write_mfa_enabled` do.
#[sqlx::test]
async fn a_write_to_identities_does_not_reach_users(pool: PgPool) {
    let (admin_id, _email, _password) = common::seed_admin(&pool).await;
    sqlx::query("UPDATE identities SET mobile = '+15550001111' WHERE id = $1")
        .bind(admin_id)
        .execute(&pool)
        .await
        .expect("update identity mobile");
    let mobile: Option<String> = sqlx::query_scalar("SELECT mobile FROM users WHERE id = $1")
        .bind(admin_id)
        .fetch_one(&pool)
        .await
        .expect("read users.mobile");
    assert_eq!(
        mobile, None,
        "the identity plane no longer writes back to users"
    );
}

/// PMS-1120: a profile edit reaches the OTHER tenant's seat by being written
/// there, not by a mirror carrying it.
///
/// MAPPS-498 had one `UPDATE identities` fan out to every `users` row at that
/// email. That direction is gone, so the same two-tenant shape is pinned from
/// the side that remains: each seat is its own row, and editing one leaves the
/// other alone. A caller that genuinely means "every seat this human holds"
/// says so, on the migrator pool, the way `write_mfa_enabled` does - RLS would
/// have stopped the mirror reaching the second tenant regardless.
#[sqlx::test]
async fn a_second_tenants_seat_is_its_own_row(pool: PgPool) {
    let (admin_id, email, _password) = common::seed_admin(&pool).await;
    let tenant_b = insert_tenant(&pool, "Beta Co", "beta-497").await;
    let user_b_id = insert_user(&pool, tenant_b, &email, "admin", "active").await;

    // Both seats back one identity.
    let identity = IdentityRepo::find_by_email(&pool, &email)
        .await
        .expect("find")
        .expect("exists");

    // Editing one seat mirrors forward to the shared identity...
    sqlx::query("UPDATE users SET first_name = 'Renamed' WHERE id = $1")
        .bind(admin_id)
        .execute(&pool)
        .await
        .expect("rename the first seat");
    let identity_name: String =
        sqlx::query_scalar("SELECT first_name FROM identities WHERE id = $1")
            .bind(identity.id)
            .fetch_one(&pool)
            .await
            .expect("read the identity");
    assert_eq!(identity_name, "Renamed", "forward mirror still carries it");

    // ...and leaves the other seat as it was, because nothing travels back.
    let other: String = sqlx::query_scalar("SELECT first_name FROM users WHERE id = $1")
        .bind(user_b_id)
        .fetch_one(&pool)
        .await
        .expect("read the second seat");
    assert_eq!(other, "First", "the other seat is untouched");
}

/// MAPPS-498: a plain UPDATE on users still round-trips via the
/// users -> identity mirror WITHOUT the identity -> users mirror
/// re-firing (would cause infinite recursion). The pg_trigger_depth()
/// guard on sync_identity_to_users breaks the cycle.
#[sqlx::test]
async fn mirror_does_not_recurse(pool: PgPool) {
    let (admin_id, _email, _password) = common::seed_admin(&pool).await;
    // A plain UPDATE. If the mirrors cycle, sqlx errors on stack
    // overflow / recursion depth.
    sqlx::query("UPDATE users SET mobile = '+15550002222' WHERE id = $1")
        .bind(admin_id)
        .execute(&pool)
        .await
        .expect("update users mobile without recursion");
    let identity_mobile: Option<String> =
        sqlx::query_scalar("SELECT mobile FROM identities WHERE id = $1")
            .bind(admin_id)
            .fetch_one(&pool)
            .await
            .expect("read identity mobile");
    assert_eq!(identity_mobile.as_deref(), Some("+15550002222"));
}

/// MAPPS-500 (MAPPS-496 stage 2b): a successful login writes
/// `identities.last_login_at`; the MAPPS-498 mirror propagates it
/// back to `users.last_login_at` for every membership.
#[sqlx::test]
async fn login_stamps_last_login_at_on_identity(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let _token = common::login(&app, &email, &password).await;

    let identity_ts: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT last_login_at FROM identities WHERE id = $1")
            .bind(admin_id)
            .fetch_one(&app.pool)
            .await
            .expect("read identity ts");
    let users_ts: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT last_login_at FROM users WHERE id = $1")
            .bind(admin_id)
            .fetch_one(&app.pool)
            .await
            .expect("read users ts");
    assert!(identity_ts.is_some(), "identity last_login_at stamped");
    assert_eq!(
        identity_ts, users_ts,
        "mirror keeps users last_login_at in sync"
    );
}

/// PMS-1120: a login through one tenant stamps THAT seat, and the identity.
///
/// MAPPS-500 wanted the stamp on every `users` row the identity backs, and
/// pinned it here. It never worked that way outside this test: the back-mirror
/// that carried it had no `SECURITY DEFINER`, so RLS filtered its `UPDATE
/// users` to the caller's tenant on the serving pool, and only a superuser
/// connection like the one below saw the fan-out. With the mirror one-way,
/// `update_last_login` writes the caller's own seat and the forward mirror
/// carries the timestamp to the identity, which is where "when did this human
/// last sign in anywhere" is answered.
#[sqlx::test]
async fn a_login_stamps_the_seat_it_signed_into_and_the_identity(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    // Second membership for the same identity in another tenant.
    // Manually insert so the password_hash matches the seeded admin's
    // real hash (otherwise the users -> identity trigger from
    // migration 128 would clobber the identity's password_hash with
    // this row's bogus 'hash' literal, and the MAPPS-498 back-mirror
    // would then propagate that bogus hash BACK to every users row -
    // breaking the login step below).
    let tenant_b = insert_tenant(&pool, "Beta Co", "beta-500").await;
    let real_hash = mokosh_server::utils::crypto::hash_password(&password)
        .await
        .expect("hash pw");
    let user_b_id = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, role, status, email_verified_at) \
         VALUES ($1, $2, $3, $4, 'First', 'Last', 'admin', 'active', NOW())",
    )
    .bind(user_b_id)
    .bind(tenant_b)
    .bind(&email)
    .bind(&real_hash)
    .execute(&pool)
    .await
    .expect("insert second users row with real hash");

    // Reset both users rows' last_login_at so the assertion is
    // sensitive to the stamp fired by the login below (not to any
    // seed_admin baseline).
    sqlx::query("UPDATE users SET last_login_at = NULL WHERE lower(email) = lower($1)")
        .bind(&email)
        .execute(&pool)
        .await
        .expect("clear last_login_at");
    sqlx::query("UPDATE identities SET last_login_at = NULL WHERE lower(email) = lower($1)")
        .bind(&email)
        .execute(&pool)
        .await
        .expect("clear identity last_login_at");

    let app = common::boot(pool).await;
    let _token = common::login(&app, &email, &password).await;

    // The seat that was signed into carries the stamp; the other does not.
    let signed_in: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
        "SELECT last_login_at FROM users WHERE lower(email) = lower($1) AND tenant_id = $2",
    )
    .bind(&email)
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&app.pool)
    .await
    .expect("read the seat that signed in");
    assert!(signed_in.is_some(), "the seat that signed in is stamped");

    let other: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT last_login_at FROM users WHERE id = $1")
            .bind(user_b_id)
            .fetch_one(&app.pool)
            .await
            .expect("read the other seat");
    assert!(
        other.is_none(),
        "a login to one tenant is not a login to another"
    );

    // And the identity holds it, through the forward mirror, so the question
    // "when did this human last sign in at all" still has one answer.
    let identity: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT last_login_at FROM identities WHERE lower(email) = lower($1)")
            .bind(&email)
            .fetch_one(&app.pool)
            .await
            .expect("read the identity");
    assert_eq!(identity, signed_in, "the identity carries the same stamp");
}

#[sqlx::test]
async fn deleting_tenant_removes_memberships_but_not_identity(pool: PgPool) {
    let tenant = insert_tenant(&pool, "Zeta Co", "zeta").await;
    insert_user(&pool, tenant, "keep@example.com", "admin", "active").await;

    sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(tenant)
        .execute(&pool)
        .await
        .expect("delete tenant");

    let identity = IdentityRepo::find_by_email(&pool, "keep@example.com")
        .await
        .expect("find")
        .expect("identity survives");
    let memberships = MembershipRepo::list_active_for_identity(&pool, identity.id)
        .await
        .expect("list");
    assert!(memberships.is_empty());
}
