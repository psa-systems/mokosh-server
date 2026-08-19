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

#[sqlx::test]
async fn update_users_password_hash_propagates_to_identity(pool: PgPool) {
    let tenant = insert_tenant(&pool, "Epsilon Co", "epsilon").await;
    let user_id = insert_user(&pool, tenant, "pw@example.com", "technician", "active").await;

    sqlx::query("UPDATE users SET password_hash = 'new-hash' WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("update pw");

    let identity = IdentityRepo::find_by_id(&pool, user_id)
        .await
        .expect("find")
        .expect("exists");
    assert_eq!(identity.password_hash.as_deref(), Some("new-hash"));
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
