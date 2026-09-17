//! MAPPS-877: integration tests for the unified members endpoint.
//!
//! Standalone mode only: constructs `MembersService` with
//! `bunyip_directory = None`, seeds `users` + `mokosh_bunyip_grants`
//! rows directly, and asserts the merged output. The SaaS-mode fan
//! out (stub bunyip on a per-test TCP socket) is the same shape as
//! `tests/owner_grant_saas.rs` and would layer on top; deliberately
//! deferred to a follow-up so this ticket's server change ships with
//! coverage of the merge itself.

use std::sync::Arc;

use mokosh_server::modules::members::{MembersFilter, MembersService};
use mokosh_server::utils::pagination::PaginationParams;
use mokosh_server::Database;
use mokosh_types::members::MemberRow;
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_user(
    pool: &PgPool,
    tenant: Uuid,
    email: &str,
    first: &str,
    last: &str,
    role: &str,
) -> Uuid {
    let user_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, tenant_id, bunyip_user_id, email, first_name, last_name, \
                            password_hash, role, status, timezone, locale, notification_preferences, settings) \
         VALUES ($1, $2, $1, $3, $4, $5, NULL, $6::user_role, 'active'::user_status, \
                 'UTC', 'en', '{}'::jsonb, '{}'::jsonb)",
    )
    .bind(user_id)
    .bind(tenant)
    .bind(email)
    .bind(first)
    .bind(last)
    .bind(role)
    .execute(pool)
    .await
    .unwrap();
    user_id
}

async fn seed_grant(
    pool: &PgPool,
    owner: Uuid,
    grantee_bunyip_user_id: Uuid,
    mokosh_account_id: &str,
    role: &str,
    email: &str,
) -> Uuid {
    let mirror_id = Uuid::new_v4();
    let bunyip_grant_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO mokosh_bunyip_grants \
            (id, bunyip_grant_id, grantee_bunyip_user_id, owner_bunyip_user_id, \
             mokosh_account_id, role, grantee_email, granted_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())",
    )
    .bind(mirror_id)
    .bind(bunyip_grant_id)
    .bind(grantee_bunyip_user_id)
    .bind(owner)
    .bind(mokosh_account_id)
    .bind(role)
    .bind(email)
    .execute(pool)
    .await
    .unwrap();
    bunyip_grant_id
}

async fn seed_tenant(pool: &PgPool) -> Uuid {
    let tenant_id = Uuid::new_v4();
    let slug = format!("test-{}", &tenant_id.to_string()[..8]);
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, status, kind) \
         VALUES ($1, 'Test Tenant', $2, 'active', 'org')",
    )
    .bind(tenant_id)
    .bind(&slug)
    .execute(pool)
    .await
    .unwrap();
    tenant_id
}

fn service(pool: PgPool) -> MembersService {
    let db = Database::from_pool(pool);
    MembersService::new(Arc::new(db), None)
}

fn default_pagination() -> PaginationParams {
    PaginationParams {
        page: 1,
        per_page: 50,
        sort: None,
        sort_dir: "asc".to_string(),
    }
}

#[sqlx::test]
async fn list_members_returns_native_users_alone_when_no_grants(pool: PgPool) {
    let tenant = seed_tenant(&pool).await;
    let owner = seed_user(&pool, tenant, "owner@acme.com", "Owner", "One", "admin").await;
    seed_user(&pool, tenant, "tech@acme.com", "Tech", "Two", "technician").await;

    let svc = service(pool);
    let resp = svc
        .list(
            tenant,
            owner,
            &MembersFilter::default(),
            &default_pagination(),
        )
        .await
        .expect("list ok");

    assert_eq!(resp.total, 2);
    assert_eq!(resp.rows.len(), 2);
    assert!(resp.bunyip_reachable);
    for row in &resp.rows {
        match row {
            MemberRow::User {
                placed_by_grant_id, ..
            } => assert!(placed_by_grant_id.is_none()),
            MemberRow::UnplacedGuest { .. } => panic!("expected only natives"),
        }
    }
}

#[sqlx::test]
async fn list_members_emits_unplaced_guest_when_grant_has_no_users_row(pool: PgPool) {
    let tenant = seed_tenant(&pool).await;
    let owner = seed_user(&pool, tenant, "owner@acme.com", "Owner", "One", "admin").await;
    let unknown_bunyip_user = Uuid::new_v4();
    seed_grant(
        &pool,
        owner,
        unknown_bunyip_user,
        "acme",
        "technician",
        "guest@partner.com",
    )
    .await;

    let svc = service(pool);
    let resp = svc
        .list(
            tenant,
            owner,
            &MembersFilter::default(),
            &default_pagination(),
        )
        .await
        .expect("list ok");

    // The owner (User) plus one UnplacedGuest.
    assert_eq!(resp.total, 2);
    let (users, guests): (Vec<_>, Vec<_>) = resp
        .rows
        .into_iter()
        .partition(|r| matches!(r, MemberRow::User { .. }));
    assert_eq!(users.len(), 1);
    assert_eq!(guests.len(), 1);
    if let MemberRow::UnplacedGuest {
        grantee_email,
        role,
        ..
    } = &guests[0]
    {
        assert_eq!(grantee_email.as_deref(), Some("guest@partner.com"));
        assert_eq!(role, "technician");
    }
}

#[sqlx::test]
async fn list_members_decorates_a_placed_guest_with_placed_by_grant_id(pool: PgPool) {
    let tenant = seed_tenant(&pool).await;
    let owner = seed_user(&pool, tenant, "owner@acme.com", "Owner", "One", "admin").await;
    // A users row inside this tenant whose bunyip_user_id is what the
    // grant names as grantee: the JIT placement shape.
    let placed_user_id = Uuid::new_v4();
    let placed_bunyip = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, tenant_id, bunyip_user_id, email, first_name, last_name, \
                            password_hash, role, status, timezone, locale, notification_preferences, settings) \
         VALUES ($1, $2, $3, 'placed@partner.com', 'Placed', 'Guest', NULL, \
                 'technician'::user_role, 'active'::user_status, 'UTC', 'en', '{}'::jsonb, '{}'::jsonb)",
    )
    .bind(placed_user_id)
    .bind(tenant)
    .bind(placed_bunyip)
    .execute(&pool)
    .await
    .unwrap();
    let grant_id = seed_grant(
        &pool,
        owner,
        placed_bunyip,
        "acme",
        "manager",
        "placed@partner.com",
    )
    .await;

    let svc = service(pool);
    let resp = svc
        .list(
            tenant,
            owner,
            &MembersFilter::default(),
            &default_pagination(),
        )
        .await
        .expect("list ok");

    // Owner + placed. No UnplacedGuest.
    assert_eq!(resp.total, 2);
    let placed = resp
        .rows
        .iter()
        .find_map(|r| match r {
            MemberRow::User {
                placed_by_grant_id: Some(g),
                role,
                ..
            } => Some((*g, role.clone())),
            _ => None,
        })
        .expect("expected a placed guest row");
    assert_eq!(placed.0, grant_id);
    // A placed guest's effective role comes from the grant, not
    // users.role (PMS-1162 keeps the two reconciled anyway).
    assert_eq!(placed.1, "manager");
}

#[sqlx::test]
async fn list_members_filters_by_q_across_kinds(pool: PgPool) {
    let tenant = seed_tenant(&pool).await;
    let owner = seed_user(&pool, tenant, "alice@acme.com", "Alice", "Chen", "admin").await;
    seed_user(&pool, tenant, "bob@acme.com", "Bob", "Kim", "technician").await;
    seed_grant(
        &pool,
        owner,
        Uuid::new_v4(),
        "acme",
        "read_only",
        "alicia@partner.com",
    )
    .await;

    let svc = service(pool);
    let filter = MembersFilter {
        q: Some("ali".to_string()),
        ..Default::default()
    };
    let resp = svc
        .list(tenant, owner, &filter, &default_pagination())
        .await
        .unwrap();

    // Alice (user) and alicia (guest) match `ali`; Bob does not.
    assert_eq!(resp.total, 2);
}

#[sqlx::test]
async fn list_members_filters_by_kind(pool: PgPool) {
    let tenant = seed_tenant(&pool).await;
    let owner = seed_user(&pool, tenant, "owner@acme.com", "Owner", "One", "admin").await;
    seed_grant(
        &pool,
        owner,
        Uuid::new_v4(),
        "acme",
        "technician",
        "guest@partner.com",
    )
    .await;
    let svc = service(pool);

    let users_only = svc
        .list(
            tenant,
            owner,
            &MembersFilter {
                kind: Some("user".to_string()),
                ..Default::default()
            },
            &default_pagination(),
        )
        .await
        .unwrap();
    assert_eq!(users_only.total, 1);
    assert!(matches!(users_only.rows[0], MemberRow::User { .. }));

    let guests_only = svc
        .list(
            tenant,
            owner,
            &MembersFilter {
                kind: Some("guest".to_string()),
                ..Default::default()
            },
            &default_pagination(),
        )
        .await
        .unwrap();
    assert_eq!(guests_only.total, 1);
    assert!(matches!(
        guests_only.rows[0],
        MemberRow::UnplacedGuest { .. }
    ));
}

#[sqlx::test]
async fn list_members_rejects_bad_role_filter(pool: PgPool) {
    let tenant = seed_tenant(&pool).await;
    let owner = seed_user(&pool, tenant, "owner@acme.com", "Owner", "One", "admin").await;
    let svc = service(pool);
    let filter = MembersFilter {
        role: Some("godmode".to_string()),
        ..Default::default()
    };
    let err = svc
        .list(tenant, owner, &filter, &default_pagination())
        .await
        .expect_err("bad role must be a 422");
    let msg = format!("{err}");
    assert!(
        msg.to_lowercase().contains("role"),
        "expected `role` in the error, got: {msg}"
    );
}

#[sqlx::test]
async fn list_members_hides_the_system_attribution_user(pool: PgPool) {
    let tenant = seed_tenant(&pool).await;
    let owner = seed_user(&pool, tenant, "owner@acme.com", "Owner", "One", "admin").await;
    // MAPPS-562's system attribution row: real users row, must never
    // appear in the roster. Uses the reserved suffix that
    // `list_members` filters on.
    seed_user(
        &pool,
        tenant,
        "system+testslug@mokosh.local",
        "System",
        "Attribution",
        "super_admin",
    )
    .await;
    let svc = service(pool);
    let resp = svc
        .list(
            tenant,
            owner,
            &MembersFilter::default(),
            &default_pagination(),
        )
        .await
        .unwrap();
    assert_eq!(resp.total, 1);
    if let MemberRow::User { email, .. } = &resp.rows[0] {
        assert_eq!(email, "owner@acme.com");
    } else {
        panic!("expected the owner row");
    }
}

#[sqlx::test]
async fn team_list_carries_member_count(pool: PgPool) {
    // Piggybacks on the same tables the MembersService uses, to pin
    // the phase-1 DTO change to `Team`. Uses the TeamsService directly
    // because the HTTP path already has its own auth harness this
    // suite deliberately avoids.
    let tenant = seed_tenant(&pool).await;
    let owner = seed_user(&pool, tenant, "owner@acme.com", "Owner", "One", "admin").await;
    let m1 = seed_user(&pool, tenant, "m1@acme.com", "M", "One", "technician").await;
    let m2 = seed_user(&pool, tenant, "m2@acme.com", "M", "Two", "technician").await;

    let team_a = Uuid::new_v4();
    let team_b = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO teams (id, tenant_id, name, manager_id, is_active) \
         VALUES ($1, $2, 'Team A', $3, TRUE), ($4, $2, 'Team B', $3, TRUE)",
    )
    .bind(team_a)
    .bind(tenant)
    .bind(owner)
    .bind(team_b)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO team_members (tenant_id, team_id, user_id, role) \
         VALUES ($1, $2, $3, 'member'), ($1, $2, $4, 'member')",
    )
    .bind(tenant)
    .bind(team_a)
    .bind(m1)
    .bind(m2)
    .execute(&pool)
    .await
    .unwrap();

    let db = Database::from_pool(pool);
    let svc = mokosh_server::modules::teams::TeamsService::new(db);
    let tenant_scoped = mokosh_server::modules::auth::TenantId::from_trusted(tenant);
    let teams = svc
        .list_teams(
            tenant_scoped,
            mokosh_server::modules::teams::TeamListFilters::default(),
        )
        .await
        .unwrap();

    let a = teams.iter().find(|t| t.name == "Team A").unwrap();
    let b = teams.iter().find(|t| t.name == "Team B").unwrap();
    assert_eq!(a.member_count, Some(2));
    assert_eq!(b.member_count, Some(0));
}
