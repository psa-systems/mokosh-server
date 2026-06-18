//! Integration test for PMS-157: first-visit demo-data seeding.
//!
//! `SeedService::ensure_demo_seeded` seeds one demo company, two contacts,
//! and three tickets into a fresh tenant, exactly once. These tests drive
//! the service directly (rather than through the detached middleware spawn)
//! so the assertions are deterministic. The migrations seed the default
//! tenant's ticket status/priority/queue defaults, which `create_ticket`
//! requires.

mod common;

use sqlx::PgPool;
use uuid::Uuid;

use mokosh_server::modules::contacts::ContactService;
use mokosh_server::modules::seed::SeedService;
use mokosh_server::modules::tickets::TicketService;
use mokosh_server::Database;

fn seed_service(pool: &PgPool) -> SeedService {
    let db = Database::from_pool(pool.clone());
    SeedService::new(
        db.clone(),
        ContactService::new(db.clone()),
        TicketService::new(db),
    )
}

async fn company_count(pool: &PgPool, tenant: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM companies WHERE tenant_id = $1 AND company_type <> 'internal'",
    )
    .bind(tenant)
        .fetch_one(pool)
        .await
        .expect("count companies")
}

async fn contact_count(pool: &PgPool, tenant: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM contacts WHERE tenant_id = $1")
        .bind(tenant)
        .fetch_one(pool)
        .await
        .expect("count contacts")
}

async fn ticket_count(pool: &PgPool, tenant: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM tickets WHERE tenant_id = $1")
        .bind(tenant)
        .fetch_one(pool)
        .await
        .expect("count tickets")
}

async fn demo_seeded_flag(pool: &PgPool, tenant: Uuid) -> Option<String> {
    sqlx::query_scalar("SELECT settings->>'demo_seeded' FROM tenants WHERE id = $1")
        .bind(tenant)
        .fetch_one(pool)
        .await
        .expect("read demo_seeded flag")
}

#[sqlx::test]
async fn seeds_demo_data_once_for_a_fresh_tenant(pool: PgPool) {
    let (admin_id, _email, _password) = common::seed_admin(&pool).await;
    let tenant = common::DEFAULT_TENANT_ID;

    // Fresh tenant: no companies yet, flag unset.
    assert_eq!(company_count(&pool, tenant).await, 0);
    assert_eq!(demo_seeded_flag(&pool, tenant).await, None);

    seed_service(&pool)
        .ensure_demo_seeded(tenant, admin_id)
        .await;

    assert_eq!(company_count(&pool, tenant).await, 1, "one demo company");
    assert_eq!(contact_count(&pool, tenant).await, 2, "two demo contacts");
    assert_eq!(ticket_count(&pool, tenant).await, 3, "three demo tickets");
    assert_eq!(
        demo_seeded_flag(&pool, tenant).await.as_deref(),
        Some("true"),
        "flag is set after seeding"
    );

    // A fresh service (empty in-process seen-set) must NOT re-seed: the
    // atomic flag claim already lost, so counts stay put. This proves the
    // cross-process idempotency guard, not just the in-memory short-circuit.
    seed_service(&pool)
        .ensure_demo_seeded(tenant, admin_id)
        .await;

    assert_eq!(
        company_count(&pool, tenant).await,
        1,
        "no duplicate company"
    );
    assert_eq!(
        contact_count(&pool, tenant).await,
        2,
        "no duplicate contacts"
    );
    assert_eq!(ticket_count(&pool, tenant).await, 3, "no duplicate tickets");
}

#[sqlx::test]
async fn skips_seeding_the_shared_landing_tenant(pool: PgPool) {
    // PMS-239: when the deployment funnels every user into one shared tenant
    // (Bunyip JIT with no tenant claim), that tenant must never be auto-seeded
    // - otherwise all users share, and can edit, the same demo rows.
    let (admin_id, _email, _password) = common::seed_admin(&pool).await;
    let tenant = common::DEFAULT_TENANT_ID;

    seed_service(&pool)
        .with_shared_tenant(Some(tenant))
        .ensure_demo_seeded(tenant, admin_id)
        .await;

    assert_eq!(
        company_count(&pool, tenant).await,
        0,
        "shared landing tenant is not seeded"
    );
    assert_eq!(contact_count(&pool, tenant).await, 0, "no demo contacts");
    assert_eq!(ticket_count(&pool, tenant).await, 0, "no demo tickets");
    assert_eq!(
        demo_seeded_flag(&pool, tenant).await,
        None,
        "skip leaves the flag untouched (no DB write)"
    );
}

#[sqlx::test]
async fn skips_seeding_a_tenant_that_already_has_companies(pool: PgPool) {
    let (admin_id, _email, _password) = common::seed_admin(&pool).await;
    let tenant = common::DEFAULT_TENANT_ID;

    // Pre-existing tenant with real data: a company predates the feature.
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, 'Existing Co')")
        .bind(Uuid::new_v4())
        .bind(tenant)
        .execute(&pool)
        .await
        .expect("seed pre-existing company");

    seed_service(&pool)
        .ensure_demo_seeded(tenant, admin_id)
        .await;

    // No demo rows added, but the flag is set so we stop checking on every
    // future request.
    assert_eq!(
        company_count(&pool, tenant).await,
        1,
        "existing company untouched, no demo company added"
    );
    assert_eq!(contact_count(&pool, tenant).await, 0, "no demo contacts");
    assert_eq!(ticket_count(&pool, tenant).await, 0, "no demo tickets");
    assert_eq!(
        demo_seeded_flag(&pool, tenant).await.as_deref(),
        Some("true"),
        "flag still set so the emptiness check runs only once"
    );
}
