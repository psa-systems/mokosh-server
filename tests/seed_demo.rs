//! Integration test for PMS-157 / PMS-710: first-visit demo-data seeding.
//!
//! `SeedService::ensure_demo_seeded` seeds the connected demo dataset (two
//! companies, four contacts, one SLA, two projects, five tickets) into a fresh
//! tenant, exactly once. These tests drive the service directly (rather than
//! through the detached middleware spawn) so the assertions are deterministic,
//! and pin the PMS-710 environment gate with `with_seed_enabled(true)` so they
//! do not depend on the process `ENVIRONMENT`. The migrations seed the default
//! tenant's ticket status/priority/queue defaults, which `create_ticket`
//! requires.
//!
//! PMS-629: the demo baseline is the clean, un-prefixed demo data (`data.rs`,
//! tagged `demo`). The `zQA`/`QA-` prefix belongs ONLY to the QA E2E fixtures
//! (`qa.rs`, gated to `is_qa` tenants) and must never appear in demo data;
//! `demo_seed_is_the_clean_baseline_with_no_qa_prefix` guards that separation.

mod common;

use sqlx::PgPool;
use uuid::Uuid;

use mokosh_server::modules::contacts::ContactService;
use mokosh_server::modules::projects::ProjectsService;
use mokosh_server::modules::seed::{LoadDemoOutcome, SeedService};
use mokosh_server::modules::sla::SlaService;
use mokosh_server::modules::tickets::TicketService;
use mokosh_server::Database;

/// The demo dataset the PMS-710 profile creates.
const DEMO_COMPANIES: i64 = 2;
const DEMO_CONTACTS: i64 = 4;
const DEMO_TICKETS: i64 = 5;
const DEMO_PROJECTS: i64 = 2;
const DEMO_SLA_POLICIES: i64 = 1;

/// A seed service with the automatic gate turned ON, for the first-visit tests.
/// The gate itself (production-on / staging-off) is covered by unit tests plus
/// `auto_seed_is_a_no_op_when_the_gate_is_off` below.
fn seed_service(pool: &PgPool) -> SeedService {
    let db = Database::from_pool(pool.clone());
    SeedService::new(
        db.clone(),
        ContactService::new(db.clone()),
        TicketService::new(db.clone()),
        ProjectsService::new(db.clone()),
        SlaService::new(db),
    )
    .with_seed_enabled(true)
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

async fn project_count(pool: &PgPool, tenant: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM projects WHERE tenant_id = $1")
        .bind(tenant)
        .fetch_one(pool)
        .await
        .expect("count projects")
}

/// Count only the demo SLA policy. A fresh tenant already ships a default SLA
/// policy (migration / `copy_default_config`), so this filters to the seeded
/// `(Demo)` one by name rather than counting every policy.
async fn sla_policy_count(pool: &PgPool, tenant: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM sla_policies WHERE tenant_id = $1 AND name LIKE '%(Demo)%'",
    )
    .bind(tenant)
    .fetch_one(pool)
    .await
    .expect("count demo sla policies")
}

/// Whether a demo company is assigned the demo SLA policy - proves the durable
/// company -> SLA relationship the demo is meant to show (ticket SLA due dates
/// are managed separately by the SLA subsystem).
async fn a_company_links_the_demo_sla(pool: &PgPool, tenant: Uuid) -> bool {
    sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM companies c
             JOIN sla_policies s ON s.id = c.sla_id AND s.tenant_id = c.tenant_id
             WHERE c.tenant_id = $1 AND s.name LIKE '%(Demo)%'
         )",
    )
    .bind(tenant)
    .fetch_one(pool)
    .await
    .expect("check company -> demo sla link")
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

    assert_eq!(
        company_count(&pool, tenant).await,
        DEMO_COMPANIES,
        "two demo companies"
    );
    assert_eq!(
        contact_count(&pool, tenant).await,
        DEMO_CONTACTS,
        "four demo contacts"
    );
    assert_eq!(
        ticket_count(&pool, tenant).await,
        DEMO_TICKETS,
        "five demo tickets"
    );
    assert_eq!(
        project_count(&pool, tenant).await,
        DEMO_PROJECTS,
        "two demo projects"
    );
    assert_eq!(
        sla_policy_count(&pool, tenant).await,
        DEMO_SLA_POLICIES,
        "one demo SLA policy"
    );
    // Relationships are visible: a company carries the demo SLA.
    assert!(
        a_company_links_the_demo_sla(&pool, tenant).await,
        "a demo company is assigned the demo SLA"
    );
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
        DEMO_COMPANIES,
        "no duplicate companies"
    );
    assert_eq!(
        contact_count(&pool, tenant).await,
        DEMO_CONTACTS,
        "no duplicate contacts"
    );
    assert_eq!(
        ticket_count(&pool, tenant).await,
        DEMO_TICKETS,
        "no duplicate tickets"
    );
    assert_eq!(
        project_count(&pool, tenant).await,
        DEMO_PROJECTS,
        "no duplicate projects"
    );
    assert_eq!(
        sla_policy_count(&pool, tenant).await,
        DEMO_SLA_POLICIES,
        "no duplicate SLA policy"
    );
}

/// PMS-710: the automatic first-visit seed must do nothing when the environment
/// gate is off (staging / dev without the opt-in). Proves "staging seeds
/// nothing" at the service level, complementing the `seed_enabled_for` unit
/// tests.
#[sqlx::test]
async fn auto_seed_is_a_no_op_when_the_gate_is_off(pool: PgPool) {
    let (admin_id, _email, _password) = common::seed_admin(&pool).await;
    let tenant = common::DEFAULT_TENANT_ID;

    let db = Database::from_pool(pool.clone());
    SeedService::new(
        db.clone(),
        ContactService::new(db.clone()),
        TicketService::new(db.clone()),
        ProjectsService::new(db.clone()),
        SlaService::new(db),
    )
    .with_seed_enabled(false)
    .ensure_demo_seeded(tenant, admin_id)
    .await;

    assert_eq!(company_count(&pool, tenant).await, 0, "no demo companies");
    assert_eq!(contact_count(&pool, tenant).await, 0, "no demo contacts");
    assert_eq!(ticket_count(&pool, tenant).await, 0, "no demo tickets");
    assert_eq!(project_count(&pool, tenant).await, 0, "no demo projects");
    assert_eq!(
        sla_policy_count(&pool, tenant).await,
        0,
        "no demo SLA policy"
    );
    assert_eq!(
        demo_seeded_flag(&pool, tenant).await,
        None,
        "the gate-off skip writes nothing, including the flag"
    );
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

// PMS-679: the explicit, admin-triggered "Load demo data" path
// (`load_demo_data`). Same underlying seed as the auto-seed, but it surfaces
// its outcome and only ever loads into an empty tenant.

#[sqlx::test]
async fn load_demo_data_seeds_an_empty_tenant(pool: PgPool) {
    let (admin_id, _email, _password) = common::seed_admin(&pool).await;
    let tenant = common::DEFAULT_TENANT_ID;

    let outcome = seed_service(&pool)
        .load_demo_data(tenant, admin_id)
        .await
        .expect("load demo data");

    assert_eq!(outcome, LoadDemoOutcome::Seeded, "empty tenant is seeded");
    assert_eq!(
        company_count(&pool, tenant).await,
        DEMO_COMPANIES,
        "two demo companies"
    );
    assert_eq!(
        contact_count(&pool, tenant).await,
        DEMO_CONTACTS,
        "four demo contacts"
    );
    assert_eq!(
        ticket_count(&pool, tenant).await,
        DEMO_TICKETS,
        "five demo tickets"
    );
    assert_eq!(
        project_count(&pool, tenant).await,
        DEMO_PROJECTS,
        "two demo projects"
    );
    assert_eq!(
        sla_policy_count(&pool, tenant).await,
        DEMO_SLA_POLICIES,
        "one demo SLA policy"
    );
    assert_eq!(
        demo_seeded_flag(&pool, tenant).await.as_deref(),
        Some("true"),
        "flag is set so the first-visit auto-seed stays a no-op afterwards"
    );
}

#[sqlx::test]
async fn load_demo_data_refuses_a_tenant_that_already_has_data(pool: PgPool) {
    let (admin_id, _email, _password) = common::seed_admin(&pool).await;
    let tenant = common::DEFAULT_TENANT_ID;

    // A tenant with real data already: the button must refuse, not wipe or
    // append demo rows.
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, 'Existing Co')")
        .bind(Uuid::new_v4())
        .bind(tenant)
        .execute(&pool)
        .await
        .expect("seed pre-existing company");

    let outcome = seed_service(&pool)
        .load_demo_data(tenant, admin_id)
        .await
        .expect("load demo data");

    assert_eq!(
        outcome,
        LoadDemoOutcome::AlreadyHasData,
        "a non-empty tenant is refused"
    );
    assert_eq!(
        company_count(&pool, tenant).await,
        1,
        "existing company untouched, no demo company added"
    );
    assert_eq!(contact_count(&pool, tenant).await, 0, "no demo contacts");
    assert_eq!(ticket_count(&pool, tenant).await, 0, "no demo tickets");
    assert_eq!(
        demo_seeded_flag(&pool, tenant).await,
        None,
        "refusing an established tenant writes nothing, including the flag"
    );
}

#[sqlx::test]
async fn load_demo_data_refuses_the_shared_landing_tenant(pool: PgPool) {
    // PMS-239: the shared multi-user landing tenant must never receive
    // per-account demo rows, even on an explicit request.
    let (admin_id, _email, _password) = common::seed_admin(&pool).await;
    let tenant = common::DEFAULT_TENANT_ID;

    let outcome = seed_service(&pool)
        .with_shared_tenant(Some(tenant))
        .load_demo_data(tenant, admin_id)
        .await
        .expect("load demo data");

    assert_eq!(
        outcome,
        LoadDemoOutcome::AlreadyHasData,
        "the shared landing tenant is refused"
    );
    assert_eq!(company_count(&pool, tenant).await, 0, "no demo company");
    assert_eq!(contact_count(&pool, tenant).await, 0, "no demo contacts");
    assert_eq!(ticket_count(&pool, tenant).await, 0, "no demo tickets");
}

/// PMS-629: a fresh tenant's first-visit seed must be the clean demo baseline,
/// never the `zQA`/`QA-` E2E fixtures. Those live only in the QA seeder
/// (`qa.rs`), gated to `is_qa` tenants; demo data (`data.rs`) is un-prefixed and
/// tagged `demo`. This locks in that separation so a future change cannot leak
/// QA fixtures into the demo baseline.
#[sqlx::test]
async fn demo_seed_is_the_clean_baseline_with_no_qa_prefix(pool: PgPool) {
    let (admin_id, _email, _password) = common::seed_admin(&pool).await;
    let tenant = common::DEFAULT_TENANT_ID;

    seed_service(&pool)
        .ensure_demo_seeded(tenant, admin_id)
        .await;

    // The demo companies are the expected, obviously-demo baseline rows.
    let company_names: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM companies WHERE tenant_id = $1 AND company_type <> 'internal' ORDER BY name",
    )
    .bind(tenant)
    .fetch_all(&pool)
    .await
    .expect("read demo company names");
    assert_eq!(
        company_names,
        vec![
            "Contoso Ltd (Demo)".to_string(),
            "Northwind Traders (Demo)".to_string(),
        ],
        "demo seed must produce the clean demo baseline companies"
    );

    // No seeded record (company / contact / ticket) carries a `QA-` or `zQA`
    // marker - those are reserved for the qa.rs E2E fixtures.
    let qa_prefixed: i64 = sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM companies WHERE tenant_id = $1 AND (name LIKE 'QA-%' OR name ILIKE '%zqa%'))
              + (SELECT COUNT(*) FROM contacts  WHERE tenant_id = $1 AND (first_name LIKE 'QA-%' OR last_name LIKE 'QA-%' OR first_name ILIKE '%zqa%' OR last_name ILIKE '%zqa%'))
              + (SELECT COUNT(*) FROM tickets   WHERE tenant_id = $1 AND (title LIKE 'QA-%' OR title ILIKE '%zqa%'))",
    )
    .bind(tenant)
    .fetch_one(&pool)
    .await
    .expect("count QA/zQA-prefixed rows");
    assert_eq!(
        qa_prefixed, 0,
        "demo seed must contain no QA-/zQA-prefixed records"
    );
}
