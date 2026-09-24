//! PMS-1380 (F7): the sync snapshot's per-contact company-names subquery
//! (`src/modules/contact_sync/sync.rs`, `snapshot`, the
//! `ARRAY(SELECT co.name FROM contact_companies cc JOIN companies co ON
//! co.id = cc.company_id WHERE cc.contact_id = c.id)` correlated subquery)
//! filters `contact_companies` on an unfiltered `contact_id = c.id`. Neither
//! `idx_contact_companies_company` (leads with `company_id`, not
//! `contact_id`) nor `idx_contact_companies_one_primary` (a partial index
//! restricted to `is_primary` rows) serves that predicate, so before
//! migration 245 this ran a sequential scan over the whole table once per
//! contact in the tenant.
//!
//! This seeds a 1,000+ contact tenant, each linked to a company through
//! `contact_companies`, then runs `EXPLAIN (ANALYZE, BUFFERS)` on exactly the
//! subquery's join shape and asserts the plan uses an index scan against
//! `contact_companies` (via the new `idx_contact_companies_contact`) rather
//! than a sequential scan.

mod common;

use sqlx::PgPool;
use uuid::Uuid;

use mokosh_server::modules::auth::TenantId;

const CONTACT_COUNT: i64 = 1_200;

#[sqlx::test]
async fn the_snapshot_company_names_subquery_uses_an_index(pool: PgPool) {
    common::init_tracing();
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let company_id = common::seed_company(&pool).await;

    // Bulk-seed enough contacts, each linked to the one company, that a
    // sequential scan and an index scan are clearly distinguishable in the
    // plan the way they would not be for a handful of rows.
    let contact_ids: Vec<Uuid> = sqlx::query_scalar(
        "INSERT INTO contacts (tenant_id, company_id, first_name, last_name) \
         SELECT $1, $2, 'First' || g, 'Last' || g \
         FROM generate_series(1, $3) AS g \
         RETURNING id",
    )
    .bind(tenant)
    .bind(company_id)
    .bind(CONTACT_COUNT)
    .fetch_all(&pool)
    .await
    .expect("seed contacts");
    assert_eq!(contact_ids.len(), CONTACT_COUNT as usize);

    sqlx::query(
        "INSERT INTO contact_companies (tenant_id, contact_id, company_id, is_primary) \
         SELECT $1, id, $2, TRUE FROM contacts WHERE tenant_id = $1 AND company_id = $2",
    )
    .bind(tenant)
    .bind(company_id)
    .execute(&pool)
    .await
    .expect("link every contact to the company");

    // Realistic planner stats: an empty-table default would let the planner
    // guess right for the wrong reason.
    sqlx::query("ANALYZE contact_companies")
        .execute(&pool)
        .await
        .expect("analyze contact_companies");
    sqlx::query("ANALYZE companies")
        .execute(&pool)
        .await
        .expect("analyze companies");
    sqlx::query("ANALYZE contacts")
        .execute(&pool)
        .await
        .expect("analyze contacts");

    let plan_lines: Vec<String> = sqlx::query_scalar(
        "EXPLAIN (ANALYZE, BUFFERS) \
         SELECT co.name FROM contact_companies cc \
         JOIN companies co ON co.id = cc.company_id \
         WHERE cc.contact_id = $1",
    )
    .bind(contact_ids[0])
    .fetch_all(&pool)
    .await
    .expect("explain the snapshot subquery");
    let plan = plan_lines.join("\n");

    assert!(
        plan.contains("idx_contact_companies_contact"),
        "the plan must use the new contact-keyed index, got:\n{plan}"
    );
    assert!(
        !plan.contains("Seq Scan on contact_companies"),
        "a 1,200-contact tenant must not sequentially scan contact_companies \
         for a single contact's company names, got:\n{plan}"
    );
}
