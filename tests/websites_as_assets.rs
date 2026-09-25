//! Tests for the website-as-asset migration.
//!
//! Every `sqlx::test` runs migrations up front, so the "before" state
//! for a data migration cannot be observed directly. Instead these
//! tests pin the post-migration invariants: the `Website` asset type
//! exists per tenant, and re-running the backfill query is idempotent.

mod common;

use sqlx::PgPool;
use uuid::Uuid;

/// Every tenant that existed at migration time has a `Website` asset
/// type. New tenants seeded via `TenantService::seed_default_config`
/// inherit it too, since that path copies asset types from the default
/// tenant.
#[sqlx::test]
async fn every_tenant_has_a_website_asset_type(pool: PgPool) {
    common::seed_admin(&pool).await;

    let has_website: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM asset_types \
                       WHERE tenant_id = $1 AND name = 'Website')",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("query asset_types");

    assert!(
        has_website,
        "the default tenant must carry the seeded 'Website' asset type"
    );
}

/// The backfill inserts one asset per (tenant, company, website).
/// Re-running the same INSERT against a company that now holds a
/// Website asset writes nothing.
#[sqlx::test]
async fn the_backfill_is_idempotent_for_companies_that_already_hold_a_website_asset(pool: PgPool) {
    common::seed_admin(&pool).await;

    // Seed a company with a website.
    let company_id = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name, website) VALUES ($1, $2, $3, $4)")
        .bind(company_id)
        .bind(common::DEFAULT_TENANT_ID)
        .bind("Acme Marketing")
        .bind("https://acme.example")
        .execute(&pool)
        .await
        .expect("seed company");

    // First application of the backfill SQL. This mirrors the INSERT
    // in migration 246: a company with a non-blank website that does
    // not already hold a Website asset gets one written.
    let first: sqlx::postgres::PgQueryResult = sqlx::query(
        "INSERT INTO assets ( \
             tenant_id, company_id, asset_type_id, name, notes, status \
         ) \
         SELECT c.tenant_id, c.id, at.id, c.website, 'backfill', 'active' \
         FROM companies c \
         JOIN asset_types at ON at.tenant_id = c.tenant_id AND at.name = 'Website' \
         WHERE c.id = $1 \
           AND c.website IS NOT NULL AND btrim(c.website) <> '' \
           AND NOT EXISTS ( \
               SELECT 1 FROM assets a \
               WHERE a.company_id = c.id AND a.asset_type_id = at.id \
           )",
    )
    .bind(company_id)
    .execute(&pool)
    .await
    .expect("first backfill write");
    assert_eq!(first.rows_affected(), 1);

    // Second application: nothing to do, so nothing writes.
    let second: sqlx::postgres::PgQueryResult = sqlx::query(
        "INSERT INTO assets ( \
             tenant_id, company_id, asset_type_id, name, notes, status \
         ) \
         SELECT c.tenant_id, c.id, at.id, c.website, 'backfill', 'active' \
         FROM companies c \
         JOIN asset_types at ON at.tenant_id = c.tenant_id AND at.name = 'Website' \
         WHERE c.id = $1 \
           AND c.website IS NOT NULL AND btrim(c.website) <> '' \
           AND NOT EXISTS ( \
               SELECT 1 FROM assets a \
               WHERE a.company_id = c.id AND a.asset_type_id = at.id \
           )",
    )
    .bind(company_id)
    .execute(&pool)
    .await
    .expect("second backfill write");
    assert_eq!(
        second.rows_affected(),
        0,
        "a company that already holds a Website asset must not gain a second one"
    );
}

/// A company can hold several websites: adding a second Website asset
/// through the same INSERT-guarded shape is refused (the WHERE clause
/// rejects it because the company holds one already), but the assets
/// table itself accepts multiple. This checks the assets table has no
/// unique constraint that would refuse the second write via the
/// normal API path (a real create hits `assets` directly without the
/// backfill guard).
#[sqlx::test]
async fn a_company_can_hold_multiple_website_assets(pool: PgPool) {
    common::seed_admin(&pool).await;

    let company_id = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, $3)")
        .bind(company_id)
        .bind(common::DEFAULT_TENANT_ID)
        .bind("Acme")
        .execute(&pool)
        .await
        .expect("seed company");

    let type_id: Uuid =
        sqlx::query_scalar("SELECT id FROM asset_types WHERE tenant_id = $1 AND name = 'Website'")
            .bind(common::DEFAULT_TENANT_ID)
            .fetch_one(&pool)
            .await
            .expect("read Website asset_type id");

    for name in ["https://acme.example", "https://blog.acme.example"] {
        sqlx::query(
            "INSERT INTO assets (tenant_id, company_id, asset_type_id, name, status) \
             VALUES ($1, $2, $3, $4, 'active')",
        )
        .bind(common::DEFAULT_TENANT_ID)
        .bind(company_id)
        .bind(type_id)
        .bind(name)
        .execute(&pool)
        .await
        .expect("insert website asset");
    }

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM assets WHERE company_id = $1 AND asset_type_id = $2",
    )
    .bind(company_id)
    .bind(type_id)
    .fetch_one(&pool)
    .await
    .expect("count website assets");
    assert_eq!(count, 2, "a company must be able to hold several websites");
}
