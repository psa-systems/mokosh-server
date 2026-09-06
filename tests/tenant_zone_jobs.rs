//! PMS-1030: the jobs that have no user to ask what day it is take the
//! tenant's day, read off the default business-hours zone, not UTC's.
//!
//! One instant, 2026-06-30T13:00Z, is 1 July 01:00 in Auckland and 30 June
//! 06:00 in Vancouver. Each test runs the job at that instant under one
//! zone, then the other, on the same tenant, so the only thing that changes
//! between the two runs is what day the tenant is on.

mod common;

use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use mokosh_server::modules::audit::AuditCtx;
use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::billing::BillingService;
use mokosh_server::modules::contracts::ContractsService;
use mokosh_server::Database;
use sqlx::PgPool;
use uuid::Uuid;

const AUCKLAND: &str = "Pacific/Auckland";
const VANCOUVER: &str = "America/Vancouver";

fn the_instant() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 6, 30, 13, 0, 0).unwrap()
}

fn ymd(y: i32, m: u32, d: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(y, m, d).unwrap()
}

/// The seeded default tenant carries one default business-hours row
/// (migration 023, `America/New_York`); point it at `zone`.
async fn set_zone(pool: &PgPool, zone: &str) {
    let n =
        sqlx::query("UPDATE business_hours SET timezone = $2 WHERE tenant_id = $1 AND is_default")
            .bind(common::DEFAULT_TENANT_ID)
            .bind(zone)
            .execute(pool)
            .await
            .expect("set the default business-hours zone")
            .rows_affected();
    assert_eq!(n, 1, "exactly one default business-hours row");
}

async fn seed_contract(
    pool: &PgPool,
    company: Uuid,
    start: NaiveDate,
    end: Option<NaiveDate>,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contracts (id, tenant_id, name, company_id, contract_type, status, \
         start_date, end_date, billing_cycle, auto_renew) \
         VALUES ($1, $2, 'Managed', $3, 'managed_services', 'active', $4, $5, 'monthly', FALSE)",
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company)
    .bind(start)
    .bind(end)
    .execute(pool)
    .await
    .expect("seed contract");
    sqlx::query(
        "INSERT INTO contract_items (id, tenant_id, contract_id, name, item_type, quantity, \
         unit_price, total_price, sort_order, billing_rule) \
         VALUES ($1, $2, $3, 'Managed Services', 'recurring_service', 1, 100, 100, 0, 'every_period')",
    )
    .bind(Uuid::new_v4())
    .bind(common::DEFAULT_TENANT_ID)
    .bind(id)
    .execute(pool)
    .await
    .expect("seed recurring item");
    id
}

async fn periods_billed(pool: &PgPool, contract: Uuid) -> Vec<NaiveDate> {
    sqlx::query_scalar(
        "SELECT period_start FROM contract_invoice_runs WHERE contract_id = $1 ORDER BY period_start",
    )
    .bind(contract)
    .fetch_all(pool)
    .await
    .expect("read the ledger")
}

/// At 13:00Z on 30 June, Vancouver is still on June and Auckland is already
/// on July. The generator bills the period the TENANT is in.
#[sqlx::test]
async fn the_recurring_generator_bills_the_period_the_tenant_is_in(pool: PgPool) {
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let company = common::seed_company(&pool).await;
    let contract = seed_contract(&pool, company, ymd(2026, 6, 1), None).await;
    let svc = BillingService::new(Database::from_pool(pool.clone()));
    let ctx = AuditCtx::system(common::DEFAULT_TENANT_ID);

    set_zone(&pool, VANCOUVER).await;
    let created = svc
        .generate_due_recurring_invoices(tenant, the_instant(), &ctx)
        .await
        .expect("generate in Vancouver");
    assert_eq!(created.len(), 1);
    assert_eq!(periods_billed(&pool, contract).await, [ymd(2026, 6, 1)]);
    let invoice_date: NaiveDate =
        sqlx::query_scalar("SELECT invoice_date FROM invoices WHERE id = $1")
            .bind(created[0])
            .fetch_one(&pool)
            .await
            .expect("invoice date");
    assert_eq!(invoice_date, ymd(2026, 6, 30), "dated on the tenant's day");

    set_zone(&pool, AUCKLAND).await;
    let created = svc
        .generate_due_recurring_invoices(tenant, the_instant(), &ctx)
        .await
        .expect("generate in Auckland");
    assert_eq!(created.len(), 1, "July has begun in Auckland");
    assert_eq!(
        periods_billed(&pool, contract).await,
        [ymd(2026, 6, 1), ymd(2026, 7, 1)]
    );
    let invoice_date: NaiveDate =
        sqlx::query_scalar("SELECT invoice_date FROM invoices WHERE id = $1")
            .bind(created[0])
            .fetch_one(&pool)
            .await
            .expect("invoice date");
    assert_eq!(invoice_date, ymd(2026, 7, 1));
}

/// A contract ending 30 June is still in force at 13:00Z that day in
/// Vancouver, and over in Auckland.
#[sqlx::test]
async fn a_contract_expires_on_its_tenants_day(pool: PgPool) {
    let company = common::seed_company(&pool).await;
    let contract = seed_contract(&pool, company, ymd(2026, 1, 1), Some(ymd(2026, 6, 30))).await;
    let svc = ContractsService::new(Database::from_pool(pool.clone()));

    set_zone(&pool, VANCOUVER).await;
    let (renewed, expired) = svc
        .expire_due_contracts(the_instant())
        .await
        .expect("sweep");
    assert_eq!((renewed, expired), (0, 0), "still 30 June in Vancouver");

    set_zone(&pool, AUCKLAND).await;
    let (renewed, expired) = svc
        .expire_due_contracts(the_instant())
        .await
        .expect("sweep");
    assert_eq!((renewed, expired), (0, 1), "1 July in Auckland");
    let status: String = sqlx::query_scalar("SELECT status FROM contracts WHERE id = $1")
        .bind(contract)
        .fetch_one(&pool)
        .await
        .expect("status");
    assert_eq!(status, "expired");
}

/// A tenant with no default business-hours row keeps the UTC day it always had.
#[sqlx::test]
async fn a_tenant_with_no_business_hours_stays_on_utc(pool: PgPool) {
    // The seeded row is named by an SLA policy, so it cannot go; the reader
    // keys on `is_default`, and a tenant with no default row has no zone.
    sqlx::query("UPDATE business_hours SET is_default = FALSE WHERE tenant_id = $1")
        .bind(common::DEFAULT_TENANT_ID)
        .execute(&pool)
        .await
        .expect("leave the tenant with no default business hours");
    let company = common::seed_company(&pool).await;
    // Ends 29 June: past in UTC (30 June) as it is anywhere; the point is
    // that the sweep still runs with no row to read, not which day it picks.
    let contract = seed_contract(&pool, company, ymd(2026, 1, 1), Some(ymd(2026, 6, 29))).await;
    let svc = ContractsService::new(Database::from_pool(pool.clone()));
    let (_, expired) = svc
        .expire_due_contracts(the_instant())
        .await
        .expect("sweep");
    assert_eq!(expired, 1);

    // And the generator: 30 June in UTC is June's period.
    let billing = BillingService::new(Database::from_pool(pool.clone()));
    let ctx = AuditCtx::system(common::DEFAULT_TENANT_ID);
    let open = seed_contract(&pool, company, ymd(2026, 6, 1), None).await;
    billing
        .generate_due_recurring_invoices(
            TenantId::from_trusted(common::DEFAULT_TENANT_ID),
            the_instant(),
            &ctx,
        )
        .await
        .expect("generate");
    assert_eq!(periods_billed(&pool, open).await, [ymd(2026, 6, 1)]);
    let _ = contract;
}
