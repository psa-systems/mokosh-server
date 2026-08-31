//! Integration tests for PMS-64 AC5: recurring billing invoices from
//! contracts' recurring line items, idempotent per billing period.
//!
//! Drives `BillingService::generate_due_recurring_invoices` directly
//! against a per-test database (no HTTP layer needed for the generation
//! math + idempotency), mirroring `tests/contracts.rs`:
//! `Database::from_pool(pool.clone())`, the seeded default tenant
//! (`common::DEFAULT_TENANT_ID`), and direct SQL for fixtures. `now` is
//! injected so periods are driven deterministically.
//!
//! Coverage:
//!   * A monthly contract with two recurring items generates exactly one
//!     invoice for the due period, with one line per item and the right
//!     total.
//!   * Running the generator twice for the same `now` does NOT create a
//!     second invoice for that period (ledger dedupe).
//!   * A `one_time` contract and an already-expired contract generate
//!     nothing.
//!   * Advancing `now` into the next month generates a second invoice
//!     (new period), and re-running again is still idempotent.

mod common;

use chrono::{NaiveDate, TimeZone, Utc};
use mokosh_server::modules::audit::AuditCtx;
use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::billing::BillingService;
use mokosh_server::Database;
use rust_decimal::Decimal;
use sqlx::PgPool;
use uuid::Uuid;

/// Insert an `active` contract with the given billing cycle, start date,
/// and optional end date. Returns the contract id.
async fn seed_contract(
    pool: &PgPool,
    company_id: Uuid,
    billing_cycle: &str,
    start: NaiveDate,
    end: Option<NaiveDate>,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO contracts
           (id, tenant_id, name, company_id, contract_type, status,
            start_date, end_date, billing_cycle)
           VALUES ($1, $2, 'Managed', $3, 'managed_services', 'active',
                   $4, $5, $6)"#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .bind(start)
    .bind(end)
    .bind(billing_cycle)
    .execute(pool)
    .await
    .expect("seed contract");
    id
}

/// Insert a recurring (`recurring_service`) item on the contract.
async fn seed_recurring_item(
    pool: &PgPool,
    contract_id: Uuid,
    name: &str,
    quantity: Decimal,
    unit_price: Decimal,
    sort_order: i32,
) {
    sqlx::query(
        // PMS-956: `billing_rule` is stated, not left to the column default.
        // The default is `manual`, deliberately: a row written by a path that
        // forgot must not start charging a client, and a missing charge is
        // recoverable where a wrong one is a conversation. That makes stating
        // it the writer's job, and this fixture is a writer.
        r#"INSERT INTO contract_items
           (id, tenant_id, contract_id, name, item_type, quantity, unit_price,
            total_price, sort_order, billing_rule)
           VALUES ($1, $2, $3, $4, 'recurring_service', $5, $6, $7, $8,
                   'every_period')"#,
    )
    .bind(Uuid::new_v4())
    .bind(common::DEFAULT_TENANT_ID)
    .bind(contract_id)
    .bind(name)
    .bind(quantity)
    .bind(unit_price)
    .bind(quantity * unit_price)
    .bind(sort_order)
    .execute(pool)
    .await
    .expect("seed recurring item");
}

#[sqlx::test]
async fn monthly_contract_generates_one_invoice_for_due_period(pool: PgPool) {
    let tenant = common::DEFAULT_TENANT_ID;
    let company = common::seed_company(&pool).await;
    let start = NaiveDate::from_ymd_opt(2026, 1, 1).unwrap();
    let contract = seed_contract(&pool, company, "monthly", start, None).await;

    // Two recurring items: 1 @ $100 + 2 @ $50 = $200 subtotal.
    seed_recurring_item(
        &pool,
        contract,
        "Managed Services",
        common::dec("1"),
        common::dec("100"),
        0,
    )
    .await;
    seed_recurring_item(
        &pool,
        contract,
        "Backup Add-on",
        common::dec("2"),
        common::dec("50"),
        1,
    )
    .await;

    let svc = BillingService::new(Database::from_pool(pool.clone()));
    let ctx = AuditCtx::system(tenant);
    // Mid-January: the current period is [2026-01-01, 2026-01-31].
    let now = Utc.with_ymd_and_hms(2026, 1, 15, 12, 0, 0).unwrap();

    let created = svc
        .generate_due_recurring_invoices(TenantId::from_trusted(tenant), now, &ctx)
        .await
        .expect("generate recurring invoices");
    assert_eq!(created.len(), 1, "exactly one invoice for the due period");
    let invoice_id = created[0];

    // Invoice header: linked to the contract + company, draft, total 200.
    let (linked_contract, linked_company, status, total): (Option<Uuid>, Uuid, String, Decimal) =
        sqlx::query_as("SELECT contract_id, company_id, status, total FROM invoices WHERE id = $1")
            .bind(invoice_id)
            .fetch_one(&pool)
            .await
            .expect("read invoice");
    assert_eq!(linked_contract, Some(contract));
    assert_eq!(linked_company, company);
    assert_eq!(status, "draft");
    assert_eq!(total, common::dec("200"), "subtotal = 1*100 + 2*50 = 200");

    // One line per recurring item.
    let line_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM invoice_lines WHERE invoice_id = $1")
            .bind(invoice_id)
            .fetch_one(&pool)
            .await
            .expect("count lines");
    assert_eq!(line_count, 2, "one line per recurring item");

    // A ledger row was recorded for the period.
    let (p_start, p_end): (NaiveDate, NaiveDate) = sqlx::query_as(
        "SELECT period_start, period_end FROM contract_invoice_runs WHERE contract_id = $1",
    )
    .bind(contract)
    .fetch_one(&pool)
    .await
    .expect("ledger row");
    assert_eq!(p_start, NaiveDate::from_ymd_opt(2026, 1, 1).unwrap());
    assert_eq!(p_end, NaiveDate::from_ymd_opt(2026, 1, 31).unwrap());
}

#[sqlx::test]
async fn second_run_same_period_is_idempotent(pool: PgPool) {
    let tenant = common::DEFAULT_TENANT_ID;
    let company = common::seed_company(&pool).await;
    let start = NaiveDate::from_ymd_opt(2026, 1, 1).unwrap();
    let contract = seed_contract(&pool, company, "monthly", start, None).await;
    seed_recurring_item(
        &pool,
        contract,
        "Managed Services",
        common::dec("1"),
        common::dec("100"),
        0,
    )
    .await;

    let svc = BillingService::new(Database::from_pool(pool.clone()));
    let ctx = AuditCtx::system(tenant);
    let now = Utc.with_ymd_and_hms(2026, 1, 20, 8, 0, 0).unwrap();

    let first = svc
        .generate_due_recurring_invoices(TenantId::from_trusted(tenant), now, &ctx)
        .await
        .expect("first run");
    assert_eq!(first.len(), 1, "first run creates the invoice");

    // Second run with the same `now`: the period is already billed, so no
    // new invoice (ledger dedupe), even though the process "restarted".
    let second = svc
        .generate_due_recurring_invoices(TenantId::from_trusted(tenant), now, &ctx)
        .await
        .expect("second run");
    assert!(
        second.is_empty(),
        "second run creates nothing for the same period"
    );

    // Exactly one invoice + one ledger row exist for the contract.
    let invoice_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM invoices WHERE contract_id = $1")
            .bind(contract)
            .fetch_one(&pool)
            .await
            .expect("count invoices");
    assert_eq!(invoice_count, 1, "no duplicate invoice for the period");
    let ledger_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM contract_invoice_runs WHERE contract_id = $1")
            .bind(contract)
            .fetch_one(&pool)
            .await
            .expect("count ledger");
    assert_eq!(ledger_count, 1, "one ledger row per billed period");
}

#[sqlx::test]
async fn one_time_and_expired_contracts_generate_nothing(pool: PgPool) {
    let tenant = common::DEFAULT_TENANT_ID;
    let company = common::seed_company(&pool).await;
    let now = Utc.with_ymd_and_hms(2026, 6, 15, 0, 0, 0).unwrap();

    // one_time contract with a recurring item: must be skipped.
    let one_time = seed_contract(
        &pool,
        company,
        "one_time",
        NaiveDate::from_ymd_opt(2026, 1, 1).unwrap(),
        None,
    )
    .await;
    seed_recurring_item(
        &pool,
        one_time,
        "Setup",
        common::dec("1"),
        common::dec("500"),
        0,
    )
    .await;

    // Expired contract: its end_date precedes the period that `now`
    // falls in, so the computed period_start is past end_date -> skip.
    // start 2025-01-01 monthly, end 2025-03-31; by 2026-06 the current
    // period starts well after the end_date.
    let expired = seed_contract(
        &pool,
        company,
        "monthly",
        NaiveDate::from_ymd_opt(2025, 1, 1).unwrap(),
        Some(NaiveDate::from_ymd_opt(2025, 3, 31).unwrap()),
    )
    .await;
    seed_recurring_item(
        &pool,
        expired,
        "Old Service",
        common::dec("1"),
        common::dec("100"),
        0,
    )
    .await;

    let svc = BillingService::new(Database::from_pool(pool.clone()));
    let ctx = AuditCtx::system(tenant);

    let created = svc
        .generate_due_recurring_invoices(TenantId::from_trusted(tenant), now, &ctx)
        .await
        .expect("generate");
    assert!(
        created.is_empty(),
        "one_time + expired contracts generate no invoices, got {created:?}"
    );

    let invoice_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM invoices")
        .fetch_one(&pool)
        .await
        .expect("count invoices");
    assert_eq!(invoice_count, 0);
}

#[sqlx::test]
async fn contract_with_no_recurring_items_generates_nothing(pool: PgPool) {
    let tenant = common::DEFAULT_TENANT_ID;
    let company = common::seed_company(&pool).await;
    let start = NaiveDate::from_ymd_opt(2026, 1, 1).unwrap();
    let contract = seed_contract(&pool, company, "monthly", start, None).await;

    // Only a block_hours item (not recurring_service / retainer).
    sqlx::query(
        r#"INSERT INTO contract_items
           (id, tenant_id, contract_id, name, item_type, quantity, unit_price, total_price)
           VALUES ($1, $2, $3, 'Block', 'block_hours', 1, 0, 0)"#,
    )
    .bind(Uuid::new_v4())
    .bind(tenant)
    .bind(contract)
    .execute(&pool)
    .await
    .expect("seed block item");

    let svc = BillingService::new(Database::from_pool(pool.clone()));
    let ctx = AuditCtx::system(tenant);
    let now = Utc.with_ymd_and_hms(2026, 1, 15, 0, 0, 0).unwrap();

    let created = svc
        .generate_due_recurring_invoices(TenantId::from_trusted(tenant), now, &ctx)
        .await
        .expect("generate");
    assert!(created.is_empty(), "no recurring items -> no invoice");

    let ledger_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM contract_invoice_runs WHERE contract_id = $1")
            .bind(contract)
            .fetch_one(&pool)
            .await
            .expect("count ledger");
    assert_eq!(
        ledger_count, 0,
        "no ledger row when there is nothing to bill, so a later-added item still bills"
    );
}

#[sqlx::test]
async fn next_period_generates_a_new_invoice(pool: PgPool) {
    let tenant = common::DEFAULT_TENANT_ID;
    let company = common::seed_company(&pool).await;
    let start = NaiveDate::from_ymd_opt(2026, 1, 1).unwrap();
    let contract = seed_contract(&pool, company, "monthly", start, None).await;
    seed_recurring_item(
        &pool,
        contract,
        "Managed Services",
        common::dec("1"),
        common::dec("300"),
        0,
    )
    .await;

    let svc = BillingService::new(Database::from_pool(pool.clone()));
    let ctx = AuditCtx::system(tenant);

    // January period.
    let jan = Utc.with_ymd_and_hms(2026, 1, 10, 0, 0, 0).unwrap();
    let jan_created = svc
        .generate_due_recurring_invoices(TenantId::from_trusted(tenant), jan, &ctx)
        .await
        .expect("january run");
    assert_eq!(jan_created.len(), 1, "january invoice");

    // February period: a new, distinct invoice.
    let feb = Utc.with_ymd_and_hms(2026, 2, 10, 0, 0, 0).unwrap();
    let feb_created = svc
        .generate_due_recurring_invoices(TenantId::from_trusted(tenant), feb, &ctx)
        .await
        .expect("february run");
    assert_eq!(feb_created.len(), 1, "february invoice (new period)");
    assert_ne!(
        jan_created[0], feb_created[0],
        "february invoice is distinct from january's"
    );

    // Re-running February is still idempotent.
    let feb_again = svc
        .generate_due_recurring_invoices(TenantId::from_trusted(tenant), feb, &ctx)
        .await
        .expect("february rerun");
    assert!(feb_again.is_empty(), "february rerun creates nothing");

    // Two invoices + two ledger rows total (Jan + Feb), distinct periods.
    let invoice_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM invoices WHERE contract_id = $1")
            .bind(contract)
            .fetch_one(&pool)
            .await
            .expect("count invoices");
    assert_eq!(invoice_count, 2, "one invoice per billed period");

    let periods: Vec<NaiveDate> = sqlx::query_scalar(
        "SELECT period_start FROM contract_invoice_runs WHERE contract_id = $1 ORDER BY period_start",
    )
    .bind(contract)
    .fetch_all(&pool)
    .await
    .expect("ledger periods");
    assert_eq!(
        periods,
        vec![
            NaiveDate::from_ymd_opt(2026, 1, 1).unwrap(),
            NaiveDate::from_ymd_opt(2026, 2, 1).unwrap(),
        ]
    );
}

// ---- PMS-956: a product or one-time item is billed by something -------------

/// Seed a contract item of any type with an explicit billing rule.
async fn seed_item(
    pool: &PgPool,
    contract_id: Uuid,
    name: &str,
    item_type: &str,
    billing_rule: &str,
    unit_price: Decimal,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO contract_items
           (id, tenant_id, contract_id, name, item_type, quantity, unit_price,
            total_price, sort_order, billing_rule)
           VALUES ($1, $2, $3, $4, $5, 1, $6, $6, 0, $7)"#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(contract_id)
    .bind(name)
    .bind(item_type)
    .bind(unit_price)
    .bind(billing_rule)
    .execute(pool)
    .await
    .expect("seed item");
    id
}

async fn line_descriptions(pool: &PgPool, invoice_id: Uuid) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT description FROM invoice_lines WHERE invoice_id = $1 ORDER BY sort_order",
    )
    .bind(invoice_id)
    .fetch_all(pool)
    .await
    .expect("read invoice lines")
}

/// The defect, from the other side. A `product` item marked `every_period`
/// bills like any other recurring line, which is what "30 licences at 22.00 a
/// user" needs and what `item_type` alone could never express.
#[sqlx::test]
async fn a_product_item_bills_when_it_says_it_should(pool: PgPool) {
    let tenant = common::DEFAULT_TENANT_ID;
    let company = common::seed_company(&pool).await;
    let start = NaiveDate::from_ymd_opt(2026, 1, 1).unwrap();
    let contract = seed_contract(&pool, company, "monthly", start, None).await;

    seed_item(
        &pool,
        contract,
        "M365 licences",
        "product",
        "every_period",
        Decimal::from(660),
    )
    .await;
    // A second product left on the default: visible, settable, and not billed.
    seed_item(
        &pool,
        contract,
        "A switch we sold once",
        "product",
        "manual",
        Decimal::from(249),
    )
    .await;

    let svc = BillingService::new(Database::from_pool(pool.clone()));
    let ctx = AuditCtx::system(tenant);
    let now = Utc.with_ymd_and_hms(2026, 1, 15, 0, 0, 0).unwrap();
    let created = svc
        .generate_due_recurring_invoices(TenantId::from_trusted(tenant), now, &ctx)
        .await
        .expect("generate");
    assert_eq!(created.len(), 1, "one invoice for the due period");

    let lines = line_descriptions(&pool, created[0]).await;
    assert_eq!(
        lines,
        vec!["M365 licences".to_string()],
        "the every_period product bills and the manual one does not"
    );
}

/// `once` means once, and the period ledger cannot enforce it: that ledger is
/// keyed on the period, so a setup fee added in March would bill again in April
/// under a new period key. Two consecutive periods is the test that would have
/// caught a naive fix.
#[sqlx::test]
async fn a_one_time_item_bills_exactly_once(pool: PgPool) {
    let tenant = common::DEFAULT_TENANT_ID;
    let company = common::seed_company(&pool).await;
    let start = NaiveDate::from_ymd_opt(2026, 1, 1).unwrap();
    let contract = seed_contract(&pool, company, "monthly", start, None).await;

    seed_item(
        &pool,
        contract,
        "Onboarding",
        "one_time",
        "once",
        Decimal::from(2000),
    )
    .await;
    seed_item(
        &pool,
        contract,
        "Managed services",
        "recurring_service",
        "every_period",
        Decimal::from(500),
    )
    .await;

    let svc = BillingService::new(Database::from_pool(pool.clone()));
    let ctx = AuditCtx::system(tenant);

    let january = svc
        .generate_due_recurring_invoices(
            TenantId::from_trusted(tenant),
            Utc.with_ymd_and_hms(2026, 1, 15, 0, 0, 0).unwrap(),
            &ctx,
        )
        .await
        .expect("january");
    assert_eq!(january.len(), 1);
    let mut lines = line_descriptions(&pool, january[0]).await;
    lines.sort();
    assert_eq!(
        lines,
        vec!["Managed services".to_string(), "Onboarding".to_string()],
        "the setup fee is on the first invoice"
    );

    let february = svc
        .generate_due_recurring_invoices(
            TenantId::from_trusted(tenant),
            Utc.with_ymd_and_hms(2026, 2, 15, 0, 0, 0).unwrap(),
            &ctx,
        )
        .await
        .expect("february");
    assert_eq!(
        february.len(),
        1,
        "a new period still bills the recurring item"
    );
    assert_eq!(
        line_descriptions(&pool, february[0]).await,
        vec!["Managed services".to_string()],
        "and never the setup fee again"
    );

    let billed_at: Option<chrono::DateTime<Utc>> =
        sqlx::query_scalar("SELECT billed_at FROM contract_items WHERE name = 'Onboarding'")
            .fetch_one(&pool)
            .await
            .expect("read billed_at");
    assert!(billed_at.is_some(), "the claim is recorded on the item");
}

/// A contract whose only item is a spent one-time charge has nothing left to
/// bill, and must not produce an empty invoice or a ledger row that would block
/// a later item.
#[sqlx::test]
async fn a_spent_one_time_item_leaves_nothing_to_bill(pool: PgPool) {
    let tenant = common::DEFAULT_TENANT_ID;
    let company = common::seed_company(&pool).await;
    let start = NaiveDate::from_ymd_opt(2026, 1, 1).unwrap();
    let contract = seed_contract(&pool, company, "monthly", start, None).await;
    seed_item(
        &pool,
        contract,
        "Onboarding",
        "one_time",
        "once",
        Decimal::from(2000),
    )
    .await;

    let svc = BillingService::new(Database::from_pool(pool.clone()));
    let ctx = AuditCtx::system(tenant);

    assert_eq!(
        svc.generate_due_recurring_invoices(
            TenantId::from_trusted(tenant),
            Utc.with_ymd_and_hms(2026, 1, 15, 0, 0, 0).unwrap(),
            &ctx,
        )
        .await
        .expect("january")
        .len(),
        1
    );

    let february = svc
        .generate_due_recurring_invoices(
            TenantId::from_trusted(tenant),
            Utc.with_ymd_and_hms(2026, 2, 15, 0, 0, 0).unwrap(),
            &ctx,
        )
        .await
        .expect("february");
    assert!(february.is_empty(), "nothing left, so no invoice at all");

    let invoices: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM invoices WHERE tenant_id = $1")
        .bind(tenant)
        .fetch_one(&pool)
        .await
        .expect("count invoices");
    assert_eq!(invoices, 1, "and no empty second invoice was written");
}

/// The safety property of the whole change. Every existing row was written by
/// somebody who has not been charging for it, so the backfill marks only the
/// two types that already billed, and a row left on the column default bills
/// nothing rather than starting to charge a client for something recorded
/// months ago.
#[sqlx::test]
async fn an_item_that_never_billed_does_not_start(pool: PgPool) {
    let tenant = common::DEFAULT_TENANT_ID;
    let company = common::seed_company(&pool).await;
    let start = NaiveDate::from_ymd_opt(2026, 1, 1).unwrap();
    let contract = seed_contract(&pool, company, "monthly", start, None).await;

    // Written the way a pre-PMS-956 row was: no billing_rule at all.
    for (name, item_type) in [
        ("A switch", "product"),
        ("Onboarding", "one_time"),
        ("Block", "block_hours"),
    ] {
        sqlx::query(
            r#"INSERT INTO contract_items
               (id, tenant_id, contract_id, name, item_type, quantity, unit_price, total_price)
               VALUES ($1, $2, $3, $4, $5, 1, 100, 100)"#,
        )
        .bind(Uuid::new_v4())
        .bind(tenant)
        .bind(contract)
        .bind(name)
        .bind(item_type)
        .execute(&pool)
        .await
        .expect("seed legacy item");
    }

    let svc = BillingService::new(Database::from_pool(pool.clone()));
    let ctx = AuditCtx::system(tenant);
    let created = svc
        .generate_due_recurring_invoices(
            TenantId::from_trusted(tenant),
            Utc.with_ymd_and_hms(2026, 1, 15, 0, 0, 0).unwrap(),
            &ctx,
        )
        .await
        .expect("generate");
    assert!(
        created.is_empty(),
        "none of these was billing before and none of them starts"
    );
}
