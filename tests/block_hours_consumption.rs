//! PMS-951: time logged against a block-hours contract draws on it.
//!
//! `time_entries.contract_id` existed since migration 006 and the consumption
//! machinery read it since PMS-405, and nothing set it, so the whole path was
//! dead: a prepaid block never went down. These tests drive the real write
//! paths rather than calling `consume_hours` directly, which is precisely how
//! PMS-405's own tests passed against a write path that could not reach it.

mod common;

use chrono::NaiveDate;
use mokosh_server::modules::audit::AuditCtx;
use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::time_tracking::TimeTrackingService;
use mokosh_server::Database;
use rust_decimal::Decimal;
use sqlx::PgPool;
use std::str::FromStr;
use uuid::Uuid;

const START: fn() -> NaiveDate = || NaiveDate::from_ymd_opt(2026, 1, 1).unwrap();
const WHEN: fn() -> NaiveDate = || NaiveDate::from_ymd_opt(2026, 1, 15).unwrap();

async fn seed_work_type(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO work_types (id, tenant_id, name, default_billable, default_rate) \
         VALUES ($1, $2, 'Block work', TRUE, 150.00)",
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .execute(pool)
    .await
    .expect("seed work type");
    id
}

/// A live contract for `company` with a block of `included` hours.
async fn seed_block_contract(pool: &PgPool, company: Uuid, included: i32) -> Uuid {
    let contract = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contracts (id, tenant_id, name, company_id, contract_type, status, \
         start_date, billing_cycle) \
         VALUES ($1, $2, 'Block', $3, 'block_hours', 'active', $4, 'monthly')",
    )
    .bind(contract)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company)
    .bind(START())
    .execute(pool)
    .await
    .expect("seed contract");
    sqlx::query(
        "INSERT INTO contract_items (id, tenant_id, contract_id, name, item_type, quantity, \
         unit_price, total_price, included_hours, overage_rate, billing_rule) \
         VALUES ($1, $2, $3, 'Block', 'block_hours', 1, 0, 0, $4, 200, 'manual')",
    )
    .bind(Uuid::new_v4())
    .bind(common::DEFAULT_TENANT_ID)
    .bind(contract)
    .bind(Decimal::from(included))
    .execute(pool)
    .await
    .expect("seed block item");
    contract
}

async fn balance(pool: &PgPool, contract: Uuid) -> Option<(Decimal, Decimal)> {
    sqlx::query_as(
        "SELECT hours_used, hours_remaining FROM contract_hour_balances \
                    WHERE tenant_id = $1 AND contract_id = $2",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(contract)
    .fetch_optional(pool)
    .await
    .expect("read balance")
}

async fn entry_draw(pool: &PgPool, entry: Uuid) -> (Option<Uuid>, Option<Decimal>) {
    sqlx::query_as("SELECT contract_id, hours_consumed FROM time_entries WHERE id = $1")
        .bind(entry)
        .fetch_one(pool)
        .await
        .expect("read entry")
}

fn create_request(
    user_id: Uuid,
    work_type_id: Uuid,
    company_id: Option<Uuid>,
    minutes: i32,
    billable: bool,
) -> mokosh_types::time_tracking::CreateTimeEntryRequest {
    serde_json::from_value(serde_json::json!({
        "user_id": user_id,
        "date": WHEN(),
        "duration_minutes": minutes,
        "work_type_id": work_type_id,
        "company_id": company_id,
        "is_billable": billable,
        "notes": "Block work",
    }))
    .expect("build request")
}

/// The bug, from the other side: logging time draws on the block, without
/// anybody approving anything.
#[sqlx::test]
async fn logging_time_draws_on_the_block(pool: PgPool) {
    let (user_id, _e, _p) = common::seed_admin(&pool).await;
    let company = common::seed_company(&pool).await;
    let work_type = seed_work_type(&pool).await;
    let contract = seed_block_contract(&pool, company, 10).await;

    let svc = TimeTrackingService::new(Database::from_pool(pool.clone()));
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let ctx = AuditCtx::system(common::DEFAULT_TENANT_ID);

    assert!(
        balance(&pool, contract).await.is_none(),
        "nothing drawn before any time is logged"
    );

    let entry = svc
        .create_time_entry(
            tenant,
            &create_request(user_id, work_type, Some(company), 120, true),
            &ctx,
        )
        .await
        .expect("create entry");

    let (linked, consumed) = entry_draw(&pool, entry.id).await;
    assert_eq!(
        linked,
        Some(contract),
        "the contract is derived from the company, not asked for"
    );
    assert_eq!(consumed, Some(Decimal::from(2)));
    assert_eq!(
        balance(&pool, contract).await,
        Some((Decimal::from(2), Decimal::from(8)))
    );
}

/// Only billable client work draws. Employee time has no client to bill and a
/// non-billable hour is not being charged for, so neither should come out of an
/// allotment the client paid for.
#[sqlx::test]
async fn time_that_is_not_a_clients_billable_work_draws_nothing(pool: PgPool) {
    let (user_id, _e, _p) = common::seed_admin(&pool).await;
    let company = common::seed_company(&pool).await;
    let work_type = seed_work_type(&pool).await;
    let contract = seed_block_contract(&pool, company, 10).await;

    let svc = TimeTrackingService::new(Database::from_pool(pool.clone()));
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let ctx = AuditCtx::system(common::DEFAULT_TENANT_ID);

    // Non-billable, against the same company.
    svc.create_time_entry(
        tenant,
        &create_request(user_id, work_type, Some(company), 60, false),
        &ctx,
    )
    .await
    .expect("non-billable");
    // Employee time: no company at all (PMS-942).
    svc.create_time_entry(
        tenant,
        &create_request(user_id, work_type, None, 60, false),
        &ctx,
    )
    .await
    .expect("employee time");

    assert!(
        balance(&pool, contract).await.is_none(),
        "neither is a client's billable work, so the block is untouched"
    );
}

/// An edit gives back what it took and draws again, so the balance follows the
/// entry rather than the first version of it.
#[sqlx::test]
async fn editing_an_entry_moves_the_balance_with_it(pool: PgPool) {
    let (user_id, _e, _p) = common::seed_admin(&pool).await;
    let company = common::seed_company(&pool).await;
    let work_type = seed_work_type(&pool).await;
    let contract = seed_block_contract(&pool, company, 10).await;

    let svc = TimeTrackingService::new(Database::from_pool(pool.clone()));
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let ctx = AuditCtx::system(common::DEFAULT_TENANT_ID);

    let entry = svc
        .create_time_entry(
            tenant,
            &create_request(user_id, work_type, Some(company), 120, true),
            &ctx,
        )
        .await
        .expect("create");
    assert_eq!(
        balance(&pool, contract).await,
        Some((Decimal::from(2), Decimal::from(8)))
    );

    // Three hours, not two.
    let longer: mokosh_types::time_tracking::UpdateTimeEntryRequest =
        serde_json::from_value(serde_json::json!({ "duration_minutes": 180 }))
            .expect("build update");
    svc.update_time_entry(tenant, entry.id, &longer)
        .await
        .expect("lengthen");
    assert_eq!(
        balance(&pool, contract).await,
        Some((Decimal::from(3), Decimal::from(7))),
        "the extra hour is drawn, and the first two were not drawn twice"
    );

    // And turning it non-billable gives the whole draw back.
    let unbillable: mokosh_types::time_tracking::UpdateTimeEntryRequest =
        serde_json::from_value(serde_json::json!({ "is_billable": false })).expect("build update");
    svc.update_time_entry(tenant, entry.id, &unbillable)
        .await
        .expect("unbill");
    assert_eq!(
        balance(&pool, contract).await,
        Some((Decimal::ZERO, Decimal::from(10))),
        "an hour nobody is charging for comes back out of the allotment"
    );
}

/// Deleting an entry returns its hours. The record of what it drew lives on the
/// row, so the release has to happen before the row does not exist.
#[sqlx::test]
async fn deleting_an_entry_returns_its_hours(pool: PgPool) {
    let (user_id, _e, _p) = common::seed_admin(&pool).await;
    let company = common::seed_company(&pool).await;
    let work_type = seed_work_type(&pool).await;
    let contract = seed_block_contract(&pool, company, 10).await;

    let svc = TimeTrackingService::new(Database::from_pool(pool.clone()));
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let ctx = AuditCtx::system(common::DEFAULT_TENANT_ID);

    let entry = svc
        .create_time_entry(
            tenant,
            &create_request(user_id, work_type, Some(company), 240, true),
            &ctx,
        )
        .await
        .expect("create");
    assert_eq!(
        balance(&pool, contract).await,
        Some((Decimal::from(4), Decimal::from(6)))
    );

    svc.delete_time_entry(tenant, entry.id)
        .await
        .expect("delete");
    assert_eq!(
        balance(&pool, contract).await,
        Some((Decimal::ZERO, Decimal::from(10)))
    );
}

/// Past the allotment, the balance bottoms out and the rest is overage: only
/// the applied part comes out of the block. Recording the applied hours rather
/// than the duration is what makes the release exact, so a delete gives back
/// eight and not twelve.
#[sqlx::test]
async fn hours_past_the_block_are_overage_and_only_the_applied_part_returns(pool: PgPool) {
    let (user_id, _e, _p) = common::seed_admin(&pool).await;
    let company = common::seed_company(&pool).await;
    let work_type = seed_work_type(&pool).await;
    let contract = seed_block_contract(&pool, company, 8).await;

    let svc = TimeTrackingService::new(Database::from_pool(pool.clone()));
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let ctx = AuditCtx::system(common::DEFAULT_TENANT_ID);

    let entry = svc
        .create_time_entry(
            tenant,
            &create_request(user_id, work_type, Some(company), 12 * 60, true),
            &ctx,
        )
        .await
        .expect("create");

    assert_eq!(
        balance(&pool, contract).await,
        Some((Decimal::from(8), Decimal::ZERO)),
        "the block is spent, and the other four hours are overage"
    );
    let (_, consumed) = entry_draw(&pool, entry.id).await;
    assert_eq!(
        consumed,
        Some(Decimal::from(8)),
        "the entry records what it took, not what it worked"
    );

    svc.delete_time_entry(tenant, entry.id)
        .await
        .expect("delete");
    assert_eq!(
        balance(&pool, contract).await,
        Some((Decimal::ZERO, Decimal::from(8))),
        "eight back, not twelve: the contract never gave the overage"
    );
}

/// A company with no block-hours contract is every other company, and logging
/// time against one must stay exactly as cheap as it was.
#[sqlx::test]
async fn a_company_with_no_block_contract_is_unaffected(pool: PgPool) {
    let (user_id, _e, _p) = common::seed_admin(&pool).await;
    let company = common::seed_company(&pool).await;
    let work_type = seed_work_type(&pool).await;

    let svc = TimeTrackingService::new(Database::from_pool(pool.clone()));
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let ctx = AuditCtx::system(common::DEFAULT_TENANT_ID);

    let entry = svc
        .create_time_entry(
            tenant,
            &create_request(user_id, work_type, Some(company), 60, true),
            &ctx,
        )
        .await
        .expect("create");

    let (linked, consumed) = entry_draw(&pool, entry.id).await;
    assert_eq!(linked, None);
    assert_eq!(consumed, None);
    let any: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM contract_hour_balances")
        .fetch_one(&pool)
        .await
        .expect("count balances");
    assert_eq!(any, 0);
}

/// The double-draw this change had to avoid. Approval used to be the
/// consumption point (PMS-405); with `contract_id` finally being set, leaving
/// it there would have drawn every hour twice for a tenant with timesheets on.
#[sqlx::test]
async fn approving_a_timesheet_does_not_draw_again(pool: PgPool) {
    let (user_id, _e, _p) = common::seed_admin(&pool).await;
    let company = common::seed_company(&pool).await;
    let work_type = seed_work_type(&pool).await;
    let contract = seed_block_contract(&pool, company, 10).await;

    let svc = TimeTrackingService::new(Database::from_pool(pool.clone()));
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let ctx = AuditCtx::system(common::DEFAULT_TENANT_ID);

    svc.create_time_entry(
        tenant,
        &create_request(user_id, work_type, Some(company), 120, true),
        &ctx,
    )
    .await
    .expect("create");
    let after_logging = balance(&pool, contract).await;
    assert_eq!(after_logging, Some((Decimal::from(2), Decimal::from(8))));

    // Submit and approve the week the entry falls in.
    sqlx::query("UPDATE time_entries SET approval_status = 'pending' WHERE tenant_id = $1")
        .bind(common::DEFAULT_TENANT_ID)
        .execute(&pool)
        .await
        .expect("submit");
    let monday = NaiveDate::from_ymd_opt(2026, 1, 12).unwrap();
    svc.approve_timesheet(tenant, user_id, user_id, monday)
        .await
        .expect("approve");

    assert_eq!(
        balance(&pool, contract).await,
        after_logging,
        "approval is not a second consumption point"
    );
}

/// Decimal comparison sanity: the helpers above compare against whole hours, so
/// a fractional entry has to land where it should too.
#[sqlx::test]
async fn a_fractional_entry_draws_its_fraction(pool: PgPool) {
    let (user_id, _e, _p) = common::seed_admin(&pool).await;
    let company = common::seed_company(&pool).await;
    let work_type = seed_work_type(&pool).await;
    let contract = seed_block_contract(&pool, company, 10).await;

    let svc = TimeTrackingService::new(Database::from_pool(pool.clone()));
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let ctx = AuditCtx::system(common::DEFAULT_TENANT_ID);

    svc.create_time_entry(
        tenant,
        &create_request(user_id, work_type, Some(company), 90, true),
        &ctx,
    )
    .await
    .expect("create");

    let (used, remaining) = balance(&pool, contract).await.expect("balance");
    assert_eq!(used, Decimal::from_str("1.5").unwrap());
    assert_eq!(remaining, Decimal::from_str("8.5").unwrap());
}

// ============================================================================
// PMS-1035: the billing half. Hours inside the block are prepaid and never
// invoiced again; hours past it bill at the overage rate.
// ============================================================================

use mokosh_server::modules::billing::BillingService;

async fn entry_billing(
    pool: &PgPool,
    entry: Uuid,
) -> (String, Option<Decimal>, Option<Decimal>, Option<Uuid>) {
    sqlx::query_as(
        "SELECT billing_status, overage_hours, overage_rate, invoice_id \
         FROM time_entries WHERE id = $1",
    )
    .bind(entry)
    .fetch_one(pool)
    .await
    .expect("read entry billing")
}

/// Generate the company's time-entry invoice the way `POST
/// /invoices/from-time-entries` does, and hand back its lines as
/// `(description, quantity, unit_price, total)`.
async fn invoice_lines(
    pool: &PgPool,
    company: Uuid,
) -> Result<Vec<(String, Decimal, Decimal, Decimal)>, String> {
    let billing = BillingService::new(Database::from_pool(pool.clone()));
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let ctx = AuditCtx::system(common::DEFAULT_TENANT_ID);
    let request = serde_json::from_value(serde_json::json!({ "company_id": company }))
        .expect("invoice request");
    let invoice = billing
        .create_invoice_from_time_entries(tenant, "UTC", &request, &ctx)
        .await
        .map_err(|e| e.to_string())?;
    Ok(sqlx::query_as(
        "SELECT description, quantity, unit_price, total FROM invoice_lines \
         WHERE invoice_id = $1 ORDER BY sort_order",
    )
    .bind(invoice.id)
    .fetch_all(pool)
    .await
    .expect("read lines"))
}

/// An entry the block covers is `prepaid`: not on the invoice, and the
/// refusal says the hours were covered rather than calling them not ready.
#[sqlx::test]
async fn time_inside_the_block_is_prepaid_and_never_invoiced(pool: PgPool) {
    let (user_id, _e, _p) = common::seed_admin(&pool).await;
    let company = common::seed_company(&pool).await;
    let work_type = seed_work_type(&pool).await;
    seed_block_contract(&pool, company, 10).await;
    let svc = TimeTrackingService::new(Database::from_pool(pool.clone()));
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let ctx = AuditCtx::system(common::DEFAULT_TENANT_ID);

    let entry = svc
        .create_time_entry(
            tenant,
            &create_request(user_id, work_type, Some(company), 120, true),
            &ctx,
        )
        .await
        .expect("create entry");
    let (status, overage, rate, invoice) = entry_billing(&pool, entry.id).await;
    assert_eq!(status, "prepaid");
    assert_eq!((overage, rate, invoice), (None, None, None));

    let refused = invoice_lines(&pool, company)
        .await
        .expect_err("nothing to invoice");
    assert!(
        refused.contains("1 time entry (2 hours) covered by the block-hours contract"),
        "{refused}"
    );
    assert!(
        !refused.contains("not marked ready"),
        "prepaid time is not a fault: {refused}"
    );
    let (status, _, _, invoice) = entry_billing(&pool, entry.id).await;
    assert_eq!((status.as_str(), invoice), ("prepaid", None));
}

/// Ten hours against an eight-hour block: one line for the two hours over,
/// at the contract's overage rate, and nothing for the eight the customer
/// already paid for.
#[sqlx::test]
async fn overage_bills_at_the_overage_rate_and_the_prepaid_part_does_not(pool: PgPool) {
    let (user_id, _e, _p) = common::seed_admin(&pool).await;
    let company = common::seed_company(&pool).await;
    let work_type = seed_work_type(&pool).await;
    seed_block_contract(&pool, company, 8).await;
    let svc = TimeTrackingService::new(Database::from_pool(pool.clone()));
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let ctx = AuditCtx::system(common::DEFAULT_TENANT_ID);

    let entry = svc
        .create_time_entry(
            tenant,
            &create_request(user_id, work_type, Some(company), 600, true),
            &ctx,
        )
        .await
        .expect("create entry");
    let (status, overage, rate, _) = entry_billing(&pool, entry.id).await;
    assert_eq!(
        status, "ready_to_bill",
        "an entry with overage stays invoiceable"
    );
    assert_eq!(overage, Some(Decimal::from(2)));
    assert_eq!(rate, Some(Decimal::from(200)));

    let lines = invoice_lines(&pool, company).await.expect("invoice");
    assert_eq!(lines.len(), 1, "{lines:?}");
    let (description, quantity, unit_price, total) = &lines[0];
    assert_eq!(*quantity, Decimal::from(2), "the overage hours only");
    assert_eq!(
        *unit_price,
        Decimal::from(200),
        "the contract's overage rate"
    );
    assert_eq!(*total, Decimal::from(400));
    assert!(
        description.ends_with("2h over the 8h block"),
        "the line says what it is: {description}"
    );
    let (status, _, _, invoice) = entry_billing(&pool, entry.id).await;
    assert_eq!(status, "billed");
    assert!(invoice.is_some());
}

/// A block item with no overage rate bills the overage at the entry's own
/// hourly rate, and once the block is exhausted an entry is overage in full
/// and the line says so.
#[sqlx::test]
async fn overage_with_no_rate_bills_at_the_entrys_own_rate(pool: PgPool) {
    let (user_id, _e, _p) = common::seed_admin(&pool).await;
    let company = common::seed_company(&pool).await;
    let work_type = seed_work_type(&pool).await;
    let contract = seed_block_contract(&pool, company, 8).await;
    sqlx::query("UPDATE contract_items SET overage_rate = NULL WHERE contract_id = $1")
        .bind(contract)
        .execute(&pool)
        .await
        .expect("drop the overage rate");
    let svc = TimeTrackingService::new(Database::from_pool(pool.clone()));
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let ctx = AuditCtx::system(common::DEFAULT_TENANT_ID);

    // Ten hours: eight prepaid, two over. Then one more hour past the block.
    let first = svc
        .create_time_entry(
            tenant,
            &create_request(user_id, work_type, Some(company), 600, true),
            &ctx,
        )
        .await
        .expect("create first entry");
    let second = svc
        .create_time_entry(
            tenant,
            &create_request(user_id, work_type, Some(company), 60, true),
            &ctx,
        )
        .await
        .expect("create second entry");
    let own_rate = first.hourly_rate.expect("the entry priced its hour");
    assert!(own_rate > Decimal::ZERO);
    let (_, overage, rate, _) = entry_billing(&pool, first.id).await;
    assert_eq!((overage, rate), (Some(Decimal::from(2)), None));
    let (_, overage, _, _) = entry_billing(&pool, second.id).await;
    assert_eq!(
        overage,
        Some(Decimal::ONE),
        "past an exhausted block, all of it"
    );

    let lines = invoice_lines(&pool, company).await.expect("invoice");
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert_eq!(lines[0].1, Decimal::from(2));
    assert_eq!(lines[0].2, own_rate, "no overage rate: the entry's own");
    assert!(
        lines[0].0.ends_with("2h over the 8h block"),
        "{}",
        lines[0].0
    );
    assert_eq!(lines[1].1, Decimal::ONE);
    assert_eq!(lines[1].2, own_rate);
    assert!(
        lines[1].0.ends_with("1h past an exhausted block"),
        "{}",
        lines[1].0
    );
    let total: Decimal = lines.iter().map(|l| l.3).sum();
    assert_eq!(total, Decimal::from(3) * own_rate);
}

/// Releasing a draw forgets what it decided: a prepaid entry made
/// non-billable and billable again is drawn afresh, and an overage entry
/// shortened to fit the block loses its overage and becomes prepaid.
#[sqlx::test]
async fn releasing_a_draw_makes_the_entry_billable_again_in_full(pool: PgPool) {
    let (user_id, _e, _p) = common::seed_admin(&pool).await;
    let company = common::seed_company(&pool).await;
    let work_type = seed_work_type(&pool).await;
    let contract = seed_block_contract(&pool, company, 8).await;
    let svc = TimeTrackingService::new(Database::from_pool(pool.clone()));
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let ctx = AuditCtx::system(common::DEFAULT_TENANT_ID);
    let update = |json: serde_json::Value| -> mokosh_types::time_tracking::UpdateTimeEntryRequest {
        serde_json::from_value(json).expect("update request")
    };

    let entry = svc
        .create_time_entry(
            tenant,
            &create_request(user_id, work_type, Some(company), 600, true),
            &ctx,
        )
        .await
        .expect("create entry");
    assert_eq!(
        entry_billing(&pool, entry.id).await.1,
        Some(Decimal::from(2))
    );

    // Shortened to fit: the overage goes and the entry is prepaid.
    svc.update_time_entry(
        tenant,
        entry.id,
        &update(serde_json::json!({ "duration_minutes": 300 })),
    )
    .await
    .expect("shorten");
    let (status, overage, rate, _) = entry_billing(&pool, entry.id).await;
    assert_eq!((status.as_str(), overage, rate), ("prepaid", None, None));
    assert_eq!(
        balance(&pool, contract).await,
        Some((Decimal::from(5), Decimal::from(3)))
    );

    // Made non-billable: the draw is released and the entry is not billable
    // at all, with nothing left on the block.
    svc.update_time_entry(
        tenant,
        entry.id,
        &update(serde_json::json!({ "is_billable": false })),
    )
    .await
    .expect("make non-billable");
    let (status, _, _, _) = entry_billing(&pool, entry.id).await;
    assert_eq!(status, "not_billed");
    assert_eq!(entry_draw(&pool, entry.id).await.1, None);
    assert_eq!(
        balance(&pool, contract).await,
        Some((Decimal::ZERO, Decimal::from(8)))
    );

    // And billable again: drawn afresh, prepaid again.
    svc.update_time_entry(
        tenant,
        entry.id,
        &update(serde_json::json!({ "is_billable": true })),
    )
    .await
    .expect("make billable");
    let (status, _, _, _) = entry_billing(&pool, entry.id).await;
    assert_eq!(status, "prepaid");
    assert_eq!(entry_draw(&pool, entry.id).await.1, Some(Decimal::from(5)));
}
