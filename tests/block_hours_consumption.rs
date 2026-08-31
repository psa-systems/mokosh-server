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
