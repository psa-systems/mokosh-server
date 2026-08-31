//! Integration tests for the contracts core (PMS-64).
//!
//! Drives `ContractsService` directly against a per-test database (no
//! HTTP layer needed for service-level math), mirroring the `tests/rmm.rs`
//! pattern: `Database::from_pool(pool.clone())`, the seeded default tenant
//! (`common::DEFAULT_TENANT_ID`), and direct SQL for fixtures.
//!
//! Coverage:
//!   * `consume_hours` inside the included allotment debits the balance
//!     and reports no overage.
//!   * `consume_hours` past the allotment splits applied vs overage and
//!     computes `overage_amount = overage_hours * overage_rate`.
//!   * `roll_to_next_period` carries unused hours forward, capped at
//!     `max_rollover_hours`, and `consume_hours` then draws from the
//!     larger next-period allotment.
//!   * `resolve_rate` honours the emergency > after_hours > hourly
//!     precedence.
//!   * `expire_due_contracts` renews an auto_renew contract past its
//!     end_date (advancing the dates) and expires a non-auto_renew one,
//!     and records the pre-update row as the audit `old_values` and the
//!     post-update row as `new_values` (PMS-779, now both taken from the
//!     batch read and the `UPDATE ... RETURNING` rather than extra reads).

mod common;

use chrono::{NaiveDate, TimeZone, Utc};
use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::contracts::ContractsService;
use mokosh_server::modules::time_tracking::TimeTrackingService;
use mokosh_server::utils::error::AppError;
use mokosh_server::Database;
use rust_decimal::Decimal;
use sqlx::PgPool;
use uuid::Uuid;

/// Insert a `block_hours` contract starting `start` with monthly billing.
async fn seed_block_contract(pool: &PgPool, company_id: Uuid, start: NaiveDate) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO contracts
           (id, tenant_id, contract_number, name, company_id, contract_type, status,
            start_date, billing_cycle)
           VALUES ($1, $2, 'C-001', 'Block Hours', $3, 'block_hours', 'active', $4, 'monthly')"#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .bind(start)
    .execute(pool)
    .await
    .expect("seed contract");
    id
}

/// Insert a `block_hours` contract starting `start` with an explicit
/// `billing_cycle` (PMS-404: exercises sub-month cycles end to end,
/// including the DB CHECK constraint that must accept the value).
async fn seed_block_contract_with_cycle(
    pool: &PgPool,
    company_id: Uuid,
    start: NaiveDate,
    billing_cycle: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO contracts
           (id, tenant_id, contract_number, name, company_id, contract_type, status,
            start_date, billing_cycle)
           VALUES ($1, $2, 'C-002', 'Weekly Block', $3, 'block_hours', 'active', $4, $5)"#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .bind(start)
    .bind(billing_cycle)
    .execute(pool)
    .await
    .expect("seed cycle contract");
    id
}

/// Insert the contract's `block_hours` item.
#[allow(clippy::too_many_arguments)]
async fn seed_block_item(
    pool: &PgPool,
    contract_id: Uuid,
    included: Decimal,
    overage_rate: Decimal,
    rollover_enabled: bool,
    max_rollover: Option<Decimal>,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO contract_items
           (id, tenant_id, contract_id, name, item_type, quantity, unit_price, total_price,
            included_hours, overage_rate, rollover_enabled, max_rollover_hours)
           VALUES ($1, $2, $3, 'Monthly Block', 'block_hours', 1, 0, 0,
                   $4, $5, $6, $7)"#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(contract_id)
    .bind(included)
    .bind(overage_rate)
    .bind(rollover_enabled)
    .bind(max_rollover)
    .execute(pool)
    .await
    .expect("seed block item");
    id
}

#[sqlx::test]
async fn consume_within_allotment_debits_balance(pool: PgPool) {
    let tenant = common::DEFAULT_TENANT_ID;
    let company = common::seed_company(&pool).await;
    let start = NaiveDate::from_ymd_opt(2026, 1, 1).unwrap();
    let contract = seed_block_contract(&pool, company, start).await;
    seed_block_item(
        &pool,
        contract,
        common::dec("10"),
        common::dec("200"),
        false,
        None,
    )
    .await;

    let svc = ContractsService::new(Database::from_pool(pool.clone()));
    let when = Utc.with_ymd_and_hms(2026, 1, 15, 12, 0, 0).unwrap();

    let out = svc
        .consume_hours(
            TenantId::from_trusted(tenant),
            contract,
            common::dec("4"),
            when,
        )
        .await
        .expect("consume 4h");
    assert_eq!(out.hours_applied, common::dec("4"));
    assert_eq!(out.overage_hours, common::dec("0"));
    assert_eq!(out.overage_amount, common::dec("0"));

    // Balance row created with the included allotment and debited.
    let (used, remaining): (Decimal, Decimal) = sqlx::query_as(
        "SELECT hours_used, hours_remaining FROM contract_hour_balances WHERE id = $1",
    )
    .bind(out.balance_id)
    .fetch_one(&pool)
    .await
    .expect("balance row");
    assert_eq!(used, common::dec("4"));
    assert_eq!(remaining, common::dec("6"));
}

/// PMS-404: a `weekly` contract is accepted by the DB CHECK constraint and
/// `consume_hours` buckets into a contiguous 7-day window anchored on
/// `start_date`. Two consumes 9 days apart land in different weekly
/// balance rows: [Jan 1, Jan 7] and [Jan 8, Jan 14].
#[sqlx::test]
async fn consume_weekly_buckets_into_seven_day_windows(pool: PgPool) {
    let tenant = common::DEFAULT_TENANT_ID;
    let company = common::seed_company(&pool).await;
    let start = NaiveDate::from_ymd_opt(2026, 1, 1).unwrap();
    let contract = seed_block_contract_with_cycle(&pool, company, start, "weekly").await;
    seed_block_item(
        &pool,
        contract,
        common::dec("10"),
        common::dec("200"),
        false,
        None,
    )
    .await;

    let svc = ContractsService::new(Database::from_pool(pool.clone()));

    // Jan 5 falls in the first 7-day window [Jan 1, Jan 7].
    let week1 = Utc.with_ymd_and_hms(2026, 1, 5, 12, 0, 0).unwrap();
    let out1 = svc
        .consume_hours(
            TenantId::from_trusted(tenant),
            contract,
            common::dec("3"),
            week1,
        )
        .await
        .expect("consume week1");
    let (p1_start, p1_end): (NaiveDate, NaiveDate) =
        sqlx::query_as("SELECT period_start, period_end FROM contract_hour_balances WHERE id = $1")
            .bind(out1.balance_id)
            .fetch_one(&pool)
            .await
            .expect("week1 balance");
    assert_eq!(p1_start, NaiveDate::from_ymd_opt(2026, 1, 1).unwrap());
    assert_eq!(p1_end, NaiveDate::from_ymd_opt(2026, 1, 7).unwrap());

    // Jan 10 falls in the second 7-day window [Jan 8, Jan 14] -> new row.
    let week2 = Utc.with_ymd_and_hms(2026, 1, 10, 12, 0, 0).unwrap();
    let out2 = svc
        .consume_hours(
            TenantId::from_trusted(tenant),
            contract,
            common::dec("2"),
            week2,
        )
        .await
        .expect("consume week2");
    assert_ne!(out1.balance_id, out2.balance_id, "distinct weekly periods");
    let (p2_start, p2_end): (NaiveDate, NaiveDate) =
        sqlx::query_as("SELECT period_start, period_end FROM contract_hour_balances WHERE id = $1")
            .bind(out2.balance_id)
            .fetch_one(&pool)
            .await
            .expect("week2 balance");
    assert_eq!(p2_start, NaiveDate::from_ymd_opt(2026, 1, 8).unwrap());
    assert_eq!(p2_end, NaiveDate::from_ymd_opt(2026, 1, 14).unwrap());
}

/// PMS-404: a `bi_weekly` contract is accepted by the DB CHECK constraint
/// and `consume_hours` buckets into a 14-day window anchored on
/// `start_date`: Jan 10 falls in the first window [Jan 1, Jan 14].
#[sqlx::test]
async fn consume_bi_weekly_buckets_into_fourteen_day_windows(pool: PgPool) {
    let tenant = common::DEFAULT_TENANT_ID;
    let company = common::seed_company(&pool).await;
    let start = NaiveDate::from_ymd_opt(2026, 1, 1).unwrap();
    let contract = seed_block_contract_with_cycle(&pool, company, start, "bi_weekly").await;
    seed_block_item(
        &pool,
        contract,
        common::dec("10"),
        common::dec("200"),
        false,
        None,
    )
    .await;

    let svc = ContractsService::new(Database::from_pool(pool.clone()));
    let when = Utc.with_ymd_and_hms(2026, 1, 10, 12, 0, 0).unwrap();
    let out = svc
        .consume_hours(
            TenantId::from_trusted(tenant),
            contract,
            common::dec("3"),
            when,
        )
        .await
        .expect("consume bi_weekly");
    let (p_start, p_end): (NaiveDate, NaiveDate) =
        sqlx::query_as("SELECT period_start, period_end FROM contract_hour_balances WHERE id = $1")
            .bind(out.balance_id)
            .fetch_one(&pool)
            .await
            .expect("bi_weekly balance");
    assert_eq!(p_start, NaiveDate::from_ymd_opt(2026, 1, 1).unwrap());
    assert_eq!(p_end, NaiveDate::from_ymd_opt(2026, 1, 14).unwrap());
}

#[sqlx::test]
async fn consume_past_allotment_computes_overage(pool: PgPool) {
    let tenant = common::DEFAULT_TENANT_ID;
    let company = common::seed_company(&pool).await;
    let start = NaiveDate::from_ymd_opt(2026, 1, 1).unwrap();
    let contract = seed_block_contract(&pool, company, start).await;
    seed_block_item(
        &pool,
        contract,
        common::dec("10"),
        common::dec("150"),
        false,
        None,
    )
    .await;

    let svc = ContractsService::new(Database::from_pool(pool.clone()));
    let when = Utc.with_ymd_and_hms(2026, 1, 20, 9, 0, 0).unwrap();

    // included 10, request 13 -> 10 applied, 3 overage at 150/h = 450.
    let out = svc
        .consume_hours(
            TenantId::from_trusted(tenant),
            contract,
            common::dec("13"),
            when,
        )
        .await
        .expect("consume 13h");
    assert_eq!(out.hours_applied, common::dec("10"));
    assert_eq!(out.overage_hours, common::dec("3"));
    assert_eq!(out.overage_amount, common::dec("450"));

    let remaining: Decimal =
        sqlx::query_scalar("SELECT hours_remaining FROM contract_hour_balances WHERE id = $1")
            .bind(out.balance_id)
            .fetch_one(&pool)
            .await
            .expect("balance row");
    assert_eq!(remaining, common::dec("0"));
}

#[sqlx::test]
async fn rollover_carries_capped_unused_hours(pool: PgPool) {
    let tenant = common::DEFAULT_TENANT_ID;
    let company = common::seed_company(&pool).await;
    let start = NaiveDate::from_ymd_opt(2026, 1, 1).unwrap();
    let contract = seed_block_contract(&pool, company, start).await;
    // 10 included, rollover enabled, capped at 3.
    seed_block_item(
        &pool,
        contract,
        common::dec("10"),
        common::dec("100"),
        true,
        Some(common::dec("3")),
    )
    .await;

    let svc = ContractsService::new(Database::from_pool(pool.clone()));

    // January: use 4 of 10 -> 6 unused, but cap rollover at 3.
    let jan = Utc.with_ymd_and_hms(2026, 1, 10, 0, 0, 0).unwrap();
    svc.consume_hours(
        TenantId::from_trusted(tenant),
        contract,
        common::dec("4"),
        jan,
    )
    .await
    .expect("consume jan");

    // Close January (period_end = 2026-01-31) and roll into February.
    let jan_end = NaiveDate::from_ymd_opt(2026, 1, 31).unwrap();
    let rolled = svc
        .roll_to_next_period(TenantId::from_trusted(tenant), contract, jan_end)
        .await
        .expect("roll");
    assert_eq!(
        rolled,
        common::dec("3"),
        "6 unused capped at max_rollover 3"
    );

    // February balance pre-seeded with 10 + 3 = 13 included / remaining.
    let feb_start = NaiveDate::from_ymd_opt(2026, 2, 1).unwrap();
    let (included, remaining, rollover): (Decimal, Decimal, Decimal) = sqlx::query_as(
        r#"SELECT hours_included, hours_remaining, rollover_hours
           FROM contract_hour_balances
           WHERE contract_id = $1 AND period_start = $2"#,
    )
    .bind(contract)
    .bind(feb_start)
    .fetch_one(&pool)
    .await
    .expect("feb balance");
    assert_eq!(included, common::dec("13"));
    assert_eq!(remaining, common::dec("13"));
    assert_eq!(rollover, common::dec("3"));

    // Consuming 13 in February now fits exactly (rollover included).
    let feb = Utc.with_ymd_and_hms(2026, 2, 15, 0, 0, 0).unwrap();
    let out = svc
        .consume_hours(
            TenantId::from_trusted(tenant),
            contract,
            common::dec("13"),
            feb,
        )
        .await
        .expect("consume feb");
    assert_eq!(out.hours_applied, common::dec("13"));
    assert_eq!(out.overage_hours, common::dec("0"));
}

/// Seed a billable work type and return its id.
async fn seed_work_type(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO work_types
           (id, tenant_id, name, default_billable, is_active, sort_order)
           VALUES ($1, $2, 'Remote Support', TRUE, TRUE, 0)"#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .execute(pool)
    .await
    .expect("seed work type");
    id
}

/// Seed a pending time entry. `duration_minutes` and the contract / billable
/// flags drive PMS-405 consumption at approval.
#[allow(clippy::too_many_arguments)]
async fn seed_time_entry(
    pool: &PgPool,
    user_id: Uuid,
    company_id: Uuid,
    work_type_id: Uuid,
    contract_id: Option<Uuid>,
    date: NaiveDate,
    duration_minutes: i32,
    is_billable: bool,
) {
    sqlx::query(
        r#"INSERT INTO time_entries
           (id, tenant_id, user_id, date, duration_minutes, work_type_id,
            company_id, contract_id, is_billable, approval_status, billing_status)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'pending', 'not_billed')"#,
    )
    .bind(Uuid::new_v4())
    .bind(common::DEFAULT_TENANT_ID)
    .bind(user_id)
    .bind(date)
    .bind(duration_minutes)
    .bind(work_type_id)
    .bind(company_id)
    .bind(contract_id)
    .bind(is_billable)
    .execute(pool)
    .await
    .expect("seed time entry");
}

/// PMS-405: approving billable time logged against a block-hours contract
/// decrements the contract hour balance, and hours past `included_hours`
/// split into a persisted overage.
#[sqlx::test]
async fn approving_time_consumes_contract_hours_with_overage(pool: PgPool) {
    let tenant = common::DEFAULT_TENANT_ID;
    let company = common::seed_company(&pool).await;
    // 2026-01-12 is a Monday; the timesheet week is anchored on it.
    let start = NaiveDate::from_ymd_opt(2026, 1, 1).unwrap();
    let monday = NaiveDate::from_ymd_opt(2026, 1, 12).unwrap();
    let contract = seed_block_contract(&pool, company, start).await;
    let item = seed_block_item(
        &pool,
        contract,
        common::dec("10"),
        common::dec("150"),
        false,
        None,
    )
    .await;

    let work_type = seed_work_type(&pool).await;
    let (user, _, _) = common::seed_user(&pool, tenant, "tt-405@example.com", "technician").await;

    // Two billable entries (8h + 5h = 13h) against the contract, plus one
    // non-billable entry that must NOT consume, all in the same week.
    seed_time_entry(
        &pool,
        user,
        company,
        work_type,
        Some(contract),
        monday,
        480,
        true,
    )
    .await;
    seed_time_entry(
        &pool,
        user,
        company,
        work_type,
        Some(contract),
        monday + chrono::Duration::days(1),
        300,
        true,
    )
    .await;
    seed_time_entry(
        &pool,
        user,
        company,
        work_type,
        Some(contract),
        monday + chrono::Duration::days(2),
        120,
        false,
    )
    .await;

    let tt = TimeTrackingService::new(Database::from_pool(pool.clone()));
    tt.approve_timesheet(TenantId::from_trusted(tenant), user, user, monday)
        .await
        .expect("approve week");

    // 13 billable hours against a 10h allotment: 10 used, 0 remaining,
    // 3h overage persisted (only the two billable entries count).
    let (used, remaining, included): (Decimal, Decimal, Decimal) = sqlx::query_as(
        r#"SELECT hours_used, hours_remaining, hours_included
           FROM contract_hour_balances
           WHERE contract_id = $1 AND contract_item_id = $2"#,
    )
    .bind(contract)
    .bind(item)
    .fetch_one(&pool)
    .await
    .expect("balance row exists after approval");
    assert_eq!(included, common::dec("10"));
    assert_eq!(used, common::dec("10"), "hours_used capped at allotment");
    assert_eq!(remaining, common::dec("0"), "remaining fully drawn down");

    // Re-approving the (now approved) week is a no-op: no double-counting.
    tt.approve_timesheet(TenantId::from_trusted(tenant), user, user, monday)
        .await
        .expect("re-approve week");
    let used_again: Decimal = sqlx::query_scalar(
        r#"SELECT hours_used FROM contract_hour_balances
           WHERE contract_id = $1 AND contract_item_id = $2"#,
    )
    .bind(contract)
    .bind(item)
    .fetch_one(&pool)
    .await
    .expect("balance row");
    assert_eq!(
        used_again,
        common::dec("10"),
        "re-approval must not consume hours twice"
    );
}

/// PMS-405: a within-allotment week decrements without overage.
#[sqlx::test]
async fn approving_time_within_allotment_decrements_balance(pool: PgPool) {
    let tenant = common::DEFAULT_TENANT_ID;
    let company = common::seed_company(&pool).await;
    let start = NaiveDate::from_ymd_opt(2026, 1, 1).unwrap();
    let monday = NaiveDate::from_ymd_opt(2026, 1, 12).unwrap();
    let contract = seed_block_contract(&pool, company, start).await;
    let item = seed_block_item(
        &pool,
        contract,
        common::dec("10"),
        common::dec("150"),
        false,
        None,
    )
    .await;
    let work_type = seed_work_type(&pool).await;
    let (user, _, _) = common::seed_user(&pool, tenant, "tt-405b@example.com", "technician").await;

    // 4 billable hours against a 10h allotment.
    seed_time_entry(
        &pool,
        user,
        company,
        work_type,
        Some(contract),
        monday,
        240,
        true,
    )
    .await;

    let tt = TimeTrackingService::new(Database::from_pool(pool.clone()));
    tt.approve_timesheet(TenantId::from_trusted(tenant), user, user, monday)
        .await
        .expect("approve week");

    let (used, remaining): (Decimal, Decimal) = sqlx::query_as(
        r#"SELECT hours_used, hours_remaining
           FROM contract_hour_balances
           WHERE contract_id = $1 AND contract_item_id = $2"#,
    )
    .bind(contract)
    .bind(item)
    .fetch_one(&pool)
    .await
    .expect("balance row");
    assert_eq!(used, common::dec("4"));
    assert_eq!(remaining, common::dec("6"));
}

#[sqlx::test]
async fn resolve_rate_honours_tier_precedence(pool: PgPool) {
    let tenant = common::DEFAULT_TENANT_ID;
    let svc = ContractsService::new(Database::from_pool(pool.clone()));

    // Use the seeded default rate card + one of its seeded work types.
    let rate_card_id: Uuid =
        sqlx::query_scalar("SELECT id FROM rate_cards WHERE tenant_id = $1 AND is_default = TRUE")
            .bind(tenant)
            .fetch_one(&pool)
            .await
            .expect("default rate card");
    // 'Remote Support' seed: hourly 150, after_hours 150*1.5=225, emergency 150*2=300.
    let work_type_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM work_types WHERE tenant_id = $1 AND name = 'Remote Support'",
    )
    .bind(tenant)
    .fetch_one(&pool)
    .await
    .expect("work type");

    let base = svc
        .resolve_rate(
            TenantId::from_trusted(tenant),
            rate_card_id,
            work_type_id,
            false,
            false,
        )
        .await
        .expect("base rate");
    let after = svc
        .resolve_rate(
            TenantId::from_trusted(tenant),
            rate_card_id,
            work_type_id,
            true,
            false,
        )
        .await
        .expect("after-hours rate");
    let emergency = svc
        .resolve_rate(
            TenantId::from_trusted(tenant),
            rate_card_id,
            work_type_id,
            true,
            true,
        )
        .await
        .expect("emergency rate");

    assert_eq!(base, common::dec("150.00"));
    assert_eq!(after, common::dec("225.00"));
    assert_eq!(
        emergency,
        common::dec("300.00"),
        "emergency wins over after_hours"
    );
}

#[sqlx::test]
async fn expire_due_renews_auto_renew_and_expires_others(pool: PgPool) {
    let tenant = common::DEFAULT_TENANT_ID;
    let company = common::seed_company(&pool).await;

    // Auto-renew contract, 1-year term, already past end_date.
    let renew_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO contracts
           (id, tenant_id, name, company_id, contract_type, status,
            start_date, end_date, auto_renew, renewal_terms)
           VALUES ($1, $2, 'Renew Me', $3, 'managed_services', 'active',
                   '2025-01-01', '2025-12-31', TRUE, '{"term_months": 12}'::jsonb)"#,
    )
    .bind(renew_id)
    .bind(tenant)
    .bind(company)
    .execute(&pool)
    .await
    .expect("seed renew contract");

    // Non-auto-renew contract, also past end_date.
    let expire_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO contracts
           (id, tenant_id, name, company_id, contract_type, status,
            start_date, end_date, auto_renew)
           VALUES ($1, $2, 'Expire Me', $3, 'fixed_price', 'active',
                   '2025-01-01', '2025-06-30', FALSE)"#,
    )
    .bind(expire_id)
    .bind(tenant)
    .bind(company)
    .execute(&pool)
    .await
    .expect("seed expire contract");

    let svc = ContractsService::new(Database::from_pool(pool.clone()));
    let now = Utc.with_ymd_and_hms(2026, 1, 15, 0, 0, 0).unwrap();
    let (renewed, expired) = svc.expire_due_contracts(now).await.expect("sweep");
    assert_eq!(renewed, 1);
    assert_eq!(expired, 1);

    // Renewed contract: status flipped, dates advanced by 12 months.
    let (status, new_start, new_end): (String, NaiveDate, NaiveDate) =
        sqlx::query_as("SELECT status, start_date, end_date FROM contracts WHERE id = $1")
            .bind(renew_id)
            .fetch_one(&pool)
            .await
            .expect("renew row");
    assert_eq!(status, "renewed");
    assert_eq!(new_start, NaiveDate::from_ymd_opt(2026, 1, 1).unwrap());
    assert_eq!(new_end, NaiveDate::from_ymd_opt(2026, 12, 31).unwrap());

    // Expired contract.
    let status: String = sqlx::query_scalar("SELECT status FROM contracts WHERE id = $1")
        .bind(expire_id)
        .fetch_one(&pool)
        .await
        .expect("expire row");
    assert_eq!(status, "expired");

    // PMS-779: both audit snapshots survive the fold into the batch read and
    // the `UPDATE ... RETURNING`. `old_values` is the whole pre-update row,
    // `new_values` the whole post-update row.
    for (id, before_status, after_status) in [
        (renew_id, "active", "renewed"),
        (expire_id, "active", "expired"),
    ] {
        let (old_values, new_values): (Option<serde_json::Value>, Option<serde_json::Value>) =
            sqlx::query_as(
                r#"SELECT old_values, new_values FROM audit_log
                   WHERE entity_type = 'contracts' AND entity_id = $1 AND action = 'update'"#,
            )
            .bind(id)
            .fetch_one(&pool)
            .await
            .expect("sweep audit row");
        let old = old_values.expect("sweep records the pre-update snapshot");
        let new = new_values.expect("sweep records the post-update snapshot");
        assert_eq!(old["id"].as_str(), Some(id.to_string().as_str()));
        assert_eq!(old["status"].as_str(), Some(before_status));
        assert_eq!(new["status"].as_str(), Some(after_status));
        // The snapshot is the whole row, not the sweep's projection.
        assert!(
            old.get("name").is_some() && old.get("company_id").is_some(),
            "the `before` snapshot carries every column: {old}"
        );
    }

    // The renewal's dates are captured on both sides of the update.
    let old_values: serde_json::Value = sqlx::query_scalar(
        r#"SELECT old_values FROM audit_log
           WHERE entity_type = 'contracts' AND entity_id = $1 AND action = 'update'"#,
    )
    .bind(renew_id)
    .fetch_one(&pool)
    .await
    .expect("renewal audit row");
    assert_eq!(old_values["end_date"].as_str(), Some("2025-12-31"));
}

#[sqlx::test]
async fn list_recurring_items_returns_recurring_and_retainer(pool: PgPool) {
    let tenant = common::DEFAULT_TENANT_ID;
    let company = common::seed_company(&pool).await;
    let start = NaiveDate::from_ymd_opt(2026, 1, 1).unwrap();
    let contract = seed_block_contract(&pool, company, start).await;

    // One recurring, one retainer, one block_hours (excluded).
    for (name, item_type) in [
        ("Monthly Managed", "recurring_service"),
        ("Retainer", "retainer"),
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
        .expect("seed item");
    }

    let svc = ContractsService::new(Database::from_pool(pool.clone()));
    let items = svc
        .list_recurring_items(TenantId::from_trusted(tenant), contract)
        .await
        .expect("list recurring");
    assert_eq!(items.len(), 2, "only recurring_service + retainer");
    assert!(items.iter().all(|i| i.item_type != "block_hours"));
}

#[sqlx::test]
async fn get_rate_card_returns_card_in_tenant(pool: PgPool) {
    let tenant = common::DEFAULT_TENANT_ID;
    let svc = ContractsService::new(Database::from_pool(pool.clone()));

    let id: Uuid =
        sqlx::query_scalar("SELECT id FROM rate_cards WHERE tenant_id = $1 AND is_default = TRUE")
            .bind(tenant)
            .fetch_one(&pool)
            .await
            .expect("default rate card");

    let card = svc
        .get_rate_card(TenantId::from_trusted(tenant), id)
        .await
        .expect("fetch seeded rate card");
    assert_eq!(card.id, id);
    assert!(card.is_default);
}

#[sqlx::test]
async fn get_rate_card_missing_id_is_not_found(pool: PgPool) {
    let tenant = common::DEFAULT_TENANT_ID;
    let svc = ContractsService::new(Database::from_pool(pool.clone()));

    let err = svc
        .get_rate_card(TenantId::from_trusted(tenant), Uuid::new_v4())
        .await
        .expect_err("missing id is 404");
    assert!(matches!(err, AppError::NotFound(_)));
}

#[sqlx::test]
async fn get_rate_card_other_tenant_is_not_found(pool: PgPool) {
    let tenant = common::DEFAULT_TENANT_ID;
    let svc = ContractsService::new(Database::from_pool(pool.clone()));

    // A rate card owned by a different tenant must not be visible.
    let (other_tenant, _, _, _) = common::seed_tenant_with_admin(&pool, "rate-card-other").await;
    let other_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO rate_cards (id, tenant_id, name, description, is_default)
           VALUES ($1, $2, 'Foreign', NULL, FALSE)"#,
    )
    .bind(other_id)
    .bind(other_tenant)
    .execute(&pool)
    .await
    .expect("seed foreign rate card");

    let err = svc
        .get_rate_card(TenantId::from_trusted(tenant), other_id)
        .await
        .expect_err("cross-tenant id is 404");
    assert!(matches!(err, AppError::NotFound(_)));
}

// ---- PMS-956: an item states whether it bills ------------------------------

/// Omitting `billing_rule` must reproduce exactly what each type does today,
/// because every existing API client omits it. Stating it is how a product on a
/// contract becomes a licence that bills every period.
#[sqlx::test]
async fn an_items_billing_rule_is_derived_when_the_caller_omits_it(pool: PgPool) {
    use mokosh_server::modules::audit::AuditCtx;
    use mokosh_server::modules::contracts::{BillingRule, UpsertContractItemRequest};

    let company = common::seed_company(&pool).await;
    let contract =
        seed_block_contract(&pool, company, NaiveDate::from_ymd_opt(2026, 1, 1).unwrap()).await;
    let svc = ContractsService::new(Database::from_pool(pool.clone()));
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let ctx = AuditCtx::system(common::DEFAULT_TENANT_ID);

    let item = |item_type: &str, rule: Option<BillingRule>| UpsertContractItemRequest {
        name: format!("{item_type} item"),
        description: None,
        item_type: item_type.to_string(),
        quantity: Decimal::ONE,
        unit_price: Decimal::from(100),
        billing_frequency: "monthly".to_string(),
        work_type_id: None,
        included_hours: None,
        overage_rate: None,
        rollover_enabled: false,
        max_rollover_hours: None,
        sort_order: 0,
        product_id: None,
        billing_rule: rule,
    };

    for (item_type, expected) in [
        ("recurring_service", BillingRule::EveryPeriod),
        ("retainer", BillingRule::EveryPeriod),
        ("one_time", BillingRule::Once),
        ("product", BillingRule::Manual),
        ("block_hours", BillingRule::Manual),
    ] {
        let created = svc
            .create_contract_item(tenant, contract, &item(item_type, None), &ctx)
            .await
            .expect("create item");
        assert_eq!(
            created.billing_rule, expected,
            "{item_type} with no rule stated"
        );
        assert!(created.billed_at.is_none(), "nothing is billed on creation");
    }

    // And stating it wins, which is the whole point: a product that is a
    // monthly licence rather than a box sold once.
    let licences = svc
        .create_contract_item(
            tenant,
            contract,
            &UpsertContractItemRequest {
                name: "M365 licences".to_string(),
                ..item("product", Some(BillingRule::EveryPeriod))
            },
            &ctx,
        )
        .await
        .expect("create licences");
    assert_eq!(licences.billing_rule, BillingRule::EveryPeriod);
}

/// Editing a `once` item that has already billed must not report it as
/// unbilled: the response reads `billed_at` back from the write rather than
/// assuming it, or the record would say the client still owes the charge.
#[sqlx::test]
async fn editing_a_spent_one_time_item_keeps_it_spent(pool: PgPool) {
    use mokosh_server::modules::audit::AuditCtx;
    use mokosh_server::modules::contracts::{BillingRule, UpsertContractItemRequest};

    let company = common::seed_company(&pool).await;
    let contract =
        seed_block_contract(&pool, company, NaiveDate::from_ymd_opt(2026, 1, 1).unwrap()).await;
    let svc = ContractsService::new(Database::from_pool(pool.clone()));
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let ctx = AuditCtx::system(common::DEFAULT_TENANT_ID);

    let request = UpsertContractItemRequest {
        name: "Onboarding".to_string(),
        description: None,
        item_type: "one_time".to_string(),
        quantity: Decimal::ONE,
        unit_price: Decimal::from(2000),
        billing_frequency: "monthly".to_string(),
        work_type_id: None,
        included_hours: None,
        overage_rate: None,
        rollover_enabled: false,
        max_rollover_hours: None,
        sort_order: 0,
        product_id: None,
        billing_rule: None,
    };
    let created = svc
        .create_contract_item(tenant, contract, &request, &ctx)
        .await
        .expect("create");
    assert_eq!(created.billing_rule, BillingRule::Once);

    // The generator's claim, as it would leave it.
    sqlx::query("UPDATE contract_items SET billed_at = NOW() WHERE id = $1")
        .bind(created.id)
        .execute(&pool)
        .await
        .expect("mark billed");

    let edited = svc
        .update_contract_item(
            tenant,
            created.id,
            &UpsertContractItemRequest {
                name: "Onboarding (revised)".to_string(),
                ..request
            },
            &ctx,
        )
        .await
        .expect("update");
    assert_eq!(edited.name, "Onboarding (revised)");
    assert!(
        edited.billed_at.is_some(),
        "an edit does not un-bill a charge that has already gone out"
    );
}
