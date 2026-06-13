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
//!     end_date (advancing the dates) and expires a non-auto_renew one.

mod common;

use chrono::{NaiveDate, TimeZone, Utc};
use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::contracts::ContractsService;
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
