//! Integration test: business-hours-aware SLA clock (PMS-106).
//!
//! Two layers of coverage:
//!
//! 1. A pure-engine assertion driving
//!    `mokosh_server::modules::sla::clock::due_at` directly with a
//!    Mon-Fri 09:00-17:00 America/New_York schedule and a holiday, to
//!    pin the Friday-late -> following-working-day behavior with explicit
//!    UTC timestamps (deterministic, no DB).
//!
//! 2. An end-to-end assertion that inserts a business_hours row (weekday
//!    09:00-17:00, America/New_York), a holiday calendar referenced from
//!    that row, a non-default sla_policy + sla_target
//!    (operational_hours = business_hours), and a ticket on that policy,
//!    then calls `SlaService::evaluate_for_ticket` and asserts the
//!    persisted `first_response_due` / `resolution_due` skip the weekend.
//!
//! The default tenant (00000000-0000-0000-0000-000000000001) already
//! exists from migration 002 and is seeded with priorities / statuses /
//! queues by migration 023, so this test reuses it and creates only the
//! SLA-specific rows. The seed migration already inserts an
//! `is_default = TRUE` business_hours + sla_policy for that tenant; this
//! test's rows are deliberately NOT default and are referenced by id so
//! they never collide with the seeded defaults.

mod common;

use std::collections::HashSet;

use chrono::{DateTime, NaiveDate, NaiveTime, TimeZone, Utc, Weekday};
use chrono_tz::America::New_York;
use sqlx::PgPool;
use uuid::Uuid;

use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::sla::clock::{self, BusinessSchedule, OperationalHours};
use mokosh_server::modules::sla::SlaService;
use mokosh_server::Database;

fn utc(y: i32, m: u32, d: u32, h: u32, min: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(y, m, d, h, min, 0).unwrap()
}

/// Pure engine: Friday-late start skips the weekend onto Monday.
#[test]
fn friday_late_start_lands_on_monday_via_engine() {
    let nine = NaiveTime::from_hms_opt(9, 0, 0).unwrap();
    let five = NaiveTime::from_hms_opt(17, 0, 0).unwrap();
    let schedule = BusinessSchedule::from_windows(
        New_York,
        [
            (Weekday::Mon, vec![(nine, five)]),
            (Weekday::Tue, vec![(nine, five)]),
            (Weekday::Wed, vec![(nine, five)]),
            (Weekday::Thu, vec![(nine, five)]),
            (Weekday::Fri, vec![(nine, five)]),
        ],
    );

    // 2026-06-05 is a Friday. 20:00 UTC == 16:00 EDT (1h before close).
    // +4h business hours: 1h Friday (16->17 EDT), weekend skipped, 3h
    // Monday 2026-06-08 (09->12 EDT) => 12:00 EDT == 16:00 UTC.
    let start = utc(2026, 6, 5, 20, 0); // 16:00 EDT Friday
    let got = clock::due_at(
        start,
        4.0,
        &schedule,
        &HashSet::new(),
        OperationalHours::BusinessHours,
    );
    assert_eq!(got, utc(2026, 6, 8, 16, 0), "must roll Friday->Monday");

    // With Monday 2026-06-08 a holiday, the remaining 3h slide to
    // Tuesday 2026-06-09 09->12 EDT => 16:00 UTC.
    let mut holidays = HashSet::new();
    holidays.insert(NaiveDate::from_ymd_opt(2026, 6, 8).unwrap());
    let got_hol = clock::due_at(
        start,
        4.0,
        &schedule,
        &holidays,
        OperationalHours::BusinessHours,
    );
    assert_eq!(
        got_hol,
        utc(2026, 6, 9, 16, 0),
        "holiday Monday must push to Tuesday"
    );
}

/// End-to-end: persisted due times via the wired evaluate path.
#[sqlx::test]
async fn evaluate_for_ticket_uses_business_hours(pool: PgPool) {
    let tenant_id = common::DEFAULT_TENANT_ID;
    let (admin_id, _email, _password) = common::seed_admin(&pool).await;

    // A "Medium" priority is seeded as the default for the tenant.
    let priority_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM ticket_priorities WHERE tenant_id = $1 AND name = 'Medium'",
    )
    .bind(tenant_id)
    .fetch_one(&pool)
    .await
    .expect("seeded Medium priority");
    let status_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM ticket_statuses WHERE tenant_id = $1 AND is_default = TRUE",
    )
    .bind(tenant_id)
    .fetch_one(&pool)
    .await
    .expect("seeded default status");
    let queue_id: Uuid =
        sqlx::query_scalar("SELECT id FROM ticket_queues WHERE tenant_id = $1 LIMIT 1")
            .bind(tenant_id)
            .fetch_one(&pool)
            .await
            .expect("seeded queue");

    // Company for the ticket FK.
    let company_id = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, 'SLA Co')")
        .bind(company_id)
        .bind(tenant_id)
        .execute(&pool)
        .await
        .expect("seed company");

    // Holiday calendar: Monday 2026-06-08 is a holiday.
    let holiday_cal_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO holiday_calendars (id, tenant_id, name, holidays)
           VALUES ($1, $2, 'PMS-106 Test Holidays',
                   '[{"date": "2026-06-08", "name": "Test Holiday"}]'::jsonb)"#,
    )
    .bind(holiday_cal_id)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("seed holiday calendar");

    // Business hours: Mon-Fri 09:00-17:00 America/New_York, referencing
    // the holiday calendar above. NOT default (the seed owns default).
    let bh_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO business_hours (id, tenant_id, name, timezone, schedule, holidays, is_default)
           VALUES ($1, $2, 'PMS-106 Test Hours', 'America/New_York',
                   '{
                       "0": null,
                       "1": {"start": "09:00", "end": "17:00"},
                       "2": {"start": "09:00", "end": "17:00"},
                       "3": {"start": "09:00", "end": "17:00"},
                       "4": {"start": "09:00", "end": "17:00"},
                       "5": {"start": "09:00", "end": "17:00"},
                       "6": null
                   }'::jsonb,
                   ARRAY[$3]::uuid[], FALSE)"#,
    )
    .bind(bh_id)
    .bind(tenant_id)
    .bind(holiday_cal_id)
    .execute(&pool)
    .await
    .expect("seed business hours");

    // SLA policy on those business hours (non-default), and a target on
    // the Medium priority: 4h first response, 8h resolution, business
    // hours operational window.
    let policy_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO sla_policies (id, tenant_id, name, business_hours_id, is_default)
           VALUES ($1, $2, 'PMS-106 Test SLA', $3, FALSE)"#,
    )
    .bind(policy_id)
    .bind(tenant_id)
    .bind(bh_id)
    .execute(&pool)
    .await
    .expect("seed sla policy");

    sqlx::query(
        r#"INSERT INTO sla_targets
           (sla_policy_id, priority_id, first_response_hours, resolution_hours, operational_hours)
           VALUES ($1, $2, 4, 8, 'business_hours')"#,
    )
    .bind(policy_id)
    .bind(priority_id)
    .execute(&pool)
    .await
    .expect("seed sla target");

    // Ticket created Friday 2026-06-05 20:00 UTC (16:00 EDT), explicitly
    // assigned to the test policy via sla_id so resolution does not rely
    // on the seeded default.
    let ticket_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO tickets
           (id, tenant_id, ticket_number, title, status_id, priority_id, queue_id,
            company_id, sla_id, created_by_id, created_at)
           VALUES ($1, $2, 'PMS-106-1', 'Friday late ticket', $3, $4, $5, $6, $7, $8,
                   '2026-06-05T20:00:00Z')"#,
    )
    .bind(ticket_id)
    .bind(tenant_id)
    .bind(status_id)
    .bind(priority_id)
    .bind(queue_id)
    .bind(company_id)
    .bind(policy_id)
    .bind(admin_id)
    .execute(&pool)
    .await
    .expect("seed ticket");

    // Evaluate through the wired service path.
    let service = SlaService::new(Database::from_pool(pool.clone()));
    service
        .evaluate_for_ticket(TenantId::from_trusted(tenant_id), ticket_id)
        .await
        .expect("evaluate_for_ticket");

    let (fr_due, res_due): (Option<DateTime<Utc>>, Option<DateTime<Utc>>) =
        sqlx::query_as("SELECT first_response_due, resolution_due FROM tickets WHERE id = $1")
            .bind(ticket_id)
            .fetch_one(&pool)
            .await
            .expect("read back due dates");

    // First response: 4h business hours from Friday 16:00 EDT. 1h Friday
    // (16->17 EDT), Monday 2026-06-08 is the holiday (skipped), 3h
    // Tuesday 2026-06-09 (09->12 EDT) => 12:00 EDT == 16:00 UTC.
    assert_eq!(
        fr_due,
        Some(utc(2026, 6, 9, 16, 0)),
        "first_response_due must skip weekend + holiday onto Tuesday"
    );

    // Resolution: 8h business hours. 1h Friday (16->17 EDT), weekend +
    // holiday Monday skipped, then 7h Tuesday 2026-06-09 09->16 EDT =>
    // 16:00 EDT == 20:00 UTC.
    assert_eq!(
        res_due,
        Some(utc(2026, 6, 9, 20, 0)),
        "resolution_due must consume 7h on Tuesday after the holiday"
    );
}
