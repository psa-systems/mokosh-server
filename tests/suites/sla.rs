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

use crate::common;

use mokosh_test::mokosh_test;
use std::collections::HashSet;
use std::sync::Arc;

use chrono::{DateTime, NaiveDate, NaiveTime, TimeZone, Utc, Weekday};
use chrono_tz::America::New_York;
use sqlx::PgPool;
use uuid::Uuid;

use mokosh_server::modules::audit::AuditCtx;
use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::sla::clock::{self, BusinessSchedule, OperationalHours};
use mokosh_server::modules::sla::SlaService;
use mokosh_server::modules::tickets::TicketService;
use mokosh_server::Database;
use mokosh_types::tickets::{CreateTicketRequest, TicketSource, UpdateTicketRequest};

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
#[mokosh_test]
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

/// PMS-1564: `TicketService::create_ticket` and `::update_ticket` must call
/// `SlaService::evaluate_for_ticket` (via `TicketService::with_sla`,
/// `create_api_router`'s wiring) rather than leave due dates on wall-clock
/// time. Two assertions:
///
///   1. Create: the due dates `create_ticket` persists already match what a
///      second, direct `evaluate_for_ticket` call (standing in for the
///      manual `/sla/tickets/{id}/evaluate` route) returns for the same
///      ticket - i.e. create already ran the real evaluator, not a
///      wall-clock approximation.
///   2. Status change: with the ticket's `created_at` moved to a Friday
///      evening (after business hours close) and its due-date columns
///      cleared to simulate stale/missing data, an `update_ticket` call
///      that only changes `status_id` must repopulate them with the
///      business-hours-aware values `clock::due_at` computes directly,
///      proving the status-change path re-evaluates rather than leaving
///      them untouched.
#[mokosh_test]
async fn ticket_create_and_status_change_evaluate_sla(pool: PgPool) {
    let tenant_id = common::DEFAULT_TENANT_ID;
    let tenant = TenantId::from_trusted(tenant_id);
    let (admin_id, _email, _password) = common::seed_admin(&pool).await;

    let priority_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM ticket_priorities WHERE tenant_id = $1 AND name = 'Medium'",
    )
    .bind(tenant_id)
    .fetch_one(&pool)
    .await
    .expect("seeded Medium priority");
    let queue_id: Uuid =
        sqlx::query_scalar("SELECT id FROM ticket_queues WHERE tenant_id = $1 LIMIT 1")
            .bind(tenant_id)
            .fetch_one(&pool)
            .await
            .expect("seeded queue");
    let in_progress_status_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM ticket_statuses WHERE tenant_id = $1 AND name = 'In Progress'",
    )
    .bind(tenant_id)
    .fetch_one(&pool)
    .await
    .expect("seeded In Progress status");

    let company_id = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, 'PMS-1564 Co')")
        .bind(company_id)
        .bind(tenant_id)
        .execute(&pool)
        .await
        .expect("seed company");

    // Business hours Mon-Fri 09:00-17:00 America/New_York, no holidays,
    // NOT default (the seed owns default).
    let bh_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO business_hours (id, tenant_id, name, timezone, schedule, is_default)
           VALUES ($1, $2, 'PMS-1564 Test Hours', 'America/New_York',
                   '{
                       "0": null,
                       "1": {"start": "09:00", "end": "17:00"},
                       "2": {"start": "09:00", "end": "17:00"},
                       "3": {"start": "09:00", "end": "17:00"},
                       "4": {"start": "09:00", "end": "17:00"},
                       "5": {"start": "09:00", "end": "17:00"},
                       "6": null
                   }'::jsonb, FALSE)"#,
    )
    .bind(bh_id)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("seed business hours");

    let policy_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO sla_policies (id, tenant_id, name, business_hours_id, is_default)
           VALUES ($1, $2, 'PMS-1564 Test SLA', $3, FALSE)"#,
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

    let db = Database::from_pool(pool.clone());
    let sla_service = SlaService::new(db.clone());
    let ticket_service = TicketService::new(db.clone()).with_sla(Arc::new(sla_service.clone()));

    // 1. Create: due dates must already match a direct evaluate_for_ticket
    // call (the manual route's own code path) for the same ticket.
    let request = CreateTicketRequest {
        title: "PMS-1564 create probe".to_string(),
        description: None,
        priority_id: None,
        type_id: None,
        category_id: None,
        queue_id: Some(queue_id),
        source: TicketSource::Api,
        company_id,
        contact_id: None,
        site_id: None,
        assigned_to_id: None,
        team_id: None,
        parent_ticket_id: None,
        contract_id: None,
        sla_id: Some(policy_id),
        scheduled_start: None,
        scheduled_end: None,
        estimated_hours: None,
        is_billable: true,
        asset_id: None,
        custom_fields: serde_json::json!({}),
        tags: vec![],
        source_kb_article_id: None,
        procedure_kb_article_id: None,
        email_message_id: None,
        email_thread_id: None,
    };
    let created = ticket_service
        .create_ticket(tenant, admin_id, &request, &AuditCtx::system(tenant_id))
        .await
        .expect("create ticket");
    let ticket_id = created.id;

    assert!(
        created.first_response_due.is_some() && created.resolution_due.is_some(),
        "create must set SLA due dates from the wired evaluator"
    );

    sla_service
        .evaluate_for_ticket(tenant, ticket_id)
        .await
        .expect("manual evaluate route");
    let (manual_fr, manual_res): (Option<DateTime<Utc>>, Option<DateTime<Utc>>) =
        sqlx::query_as("SELECT first_response_due, resolution_due FROM tickets WHERE id = $1")
            .bind(ticket_id)
            .fetch_one(&pool)
            .await
            .expect("read back due dates after manual evaluate");
    assert_eq!(
        created.first_response_due, manual_fr,
        "create's first_response_due must match the manual evaluate route's"
    );
    assert_eq!(
        created.resolution_due, manual_res,
        "create's resolution_due must match the manual evaluate route's"
    );

    // 2. Status change: move created_at to a Friday evening (after close),
    // clear the due-date columns to simulate stale data, then change only
    // status_id. The update must repopulate them with the real
    // business-hours math.
    let friday_evening = utc(2026, 6, 5, 20, 0); // 16:00 EDT Friday
    sqlx::query(
        "UPDATE tickets SET created_at = $1, first_response_due = NULL, \
         resolution_due = NULL, sla_due_date = NULL WHERE id = $2",
    )
    .bind(friday_evening)
    .bind(ticket_id)
    .execute(&pool)
    .await
    .expect("reset created_at and clear due dates");

    let update = UpdateTicketRequest {
        title: None,
        description: None,
        status_id: Some(in_progress_status_id),
        priority_id: None,
        type_id: None,
        category_id: None,
        queue_id: None,
        contact_id: None,
        site_id: None,
        assigned_to_id: None,
        team_id: None,
        contract_id: None,
        sla_id: None,
        scheduled_start: None,
        scheduled_end: None,
        estimated_hours: None,
        is_billable: None,
        billing_status: None,
        asset_id: None,
        custom_fields: None,
        tags: None,
    };
    ticket_service
        .update_ticket(
            tenant,
            ticket_id,
            admin_id,
            &update,
            &AuditCtx::system(tenant_id),
        )
        .await
        .expect("update ticket status");

    let (fr_due, res_due): (Option<DateTime<Utc>>, Option<DateTime<Utc>>) =
        sqlx::query_as("SELECT first_response_due, resolution_due FROM tickets WHERE id = $1")
            .bind(ticket_id)
            .fetch_one(&pool)
            .await
            .expect("read back due dates after status change");

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
    let expected_fr = clock::due_at(
        friday_evening,
        4.0,
        &schedule,
        &HashSet::new(),
        OperationalHours::BusinessHours,
    );
    let expected_res = clock::due_at(
        friday_evening,
        8.0,
        &schedule,
        &HashSet::new(),
        OperationalHours::BusinessHours,
    );
    assert_eq!(
        fr_due,
        Some(expected_fr),
        "status change must re-evaluate first_response_due via business hours"
    );
    assert_eq!(
        res_due,
        Some(expected_res),
        "status change must re-evaluate resolution_due via business hours"
    );
}
