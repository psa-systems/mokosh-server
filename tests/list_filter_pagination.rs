//! Filtered-list placeholder regression suite (PMS-197).
//!
//! The May-21 mass merge introduced a latent bug class: a dynamic
//! `count_query` plus a `where_clause` whose positional placeholders
//! collide with the appended `LIMIT`/`OFFSET` binds, so any filtered
//! list 500s while the no-filter read works (which hid it for five
//! authors). PMS-178 fixed the audit-log site and proved it with
//! `tests/audit_list.rs`; this suite extends that coverage to the
//! remaining `count_query` / where-placeholder family members the
//! original PR never audited:
//!
//!   * `time_tracking::list_time_entries`  (service.rs:228)
//!   * `time_tracking::list_timesheets`    (service.rs:467)
//!   * `calendar::list_appointments`       (service.rs:164)
//!   * `knowledge_base::list_articles`     (service.rs:205)
//!   * `contracts::list_contracts`         (service.rs:48)
//!
//! Each test drives the service directly (no HTTP layer needed - the bug
//! lives at the query layer, before any row mapping) against a per-test
//! database with only the seeded default tenant. Every filter
//! combination plus pagination must return `Ok`; an empty result set is
//! still a pass. A placeholder collision surfaces as a postgres error
//! (`42P18` / bind-count mismatch) and fails the `.expect`.

mod common;

use chrono::{NaiveDate, TimeZone, Utc};
use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::calendar::{AppointmentFilter, CalendarService};
use mokosh_server::modules::contracts::{ContractFilter, ContractsService};
use mokosh_server::modules::knowledge_base::{KbArticleFilter, KbService};
use mokosh_server::modules::time_tracking::{
    TimeEntryFilter, TimeTrackingService, TimesheetFilter,
};
use mokosh_server::utils::pagination::PaginationParams;
use mokosh_server::Database;
use sqlx::PgPool;
use uuid::Uuid;

/// Pagination with a non-zero offset so both the `LIMIT` and `OFFSET`
/// placeholders are exercised alongside the dynamic filters.
fn page() -> PaginationParams {
    PaginationParams {
        page: 2,
        per_page: 5,
        sort: None,
        sort_dir: "desc".to_string(),
    }
}

fn tenant() -> TenantId {
    TenantId::from_trusted(common::DEFAULT_TENANT_ID)
}

fn d(y: i32, m: u32, day: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(y, m, day).unwrap()
}

#[sqlx::test]
async fn time_entries_list_handles_every_filter_combination(pool: PgPool) {
    let svc = TimeTrackingService::new(Database::from_pool(pool.clone()));
    let id = Uuid::new_v4();
    let combos = [
        TimeEntryFilter::default(),
        TimeEntryFilter {
            user_id: Some(id),
            ..Default::default()
        },
        TimeEntryFilter {
            ticket_id: Some(id),
            ..Default::default()
        },
        TimeEntryFilter {
            date_from: Some(d(2026, 1, 1)),
            date_to: Some(d(2026, 12, 31)),
            ..Default::default()
        },
        // All five placeholders active at once.
        TimeEntryFilter {
            user_id: Some(id),
            ticket_id: Some(id),
            project_id: Some(id),
            date_from: Some(d(2026, 1, 1)),
            date_to: Some(d(2026, 12, 31)),
        },
    ];
    for (i, filter) in combos.iter().enumerate() {
        svc.list_time_entries(tenant(), filter, &page())
            .await
            .unwrap_or_else(|e| panic!("list_time_entries combo {i} must not error: {e:?}"));
    }
}

#[sqlx::test]
async fn timesheets_list_handles_every_filter_combination(pool: PgPool) {
    let svc = TimeTrackingService::new(Database::from_pool(pool.clone()));
    let id = Uuid::new_v4();
    let combos = [
        TimesheetFilter::default(),
        TimesheetFilter {
            user_id: Some(id),
            ..Default::default()
        },
        TimesheetFilter {
            week: Some(d(2026, 6, 1)),
            ..Default::default()
        },
        TimesheetFilter {
            user_id: Some(id),
            week: Some(d(2026, 6, 1)),
            ..Default::default()
        },
    ];
    for (i, filter) in combos.iter().enumerate() {
        svc.list_timesheets(tenant(), filter, &page())
            .await
            .unwrap_or_else(|e| panic!("list_timesheets combo {i} must not error: {e:?}"));
    }
}

#[sqlx::test]
async fn appointments_list_handles_every_filter_combination(pool: PgPool) {
    let svc = CalendarService::new(Database::from_pool(pool.clone()));
    let id = Uuid::new_v4();
    let from = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let to = Utc.with_ymd_and_hms(2026, 12, 31, 23, 59, 59).unwrap();
    let combos = [
        AppointmentFilter::default(),
        AppointmentFilter {
            user_id: Some(id),
            ..Default::default()
        },
        AppointmentFilter {
            appointment_type: Some("meeting".to_string()),
            ..Default::default()
        },
        // `from`+`to` WITHOUT a type takes the in-memory recurrence path.
        AppointmentFilter {
            from: Some(from),
            to: Some(to),
            ..Default::default()
        },
        // A type alongside `from`+`to` forces the SQL path with all four
        // placeholders active.
        AppointmentFilter {
            user_id: Some(id),
            appointment_type: Some("meeting".to_string()),
            from: Some(from),
            to: Some(to),
        },
    ];
    for (i, filter) in combos.iter().enumerate() {
        svc.list_appointments(tenant(), filter, &page())
            .await
            .unwrap_or_else(|e| panic!("list_appointments combo {i} must not error: {e:?}"));
    }
}

#[sqlx::test]
async fn kb_articles_list_handles_every_filter_combination(pool: PgPool) {
    let svc = KbService::new(Database::from_pool(pool.clone()));
    let id = Uuid::new_v4();
    let combos = [
        KbArticleFilter::default(),
        KbArticleFilter {
            category_id: Some(id),
            ..Default::default()
        },
        KbArticleFilter {
            status: Some("published".to_string()),
            ..Default::default()
        },
        KbArticleFilter {
            visibility: Some("internal".to_string()),
            ..Default::default()
        },
        // `q` adds both a WHERE placeholder and an ORDER BY placeholder.
        KbArticleFilter {
            q: Some("printer".to_string()),
            ..Default::default()
        },
        KbArticleFilter {
            category_id: Some(id),
            status: Some("published".to_string()),
            visibility: Some("internal".to_string()),
            q: Some("printer".to_string()),
        },
    ];
    for (i, filter) in combos.iter().enumerate() {
        svc.list_articles(tenant(), filter, &page())
            .await
            .unwrap_or_else(|e| panic!("list_articles combo {i} must not error: {e:?}"));
    }
}

#[sqlx::test]
async fn contracts_list_handles_every_filter_combination(pool: PgPool) {
    let svc = ContractsService::new(Database::from_pool(pool.clone()));
    let id = Uuid::new_v4();
    let combos = [
        ContractFilter::default(),
        ContractFilter {
            company_id: Some(id),
            ..Default::default()
        },
        ContractFilter {
            contract_type: Some("managed_services".to_string()),
            ..Default::default()
        },
        ContractFilter {
            status: Some("active".to_string()),
            ..Default::default()
        },
        ContractFilter {
            company_id: Some(id),
            contract_type: Some("managed_services".to_string()),
            status: Some("active".to_string()),
        },
    ];
    for (i, filter) in combos.iter().enumerate() {
        svc.list_contracts(tenant(), filter, &page())
            .await
            .unwrap_or_else(|e| panic!("list_contracts combo {i} must not error: {e:?}"));
    }
}
