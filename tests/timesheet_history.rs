//! PMS-506: integration tests for the multi-status, multi-week
//! timesheet list filter. Pins:
//!   - The default (`status=all`, no range) keeps returning pending +
//!     approved + rejected rows so the history surface is exercised.
//!   - `status=approved` filters down to approved weeks only; same
//!     for `pending` / `rejected`.
//!   - `from` + `to` widen the scan to a multi-week range.
//!   - The response carries `decided_at` / `decided_by_id` /
//!     `rejection_reason` on decided weeks so the SPA can render the
//!     audit label.

mod common;

use chrono::NaiveDate;
use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::time_tracking::{
    CreateTimeEntryRequest, TimeTrackingService, TimesheetFilter,
};
use mokosh_server::utils::pagination::PaginationParams;
use mokosh_server::Database;
use sqlx::PgPool;
use uuid::Uuid;

fn tenant() -> TenantId {
    TenantId::from_trusted(common::DEFAULT_TENANT_ID)
}

fn page() -> PaginationParams {
    PaginationParams::default()
}

async fn seeded_work_type(pool: &PgPool) -> Uuid {
    sqlx::query_scalar("SELECT id FROM work_types WHERE tenant_id = $1 ORDER BY sort_order LIMIT 1")
        .bind(common::DEFAULT_TENANT_ID)
        .fetch_one(pool)
        .await
        .expect("seeded work type")
}

fn entry_req(
    user_id: Uuid,
    work_type_id: Uuid,
    company_id: Uuid,
    date: NaiveDate,
) -> CreateTimeEntryRequest {
    CreateTimeEntryRequest {
        user_id,
        date,
        start_time: None,
        end_time: None,
        duration_minutes: Some(60),
        work_type_id,
        ticket_id: None,
        project_id: None,
        task_id: None,
        company_id,
        notes: Some("history fixture".to_string()),
        work_category: None,
        is_billable: true,
        hourly_rate: None,
    }
}

#[sqlx::test]
async fn list_timesheets_status_filter_and_range(pool: PgPool) {
    let (admin_id, _, _) = common::seed_admin(&pool).await;
    let company = common::seed_company(&pool).await;
    let work_type = seeded_work_type(&pool).await;

    let db = Database::from_pool(pool.clone());
    let svc = TimeTrackingService::new(db);

    let actx = mokosh_server::modules::audit::AuditCtx {
        tenant_id: Some(common::DEFAULT_TENANT_ID),
        user_id: Some(admin_id),
        ip: None,
        user_agent: None,
    };

    // Three Monday-anchored weeks. Each gets one billable entry.
    let week_a = NaiveDate::from_ymd_opt(2026, 6, 1).unwrap(); // approved
    let week_b = NaiveDate::from_ymd_opt(2026, 6, 8).unwrap(); // rejected
    let week_c = NaiveDate::from_ymd_opt(2026, 6, 15).unwrap(); // pending

    for date in [week_a, week_b, week_c] {
        svc.create_time_entry(
            tenant(),
            &entry_req(admin_id, work_type, company, date),
            &actx,
        )
        .await
        .expect("seed entry");
    }

    // Move every week to pending.
    for date in [week_a, week_b, week_c] {
        svc.submit_timesheet(tenant(), admin_id, date)
            .await
            .expect("submit");
    }

    // Approve A, reject B, leave C pending.
    svc.approve_timesheet(tenant(), admin_id, admin_id, week_a)
        .await
        .expect("approve A");
    svc.reject_timesheet(tenant(), admin_id, admin_id, week_b, "needs more detail")
        .await
        .expect("reject B");

    // status=all returns all three weeks for the admin.
    let (all, _) = svc
        .list_timesheets(
            tenant(),
            &TimesheetFilter {
                user_id: Some(admin_id),
                from: Some(week_a),
                to: Some(week_c),
                status: Some("all".to_string()),
                ..Default::default()
            },
            &page(),
        )
        .await
        .expect("list all");
    assert_eq!(all.len(), 3, "status=all over the range; got {all:?}");

    // status=approved returns week A only, with the decision audit set.
    let (approved, _) = svc
        .list_timesheets(
            tenant(),
            &TimesheetFilter {
                user_id: Some(admin_id),
                from: Some(week_a),
                to: Some(week_c),
                status: Some("approved".to_string()),
                ..Default::default()
            },
            &page(),
        )
        .await
        .expect("list approved");
    assert_eq!(approved.len(), 1, "approved must be 1; got {approved:?}");
    let row_a = &approved[0];
    assert_eq!(row_a.week_start, week_a);
    assert_eq!(row_a.approval_status, "approved");
    assert_eq!(row_a.decided_by_id, Some(admin_id));
    assert!(
        row_a.decided_at.is_some(),
        "approved row must carry decided_at"
    );
    assert!(
        row_a.rejection_reason.is_none(),
        "approved row must not carry a rejection reason; got {:?}",
        row_a.rejection_reason
    );

    // status=rejected returns week B with the reason.
    let (rejected, _) = svc
        .list_timesheets(
            tenant(),
            &TimesheetFilter {
                user_id: Some(admin_id),
                from: Some(week_a),
                to: Some(week_c),
                status: Some("rejected".to_string()),
                ..Default::default()
            },
            &page(),
        )
        .await
        .expect("list rejected");
    assert_eq!(rejected.len(), 1);
    let row_b = &rejected[0];
    assert_eq!(row_b.week_start, week_b);
    assert_eq!(row_b.approval_status, "rejected");
    assert_eq!(row_b.rejection_reason.as_deref(), Some("needs more detail"));
    assert_eq!(row_b.decided_by_id, Some(admin_id));

    // status=pending returns week C with no decision audit.
    let (pending, _) = svc
        .list_timesheets(
            tenant(),
            &TimesheetFilter {
                user_id: Some(admin_id),
                from: Some(week_a),
                to: Some(week_c),
                status: Some("pending".to_string()),
                ..Default::default()
            },
            &page(),
        )
        .await
        .expect("list pending");
    assert_eq!(pending.len(), 1);
    let row_c = &pending[0];
    assert_eq!(row_c.week_start, week_c);
    assert_eq!(row_c.approval_status, "pending");
    assert!(row_c.decided_by_id.is_none());
    assert!(row_c.decided_at.is_none());
}

#[sqlx::test]
async fn list_timesheets_rejects_unknown_status(pool: PgPool) {
    let _ = common::seed_admin(&pool).await;
    let db = Database::from_pool(pool.clone());
    let svc = TimeTrackingService::new(db);
    let err = svc
        .list_timesheets(
            tenant(),
            &TimesheetFilter {
                status: Some("done".to_string()),
                ..Default::default()
            },
            &page(),
        )
        .await
        .expect_err("unknown status must 422");
    let msg = format!("{err}");
    assert!(
        msg.contains("done") || msg.contains("status"),
        "error must mention the bad value; got {msg}"
    );
}

#[sqlx::test]
async fn list_timesheets_caps_range_at_26_weeks(pool: PgPool) {
    let _ = common::seed_admin(&pool).await;
    let db = Database::from_pool(pool.clone());
    let svc = TimeTrackingService::new(db);
    let from = NaiveDate::from_ymd_opt(2026, 1, 5).unwrap();
    // 30 weeks later - over the 26-week cap.
    let to = from + chrono::Duration::weeks(30);
    let err = svc
        .list_timesheets(
            tenant(),
            &TimesheetFilter {
                from: Some(from),
                to: Some(to),
                ..Default::default()
            },
            &page(),
        )
        .await
        .expect_err("over-cap range must 422");
    assert!(
        format!("{err}").contains("26"),
        "error must mention the 26-week cap; got {err}"
    );
}
