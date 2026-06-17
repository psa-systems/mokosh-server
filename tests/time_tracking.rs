//! Integration test: the Milestone 1 Service Desk time slice, end to end.
//!
//! Two actors, mirroring the real workflow handoff:
//!   technician  -> start timer on a ticket -> stop -> a rounded, billable,
//!                  ticket-linked time entry -> submit the week
//!   manager     -> approve the technician's week
//!
//! The seed migration supplies the default tenant's work types (Remote
//! Support, sort_order 1, billable, $150/hr) and the default rounding rule
//! ('Standard Rounding', 15-min increment, 15-min minimum, round up), so the
//! assertions below pin the locked billing-correctness behaviour: an
//! instantly-stopped timer floors to 15 minutes and prices from the work
//! type. A guard check confirms a technician cannot approve.

mod common;

use sqlx::PgPool;
use uuid::Uuid;

/// Seed a technician under the default tenant. Returns
/// `(user_id, email, plaintext_password)` so the test can drive `/login`.
async fn seed_technician(pool: &PgPool) -> (Uuid, String, String) {
    let email = "test-tech@example.com".to_string();
    let password = "tech-password-12345".to_string();
    let password_hash =
        mokosh_server::utils::crypto::hash_password(&password).expect("hash technician password");
    let user_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO users (
            id, tenant_id, email, password_hash,
            first_name, last_name, role, status, email_verified_at
        )
        VALUES ($1, $2, $3, $4, 'Tess', 'Tech', 'technician', 'active', NOW())
        "#,
    )
    .bind(user_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(&email)
    .bind(&password_hash)
    .execute(pool)
    .await
    .expect("insert seeded technician");
    (user_id, email, password)
}

#[sqlx::test]
async fn service_desk_time_slice_happy_path(pool: PgPool) {
    let (_admin_id, admin_email, admin_pw) = common::seed_admin(&pool).await;
    let (tech_id, tech_email, tech_pw) = seed_technician(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool).await;

    let admin_token = common::login(&app, &admin_email, &admin_pw).await;
    let tech_token = common::login(&app, &tech_email, &tech_pw).await;

    // Grab a seeded work type (Remote Support sorts first) so the timer can
    // classify and price the work.
    let work_types: serde_json::Value = app
        .client
        .get(app.url("/api/v1/work-types"))
        .bearer_auth(&admin_token)
        .send()
        .await
        .expect("list work types")
        .json()
        .await
        .expect("work types JSON");
    let work_type_id = work_types["data"][0]["id"]
        .as_str()
        .expect("seed has at least one work type")
        .to_string();

    // A ticket for the technician to log time against.
    let ticket: serde_json::Value = app
        .client
        .post(app.url("/api/v1/tickets"))
        .bearer_auth(&admin_token)
        .json(&serde_json::json!({
            "title": "Printer down",
            "company_id": company_id,
            "description": "PCL errors on every job.",
            "custom_fields": {},
        }))
        .send()
        .await
        .expect("create ticket")
        .json()
        .await
        .expect("ticket JSON");
    let ticket_id = ticket["id"].as_str().expect("ticket id").to_string();

    // START timer as the technician.
    let timer: serde_json::Value = app
        .client
        .post(app.url("/api/v1/timers/start"))
        .bearer_auth(&tech_token)
        .json(&serde_json::json!({
            "ticket_id": ticket_id,
            "company_id": company_id,
            "work_type_id": work_type_id,
            "notes": "Diagnosing printer",
        }))
        .send()
        .await
        .expect("start timer")
        .json()
        .await
        .expect("timer JSON");
    let timer_id = timer["id"].as_str().expect("timer id").to_string();

    // STOP the timer -> creates the time entry.
    let stop_resp = app
        .client
        .post(app.url(&format!("/api/v1/timers/{timer_id}/stop")))
        .bearer_auth(&tech_token)
        .send()
        .await
        .expect("stop timer");
    let stop_status = stop_resp.status();
    let stop_text = stop_resp.text().await.expect("stop body");
    assert!(
        stop_status.is_success(),
        "stop timer should 2xx, got {stop_status} body={stop_text}"
    );
    let entry: serde_json::Value = serde_json::from_str(&stop_text).expect("entry JSON");

    // Locked rounding: an instantly-stopped timer (raw ~1 min) floors to the
    // seed rule's 15-minute minimum.
    assert_eq!(
        entry["duration_minutes"].as_i64(),
        Some(15),
        "seed rounding floor (minimum 15) should apply"
    );
    assert_eq!(
        entry["ticket_id"].as_str(),
        Some(ticket_id.as_str()),
        "stopped entry stays linked to the ticket"
    );
    // G2: the stop path now derives billable + rate from the work type
    // (previously is_billable was hardcoded TRUE and rate/total were NULL).
    assert_eq!(
        entry["is_billable"].as_bool(),
        Some(true),
        "Remote Support is billable by default"
    );
    assert!(
        !entry["hourly_rate"].is_null(),
        "rate should be derived from the work type"
    );
    assert!(
        !entry["total_amount"].is_null(),
        "total should be priced from the derived rate"
    );

    // PMS-145: listing time entries filtered by ticket_id must 200 (the
    // count query previously referenced an unbound placeholder and 500'd on
    // any filter) and return the entry we just logged.
    let filtered = app
        .client
        .get(app.url(&format!("/api/v1/time-entries?ticket_id={ticket_id}")))
        .bearer_auth(&tech_token)
        .send()
        .await
        .expect("list time entries by ticket");
    let filtered_status = filtered.status();
    let filtered_text = filtered.text().await.expect("filtered list body");
    assert_eq!(
        filtered_status,
        reqwest::StatusCode::OK,
        "filtered time-entries list should 200, got {filtered_status} body={filtered_text}"
    );
    let filtered: serde_json::Value =
        serde_json::from_str(&filtered_text).expect("filtered list JSON");
    let entry_id = entry["id"].as_str().expect("entry id");
    assert!(
        filtered["data"]
            .as_array()
            .expect("filtered list has data")
            .iter()
            .any(|e| e["id"].as_str() == Some(entry_id)),
        "the ticket's time entry should appear in the ticket_id-filtered list"
    );
    assert!(
        filtered["meta"]["total"].as_i64().unwrap_or(0) >= 1,
        "filtered list total should count the entry"
    );

    // SUBMIT the technician's week (any date in the week anchors to Monday).
    let entry_date = entry["date"].as_str().expect("entry date").to_string();
    let submit: serde_json::Value = app
        .client
        .post(app.url(&format!("/api/v1/timesheets/{tech_id}/{entry_date}/submit")))
        .bearer_auth(&tech_token)
        .send()
        .await
        .expect("submit timesheet")
        .json()
        .await
        .expect("submit JSON");
    assert_eq!(
        submit["approval_status"].as_str(),
        Some("pending"),
        "a submitted week with entries reads as pending (awaiting approval)"
    );
    assert!(
        submit["entry_count"].as_i64().unwrap_or(0) >= 1,
        "submitted week has the stopped entry"
    );

    // PMS-183 WITHDRAW: the owner can pull a submitted (not-yet-approved)
    // timesheet back to draft, then resubmit.
    let withdraw: serde_json::Value = app
        .client
        .post(app.url(&format!(
            "/api/v1/timesheets/{tech_id}/{entry_date}/withdraw"
        )))
        .bearer_auth(&tech_token)
        .send()
        .await
        .expect("withdraw timesheet")
        .json()
        .await
        .expect("withdraw JSON");
    assert_eq!(
        withdraw["approval_status"].as_str(),
        Some("draft"),
        "a withdrawn week returns to draft (unsubmitted)"
    );
    // Resubmit so the rest of the flow (approve) proceeds.
    let resubmit: serde_json::Value = app
        .client
        .post(app.url(&format!("/api/v1/timesheets/{tech_id}/{entry_date}/submit")))
        .bearer_auth(&tech_token)
        .send()
        .await
        .expect("resubmit timesheet")
        .json()
        .await
        .expect("resubmit JSON");
    assert_eq!(
        resubmit["approval_status"].as_str(),
        Some("pending"),
        "resubmitting a draft week returns it to pending"
    );

    // GUARD: a technician cannot approve a timesheet (manager+ only).
    let tech_approve = app
        .client
        .post(app.url(&format!(
            "/api/v1/timesheets/{tech_id}/{entry_date}/approve"
        )))
        .bearer_auth(&tech_token)
        .send()
        .await
        .expect("technician approve attempt");
    assert_eq!(
        tech_approve.status(),
        reqwest::StatusCode::FORBIDDEN,
        "technician must not be able to approve"
    );

    // APPROVE as the manager (the seeded super_admin satisfies RequireManager).
    let approve: serde_json::Value = app
        .client
        .post(app.url(&format!(
            "/api/v1/timesheets/{tech_id}/{entry_date}/approve"
        )))
        .bearer_auth(&admin_token)
        .send()
        .await
        .expect("approve timesheet")
        .json()
        .await
        .expect("approve JSON");
    assert_eq!(
        approve["approval_status"].as_str(),
        Some("approved"),
        "week reads as approved after the manager approves"
    );

    // PMS-144: approval is the billing gate. The billable entry must flip
    // from not_billed to ready_to_bill so PMS-33 invoicing can consume it.
    let entry_id = entry["id"].as_str().expect("entry id");
    let after: serde_json::Value = app
        .client
        .get(app.url(&format!("/api/v1/time-entries/{entry_id}")))
        .bearer_auth(&tech_token)
        .send()
        .await
        .expect("get entry after approve")
        .json()
        .await
        .expect("entry JSON after approve");
    assert_eq!(
        after["billing_status"].as_str(),
        Some("ready_to_bill"),
        "approving a billable entry must flip billing_status to ready_to_bill"
    );

    // PMS-183 GUARD: an approved timesheet can no longer be withdrawn.
    let withdraw_approved = app
        .client
        .post(app.url(&format!(
            "/api/v1/timesheets/{tech_id}/{entry_date}/withdraw"
        )))
        .bearer_auth(&tech_token)
        .send()
        .await
        .expect("withdraw-after-approve attempt");
    assert_eq!(
        withdraw_approved.status(),
        reqwest::StatusCode::CONFLICT,
        "withdrawing an approved timesheet must be rejected"
    );
}

// ============================================================================
// PMS-328: PUT /time-entries preserves task_id, and the read paths expose it.
// ============================================================================

use mokosh_server::modules::audit::AuditCtx;
use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::settings::SettingsService;
use mokosh_server::modules::time_tracking::{
    CreateTimeEntryRequest, TimeTrackingService, UpdateTimeEntryRequest,
};
use mokosh_server::utils::error::AppError;
use mokosh_server::Database;

// PMS-318 sweep: create_time_entry now writes a Create audit row, so the
// service signature carries an AuditCtx. A default ctx suffices for tests.
fn actx() -> AuditCtx {
    AuditCtx {
        tenant_id: Some(common::DEFAULT_TENANT_ID),
        user_id: None,
        ip: None,
        user_agent: None,
    }
}

/// Fetch the default tenant's first seeded work type, needed to classify a
/// service-level time entry.
async fn seeded_work_type(pool: &PgPool) -> Uuid {
    sqlx::query_scalar("SELECT id FROM work_types WHERE tenant_id = $1 ORDER BY sort_order LIMIT 1")
        .bind(common::DEFAULT_TENANT_ID)
        .fetch_one(pool)
        .await
        .expect("seeded work type")
}

/// Build a create request for the default tenant with a given task link.
fn create_req(
    user_id: Uuid,
    work_type_id: Uuid,
    company_id: Uuid,
    task_id: Option<Uuid>,
) -> CreateTimeEntryRequest {
    CreateTimeEntryRequest {
        user_id,
        date: chrono::NaiveDate::from_ymd_opt(2026, 6, 15).unwrap(),
        start_time: None,
        end_time: None,
        duration_minutes: Some(60),
        work_type_id,
        ticket_id: None,
        project_id: None,
        task_id,
        company_id,
        notes: Some("initial".to_string()),
        work_category: None,
        is_billable: true,
        hourly_rate: None,
    }
}

/// Build a create request for the default tenant on a given date with an
/// explicit duration in minutes (PMS-396 day-cap tests).
fn create_minutes(
    user_id: Uuid,
    work_type_id: Uuid,
    company_id: Uuid,
    date: chrono::NaiveDate,
    minutes: i32,
) -> CreateTimeEntryRequest {
    CreateTimeEntryRequest {
        user_id,
        date,
        start_time: None,
        end_time: None,
        duration_minutes: Some(minutes),
        work_type_id,
        ticket_id: None,
        project_id: None,
        task_id: None,
        company_id,
        notes: None,
        is_billable: true,
        hourly_rate: None,
    }
}

/// An update that sets only `duration_minutes`, omitting every other field.
fn duration_only_update(minutes: i32) -> UpdateTimeEntryRequest {
    UpdateTimeEntryRequest {
        date: None,
        start_time: None,
        end_time: None,
        duration_minutes: Some(minutes),
        work_type_id: None,
        ticket_id: None,
        project_id: None,
        task_id: None,
        notes: None,
        is_billable: None,
        hourly_rate: None,
    }
}

/// An update that touches only `notes`, omitting every other field.
fn notes_only_update(notes: &str) -> UpdateTimeEntryRequest {
    UpdateTimeEntryRequest {
        date: None,
        start_time: None,
        end_time: None,
        duration_minutes: None,
        work_type_id: None,
        ticket_id: None,
        project_id: None,
        work_category: None,
        task_id: None,
        notes: Some(notes.to_string()),
        is_billable: None,
        hourly_rate: None,
    }
}

/// AC1: a partial PUT that omits `task_id` leaves the existing link intact.
#[sqlx::test]
async fn update_preserves_task_id_when_omitted(pool: PgPool) {
    let (user_id, _, _) = seed_technician(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let work_type_id = seeded_work_type(&pool).await;
    let svc = TimeTrackingService::new(Database::from_pool(pool.clone()));
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);

    let task_id = Uuid::new_v4();
    let created = svc
        .create_time_entry(
            tenant,
            &create_req(user_id, work_type_id, company_id, Some(task_id)),
            &actx(),
        )
        .await
        .expect("create entry with task");
    assert_eq!(created.task_id, Some(task_id), "create keeps the task link");

    let updated = svc
        .update_time_entry(tenant, created.id, &notes_only_update("edited"))
        .await
        .expect("update notes only");
    assert_eq!(
        updated.task_id,
        Some(task_id),
        "omitting task_id must preserve the existing link, not wipe it"
    );
    assert_eq!(updated.notes.as_deref(), Some("edited"));
}

/// AC3 (change): sending an explicit `task_id` reassigns the link.
#[sqlx::test]
async fn update_with_explicit_task_id_changes_link(pool: PgPool) {
    let (user_id, _, _) = seed_technician(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let work_type_id = seeded_work_type(&pool).await;
    let svc = TimeTrackingService::new(Database::from_pool(pool.clone()));
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);

    let first = Uuid::new_v4();
    let created = svc
        .create_time_entry(
            tenant,
            &create_req(user_id, work_type_id, company_id, Some(first)),
            &actx(),
        )
        .await
        .expect("create entry");

    let second = Uuid::new_v4();
    let mut req = notes_only_update("retask");
    req.task_id = Some(second);
    let updated = svc
        .update_time_entry(tenant, created.id, &req)
        .await
        .expect("update task link");
    assert_eq!(
        updated.task_id,
        Some(second),
        "an explicit task_id must replace the prior link"
    );
}

/// AC2: the get and list read paths surface `task_id`.
#[sqlx::test]
async fn read_paths_expose_task_id(pool: PgPool) {
    let (user_id, _, _) = seed_technician(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let work_type_id = seeded_work_type(&pool).await;
    let svc = TimeTrackingService::new(Database::from_pool(pool.clone()));
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);

    let task_id = Uuid::new_v4();
    let created = svc
        .create_time_entry(
            tenant,
            &create_req(user_id, work_type_id, company_id, Some(task_id)),
            &actx(),
        )
        .await
        .expect("create entry");

    let got = svc.get_time_entry(tenant, created.id).await.expect("get");
    assert_eq!(got.task_id, Some(task_id), "get exposes task_id");

    let filter = mokosh_server::modules::time_tracking::TimeEntryFilter::default();
    let pagination = mokosh_server::utils::pagination::PaginationParams::default();
    let (items, _) = svc
        .list_time_entries(tenant, &filter, &pagination)
        .await
        .expect("list");
    let listed = items
        .iter()
        .find(|e| e.id == created.id)
        .expect("entry in list");
    assert_eq!(listed.task_id, Some(task_id), "list exposes task_id");
}

/// PMS-328 (auth gate): edit/delete of a time entry is restricted to the
/// entry's owner or an admin. A second technician must not be able to edit or
/// delete an entry they do not own, while the owner and an admin can.
#[sqlx::test]
async fn non_owner_cannot_edit_or_delete_time_entry(pool: PgPool) {
    let (_admin_id, admin_email, admin_pw) = common::seed_admin(&pool).await;
    let (_a_id, a_email, a_pw) = seed_technician(&pool).await;
    let (_b_id, b_email, b_pw) = common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "tech-b@example.com",
        "technician",
    )
    .await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool).await;

    let admin_token = common::login(&app, &admin_email, &admin_pw).await;
    let a_token = common::login(&app, &a_email, &a_pw).await;
    let b_token = common::login(&app, &b_email, &b_pw).await;

    let work_types: serde_json::Value = app
        .client
        .get(app.url("/api/v1/work-types"))
        .bearer_auth(&admin_token)
        .send()
        .await
        .expect("list work types")
        .json()
        .await
        .expect("work types JSON");
    let work_type_id = work_types["data"][0]["id"].as_str().expect("a work type");

    // Technician A logs an entry for themselves.
    let entry: serde_json::Value = app
        .client
        .post(app.url("/api/v1/time-entries"))
        .bearer_auth(&a_token)
        .json(&serde_json::json!({
            "user_id": _a_id,
            "date": "2026-06-15",
            "duration_minutes": 60,
            "work_type_id": work_type_id,
            "company_id": company_id,
        }))
        .send()
        .await
        .expect("create entry")
        .json()
        .await
        .expect("entry JSON");
    let entry_id = entry["id"].as_str().expect("entry id");

    // Technician B cannot edit A's entry.
    let b_edit = app
        .client
        .put(app.url(&format!("/api/v1/time-entries/{entry_id}")))
        .bearer_auth(&b_token)
        .json(&serde_json::json!({ "notes": "not mine" }))
        .send()
        .await
        .expect("B edit attempt");
    assert_eq!(
        b_edit.status(),
        reqwest::StatusCode::FORBIDDEN,
        "a non-owner technician must not edit another user's entry"
    );

    // Technician B cannot delete A's entry.
    let b_delete = app
        .client
        .delete(app.url(&format!("/api/v1/time-entries/{entry_id}")))
        .bearer_auth(&b_token)
        .send()
        .await
        .expect("B delete attempt");
    assert_eq!(
        b_delete.status(),
        reqwest::StatusCode::FORBIDDEN,
        "a non-owner technician must not delete another user's entry"
    );

    // The owner can edit their own entry.
    let a_edit = app
        .client
        .put(app.url(&format!("/api/v1/time-entries/{entry_id}")))
        .bearer_auth(&a_token)
        .json(&serde_json::json!({ "notes": "mine, edited" }))
        .send()
        .await
        .expect("owner edit");
    assert_eq!(
        a_edit.status(),
        reqwest::StatusCode::OK,
        "the owner can edit their own entry"
    );

    // An admin can delete any entry in the tenant.
    let admin_delete = app
        .client
        .delete(app.url(&format!("/api/v1/time-entries/{entry_id}")))
        .bearer_auth(&admin_token)
        .send()
        .await
        .expect("admin delete");
    assert!(
        admin_delete.status().is_success(),
        "an admin can delete any entry, got {}",
        admin_delete.status()
    );
}

// ============================================================================
// PMS-396: per-tenant max-hours-per-day cap on a user's day total.
// ============================================================================

/// AC6: two entries totaling under the default 24h cap both succeed; a third
/// that would cross the cap is rejected with a BadRequest naming the cap and
/// the remaining minutes.
#[sqlx::test]
async fn create_rejects_day_total_over_default_cap(pool: PgPool) {
    let (user_id, _, _) = seed_technician(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let work_type_id = seeded_work_type(&pool).await;
    let svc = TimeTrackingService::new(Database::from_pool(pool.clone()));
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let date = chrono::NaiveDate::from_ymd_opt(2026, 6, 15).unwrap();

    // 10h + 10h = 20h, comfortably under the default 24h cap.
    svc.create_time_entry(
        tenant,
        &create_minutes(user_id, work_type_id, company_id, date, 10 * 60),
        &actx(),
    )
    .await
    .expect("first 10h entry under cap");
    svc.create_time_entry(
        tenant,
        &create_minutes(user_id, work_type_id, company_id, date, 10 * 60),
        &actx(),
    )
    .await
    .expect("second 10h entry under cap");

    // A third 10h entry would reach 30h > 24h cap: rejected.
    let err = svc
        .create_time_entry(
            tenant,
            &create_minutes(user_id, work_type_id, company_id, date, 10 * 60),
            &actx(),
        )
        .await
        .unwrap_err();
    match err {
        AppError::BadRequest(msg) => {
            assert!(msg.contains("24h/day"), "error names the 24h cap: {msg}");
            assert!(
                msg.contains("240 minutes for the day"),
                "error names the remaining minutes (1440 - 1200): {msg}"
            );
        }
        other => panic!("expected BadRequest, got {other:?}"),
    }
}

/// AC7: with the setting at 18, a day total reaching 19h is rejected while 18h
/// is allowed; the configured cap overrides the 24h default.
#[sqlx::test]
async fn create_honors_configured_lower_cap(pool: PgPool) {
    let (user_id, _, _) = seed_technician(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let work_type_id = seeded_work_type(&pool).await;
    let db = Database::from_pool(pool.clone());
    let svc = TimeTrackingService::new(db.clone());
    let settings = SettingsService::new(db);
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let date = chrono::NaiveDate::from_ymd_opt(2026, 6, 15).unwrap();

    settings
        .put_setting(
            tenant,
            "time_tracking",
            "max_hours_per_day",
            serde_json::json!(18),
        )
        .await
        .expect("set the day cap to 18 hours");

    // 17h is under the 18h cap.
    svc.create_time_entry(
        tenant,
        &create_minutes(user_id, work_type_id, company_id, date, 17 * 60),
        &actx(),
    )
    .await
    .expect("17h under the 18h cap");

    // A further 2h would reach 19h > 18h cap: rejected.
    let err = svc
        .create_time_entry(
            tenant,
            &create_minutes(user_id, work_type_id, company_id, date, 2 * 60),
            &actx(),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, AppError::BadRequest(_)),
        "19h total against an 18h cap must be BadRequest, got {err:?}"
    );
}

/// AC4: update enforces the cap against the day, excluding the row being edited
/// from the sum (so an in-place grow is measured against peers, not itself) and
/// rejects an edit that would push the target day over the cap.
#[sqlx::test]
async fn update_enforces_day_cap_excluding_self(pool: PgPool) {
    let (user_id, _, _) = seed_technician(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let work_type_id = seeded_work_type(&pool).await;
    let svc = TimeTrackingService::new(Database::from_pool(pool.clone()));
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let date = chrono::NaiveDate::from_ymd_opt(2026, 6, 15).unwrap();

    // Entry A starts at 10h.
    let a = svc
        .create_time_entry(
            tenant,
            &create_minutes(user_id, work_type_id, company_id, date, 10 * 60),
            &actx(),
        )
        .await
        .expect("entry A");

    // Grow A to 20h: excluding A itself the day holds 0h, so 20h <= 24h is OK.
    // Were A double-counted (10h + 20h = 30h) this would be wrongly rejected.
    let grown = svc
        .update_time_entry(tenant, a.id, &duration_only_update(20 * 60))
        .await
        .expect("grow A to 20h excluding self");
    assert_eq!(grown.duration_minutes, 20 * 60);

    // Entry B of 4h reaches exactly 24h (20h + 4h): allowed.
    let b = svc
        .create_time_entry(
            tenant,
            &create_minutes(user_id, work_type_id, company_id, date, 4 * 60),
            &actx(),
        )
        .await
        .expect("entry B to exactly the cap");

    // Growing B to 5h would push the day to 25h > 24h: rejected.
    let err = svc
        .update_time_entry(tenant, b.id, &duration_only_update(5 * 60))
        .await
        .unwrap_err();
    assert!(
        matches!(err, AppError::BadRequest(_)),
        "updating B over the cap must be BadRequest, got {err:?}"
    );
}

/// PMS-332: the time-entry response carries joined work-item names. A
/// ticket-linked entry returns ticket_number + ticket_title (null project/
/// task); a project+task entry returns project_name + task_title (null
/// ticket). Exercised over HTTP through both the get and list read paths.
#[sqlx::test]
async fn time_entry_response_carries_work_item_names(pool: PgPool) {
    let (admin_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    let work_types: serde_json::Value = app
        .client
        .get(app.url("/api/v1/work-types"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("work types")
        .json()
        .await
        .expect("work types JSON");
    let work_type_id = work_types["data"][0]["id"].as_str().expect("a work type");

    // A ticket, a project, and a task to link against.
    let ticket: serde_json::Value = app
        .client
        .post(app.url("/api/v1/tickets"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "title": "Printer down",
            "company_id": company_id,
            "description": "PCL errors.",
            "custom_fields": {},
        }))
        .send()
        .await
        .expect("create ticket")
        .json()
        .await
        .expect("ticket JSON");
    let ticket_id = ticket["id"].as_str().expect("ticket id");

    let project: serde_json::Value = app
        .client
        .post(app.url("/api/v1/projects"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "name": "Delivery", "company_id": company_id, "status": "active" }))
        .send()
        .await
        .expect("create project")
        .json()
        .await
        .expect("project JSON");
    let project_id = project["id"].as_str().expect("project id").to_string();

    let statuses: serde_json::Value = app
        .client
        .get(app.url("/api/v1/task-statuses"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("task statuses")
        .json()
        .await
        .expect("statuses JSON");
    let status_id = statuses["data"][0]["id"].as_str().expect("a task status");
    let task: serde_json::Value = app
        .client
        .post(app.url(&format!("/api/v1/projects/{project_id}/tasks")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "title": "Build", "status_id": status_id }))
        .send()
        .await
        .expect("create task")
        .json()
        .await
        .expect("task JSON");
    let task_id = task["id"].as_str().expect("task id");

    // Helper: POST a time entry and return its created response.
    let create_entry = |body: serde_json::Value| {
        let app = &app;
        let token = &token;
        async move {
            app.client
                .post(app.url("/api/v1/time-entries"))
                .bearer_auth(token)
                .json(&body)
                .send()
                .await
                .expect("create entry")
                .json::<serde_json::Value>()
                .await
                .expect("entry JSON")
        }
    };

    // Ticket-linked entry: ticket name present, project/task null.
    let ticket_entry = create_entry(serde_json::json!({
        "user_id": admin_id,
        "date": "2026-03-02",
        "duration_minutes": 60,
        "work_type_id": work_type_id,
        "ticket_id": ticket_id,
        "company_id": company_id,
    }))
    .await;
    let ticket_entry_id = ticket_entry["id"].as_str().expect("entry id").to_string();

    let got: serde_json::Value = app
        .client
        .get(app.url(&format!("/api/v1/time-entries/{ticket_entry_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get ticket entry")
        .json()
        .await
        .expect("entry JSON");
    assert!(
        got["ticket_number"].as_str().is_some(),
        "ticket entry carries a ticket_number"
    );
    assert_eq!(
        got["ticket_title"].as_str(),
        Some("Printer down"),
        "ticket entry carries the ticket title"
    );
    assert!(
        got["project_name"].is_null(),
        "no project link -> null name"
    );
    assert!(got["task_title"].is_null(), "no task link -> null title");

    // Project + task entry: project/task names present, ticket null.
    let project_entry = create_entry(serde_json::json!({
        "user_id": admin_id,
        "date": "2026-03-03",
        "duration_minutes": 90,
        "work_type_id": work_type_id,
        "project_id": project_id,
        "task_id": task_id,
        "company_id": company_id,
    }))
    .await;
    let project_entry_id = project_entry["id"].as_str().expect("entry id").to_string();

    let got: serde_json::Value = app
        .client
        .get(app.url(&format!("/api/v1/time-entries/{project_entry_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get project entry")
        .json()
        .await
        .expect("entry JSON");
    assert_eq!(
        got["project_name"].as_str(),
        Some("Delivery"),
        "project entry carries the project name"
    );
    assert_eq!(
        got["task_title"].as_str(),
        Some("Build"),
        "project entry carries the task title"
    );
    assert!(
        got["ticket_number"].is_null(),
        "no ticket link -> null number"
    );
    assert!(
        got["ticket_title"].is_null(),
        "no ticket link -> null title"
    );

    // The list read path carries the same joined names.
    let list: serde_json::Value = app
        .client
        .get(app.url("/api/v1/time-entries"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list entries")
        .json()
        .await
        .expect("list JSON");
    let rows = list["data"].as_array().expect("list data");
    let listed_ticket = rows
        .iter()
        .find(|e| e["id"].as_str() == Some(ticket_entry_id.as_str()))
        .expect("ticket entry listed");
    assert_eq!(listed_ticket["ticket_title"].as_str(), Some("Printer down"));
    let listed_project = rows
        .iter()
        .find(|e| e["id"].as_str() == Some(project_entry_id.as_str()))
        .expect("project entry listed");
    assert_eq!(listed_project["task_title"].as_str(), Some("Build"));
}
