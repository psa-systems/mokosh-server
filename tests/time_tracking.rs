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

use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::time_tracking::{
    CreateTimeEntryRequest, TimeTrackingService, UpdateTimeEntryRequest,
};
use mokosh_server::Database;

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
        is_billable: true,
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
