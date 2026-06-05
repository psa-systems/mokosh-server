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

async fn seed_company(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO companies (id, tenant_id, name)
        VALUES ($1, $2, 'Acme Co')
        "#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .execute(pool)
    .await
    .expect("seed test company");
    id
}

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
    let company_id = seed_company(&pool).await;
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
}
