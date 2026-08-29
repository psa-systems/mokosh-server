//! PMS-933, carried forward through PMS-944: "No billable time found" must not
//! be said when there is some.
//!
//! PMS-933 wrote these against the PMS-144 rule, where weekly timesheet
//! approval was what made billable time invoiceable, so the sentence they
//! demanded named a timesheet. PMS-944 removed that gate: an entry is armed at
//! creation and reaches an invoice because it was logged. The requirement is
//! untouched by that and is the reason this file still exists. What a company's
//! time is doing when no invoice comes out of it changed completely; that the
//! app must not answer "you have none" changed not at all.
//!
//! Kept out of `tests/billing.rs` so the message assertions sit next to the
//! states that produce them rather than among the happy-path invoice maths.

mod common;

use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

/// The first active work type, which the seed migration supplies.
async fn work_type(app: &common::TestApp, token: &str) -> Uuid {
    let body: Value = app
        .client
        .get(app.url("/api/v1/work-types"))
        .bearer_auth(token)
        .send()
        .await
        .expect("list work types")
        .json()
        .await
        .expect("work types json");
    Uuid::parse_str(body["data"][0]["id"].as_str().expect("a seeded work type"))
        .expect("work type id")
}

/// Log an hour of client work through the API, the way the app does.
async fn log_time(
    app: &common::TestApp,
    token: &str,
    user_id: Uuid,
    company_id: Uuid,
    work_type_id: Uuid,
    minutes: i64,
    billable: bool,
) -> Uuid {
    let response = app
        .client
        .post(app.url("/api/v1/time-entries"))
        .bearer_auth(token)
        .json(&json!({
            "user_id": user_id,
            "company_id": company_id,
            "work_type_id": work_type_id,
            "date": "2026-06-15",
            "duration_minutes": minutes,
            "is_billable": billable,
            "hourly_rate": "150.00",
        }))
        .send()
        .await
        .expect("create time entry");
    assert_eq!(response.status(), 200, "{:?}", response.text().await);
    let body: Value = response.json().await.expect("entry json");
    Uuid::parse_str(body["id"].as_str().expect("entry id")).expect("entry uuid")
}

/// A billable, uninvoiced entry written straight to the table at the
/// `not_billed` default, which is the shape every row had before PMS-944 and
/// which nothing in the app produces now.
async fn seed_unarmed_entry(
    pool: &PgPool,
    user_id: Uuid,
    company_id: Uuid,
    work_type_id: Uuid,
    minutes: i32,
) {
    sqlx::query(
        r#"
        INSERT INTO time_entries (
            id, tenant_id, user_id, date, duration_minutes, work_type_id,
            company_id, is_billable, billing_status, approval_status,
            invoice_id, hourly_rate, total_amount
        )
        VALUES ($1, $2, $3, CURRENT_DATE, $4, $5, $6, TRUE, 'not_billed',
                'draft', NULL, 150.00, 150.00)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(common::DEFAULT_TENANT_ID)
    .bind(user_id)
    .bind(minutes)
    .bind(work_type_id)
    .bind(company_id)
    .execute(pool)
    .await
    .expect("seed unarmed time entry");
}

async fn generate(app: &common::TestApp, token: &str, company_id: Uuid) -> (u16, String) {
    let resp = app
        .client
        .post(app.url("/api/v1/invoices/from-time-entries"))
        .bearer_auth(token)
        .json(&json!({ "company_id": company_id }))
        .send()
        .await
        .expect("send generate request");
    let status = resp.status().as_u16();
    let body: Value = resp.json().await.expect("JSON body");
    let message = body["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    (status, message)
}

/// A company with nothing at all still gets the original sentence, because it
/// is the one case in which it is true.
#[sqlx::test]
async fn a_company_with_no_time_at_all_is_told_exactly_that(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;

    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let (status, message) = generate(&app, &token, company_id).await;
    assert_eq!(status, 400);
    assert_eq!(
        message,
        "No billable time or mileage entries found for this company"
    );
}

/// The headline of PMS-944. Log an hour, invoice it. No submit, no approve, and
/// nothing in between - which is also the case PMS-933's message existed to
/// explain away, and now simply does not arise.
#[sqlx::test]
async fn logged_billable_time_invoices_with_no_approval_step(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;

    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;
    let work_type_id = work_type(&app, &token).await;

    log_time(&app, &token, admin_id, company_id, work_type_id, 60, true).await;

    let resp = app
        .client
        .post(app.url("/api/v1/invoices/from-time-entries"))
        .bearer_auth(&token)
        .json(&json!({ "company_id": company_id }))
        .send()
        .await
        .expect("generate invoice");
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);
    let invoice: Value = resp.json().await.expect("invoice json");
    assert_eq!(invoice["subtotal"], "150.00", "{invoice}");
}

/// Time deliberately logged as non-billable. The entry exists, so the message
/// must not deny it, and the fix is a decision to revisit rather than hours to
/// re-log.
#[sqlx::test]
async fn non_billable_time_is_named_rather_than_denied(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;

    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;
    let work_type_id = work_type(&app, &token).await;

    log_time(&app, &token, admin_id, company_id, work_type_id, 90, false).await;

    let (status, message) = generate(&app, &token, company_id).await;
    assert_eq!(status, 400);
    assert!(
        message.contains("1 time entry (1.5 hours) logged as non-billable"),
        "{message}"
    );
    assert!(message.contains("Mark them billable"), "{message}");
    assert!(!message.contains("No billable time"), "{message}");
}

/// Already invoiced is the opposite problem: nothing is missing. Sending this
/// user to log hours would have them bill the same work twice.
#[sqlx::test]
async fn already_invoiced_time_does_not_ask_for_more_hours(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;

    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;
    let work_type_id = work_type(&app, &token).await;

    log_time(&app, &token, admin_id, company_id, work_type_id, 60, true).await;

    let first = app
        .client
        .post(app.url("/api/v1/invoices/from-time-entries"))
        .bearer_auth(&token)
        .json(&json!({ "company_id": company_id }))
        .send()
        .await
        .expect("generate the first invoice");
    assert_eq!(first.status(), 200, "{:?}", first.text().await);

    let (status, message) = generate(&app, &token, company_id).await;
    assert_eq!(status, 400);
    assert!(
        message.contains("1 billable time entry already on an invoice"),
        "{message}"
    );
    assert!(message.contains("nothing new to bill"), "{message}");
    assert!(!message.contains("No billable time"), "{message}");
}

/// The regression this file was written for, in the shape it takes after
/// PMS-944. A billable, uninvoiced row that is not armed cannot be produced by
/// the app any more, but it is exactly what every pre-PMS-944 row looked like,
/// and answering "you have none" about it is the failure MAPPS-598 reported.
#[sqlx::test]
async fn an_unarmed_entry_is_reported_rather_than_denied(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let work_type_id = work_type(&app, &token).await;

    seed_unarmed_entry(&pool, admin_id, company_id, work_type_id, 120).await;

    let (status, message) = generate(&app, &token, company_id).await;
    assert_eq!(status, 400);
    assert!(
        message.contains("1 billable time entry (2 hours) that is not marked ready to bill"),
        "{message}"
    );
    assert!(!message.contains("No billable time"), "{message}");
}

/// No message on any of these paths may name approval or a timesheet. It is not
/// the gate any more, so pointing the reader at the approvals queue sends them
/// to a screen that cannot help - the same failure MAPPS-598 reported, aimed
/// the other way.
#[sqlx::test]
async fn no_message_sends_the_user_to_a_timesheet(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let work_type_id = work_type(&app, &token).await;

    log_time(&app, &token, admin_id, company_id, work_type_id, 30, false).await;
    seed_unarmed_entry(&pool, admin_id, company_id, work_type_id, 60).await;

    let (status, message) = generate(&app, &token, company_id).await;
    assert_eq!(status, 400);
    assert!(!message.contains("approv"), "{message}");
    assert!(!message.contains("timesheet"), "{message}");
}
