//! PMS-933: "No billable time found" must not be said when there is some.
//!
//! `create_invoice_from_time_entries` bills only `billing_status =
//! 'ready_to_bill'`, and PMS-144 made timesheet approval the gate that sets it.
//! That rule is right and is not what these tests question. What they pin is the
//! SENTENCE on the empty path: a company with billable time held by approval
//! used to be told none existed, which is a claim about the user's data and a
//! false one. Reported as MAPPS-598, where it sent the reporter looking at the
//! ticket instead of the timesheet.
//!
//! Kept out of `tests/billing.rs` so the message assertions sit next to the
//! states that produce them rather than among the happy-path invoice maths.

mod common;

use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_work_type(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO work_types (id, tenant_id, name, default_billable, default_rate)
        VALUES ($1, $2, 'Billing Test Work', TRUE, 150.00)
        "#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .execute(pool)
    .await
    .expect("seed test work type");
    id
}

/// A billable, unbilled entry in a chosen approval state.
async fn seed_entry(
    pool: &PgPool,
    user_id: Uuid,
    company_id: Uuid,
    work_type_id: Uuid,
    minutes: i32,
    approval_status: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO time_entries (
            id, tenant_id, user_id, date, duration_minutes, work_type_id,
            company_id, is_billable, billing_status, approval_status,
            invoice_id, hourly_rate, total_amount
        )
        VALUES ($1, $2, $3, CURRENT_DATE, $4, $5, $6, TRUE, 'not_billed', $7,
                NULL, 150.00, 150.00)
        "#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(user_id)
    .bind(minutes)
    .bind(work_type_id)
    .bind(company_id)
    .bind(approval_status)
    .execute(pool)
    .await
    .expect("seed time entry");
    id
}

async fn generate(app: &common::TestApp, token: &str, company_id: Uuid) -> (u16, String) {
    let resp = app
        .client
        .post(app.url("/api/v1/invoices/from-time-entries"))
        .bearer_auth(token)
        .json(&serde_json::json!({ "company_id": company_id }))
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
async fn a_company_with_no_billable_time_is_told_exactly_that(pool: PgPool) {
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

/// The reported case. Time logged on a ticket, never submitted, and the app
/// said it did not exist.
#[sqlx::test]
async fn unsubmitted_time_is_not_reported_as_missing(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let work_type_id = seed_work_type(&pool).await;
    seed_entry(&pool, admin_id, company_id, work_type_id, 90, "draft").await;

    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let (status, message) = generate(&app, &token, company_id).await;
    assert_eq!(status, 400, "the gate still holds: {message}");
    assert!(
        !message.contains("No billable time"),
        "it must stop claiming the time is not there: {message}"
    );
    assert!(message.contains("1 billable time entry"), "{message}");
    assert!(message.contains("1.5 hours"), "{message}");
    assert!(
        message.contains("Submit the timesheet"),
        "and name the step that unblocks it: {message}"
    );
}

/// Submitted but unapproved is a different person's next action, so it gets a
/// different sentence.
#[sqlx::test]
async fn time_awaiting_approval_names_the_approver_step(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let work_type_id = seed_work_type(&pool).await;
    seed_entry(&pool, admin_id, company_id, work_type_id, 60, "pending").await;
    seed_entry(&pool, admin_id, company_id, work_type_id, 60, "pending").await;

    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let (_status, message) = generate(&app, &token, company_id).await;
    assert!(message.contains("2 billable time entries"), "{message}");
    assert!(message.contains("Approve the timesheet"), "{message}");
    assert!(
        !message.contains("Submit the timesheet"),
        "nobody needs to submit anything here: {message}"
    );
}

/// Both states at once is the realistic case on a team.
#[sqlx::test]
async fn a_mix_of_states_names_both(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let work_type_id = seed_work_type(&pool).await;
    seed_entry(&pool, admin_id, company_id, work_type_id, 60, "draft").await;
    seed_entry(&pool, admin_id, company_id, work_type_id, 60, "pending").await;

    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let (_status, message) = generate(&app, &token, company_id).await;
    assert!(message.contains("2 billable time entries"), "{message}");
    assert!(
        message.contains("1 of them are not on a submitted timesheet"),
        "{message}"
    );
    assert!(message.contains("1 are waiting for approval"), "{message}");
}

/// A rejected entry is back with whoever logged it and has to be resubmitted,
/// which is the same next action as one that was never submitted.
#[sqlx::test]
async fn rejected_time_reads_as_needing_resubmission(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let work_type_id = seed_work_type(&pool).await;
    seed_entry(&pool, admin_id, company_id, work_type_id, 30, "rejected").await;

    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let (_status, message) = generate(&app, &token, company_id).await;
    assert!(message.contains("Submit the timesheet"), "{message}");
}

/// The diagnosis describes only entries the eligibility clause excluded. An
/// already-invoiced entry is not held by approval and must not be counted, or
/// the message explains an absence with rows that were never candidates.
#[sqlx::test]
async fn an_already_invoiced_entry_is_not_counted_as_held(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let work_type_id = seed_work_type(&pool).await;
    let billed = seed_entry(&pool, admin_id, company_id, work_type_id, 60, "draft").await;
    sqlx::query("UPDATE time_entries SET invoice_id = $1 WHERE id = $2")
        .bind(Uuid::new_v4())
        .bind(billed)
        .execute(&pool)
        .await
        .ok();

    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let (_status, message) = generate(&app, &token, company_id).await;
    assert_eq!(
        message, "No billable time or mileage entries found for this company",
        "an invoiced entry is not time waiting on a timesheet: {message}"
    );
}

/// And the whole point: approving it makes the invoice happen. The gate is not
/// being loosened, only explained.
#[sqlx::test]
async fn approved_time_still_generates_an_invoice(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let work_type_id = seed_work_type(&pool).await;
    let entry = seed_entry(&pool, admin_id, company_id, work_type_id, 60, "draft").await;

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let (status, _) = generate(&app, &token, company_id).await;
    assert_eq!(status, 400, "held before approval");

    sqlx::query(
        "UPDATE time_entries SET approval_status = 'approved', billing_status = 'ready_to_bill' \
         WHERE id = $1",
    )
    .bind(entry)
    .execute(&pool)
    .await
    .expect("approve the entry");

    let resp = app
        .client
        .post(app.url("/api/v1/invoices/from-time-entries"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "company_id": company_id }))
        .send()
        .await
        .expect("send generate request");
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);
}
