//! PMS-1359: structured fields on a technician note persist alongside the
//! free-text body, round-trip through the API, and stay optional so a plain
//! note is unchanged.
//!
//! The design keeps parsing out of the picture: a technician enters the four
//! fields directly in the form rather than having a model shape them from the
//! body. These tests pin the write + read + omission paths end-to-end through
//! the HTTP surface, so a later edit that bypasses the migration's columns or
//! drops a field from the SELECT fails here instead of in production.

mod common;

use mokosh_test::mokosh_test;
use reqwest::StatusCode;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_ticket_for_notes(pool: &PgPool, admin_id: Uuid, company_id: Uuid) -> Uuid {
    let status_id: Uuid =
        sqlx::query_scalar("SELECT id FROM ticket_statuses WHERE tenant_id = $1 LIMIT 1")
            .bind(common::DEFAULT_TENANT_ID)
            .fetch_one(pool)
            .await
            .expect("status");
    let priority_id: Uuid =
        sqlx::query_scalar("SELECT id FROM ticket_priorities WHERE tenant_id = $1 LIMIT 1")
            .bind(common::DEFAULT_TENANT_ID)
            .fetch_one(pool)
            .await
            .expect("priority");
    let queue_id: Uuid =
        sqlx::query_scalar("SELECT id FROM ticket_queues WHERE tenant_id = $1 LIMIT 1")
            .bind(common::DEFAULT_TENANT_ID)
            .fetch_one(pool)
            .await
            .expect("queue");
    let ticket_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO tickets
           (id, tenant_id, ticket_number, title, status_id, priority_id,
            queue_id, company_id, created_by_id)
           VALUES ($1, $2, $3, 'Structured-fields ticket', $4, $5, $6, $7, $8)"#,
    )
    .bind(ticket_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(format!("T-{}", &ticket_id.to_string()[..8]))
    .bind(status_id)
    .bind(priority_id)
    .bind(queue_id)
    .bind(company_id)
    .bind(admin_id)
    .execute(pool)
    .await
    .expect("seed ticket");
    ticket_id
}

async fn add_note(app: &common::TestApp, token: &str, ticket_id: Uuid, body: Value) -> Value {
    let resp = app
        .client
        .post(app.url(&format!("/api/v1/tickets/{ticket_id}/notes")))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("send add note");
    assert!(
        resp.status().is_success(),
        "add note should 2xx, got {}: {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
    resp.json().await.expect("note JSON")
}

/// A note that carries all four structured fields saves them, returns them in
/// the create response, and returns them again on a subsequent list.
#[mokosh_test]
async fn a_note_with_all_four_structured_fields_round_trips(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company = common::seed_company_named(&pool, "Acme").await;
    let ticket_id = seed_ticket_for_notes(&pool, admin_id, company).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let follow_up = json!({
        "needed": true,
        "description": "Confirm the UPS kicked back on after the swap.",
        "target_date": "2026-11-01",
    });
    let created = add_note(
        &app,
        &token,
        ticket_id,
        json!({
            "note_type": "internal",
            "content": "Replaced the failing PSU.",
            "time_minutes": 45,
            "work_summary": "PSU swap",
            "parts_used": ["EVGA 650W PSU", "SATA power splitter"],
            "follow_up": follow_up,
        }),
    )
    .await;
    assert_eq!(created["time_minutes"].as_i64(), Some(45));
    assert_eq!(created["work_summary"].as_str(), Some("PSU swap"));
    let parts = created["parts_used"].as_array().expect("parts_used array");
    assert_eq!(parts.len(), 2);
    assert_eq!(created["follow_up"], follow_up);

    // Read back through the list endpoint; the row we just inserted is the
    // only note on this ticket, so it is the first (and only) entry.
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/tickets/{ticket_id}/notes")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send list");
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.expect("list JSON");
    let notes = body["data"].as_array().expect("data array");
    assert_eq!(notes.len(), 1);
    let note = &notes[0];
    assert_eq!(note["time_minutes"].as_i64(), Some(45));
    assert_eq!(note["work_summary"].as_str(), Some("PSU swap"));
    assert_eq!(note["parts_used"].as_array().unwrap().len(), 2);
    assert_eq!(note["follow_up"], follow_up);
}

/// A plain note that omits every structured field is wire-identical to how
/// notes looked before PMS-1359 landed: the four keys are absent from the
/// response rather than present-as-null.
#[mokosh_test]
async fn a_note_without_any_structured_fields_omits_them_from_the_response(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company = common::seed_company_named(&pool, "Acme").await;
    let ticket_id = seed_ticket_for_notes(&pool, admin_id, company).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let created = add_note(
        &app,
        &token,
        ticket_id,
        json!({
            "note_type": "internal",
            "content": "Just a note.",
        }),
    )
    .await;
    let obj = created.as_object().expect("object");
    for key in ["time_minutes", "work_summary", "parts_used", "follow_up"] {
        assert!(
            !obj.contains_key(key),
            "unset {key} must not appear in the response: {created}"
        );
    }
}

/// The migration's CHECK constraints are mirrored at the request layer by
/// validator attributes, so bad input is a 422 at the API boundary rather
/// than a 500 bubbling the Postgres error.
#[mokosh_test]
async fn a_non_positive_time_minutes_is_refused_at_validation(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company = common::seed_company_named(&pool, "Acme").await;
    let ticket_id = seed_ticket_for_notes(&pool, admin_id, company).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let resp = app
        .client
        .post(app.url(&format!("/api/v1/tickets/{ticket_id}/notes")))
        .bearer_auth(&token)
        .json(&json!({
            "note_type": "internal",
            "content": "Negative time is nonsense.",
            "time_minutes": 0,
        }))
        .send()
        .await
        .expect("send add note");
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}
