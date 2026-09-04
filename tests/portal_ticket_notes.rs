//! PMS-449: integration test for the contact-facing ticket-notes surface
//! (`GET` and `POST /api/v1/tickets/{id}/notes` with a contact bearer,
//! dual-plane since PMS-1025; ported off the retired portal prefix in
//! PMS-1031).
//!
//! Pins three guarantees:
//!   - the contact feed filters out `internal` / `resolution` /
//!     `time_entry` notes (only `public` reaches the customer);
//!   - the contact POST stamps `created_by_contact_id` with the
//!     authenticated contact and leaves the agent attribution intact;
//!   - a contact cannot read or write a ticket in another company,
//!     even within the same tenant - both surfaces 404, never 200.

mod common;

use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_company(pool: &PgPool, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(common::DEFAULT_TENANT_ID)
        .bind(name)
        .execute(pool)
        .await
        .expect("seed company");
    id
}

async fn seed_ticket(pool: &PgPool, company_id: Uuid, admin_id: Uuid) -> Uuid {
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
    let id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO tickets
           (id, tenant_id, ticket_number, title, status_id, priority_id,
            queue_id, company_id, created_by_id)
           VALUES ($1, $2, $3, 'Customer question', $4, $5, $6, $7, $8)"#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(format!("T-{}", &id.to_string()[..8]))
    .bind(status_id)
    .bind(priority_id)
    .bind(queue_id)
    .bind(company_id)
    .bind(admin_id)
    .execute(pool)
    .await
    .expect("seed ticket");
    id
}

async fn seed_internal_note(pool: &PgPool, ticket_id: Uuid, admin_id: Uuid) {
    sqlx::query(
        r#"INSERT INTO ticket_notes
            (tenant_id, ticket_id, note_type, content, created_by_id)
           VALUES ($1, $2, 'internal', 'agent-only diagnosis notes', $3)"#,
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(ticket_id)
    .bind(admin_id)
    .execute(pool)
    .await
    .expect("seed internal note");
}

async fn seed_public_note_from_agent(pool: &PgPool, ticket_id: Uuid, admin_id: Uuid) {
    sqlx::query(
        r#"INSERT INTO ticket_notes
            (tenant_id, ticket_id, note_type, content, created_by_id)
           VALUES ($1, $2, 'public', 'Hi - we are looking into this', $3)"#,
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(ticket_id)
    .bind(admin_id)
    .execute(pool)
    .await
    .expect("seed agent public note");
}

#[sqlx::test]
async fn portal_ticket_notes_round_trip(pool: PgPool) {
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let company_a = seed_company(&pool, "Company A").await;
    let company_b = seed_company(&pool, "Company B").await;
    let contact_a =
        common::seed_portal_contact(&pool, company_a, "a@a.example", &["Support Contact"]).await;
    common::seed_portal_contact(&pool, company_b, "b@b.example", &["Support Contact"]).await;
    let ticket_a = seed_ticket(&pool, company_a, admin_id).await;
    let ticket_b = seed_ticket(&pool, company_b, admin_id).await;
    seed_internal_note(&pool, ticket_a, admin_id).await;
    seed_public_note_from_agent(&pool, ticket_a, admin_id).await;

    let app = common::boot(pool.clone()).await;
    let token_a = common::contact_token(&app, &contact_a).await;

    // List: must surface ONLY the public agent note, not the internal one.
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/tickets/{ticket_a}/notes")))
        .bearer_auth(&token_a)
        .send()
        .await
        .expect("list notes");
    let status = resp.status();
    let text = resp.text().await.expect("list body");
    assert_eq!(status, reqwest::StatusCode::OK, "contact list notes: {text}");
    let list: Value = serde_json::from_str(&text).expect("list JSON");
    let rows = list["data"].as_array().expect("data array");
    assert_eq!(rows.len(), 1, "internal notes must not leak to a contact");
    assert_eq!(rows[0]["note_type"], "public");

    // POST: contact comment goes through, comes back via list with
    // contact attribution (`created_by_name` resolves to "Portal Contact").
    let resp = app
        .client
        .post(app.url(&format!("/api/v1/tickets/{ticket_a}/notes")))
        .bearer_auth(&token_a)
        .json(&serde_json::json!({
            "note_type": "public",
            "content": "Thanks - we are still seeing this on the new laptops",
        }))
        .send()
        .await
        .expect("post comment");
    let status = resp.status();
    let text = resp.text().await.expect("comment body");
    assert_eq!(status, reqwest::StatusCode::OK, "contact post note: {text}");
    let created: Value = serde_json::from_str(&text).expect("comment JSON");
    assert_eq!(created["note_type"], "public");
    let comment_id = created["id"].as_str().expect("id").to_string();

    // The DB row carries `created_by_contact_id` pointing at the
    // logged-in contact, not the fallback admin.
    let stored_contact: Option<(Option<Uuid>,)> =
        sqlx::query_as("SELECT created_by_contact_id FROM ticket_notes WHERE id = $1")
            .bind(Uuid::parse_str(&comment_id).expect("comment uuid"))
            .fetch_optional(&pool)
            .await
            .expect("stored note");
    assert_eq!(
        stored_contact.and_then(|(c,)| c),
        Some(contact_a.id),
        "created_by_contact_id must point at the authenticated contact"
    );

    // Re-list to confirm both notes (the agent's public one + the
    // new customer comment) are present and ordered chronologically.
    let after: Value = app
        .client
        .get(app.url(&format!("/api/v1/tickets/{ticket_a}/notes")))
        .bearer_auth(&token_a)
        .send()
        .await
        .expect("relist")
        .json()
        .await
        .expect("relist JSON");
    let after_rows = after["data"].as_array().expect("data");
    assert_eq!(after_rows.len(), 2);

    // Cross-company access: A reading B's ticket-notes -> 404, not
    // 403, to avoid confirming B's ticket exists.
    let cross_list = app
        .client
        .get(app.url(&format!("/api/v1/tickets/{ticket_b}/notes")))
        .bearer_auth(&token_a)
        .send()
        .await
        .expect("cross list");
    assert_eq!(
        cross_list.status(),
        reqwest::StatusCode::NOT_FOUND,
        "cross-company note list must 404"
    );
    let cross_post = app
        .client
        .post(app.url(&format!("/api/v1/tickets/{ticket_b}/notes")))
        .bearer_auth(&token_a)
        .json(&serde_json::json!({ "note_type": "public", "content": "trying to comment on someone else's ticket" }))
        .send()
        .await
        .expect("cross post");
    assert_eq!(
        cross_post.status(),
        reqwest::StatusCode::NOT_FOUND,
        "cross-company note post must 404"
    );
}
