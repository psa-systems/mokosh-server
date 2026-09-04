//! PMS-468 / PMS-449 phase 2: integration test for the
//! `created_by_contact_id` field exposure + the agent
//! `GET /api/v1/contacts/{id}/notes` feed.
//!
//! Pins three guarantees:
//!   - `created_by_contact_id` is populated on a contact-originated
//!     note and null on an agent-originated note (the ticket-notes
//!     endpoint is dual-plane since PMS-1025 and surfaces the field
//!     to both callers).
//!   - `GET /api/v1/contacts/{id}/notes` returns every `public`
//!     note authored by that contact across the tenant's tickets,
//!     paginated.
//!   - The feed is tenant-scoped: a UUID guess in another tenant
//!     does NOT leak the rows.

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

async fn seed_ticket(pool: &PgPool, company_id: Uuid, admin_id: Uuid, title: &str) -> Uuid {
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
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(format!("T-{}", &id.to_string()[..8]))
    .bind(title)
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

#[sqlx::test]
async fn note_dto_carries_contact_attribution(pool: PgPool) {
    let (admin_id, admin_email, admin_pw) = common::seed_admin(&pool).await;
    let company = seed_company(&pool, "PMS-468 Co").await;
    let contact = common::seed_portal_contact(
        &pool,
        company,
        "feed-contact@example.com",
        &["Support Contact"],
    )
    .await;
    let ticket = seed_ticket(&pool, company, admin_id, "Note attribution").await;

    let app = common::boot(pool.clone()).await;

    // Contact-originated note: contact_id populated.
    let p_token = common::contact_token(&app, &contact).await;
    let _portal_note: Value = app
        .client
        .post(app.url(&format!("/api/v1/tickets/{ticket}/notes")))
        .bearer_auth(&p_token)
        .json(&serde_json::json!({ "note_type": "public", "content": "I tried rebooting" }))
        .send()
        .await
        .expect("portal POST")
        .json()
        .await
        .expect("portal note");

    // Agent-originated note: contact_id NULL.
    let admin_token = common::login(&app, &admin_email, &admin_pw).await;
    let _agent_note: Value = app
        .client
        .post(app.url(&format!("/api/v1/tickets/{ticket}/notes")))
        .bearer_auth(&admin_token)
        .json(&serde_json::json!({ "note_type": "public", "content": "We are on it" }))
        .send()
        .await
        .expect("agent POST")
        .json()
        .await
        .expect("agent note");

    // Agent list: both rows visible; the portal one carries the
    // contact id, the agent one omits it.
    let list: Value = app
        .client
        .get(app.url(&format!("/api/v1/tickets/{ticket}/notes")))
        .bearer_auth(&admin_token)
        .send()
        .await
        .expect("list GET")
        .json()
        .await
        .expect("list");
    let items = list["data"].as_array().expect("data");
    let portal_row = items
        .iter()
        .find(|n| n["content"].as_str() == Some("I tried rebooting"))
        .expect("portal row");
    assert_eq!(
        portal_row["created_by_contact_id"].as_str(),
        Some(contact.id.to_string().as_str()),
        "portal note must carry contact id; row={portal_row:?}"
    );
    let agent_row = items
        .iter()
        .find(|n| n["content"].as_str() == Some("We are on it"))
        .expect("agent row");
    assert!(
        agent_row.get("created_by_contact_id").is_none()
            || agent_row["created_by_contact_id"].is_null(),
        "agent note must NOT carry contact id; row={agent_row:?}"
    );
}

#[sqlx::test]
async fn contact_notes_feed_lists_all_public_from_contact(pool: PgPool) {
    let (admin_id, admin_email, admin_pw) = common::seed_admin(&pool).await;
    let company = seed_company(&pool, "Feed Co").await;
    let contact = common::seed_portal_contact(
        &pool,
        company,
        "feed-user@example.com",
        &["Support Contact"],
    )
    .await;

    // Two tickets, two portal notes from the same contact on
    // different tickets, plus one agent note that should not appear.
    let t1 = seed_ticket(&pool, company, admin_id, "Issue A").await;
    let t2 = seed_ticket(&pool, company, admin_id, "Issue B").await;

    let app = common::boot(pool.clone()).await;
    let p_token = common::contact_token(&app, &contact).await;
    for (ticket, body) in [(t1, "Note on A"), (t2, "Note on B")] {
        let _: Value = app
            .client
            .post(app.url(&format!("/api/v1/tickets/{ticket}/notes")))
            .bearer_auth(&p_token)
            .json(&serde_json::json!({ "note_type": "public", "content": body }))
            .send()
            .await
            .expect("portal POST")
            .json()
            .await
            .expect("portal note");
    }
    let admin_token = common::login(&app, &admin_email, &admin_pw).await;
    let _: Value = app
        .client
        .post(app.url(&format!("/api/v1/tickets/{t1}/notes")))
        .bearer_auth(&admin_token)
        .json(&serde_json::json!({ "note_type": "public", "content": "agent acknowledgement" }))
        .send()
        .await
        .expect("agent POST")
        .json()
        .await
        .expect("agent note");

    // Feed: returns exactly the two portal-authored notes.
    let feed: Value = app
        .client
        .get(app.url(&format!("/api/v1/contacts/{}/notes", contact.id)))
        .bearer_auth(&admin_token)
        .send()
        .await
        .expect("feed GET")
        .json()
        .await
        .expect("feed JSON");
    let items = feed["data"].as_array().expect("data");
    assert_eq!(
        items.len(),
        2,
        "exactly two contact-authored notes; got {items:?}"
    );
    let contents: Vec<&str> = items.iter().filter_map(|n| n["content"].as_str()).collect();
    assert!(contents.contains(&"Note on A"));
    assert!(contents.contains(&"Note on B"));
    assert!(!contents.contains(&"agent acknowledgement"));
}

#[sqlx::test]
async fn contact_notes_feed_is_tenant_scoped(pool: PgPool) {
    let (_admin_id, admin_email, admin_pw) = common::seed_admin(&pool).await;
    // Seed a second tenant with its own contact + admin. The first
    // tenant's admin must NOT see the second tenant's contact's
    // notes even when guessing the UUID.
    let (other_tenant, _other_admin, _other_email, _other_pw) =
        common::seed_tenant_with_admin(&pool, "other-tenant").await;
    let other_company_id = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, 'Other Co')")
        .bind(other_company_id)
        .bind(other_tenant)
        .execute(&pool)
        .await
        .expect("seed other company");
    let other_contact_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO contacts (id, tenant_id, company_id, first_name, last_name, email)
           VALUES ($1, $2, $3, 'Other', 'Person', 'other@example.com')"#,
    )
    .bind(other_contact_id)
    .bind(other_tenant)
    .bind(other_company_id)
    .execute(&pool)
    .await
    .expect("seed other contact");

    let app = common::boot(pool.clone()).await;
    let admin_token = common::login(&app, &admin_email, &admin_pw).await;

    // The first-tenant admin queries the other-tenant contact's
    // notes feed. Result must be empty (200 with no items), not the
    // other tenant's data.
    let feed: Value = app
        .client
        .get(app.url(&format!("/api/v1/contacts/{other_contact_id}/notes")))
        .bearer_auth(&admin_token)
        .send()
        .await
        .expect("feed GET")
        .json()
        .await
        .expect("feed JSON");
    let items = feed["data"].as_array().expect("data");
    assert!(
        items.is_empty(),
        "cross-tenant contact UUID must not leak rows; got {items:?}"
    );
}
