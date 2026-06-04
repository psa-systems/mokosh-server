//! Integration test: tickets create / list / get / update / add note happy path.
//!
//! The seed migration populates the default tenant with ticket statuses,
//! priorities, and types, so `CreateTicketRequest` can omit those FKs and
//! the service layer fills them from the defaults. We seed a company
//! directly via SQL because the contacts CRUD path is covered in its own
//! test file - this one keeps its assertions on the tickets surface.

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

#[sqlx::test]
async fn ticket_lifecycle_happy_path(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = seed_company(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    // CREATE
    //
    // `custom_fields` is sent as `{}` (not omitted) because
    // `CreateTicketRequest.custom_fields` defaults to `serde_json::Value::Null`,
    // and sqlx encodes `Value::Null` as SQL NULL, which trips the
    // `custom_fields JSONB NOT NULL DEFAULT '{}'` constraint on `tickets`.
    let create_body = serde_json::json!({
        "title": "Server is on fire",
        "company_id": company_id,
        "description": "Smoke coming out of rack 3.",
        "custom_fields": {},
    });
    let create_resp = app
        .client
        .post(app.url("/api/v1/tickets"))
        .bearer_auth(&token)
        .json(&create_body)
        .send()
        .await
        .expect("send create ticket");
    let create_status = create_resp.status();
    let create_text = create_resp.text().await.expect("create ticket body");
    assert!(
        create_status.is_success(),
        "create ticket should 2xx, got {create_status} body={create_text}"
    );
    let created: serde_json::Value =
        serde_json::from_str(&create_text).expect("create ticket JSON");
    let ticket_id = created["id"]
        .as_str()
        .expect("created ticket has id")
        .to_string();
    assert_eq!(created["title"].as_str(), Some("Server is on fire"));

    // LIST
    let list_resp = app
        .client
        .get(app.url("/api/v1/tickets"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send list tickets");
    assert_eq!(list_resp.status(), reqwest::StatusCode::OK);
    let list: serde_json::Value = list_resp.json().await.expect("list tickets JSON");
    let items = list["data"].as_array().expect("tickets list has data");
    assert!(
        items.iter().any(|t| t["id"].as_str() == Some(&ticket_id)),
        "list should contain the ticket we just created"
    );

    // GET
    let get_resp = app
        .client
        .get(app.url(&format!("/api/v1/tickets/{ticket_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send get ticket");
    assert_eq!(get_resp.status(), reqwest::StatusCode::OK);
    let got: serde_json::Value = get_resp.json().await.expect("get ticket JSON");
    assert_eq!(got["title"].as_str(), Some("Server is on fire"));

    // UPDATE
    let update_resp = app
        .client
        .put(app.url(&format!("/api/v1/tickets/{ticket_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "title": "Server is now smouldering" }))
        .send()
        .await
        .expect("send update ticket");
    assert_eq!(update_resp.status(), reqwest::StatusCode::OK);
    let updated: serde_json::Value = update_resp.json().await.expect("update ticket JSON");
    assert_eq!(
        updated["title"].as_str(),
        Some("Server is now smouldering"),
        "PUT must change the title"
    );

    // ADD NOTE
    let note_resp = app
        .client
        .post(app.url(&format!("/api/v1/tickets/{ticket_id}/notes")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "content": "Operator on-site, found wet wires." }))
        .send()
        .await
        .expect("send add note");
    assert!(
        note_resp.status().is_success(),
        "add note should 2xx, got {}",
        note_resp.status()
    );
}
