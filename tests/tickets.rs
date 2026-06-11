//! Integration test: tickets create / list / get / update / assign / add note happy path.
//!
//! The seed migration populates the default tenant with ticket statuses,
//! priorities, and types, so `CreateTicketRequest` can omit those FKs and
//! the service layer fills them from the defaults. We seed a company
//! directly via SQL because the contacts CRUD path is covered in its own
//! test file - this one keeps its assertions on the tickets surface.
//!
//! Beyond the happy path, this pins the PMS-11 / F3 fix: every ticket
//! response must carry its JOINed name/color fields populated from the
//! database, not the empty strings the route layer used to emit. Each
//! returned DTO is run through `assert_joined_fields_populated`, and the
//! assign step additionally asserts `assigned_to_name` resolves once an
//! assignee is set.

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

/// Assert a ticket DTO carries its JOINed name/color fields populated from
/// the database. This is the F3 regression guard: the route layer used to
/// build `TicketResponse` with `String::new()` for these, returning `200`
/// with blank names that any name-rendering client showed empty. `label`
/// identifies which endpoint's response is under test in failure output.
fn assert_joined_fields_populated(t: &serde_json::Value, label: &str) {
    let non_empty = |path: &str, v: Option<&str>| {
        assert!(
            v.is_some_and(|s| !s.is_empty()),
            "{label}: joined field {path} must be populated, got {v:?}"
        );
    };
    non_empty("status.name", t["status"]["name"].as_str());
    non_empty("status.color", t["status"]["color"].as_str());
    non_empty("priority.name", t["priority"]["name"].as_str());
    non_empty("priority.color", t["priority"]["color"].as_str());
    non_empty("queue_name", t["queue_name"].as_str());
    non_empty("company_name", t["company_name"].as_str());
    non_empty("created_by_name", t["created_by_name"].as_str());
}

#[sqlx::test]
async fn ticket_lifecycle_happy_path(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
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
    assert_eq!(
        created["company_name"].as_str(),
        Some("Acme Co"),
        "create response must resolve the company name from the JOIN"
    );
    assert_joined_fields_populated(&created, "create");

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
    let listed = items
        .iter()
        .find(|t| t["id"].as_str() == Some(&ticket_id))
        .expect("list should contain the ticket we just created");
    assert_joined_fields_populated(listed, "list");

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
    assert_joined_fields_populated(&got, "get");

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
    assert_joined_fields_populated(&updated, "update");

    // ASSIGN
    //
    // Assign to the seeded admin (the only user in the tenant). The handler
    // returns the freshly re-fetched DTO, so `assigned_to_id` must echo the
    // assignee and `assigned_to_name` must resolve via the users JOIN that
    // F3 left blank.
    let assign_resp = app
        .client
        .post(app.url(&format!("/api/v1/tickets/{ticket_id}/assign")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "assigned_to_id": admin_id }))
        .send()
        .await
        .expect("send assign ticket");
    assert_eq!(assign_resp.status(), reqwest::StatusCode::OK);
    let assigned: serde_json::Value = assign_resp.json().await.expect("assign ticket JSON");
    assert_eq!(
        assigned["assigned_to_id"].as_str(),
        Some(admin_id.to_string().as_str()),
        "assign must set assigned_to_id to the requested user"
    );
    assert!(
        assigned["assigned_to_name"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "assign response must resolve assigned_to_name from the users JOIN, got {:?}",
        assigned["assigned_to_name"]
    );
    assert_joined_fields_populated(&assigned, "assign");

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

/// PMS-182: editing a ticket's description records a change-history entry,
/// and the per-record history endpoint exposes it to a normal tenant member
/// with the changed field surfaced. Also pins that an unknown entity type is
/// a 404 (the whitelist guard) rather than an empty 200.
#[sqlx::test]
async fn ticket_history_records_description_edit(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = seed_company(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let created: serde_json::Value = app
        .client
        .post(app.url("/api/v1/tickets"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "title": "Printer jammed",
            "company_id": company_id,
            "description": "Paper stuck in tray 2.",
            "custom_fields": {},
        }))
        .send()
        .await
        .expect("create ticket")
        .json()
        .await
        .expect("create ticket JSON");
    let ticket_id = created["id"].as_str().expect("ticket id").to_string();

    // Edit the description.
    let update_status = app
        .client
        .put(app.url(&format!("/api/v1/tickets/{ticket_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "description": "Paper stuck in tray 2 and toner low." }))
        .send()
        .await
        .expect("update ticket")
        .status();
    assert!(update_status.is_success(), "PUT description should 2xx");

    // History endpoint must surface the edit, attributing the changed field.
    let hist: serde_json::Value = app
        .client
        .get(app.url(&format!("/api/v1/audit-log/entity/tickets/{ticket_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get ticket history")
        .json()
        .await
        .expect("history JSON");
    let entries = hist["data"].as_array().expect("history has data");
    let edit = entries
        .iter()
        .find(|e| {
            e["action"].as_str() == Some("update")
                && e["changed_fields"]
                    .as_array()
                    .is_some_and(|f| f.iter().any(|v| v.as_str() == Some("description")))
        })
        .expect("history must contain the description edit with changed_fields");
    assert!(
        edit["timestamp"].as_str().is_some(),
        "history entry must carry a timestamp"
    );

    // Unknown entity type is rejected by the whitelist, not silently emptied.
    let bad = app
        .client
        .get(app.url(&format!("/api/v1/audit-log/entity/secrets/{ticket_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send bad-entity history");
    assert_eq!(
        bad.status(),
        reqwest::StatusCode::NOT_FOUND,
        "non-whitelisted entity type must 404"
    );
}
