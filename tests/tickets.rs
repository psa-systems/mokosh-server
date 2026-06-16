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
    let company_id = common::seed_company(&pool).await;
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
    let company_id = common::seed_company(&pool).await;
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
    // PMS-204: the entry must carry the before/after content of the change,
    // not just the field name.
    let desc_change = edit["changes"]
        .as_array()
        .expect("entry has a changes array")
        .iter()
        .find(|c| c["field"].as_str() == Some("description"))
        .expect("changes must include the description field");
    assert_eq!(
        desc_change["old"].as_str(),
        Some("Paper stuck in tray 2."),
        "change must carry the old description"
    );
    assert_eq!(
        desc_change["new"].as_str(),
        Some("Paper stuck in tray 2 and toner low."),
        "change must carry the new description"
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

/// PMS-370 (PMS-359 follow-up): a Status edit via the inline editor must show
/// up in the change history with the humanised field name `status`, not the
/// raw column `status_id`. The SPA capitalises for display, so a leaked `_id`
/// suffix renders as `Updated: Status id`; stripping it server-side at the
/// history read boundary gives `Updated: Status`. The stored audit row is
/// unaffected; only the rendered field label is cleaned up.
#[sqlx::test]
async fn ticket_history_humanises_status_id_field(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let created: serde_json::Value = app
        .client
        .post(app.url("/api/v1/tickets"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "title": "Printer jammed",
            "company_id": company_id,
            "custom_fields": {},
        }))
        .send()
        .await
        .expect("create ticket")
        .json()
        .await
        .expect("create ticket JSON");
    let ticket_id = created["id"].as_str().expect("ticket id").to_string();

    // A second status to switch the ticket to (distinct from the seeded default).
    let new_status: serde_json::Value = app
        .client
        .post(app.url("/api/v1/tickets/statuses"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "name": "Escalated",
            "color": "#ff0000",
            "is_closed": false,
            "sort_order": 99,
        }))
        .send()
        .await
        .expect("create status")
        .json()
        .await
        .expect("create status JSON");
    let new_status_id = new_status["id"].as_str().expect("status id").to_string();

    // Inline-editor Status change.
    let update_status = app
        .client
        .put(app.url(&format!("/api/v1/tickets/{ticket_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "status_id": new_status_id }))
        .send()
        .await
        .expect("update ticket status")
        .status();
    assert!(update_status.is_success(), "PUT status_id should 2xx");

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
                    .is_some_and(|f| f.iter().any(|v| v.as_str() == Some("status")))
        })
        .expect("history must surface the status edit under the humanised field `status`");

    // The raw column name must NOT leak into the rendered field labels.
    assert!(
        edit["changed_fields"]
            .as_array()
            .expect("changed_fields array")
            .iter()
            .all(|v| v.as_str() != Some("status_id")),
        "changed_fields must not carry the raw column `status_id`"
    );
    let status_change = edit["changes"]
        .as_array()
        .expect("entry has a changes array")
        .iter()
        .find(|c| c["field"].as_str() == Some("status"))
        .expect("changes must include the humanised `status` field");
    assert_eq!(
        status_change["field"].as_str(),
        Some("status"),
        "change field must be the humanised `status`, not `status_id`"
    );
    assert!(
        edit["timestamp"].as_str().is_some(),
        "history entry must carry a timestamp"
    );
}

// ============================================================================
// PMS-321: ticket lookup management CRUD (statuses, priorities, types,
// queues, categories).
// ============================================================================

/// Full create/list/update/delete cycle for a ticket status, plus the
/// re-delete 404. Exercises the admin-gated mutation routes end to end.
#[sqlx::test]
async fn lookup_status_crud_lifecycle(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    // CREATE
    let create_resp = app
        .client
        .post(app.url("/api/v1/tickets/statuses"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "name": "Escalated",
            "color": "#ff0000",
            "is_closed": false,
            "sort_order": 42,
        }))
        .send()
        .await
        .expect("send create status");
    assert_eq!(
        create_resp.status(),
        reqwest::StatusCode::OK,
        "create status should 2xx"
    );
    let created: serde_json::Value = create_resp.json().await.expect("create status JSON");
    let status_id = created["id"].as_str().expect("status id").to_string();
    assert_eq!(created["name"].as_str(), Some("Escalated"));
    assert_eq!(created["sort_order"].as_i64(), Some(42));

    // LIST contains it
    let list_resp = app
        .client
        .get(app.url("/api/v1/tickets/statuses?per_page=100"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send list statuses");
    let list: serde_json::Value = list_resp.json().await.expect("list statuses JSON");
    assert!(
        list["data"]
            .as_array()
            .expect("statuses data")
            .iter()
            .any(|s| s["id"].as_str() == Some(&status_id)),
        "list must contain the created status"
    );

    // UPDATE
    let update_resp = app
        .client
        .put(app.url(&format!("/api/v1/tickets/statuses/{status_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "name": "Escalated (P1)",
            "color": "#cc0000",
            "is_closed": true,
            "sort_order": 7,
        }))
        .send()
        .await
        .expect("send update status");
    assert_eq!(update_resp.status(), reqwest::StatusCode::OK);
    let updated: serde_json::Value = update_resp.json().await.expect("update status JSON");
    assert_eq!(updated["name"].as_str(), Some("Escalated (P1)"));
    assert_eq!(updated["is_closed"].as_bool(), Some(true));

    // DELETE
    let del_resp = app
        .client
        .delete(app.url(&format!("/api/v1/tickets/statuses/{status_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send delete status");
    assert!(
        del_resp.status().is_success(),
        "delete status should 2xx, got {}",
        del_resp.status()
    );

    // Re-delete is 404
    let redel_resp = app
        .client
        .delete(app.url(&format!("/api/v1/tickets/statuses/{status_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send re-delete status");
    assert_eq!(
        redel_resp.status(),
        reqwest::StatusCode::NOT_FOUND,
        "deleting an absent status must 404"
    );
}

/// Setting a new default status clears the previously-seeded default, so a
/// tenant never carries two defaults at once.
#[sqlx::test]
async fn setting_new_default_status_clears_prior(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    // Create a fresh status flagged default.
    let create_resp = app
        .client
        .post(app.url("/api/v1/tickets/statuses"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "name": "Brand New Default",
            "color": "#00aa00",
            "is_default": true,
        }))
        .send()
        .await
        .expect("send create default status");
    assert_eq!(create_resp.status(), reqwest::StatusCode::OK);
    let new_default_id = create_resp.json::<serde_json::Value>().await.expect("json")["id"]
        .as_str()
        .expect("id")
        .to_string();

    // Exactly one default remains, and it is the new one.
    let list: serde_json::Value = app
        .client
        .get(app.url("/api/v1/tickets/statuses?per_page=100"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send list statuses")
        .json()
        .await
        .expect("list statuses JSON");
    let defaults: Vec<&serde_json::Value> = list["data"]
        .as_array()
        .expect("statuses data")
        .iter()
        .filter(|s| s["is_default"].as_bool() == Some(true))
        .collect();
    assert_eq!(
        defaults.len(),
        1,
        "exactly one status may be default, found {}",
        defaults.len()
    );
    assert_eq!(
        defaults[0]["id"].as_str(),
        Some(new_default_id.as_str()),
        "the new status must be the sole default"
    );
}

/// Deleting a lookup still referenced by a ticket returns 409, not 500 (and
/// not a silent FK 500 from Postgres).
#[sqlx::test]
async fn delete_status_referenced_by_ticket_returns_409(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    // Create a ticket; it adopts the seeded default status.
    let created: serde_json::Value = app
        .client
        .post(app.url("/api/v1/tickets"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "title": "Reference holder",
            "company_id": company_id,
            "custom_fields": {},
        }))
        .send()
        .await
        .expect("send create ticket")
        .json()
        .await
        .expect("create ticket JSON");
    let status_id = created["status"]["id"]
        .as_str()
        .expect("ticket status id")
        .to_string();

    let del_resp = app
        .client
        .delete(app.url(&format!("/api/v1/tickets/statuses/{status_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send delete referenced status");
    assert_eq!(
        del_resp.status(),
        reqwest::StatusCode::CONFLICT,
        "deleting a status a ticket still references must 409, got {}",
        del_resp.status()
    );
}

/// Category create + child-via-parent + cross-tenant/self parent rejection.
#[sqlx::test]
async fn category_crud_and_parent_validation(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    // Parent category.
    let parent: serde_json::Value = app
        .client
        .post(app.url("/api/v1/tickets/categories"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "name": "Hardware" }))
        .send()
        .await
        .expect("send create parent category")
        .json()
        .await
        .expect("parent category JSON");
    let parent_id = parent["id"].as_str().expect("parent id").to_string();

    // Child referencing the parent.
    let child_resp = app
        .client
        .post(app.url("/api/v1/tickets/categories"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "name": "Laptops", "parent_id": parent_id }))
        .send()
        .await
        .expect("send create child category");
    assert_eq!(child_resp.status(), reqwest::StatusCode::OK);
    let child_id = child_resp
        .json::<serde_json::Value>()
        .await
        .expect("child JSON")["id"]
        .as_str()
        .expect("child id")
        .to_string();

    // List shows both.
    let list: serde_json::Value = app
        .client
        .get(app.url("/api/v1/tickets/categories?per_page=100"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send list categories")
        .json()
        .await
        .expect("list categories JSON");
    let ids: Vec<&str> = list["data"]
        .as_array()
        .expect("categories data")
        .iter()
        .filter_map(|c| c["id"].as_str())
        .collect();
    assert!(ids.contains(&parent_id.as_str()) && ids.contains(&child_id.as_str()));

    // A parent_id that is not a category in this tenant is rejected (400).
    let unknown_parent = uuid::Uuid::new_v4();
    let bad_parent = app
        .client
        .post(app.url("/api/v1/tickets/categories"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "name": "Orphan", "parent_id": unknown_parent }))
        .send()
        .await
        .expect("send create with bad parent");
    assert_eq!(
        bad_parent.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "an unknown parent_id must 400"
    );

    // A category cannot be its own parent (400).
    let self_parent = app
        .client
        .put(app.url(&format!("/api/v1/tickets/categories/{child_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "name": "Laptops", "parent_id": child_id }))
        .send()
        .await
        .expect("send self-parent update");
    assert_eq!(
        self_parent.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "a self-referential parent_id must 400"
    );
}

/// A non-admin (technician) is refused on the lookup mutation routes; reads
/// stay open to any authenticated member.
#[sqlx::test]
async fn non_admin_cannot_mutate_lookups(pool: PgPool) {
    let (_tech_id, email, password) = common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "tech@example.com",
        "technician",
    )
    .await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    // Read is allowed.
    let list = app
        .client
        .get(app.url("/api/v1/tickets/statuses"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send list statuses");
    assert_eq!(list.status(), reqwest::StatusCode::OK);

    // Write is forbidden.
    let create = app
        .client
        .post(app.url("/api/v1/tickets/statuses"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "name": "Nope", "color": "#000000" }))
        .send()
        .await
        .expect("send create status as technician");
    assert_eq!(
        create.status(),
        reqwest::StatusCode::FORBIDDEN,
        "a technician must not create a status"
    );
}

/// Priority create + update exercises the `sla_multiplier` f64 -> DECIMAL(3,2)
/// binding (the lookup whose numeric column is most likely to trip an
/// encode/decode mismatch) and the priority default-clearing invariant.
#[sqlx::test]
async fn lookup_priority_crud_and_default(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    // CREATE with a non-integer multiplier and default flag.
    let created: serde_json::Value = app
        .client
        .post(app.url("/api/v1/tickets/priorities"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "name": "Critical",
            "color": "#ff0000",
            "icon": "alert",
            "sla_multiplier": 1.5,
            "is_default": true,
        }))
        .send()
        .await
        .expect("send create priority")
        .json()
        .await
        .expect("create priority JSON");
    let priority_id = created["id"].as_str().expect("priority id").to_string();
    assert_eq!(created["sla_multiplier"].as_f64(), Some(1.5));

    // The new priority is now the sole default.
    let list: serde_json::Value = app
        .client
        .get(app.url("/api/v1/tickets/priorities?per_page=100"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send list priorities")
        .json()
        .await
        .expect("list priorities JSON");
    let defaults = list["data"]
        .as_array()
        .expect("priorities data")
        .iter()
        .filter(|p| p["is_default"].as_bool() == Some(true))
        .count();
    assert_eq!(defaults, 1, "exactly one default priority");

    // UPDATE round-trips the multiplier.
    let updated: serde_json::Value = app
        .client
        .put(app.url(&format!("/api/v1/tickets/priorities/{priority_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "name": "Critical",
            "color": "#ee0000",
            "sla_multiplier": 2.25,
            "is_default": true,
        }))
        .send()
        .await
        .expect("send update priority")
        .json()
        .await
        .expect("update priority JSON");
    assert_eq!(updated["sla_multiplier"].as_f64(), Some(2.25));

    // An out-of-range multiplier (> DECIMAL(3,2) max) is rejected by request
    // validation (422) before it can reach Postgres, never a 500.
    let bad = app
        .client
        .post(app.url("/api/v1/tickets/priorities"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "name": "Overflow",
            "color": "#000000",
            "sla_multiplier": 99.9,
        }))
        .send()
        .await
        .expect("send overflow priority");
    assert_eq!(
        bad.status(),
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "an over-range sla_multiplier must be a validation 422, not a 500"
    );
}

/// A transitive parent cycle (A -> B, then re-parent A under B) is rejected,
/// not just the depth-1 self-parent case.
#[sqlx::test]
async fn category_transitive_cycle_rejected(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let mk = |body: serde_json::Value| {
        let app = &app;
        let token = &token;
        async move {
            app.client
                .post(app.url("/api/v1/tickets/categories"))
                .bearer_auth(token)
                .json(&body)
                .send()
                .await
                .expect("send create category")
                .json::<serde_json::Value>()
                .await
                .expect("category JSON")
        }
    };

    // A is the root; B is a child of A.
    let a = mk(serde_json::json!({ "name": "A" })).await;
    let a_id = a["id"].as_str().expect("a id").to_string();
    let b = mk(serde_json::json!({ "name": "B", "parent_id": a_id })).await;
    let b_id = b["id"].as_str().expect("b id").to_string();

    // Re-parenting A under B (its own descendant) would close a cycle.
    let cycle = app
        .client
        .put(app.url(&format!("/api/v1/tickets/categories/{a_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "name": "A", "parent_id": b_id }))
        .send()
        .await
        .expect("send cycle update");
    assert_eq!(
        cycle.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "a transitive parent cycle must 400"
    );
}

/// PMS-321 schema hardening: the composite `(tenant_id, parent_id)` FK added
/// in migration 047 rejects a cross-tenant parent at the database layer, even
/// for a write that bypasses the service-layer `validate_fk` guard. Same-tenant
/// parenting still works.
#[sqlx::test]
async fn category_parent_cross_tenant_blocked_at_db(pool: PgPool) {
    let (tenant_b, _u, _e, _p) = common::seed_tenant_with_admin(&pool, "tenant-b").await;

    // Root category in the default tenant (tenant A).
    let parent_a = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO ticket_categories (id, tenant_id, name) VALUES ($1, $2, 'A-root')")
        .bind(parent_a)
        .bind(common::DEFAULT_TENANT_ID)
        .execute(&pool)
        .await
        .expect("insert tenant-A root category");

    // Same-tenant child is allowed.
    sqlx::query(
        "INSERT INTO ticket_categories (id, tenant_id, parent_id, name) VALUES ($1, $2, $3, 'A-child')",
    )
    .bind(uuid::Uuid::new_v4())
    .bind(common::DEFAULT_TENANT_ID)
    .bind(parent_a)
    .execute(&pool)
    .await
    .expect("same-tenant child must be allowed");

    // A tenant-B category parented under tenant A's row must violate the FK.
    let res = sqlx::query(
        "INSERT INTO ticket_categories (id, tenant_id, parent_id, name) VALUES ($1, $2, $3, 'B-bad')",
    )
    .bind(uuid::Uuid::new_v4())
    .bind(tenant_b)
    .bind(parent_a)
    .execute(&pool)
    .await;
    let err = res.expect_err("cross-tenant parent must violate the composite FK");
    let code = err
        .as_database_error()
        .and_then(|d| d.code())
        .map(|c| c.into_owned());
    assert_eq!(
        code.as_deref(),
        Some("23503"),
        "expected a foreign-key violation, got {err}"
    );
}
