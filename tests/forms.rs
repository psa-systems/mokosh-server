//! Integration test: PMS-731 form definitions with per-field validation.
//!
//! Exercises the three acceptance criteria over HTTP: a definition can be
//! created with an ordered field set carrying type, label, required flag and
//! validation rules; a submission is validated field by field and rejected
//! with per-field errors; and a valid submission is stored. The per-rule
//! behaviour of the validator itself is unit-tested in
//! `src/modules/forms/validation.rs`; this file pins the wiring, the
//! persisted result, and the surfaces the unit tests cannot reach (auth
//! gating, retirement, deletion).
//!
//! RLS coverage for `form_definitions`, `form_fields` and `form_submissions`
//! is asserted generically by `tests/rls_coverage.rs`, which fails any
//! tenant-scoped table that lacks a policy, so it is not repeated here.

mod common;

use serde_json::json;
use sqlx::PgPool;

/// The MACD departure form from the PMS-731 field-list review, trimmed to the
/// fields that carry a distinct rule. `forward_to` is the conditional case:
/// required only when `mailbox_handling` is `forward`.
fn departure_form() -> serde_json::Value {
    json!({
        "name": "Departure",
        "slug": "departure",
        "description": "Offboard a leaver",
        "fields": [
            {
                "name": "employee_name",
                "label": "Employee name",
                "field_type": "text",
                "is_required": true,
                "min_length": 1,
                "max_length": 200,
                "sort_order": 1
            },
            {
                "name": "last_working_day",
                "label": "Last working day",
                "field_type": "date",
                "is_required": true,
                "date_not_in_past": true,
                "sort_order": 2
            },
            {
                "name": "mailbox_handling",
                "label": "Mailbox handling",
                "field_type": "select",
                "is_required": true,
                "options": ["forward", "convert to shared", "delete after retention"],
                "sort_order": 3
            },
            {
                "name": "forward_to",
                "label": "Forward to",
                "field_type": "email",
                "is_required": false,
                "sort_order": 4
            },
            {
                "name": "notes",
                "label": "Notes",
                "field_type": "textarea",
                "is_required": false,
                "max_length": 2000,
                "sort_order": 5
            }
        ],
        "rules": [
            {
                "kind": "required_if",
                "field": "forward_to",
                "when_field": "mailbox_handling",
                "equals": "forward"
            }
        ]
    })
}

async fn create_form(
    app: &common::TestApp,
    token: &str,
    body: serde_json::Value,
) -> serde_json::Value {
    let resp = app
        .client
        .post(app.url("/api/v1/forms"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("send create form");
    let status = resp.status();
    let text = resp.text().await.expect("create form body");
    assert!(
        status.is_success(),
        "create form should 2xx, got {status} body={text}"
    );
    serde_json::from_str(&text).expect("create form JSON")
}

async fn submit(
    app: &common::TestApp,
    token: &str,
    form_id: &str,
    payload: serde_json::Value,
) -> (reqwest::StatusCode, serde_json::Value) {
    let resp = app
        .client
        .post(app.url(&format!("/api/v1/forms/{form_id}/submissions")))
        .bearer_auth(token)
        .json(&json!({ "payload": payload }))
        .send()
        .await
        .expect("send submission");
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.expect("submission JSON");
    (status, body)
}

/// Collect `{field: code}` pairs from a 422 body so assertions read as the
/// contract ("these fields failed, for these reasons") rather than as an
/// index into an array whose order is incidental.
fn field_codes(body: &serde_json::Value) -> Vec<(String, String)> {
    // The canonical envelope is `{error: {code, message, errors: []}}`.
    let mut pairs: Vec<(String, String)> = body["error"]["errors"]
        .as_array()
        .expect("a 422 body carries error.errors[]")
        .iter()
        .map(|e| {
            (
                e["field"].as_str().unwrap_or_default().to_string(),
                e["code"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    pairs.sort();
    pairs
}

#[sqlx::test]
async fn definition_round_trips_with_its_ordered_field_set(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let created = create_form(&app, &token, departure_form()).await;
    let form_id = created["id"].as_str().expect("form id").to_string();

    assert_eq!(created["slug"].as_str(), Some("departure"));
    assert_eq!(created["is_active"].as_bool(), Some(true));

    let fields = created["fields"].as_array().expect("fields[]");
    assert_eq!(fields.len(), 5);
    let names: Vec<&str> = fields.iter().map(|f| f["name"].as_str().unwrap()).collect();
    assert_eq!(
        names,
        vec![
            "employee_name",
            "last_working_day",
            "mailbox_handling",
            "forward_to",
            "notes"
        ],
        "fields must come back in sort_order"
    );
    assert_eq!(fields[2]["field_type"].as_str(), Some("select"));
    assert_eq!(
        fields[2]["options"].as_array().map(|o| o.len()),
        Some(3),
        "a select carries its option set"
    );
    assert_eq!(fields[1]["date_not_in_past"].as_bool(), Some(true));
    assert_eq!(
        created["rules"].as_array().map(|r| r.len()),
        Some(1),
        "the cross-field rule survives the round trip"
    );

    // GET returns the same shape as the create response.
    let fetched: serde_json::Value = app
        .client
        .get(app.url(&format!("/api/v1/forms/{form_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send get form")
        .json()
        .await
        .expect("get form JSON");
    assert_eq!(fetched["fields"].as_array().map(|f| f.len()), Some(5));
    assert_eq!(fetched["rules"], created["rules"]);
}

#[sqlx::test]
async fn a_submission_is_rejected_with_every_field_error_at_once(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let form = create_form(&app, &token, departure_form()).await;
    let form_id = form["id"].as_str().expect("form id");

    // Empty payload: all three required fields must be reported together,
    // not one at a time.
    let (status, body) = submit(&app, &token, form_id, json!({})).await;
    assert_eq!(status, reqwest::StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        field_codes(&body),
        vec![
            ("employee_name".to_string(), "required".to_string()),
            ("last_working_day".to_string(), "required".to_string()),
            ("mailbox_handling".to_string(), "required".to_string()),
        ]
    );

    // One payload exercising several distinct rules at once.
    let (status, body) = submit(
        &app,
        &token,
        form_id,
        json!({
            "employee_name": "Dana Reyes",
            "last_working_day": "1999-01-01",
            "mailbox_handling": "shred it",
            "forward_to": "not-an-email",
            "typo_field": "x"
        }),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        field_codes(&body),
        vec![
            ("forward_to".to_string(), "email".to_string()),
            ("last_working_day".to_string(), "date_in_past".to_string()),
            ("mailbox_handling".to_string(), "option".to_string()),
            ("typo_field".to_string(), "unknown_field".to_string()),
        ]
    );

    // The conditional rule: forwarding without an address is the one error.
    let (status, body) = submit(
        &app,
        &token,
        form_id,
        json!({
            "employee_name": "Dana Reyes",
            "last_working_day": "2099-01-01",
            "mailbox_handling": "forward"
        }),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        field_codes(&body),
        vec![("forward_to".to_string(), "required".to_string())]
    );

    // Nothing was stored by any of the rejected attempts.
    let listed: serde_json::Value = app
        .client
        .get(app.url(&format!("/api/v1/forms/{form_id}/submissions")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send list submissions")
        .json()
        .await
        .expect("submissions JSON");
    assert_eq!(
        listed.as_array().map(|a| a.len()),
        Some(0),
        "a rejected submission must not persist"
    );
}

#[sqlx::test]
async fn a_valid_submission_is_stored_normalised(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let form = create_form(&app, &token, departure_form()).await;
    let form_id = form["id"].as_str().expect("form id");

    let (status, body) = submit(
        &app,
        &token,
        form_id,
        json!({
            "employee_name": "  Dana Reyes  ",
            "last_working_day": "2099-06-01",
            "mailbox_handling": "forward",
            "forward_to": "manager@example.com",
            "notes": "   "
        }),
    )
    .await;
    assert!(
        status.is_success(),
        "valid submission should 2xx, got {status} body={body}"
    );

    let payload = &body["payload"];
    assert_eq!(
        payload["employee_name"].as_str(),
        Some("Dana Reyes"),
        "answers are trimmed before storage"
    );
    assert_eq!(payload["forward_to"].as_str(), Some("manager@example.com"));
    assert!(
        payload.get("notes").is_none(),
        "an optional field answered with whitespace is omitted, not stored blank"
    );
    assert!(
        body["ticket_id"].is_null(),
        "turning a submission into a ticket is PMS-730, not this issue"
    );

    let listed: serde_json::Value = app
        .client
        .get(app.url(&format!("/api/v1/forms/{form_id}/submissions")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send list submissions")
        .json()
        .await
        .expect("submissions JSON");
    assert_eq!(listed.as_array().map(|a| a.len()), Some(1));
}

#[sqlx::test]
async fn a_definition_is_rejected_when_its_field_set_cannot_work(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    // A select with no options can never be satisfied, and a rule naming a
    // field the form does not have can never fire. Both are author errors and
    // are reported in the same per-field shape a bad submission gets.
    let resp = app
        .client
        .post(app.url("/api/v1/forms"))
        .bearer_auth(&token)
        .json(&json!({
            "name": "Broken",
            "slug": "broken",
            "fields": [
                {"name": "choice", "label": "Choice", "field_type": "select"}
            ],
            "rules": [
                {"kind": "required_if", "field": "ghost", "when_field": "choice", "equals": "x"}
            ]
        }))
        .send()
        .await
        .expect("send create broken form");
    assert_eq!(resp.status(), reqwest::StatusCode::UNPROCESSABLE_ENTITY);
    let body: serde_json::Value = resp.json().await.expect("error JSON");
    let codes = field_codes(&body);
    assert!(
        codes
            .iter()
            .any(|(f, c)| f == "fields[0].options" && c == "required"),
        "a select without options must be rejected, got {codes:?}"
    );
}

#[sqlx::test]
async fn a_retired_form_refuses_submissions_and_a_submitted_form_refuses_deletion(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let form = create_form(&app, &token, departure_form()).await;
    let form_id = form["id"].as_str().expect("form id").to_string();

    let valid = json!({
        "employee_name": "Dana Reyes",
        "last_working_day": "2099-06-01",
        "mailbox_handling": "convert to shared"
    });
    let (status, _) = submit(&app, &token, &form_id, valid.clone()).await;
    assert!(status.is_success());

    // A form with submissions cannot be deleted: the submission is a record
    // of something a client asked for. Retiring is the supported path.
    let del = app
        .client
        .delete(app.url(&format!("/api/v1/forms/{form_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send delete");
    assert_eq!(
        del.status(),
        reqwest::StatusCode::CONFLICT,
        "deleting a submitted form must 409 rather than cascade"
    );

    // Retire it, and new submissions stop.
    let patched = app
        .client
        .patch(app.url(&format!("/api/v1/forms/{form_id}")))
        .bearer_auth(&token)
        .json(&json!({"is_active": false}))
        .send()
        .await
        .expect("send retire");
    assert!(patched.status().is_success());

    let (status, _) = submit(&app, &token, &form_id, valid).await;
    assert_eq!(
        status,
        reqwest::StatusCode::CONFLICT,
        "a retired form must stop collecting, or the flag is decorative"
    );
}

#[sqlx::test]
async fn authoring_is_admin_gated_but_submitting_is_not(pool: PgPool) {
    let (_admin_id, admin_email, admin_password) = common::seed_admin(&pool).await;
    let (_tech_id, tech_email, tech_password) = common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "tech@example.com",
        "technician",
    )
    .await;
    let app = common::boot(pool.clone()).await;
    let admin_token = common::login(&app, &admin_email, &admin_password).await;
    let tech_token = common::login(&app, &tech_email, &tech_password).await;

    let form = create_form(&app, &admin_token, departure_form()).await;
    let form_id = form["id"].as_str().expect("form id").to_string();

    let denied = app
        .client
        .post(app.url("/api/v1/forms"))
        .bearer_auth(&tech_token)
        .json(&json!({
            "name": "Sneaky",
            "slug": "sneaky",
            "fields": [{"name": "x", "label": "X", "field_type": "text"}]
        }))
        .send()
        .await
        .expect("send create as technician");
    assert_eq!(
        denied.status(),
        reqwest::StatusCode::FORBIDDEN,
        "authoring a definition is tenant-wide config and stays admin-only"
    );

    // Reading and submitting are open to any authenticated agent: filling a
    // request on a client's behalf is a normal path.
    let (status, _) = submit(
        &app,
        &tech_token,
        &form_id,
        json!({
            "employee_name": "Dana Reyes",
            "last_working_day": "2099-06-01",
            "mailbox_handling": "convert to shared"
        }),
    )
    .await;
    assert!(
        status.is_success(),
        "an authenticated agent must be able to submit, got {status}"
    );
}
