//! Integration test: PMS-731 form definitions with per-field validation.
//!
//! Exercises the three acceptance criteria over HTTP: a definition can be
//! created with an ordered field set carrying type, label, required flag and
//! validation rules; a submission is validated field by field and rejected
//! with per-field errors; and a valid submission is stored. The per-rule
//! behaviour of the validator itself is unit-tested in
//! `src/modules/forms/validation.rs`; this file pins the wiring, the
//! persisted result, and the surfaces the unit tests cannot reach (auth
//! gating, retirement).
//!
//! PMS-840 retired the authenticated `POST /forms/{id}/submissions` as
//! unconsumed, so every submission here goes through the PMS-730 magic link,
//! which is now the only writer of `form_submissions`. That makes these tests
//! a little longer (a submission needs a company and an issued link) and
//! makes them exercise the path a real client actually takes.
//!
//! RLS coverage for `form_definitions`, `form_fields` and `form_submissions`
//! is asserted generically by `tests/rls_coverage.rs`, which fails any
//! tenant-scoped table that lacks a policy, so it is not repeated here.

mod common;

use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

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

/// Issue a client a magic link and recover its token out of the queued email,
/// the way the recipient does. The token is never returned by the API.
async fn issue_link(
    app: &common::TestApp,
    token: &str,
    pool: &PgPool,
    form_id: &str,
    company_id: Uuid,
) -> String {
    let resp = app
        .client
        .post(app.url("/api/v1/form-request-links"))
        .bearer_auth(token)
        .json(&json!({
            "form_definition_id": form_id,
            "company_id": company_id,
            "recipient_email": "client@example.com"
        }))
        .send()
        .await
        .expect("send issue link");
    let status = resp.status();
    let text = resp.text().await.expect("issue link body");
    assert!(
        status.is_success(),
        "issue link should 2xx, got {status} body={text}"
    );

    // Match on the link body rather than taking the newest notification
    // outright: a successful submission creates a ticket, which queues
    // notifications of its own.
    let body_text: String = sqlx::query_scalar(
        "SELECT body FROM notifications \
         WHERE tenant_id = $1 AND body LIKE '%/request-forms/%' \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(pool)
    .await
    .expect("a request-link email was queued");

    body_text
        .split("/request-forms/")
        .nth(1)
        .expect("the queued email carries the link")
        .split_whitespace()
        .next()
        .expect("the link has a token")
        .to_string()
}

/// Submit `payload` behind an issued link. A rejected submission leaves the
/// link live, so one link carries as many invalid attempts as a test needs; a
/// successful one burns it and the next submission needs a fresh link.
async fn submit(
    app: &common::TestApp,
    link_token: &str,
    payload: serde_json::Value,
) -> (reqwest::StatusCode, serde_json::Value) {
    let resp = app
        .client
        .post(app.url(&format!("/api/v1/public/request-forms/{link_token}")))
        .json(&json!({ "payload": payload }))
        .send()
        .await
        .expect("send submission");
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.expect("submission JSON");
    (status, body)
}

/// The submissions of one definition, read back through the surface an agent
/// uses (`GET /forms/{id}/submissions`).
async fn list_submissions(
    app: &common::TestApp,
    token: &str,
    form_id: &str,
) -> Vec<serde_json::Value> {
    let body: serde_json::Value = app
        .client
        .get(app.url(&format!("/api/v1/forms/{form_id}/submissions")))
        .bearer_auth(token)
        .send()
        .await
        .expect("send list submissions")
        .json()
        .await
        .expect("submissions JSON");
    body.as_array().expect("submissions[]").clone()
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
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let form = create_form(&app, &token, departure_form()).await;
    let form_id = form["id"].as_str().expect("form id").to_string();
    let link = issue_link(&app, &token, &pool, &form_id, company_id).await;

    // Empty payload: all three required fields must be reported together,
    // not one at a time.
    let (status, body) = submit(&app, &link, json!({})).await;
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
        &link,
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
        &link,
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
    assert!(
        list_submissions(&app, &token, &form_id).await.is_empty(),
        "a rejected submission must not persist"
    );
}

#[sqlx::test]
async fn a_valid_submission_is_stored_normalised(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let form = create_form(&app, &token, departure_form()).await;
    let form_id = form["id"].as_str().expect("form id").to_string();
    let link = issue_link(&app, &token, &pool, &form_id, company_id).await;

    let (status, body) = submit(
        &app,
        &link,
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

    // Read back through `GET /forms/{id}/submissions`, the surface PMS-840
    // kept: what a client answered has to be legible after the fact, not only
    // in the ticket description it was rendered into once.
    let listed = list_submissions(&app, &token, &form_id).await;
    assert_eq!(listed.len(), 1);
    let stored = &listed[0];

    let payload = &stored["payload"];
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
        !stored["ticket_id"].is_null(),
        "the magic-link path links the stored submission to the ticket it created (PMS-730)"
    );
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

/// PMS-842: a `required_if` whose condition is a checkbox must fire on the
/// server, not only in the SPA. `equals` is authored as text whatever the
/// condition field's type, so `"true"` has to match a JSON `true` answer, and
/// an `equals` outside `true`/`false` has to be refused at authoring time
/// rather than stored as a rule that can never fire.
#[sqlx::test]
async fn a_boolean_conditioned_rule_fires_and_is_bounded_at_authoring_time(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let definition = json!({
        "name": "Mailbox",
        "slug": "mailbox",
        "fields": [
            {
                "name": "keep_mailbox",
                "label": "Keep the mailbox",
                "field_type": "boolean",
                "is_required": true,
                "sort_order": 1
            },
            {
                "name": "forward_to",
                "label": "Forward to",
                "field_type": "email",
                "is_required": false,
                "sort_order": 2
            }
        ],
        "rules": [
            {
                "kind": "required_if",
                "field": "forward_to",
                "when_field": "keep_mailbox",
                "equals": "true"
            }
        ]
    });

    let form = create_form(&app, &token, definition.clone()).await;
    let form_id = form["id"].as_str().expect("form id").to_string();
    let link = issue_link(&app, &token, &pool, &form_id, company_id).await;

    // Condition holds and the dependent field is absent -> 422 naming it.
    let (status, body) = submit(&app, &link, json!({"keep_mailbox": true})).await;
    assert_eq!(status, reqwest::StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        field_codes(&body),
        vec![("forward_to".to_string(), "required".to_string())],
        "a boolean condition must make the rule fire server-side"
    );

    // Condition does not hold -> the dependent field stays optional. The
    // rejected attempt above left the link live, so it still works here.
    let (status, body) = submit(&app, &link, json!({"keep_mailbox": false})).await;
    assert!(
        status.is_success(),
        "no address is needed when the mailbox is not kept, got {status} body={body}"
    );

    // An `equals` a boolean can never take is an author error.
    let mut broken = definition;
    broken["name"] = json!("Mailbox yes");
    broken["slug"] = json!("mailbox-yes");
    broken["rules"][0]["equals"] = json!("yes");
    let resp = app
        .client
        .post(app.url("/api/v1/forms"))
        .bearer_auth(&token)
        .json(&broken)
        .send()
        .await
        .expect("send create with an unsatisfiable rule");
    assert_eq!(resp.status(), reqwest::StatusCode::UNPROCESSABLE_ENTITY);
    let body: serde_json::Value = resp.json().await.expect("error JSON");
    assert_eq!(
        field_codes(&body),
        vec![("rules[0].equals".to_string(), "option".to_string())],
        "a rule that can never fire must be refused, not stored inert"
    );
}

/// PMS-840 removed `DELETE /forms/{id}`, so `is_active` is the whole
/// retirement story and this pins both halves of it: a link already in a
/// client's inbox stops working, and no new link can be sent.
#[sqlx::test]
async fn a_retired_form_refuses_submissions_and_refuses_new_links(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let form = create_form(&app, &token, departure_form()).await;
    let form_id = form["id"].as_str().expect("form id").to_string();

    // Two links up front: the second is the one already in a client's inbox
    // when the form is retired, and a link cannot be issued after that point.
    let spent = issue_link(&app, &token, &pool, &form_id, company_id).await;
    let in_flight = issue_link(&app, &token, &pool, &form_id, company_id).await;

    let valid = json!({
        "employee_name": "Dana Reyes",
        "last_working_day": "2099-06-01",
        "mailbox_handling": "convert to shared"
    });
    let (status, body) = submit(&app, &spent, valid.clone()).await;
    assert!(status.is_success(), "got {status} body={body}");

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

    let (status, _) = submit(&app, &in_flight, valid).await;
    assert_eq!(
        status,
        reqwest::StatusCode::CONFLICT,
        "a retired form must stop collecting, or the flag is decorative"
    );

    let refused = app
        .client
        .post(app.url("/api/v1/form-request-links"))
        .bearer_auth(&token)
        .json(&json!({
            "form_definition_id": form_id,
            "company_id": company_id,
            "recipient_email": "client@example.com"
        }))
        .send()
        .await
        .expect("send issue link for a retired form");
    assert_eq!(
        refused.status(),
        reqwest::StatusCode::CONFLICT,
        "a link issued for a retired form would die on arrival"
    );

    // The submission taken before retirement is still readable: retiring
    // stops collection, it does not erase what a client asked for. That is
    // the property the removed hard delete would have broken.
    assert_eq!(
        list_submissions(&app, &token, &form_id).await.len(),
        1,
        "retiring must keep existing submissions"
    );
}

#[sqlx::test]
async fn authoring_is_admin_gated_but_sending_a_link_is_not(pool: PgPool) {
    let (_admin_id, admin_email, admin_password) = common::seed_admin(&pool).await;
    let (_tech_id, tech_email, tech_password) = common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "tech@example.com",
        "technician",
    )
    .await;
    let company_id = common::seed_company(&pool).await;
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

    // Reading a definition and emailing a client its link are open to any
    // authenticated agent: sending a request out is ordinary account work.
    let read = app
        .client
        .get(app.url(&format!("/api/v1/forms/{form_id}")))
        .bearer_auth(&tech_token)
        .send()
        .await
        .expect("send get as technician");
    assert!(
        read.status().is_success(),
        "an authenticated agent must be able to read a definition, got {}",
        read.status()
    );

    let sent = app
        .client
        .post(app.url("/api/v1/form-request-links"))
        .bearer_auth(&tech_token)
        .json(&json!({
            "form_definition_id": form_id,
            "company_id": company_id,
            "recipient_email": "client@example.com"
        }))
        .send()
        .await
        .expect("send issue link as technician");
    assert!(
        sent.status().is_success(),
        "an authenticated agent must be able to issue a request link, got {}",
        sent.status()
    );
}

/// Replacing a field set without touching the rules can strand a rule on a
/// field that no longer exists. Left unchecked the rule would be silently
/// inert, so the update path validates whichever rule set is in force against
/// whichever field set is in force, even when only one of the two changed.
#[sqlx::test]
async fn replacing_the_field_set_cannot_strand_an_existing_rule(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let form = create_form(&app, &token, departure_form()).await;
    let form_id = form["id"].as_str().expect("form id").to_string();

    // Drop `forward_to` while leaving the `required_if` rule that targets it.
    let resp = app
        .client
        .patch(app.url(&format!("/api/v1/forms/{form_id}")))
        .bearer_auth(&token)
        .json(&json!({
            "fields": [
                {
                    "name": "employee_name",
                    "label": "Employee name",
                    "field_type": "text",
                    "is_required": true,
                    "sort_order": 1
                },
                {
                    "name": "mailbox_handling",
                    "label": "Mailbox handling",
                    "field_type": "select",
                    "is_required": true,
                    "options": ["forward", "convert to shared"],
                    "sort_order": 2
                }
            ]
        }))
        .send()
        .await
        .expect("send patch dropping a rule target");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "dropping a field a rule targets must be rejected, not silently accepted"
    );
    let body: serde_json::Value = resp.json().await.expect("error JSON");
    assert!(
        field_codes(&body)
            .iter()
            .any(|(f, c)| f == "rules[0].field" && c == "unknown_field"),
        "the stranded rule must be named, got {:?}",
        field_codes(&body)
    );

    // Dropping the field AND the rule together is fine.
    let ok = app
        .client
        .patch(app.url(&format!("/api/v1/forms/{form_id}")))
        .bearer_auth(&token)
        .json(&json!({
            "rules": [],
            "fields": [
                {
                    "name": "employee_name",
                    "label": "Employee name",
                    "field_type": "text",
                    "is_required": true,
                    "sort_order": 1
                }
            ]
        }))
        .send()
        .await
        .expect("send patch dropping both");
    assert!(
        ok.status().is_success(),
        "dropping the field and its rule together is a legitimate edit"
    );
}

/// PMS-841: the 200-character cap on `contact_info` is the server's, so it has
/// to answer the same way on both of the server's own write paths. Before this,
/// create refused an over-length line and update stored it, which made the cap
/// a suggestion for anyone who edited an existing form.
#[sqlx::test]
async fn an_over_length_contact_line_is_refused_on_create_and_on_update(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let too_long = "x".repeat(201);

    // Create: the same value, refused.
    let mut body = departure_form();
    body["slug"] = json!("departure-overlong");
    body["contact_info"] = json!(too_long);
    let resp = app
        .client
        .post(app.url("/api/v1/forms"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .expect("send create with an over-length contact line");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "create must refuse a contact line over 200 characters"
    );
    let created_err: serde_json::Value = resp.json().await.expect("create error JSON");
    assert!(
        field_codes(&created_err)
            .iter()
            .any(|(f, c)| f == "contact_info" && c == "length"),
        "the create refusal must name contact_info, got {:?}",
        field_codes(&created_err)
    );

    // A form that exists, with a contact line inside the cap.
    let mut ok_body = departure_form();
    ok_body["contact_info"] = json!("support@example.com");
    let form = create_form(&app, &token, ok_body).await;
    let form_id = form["id"].as_str().expect("form id").to_string();
    assert_eq!(form["contact_info"].as_str(), Some("support@example.com"));

    // Update: the same value, refused the same way.
    let resp = app
        .client
        .patch(app.url(&format!("/api/v1/forms/{form_id}")))
        .bearer_auth(&token)
        .json(&json!({ "contact_info": too_long }))
        .send()
        .await
        .expect("send patch with an over-length contact line");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "update must refuse what create refuses"
    );
    let updated_err: serde_json::Value = resp.json().await.expect("update error JSON");
    assert!(
        field_codes(&updated_err)
            .iter()
            .any(|(f, c)| f == "contact_info" && c == "length"),
        "the update refusal must name contact_info, got {:?}",
        field_codes(&updated_err)
    );

    // Exactly 200 is inside the cap on the update path.
    let at_cap = "y".repeat(200);
    let resp = app
        .client
        .patch(app.url(&format!("/api/v1/forms/{form_id}")))
        .bearer_auth(&token)
        .json(&json!({ "contact_info": at_cap }))
        .send()
        .await
        .expect("send patch at the cap");
    assert!(
        resp.status().is_success(),
        "200 characters is inside the cap, got {}",
        resp.status()
    );
    let at_cap_body: serde_json::Value = resp.json().await.expect("patch JSON");
    assert_eq!(at_cap_body["contact_info"].as_str(), Some(at_cap.as_str()));

    // An explicit null still clears: `length` passes on an absent inner value,
    // so the double-option clear semantics survive the new attribute.
    let resp = app
        .client
        .patch(app.url(&format!("/api/v1/forms/{form_id}")))
        .bearer_auth(&token)
        .json(&json!({ "contact_info": serde_json::Value::Null }))
        .send()
        .await
        .expect("send patch clearing the contact line");
    assert!(
        resp.status().is_success(),
        "clearing the contact line must stay legal, got {}",
        resp.status()
    );
    let cleared: serde_json::Value = resp.json().await.expect("cleared JSON");
    assert!(
        cleared["contact_info"].is_null(),
        "null must clear the stored contact line, got {:?}",
        cleared["contact_info"]
    );
}

/// PMS-898: a rule kind the server cannot name is refused on a write.
///
/// The shared `FormRule` gained a catch-all so the READ path stays tolerant: a
/// client older than a rule kind renders the form and lets the server enforce
/// it, rather than failing to deserialise the definition. That tolerance must
/// not reach writes, or a definition would store a rule this server can never
/// enforce, and the form would carry a constraint that exists only in the
/// payload that created it.
///
/// The compiler is what made this unavoidable: `check_rules_against_fields`
/// destructured `FormRule` irrefutably, so adding the catch-all broke the build
/// until someone decided what an unnamed rule means on a write.
#[sqlx::test]
async fn a_rule_kind_the_server_cannot_name_is_refused(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let mut body = departure_form();
    body["slug"] = json!("departure-unknown-rule");
    body["rules"] = json!([
        {
            "kind": "required_if",
            "field": "forward_to",
            "when_field": "mailbox_handling",
            "equals": "forward"
        },
        {
            "kind": "invented_by_a_newer_server",
            "field": "forward_to"
        }
    ]);

    let resp = app
        .client
        .post(app.url("/api/v1/forms"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .expect("create definition with an unknown rule kind");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "an unnamed rule must not be storable"
    );

    let error: serde_json::Value = resp.json().await.expect("error JSON");
    let errors = error["error"]["errors"]
        .as_array()
        .unwrap_or_else(|| panic!("the 422 carries field errors, got {error}"));
    assert!(
        errors.iter().any(|e| e["field"]
            .as_str()
            .unwrap_or_default()
            .starts_with("rules[")
            && e["code"].as_str() == Some("unknown_rule_kind")),
        "the rejection names which rule, got {error}"
    );

    // The known rule alone still creates, so the rejection is about the
    // unnamed kind and not about rules in general.
    let mut ok_body = departure_form();
    ok_body["slug"] = json!("departure-known-rule-only");
    let created = create_form(&app, &token, ok_body).await;
    assert_eq!(created["rules"].as_array().map(|r| r.len()), Some(1));

    // Update refuses what create refuses. PMS-841 is the precedent for testing
    // both: the `contact_info` cap was enforced on create and ignored on
    // update, so the rule held only for whoever authored the form first. The
    // refusal names the rule by its own index, not the first one.
    let form_id = created["id"].as_str().expect("form id").to_string();
    let resp = app
        .client
        .patch(app.url(&format!("/api/v1/forms/{form_id}")))
        .bearer_auth(&token)
        .json(&json!({
            "rules": [
                {
                    "kind": "required_if",
                    "field": "forward_to",
                    "when_field": "mailbox_handling",
                    "equals": "forward"
                },
                { "kind": "invented_by_a_newer_server", "field": "forward_to" }
            ]
        }))
        .send()
        .await
        .expect("send patch with an unknown rule kind");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "update must refuse the rule kind create refuses"
    );
    let error: serde_json::Value = resp.json().await.expect("update error JSON");
    assert_eq!(
        field_codes(&error),
        vec![("rules[1].kind".to_string(), "unknown_rule_kind".to_string())],
        "the refusal names the offending rule's own index, got {:?}",
        field_codes(&error)
    );

    // The stored definition is untouched: a refused write leaves the rule set
    // that was already enforceable.
    let after: serde_json::Value = app
        .client
        .get(app.url(&format!("/api/v1/forms/{form_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("read the definition back")
        .json()
        .await
        .expect("definition JSON");
    assert_eq!(after["rules"].as_array().map(|r| r.len()), Some(1));
}

/// PMS-898: the same tolerant-read / strict-write split for `field_type`, and
/// the reason it is sharper than the rule case. The public request form is
/// rendered for someone with no account, off an emailed link, so a client that
/// predates a field type has to render it as a text input rather than fail to
/// deserialise the definition and show a blank page.
///
/// On this server the write refusal is what makes that safe to keep: the
/// definition can never store a type this build cannot validate, so the
/// tolerant read is only ever exercised by a client talking to a NEWER server.
/// `migrations/100_form_definitions.sql` also has a CHECK constraint on the
/// column, which is the backstop, not the contract - it would answer a 500.
/// The service check is what turns an unknown type into a 422 that names the
/// field.
#[sqlx::test]
async fn a_field_type_the_server_cannot_name_is_refused(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let unknown_field = json!({
        "name": "signature",
        "label": "Signature",
        "field_type": "signature",
        "is_required": false,
        "sort_order": 6
    });

    // Create: refused, naming the field rather than the payload.
    let mut body = departure_form();
    body["slug"] = json!("departure-unknown-field-type");
    body["fields"]
        .as_array_mut()
        .expect("the fixture carries a field array")
        .push(unknown_field.clone());
    let resp = app
        .client
        .post(app.url("/api/v1/forms"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .expect("send create with an unknown field type");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "a type this build cannot validate must not be storable"
    );
    let error: serde_json::Value = resp.json().await.expect("create error JSON");
    assert!(
        field_codes(&error)
            .iter()
            .any(|(f, c)| f.starts_with("fields[") && c == "unknown_field_type"),
        "the refusal names which field, got {:?}",
        field_codes(&error)
    );

    // Update: the field set is replaced wholesale, so the same value arrives on
    // the other write path and must be refused there too.
    let form = create_form(&app, &token, departure_form()).await;
    let form_id = form["id"].as_str().expect("form id").to_string();
    let resp = app
        .client
        .patch(app.url(&format!("/api/v1/forms/{form_id}")))
        .bearer_auth(&token)
        .json(&json!({ "fields": [unknown_field] }))
        .send()
        .await
        .expect("send patch with an unknown field type");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "update must refuse the field type create refuses"
    );
    let error: serde_json::Value = resp.json().await.expect("update error JSON");
    assert!(
        field_codes(&error)
            .iter()
            .any(|(f, c)| f.starts_with("fields[") && c == "unknown_field_type"),
        "the update refusal names which field, got {:?}",
        field_codes(&error)
    );

    // The known types on the same path still write, so the refusal is about the
    // unnamed type and not about replacing a field set.
    let resp = app
        .client
        .patch(app.url(&format!("/api/v1/forms/{form_id}")))
        .bearer_auth(&token)
        .json(&json!({
            "fields": [
                {
                    "name": "employee_name",
                    "label": "Employee name",
                    "field_type": "text",
                    "is_required": true,
                    "sort_order": 1
                }
            ],
            "rules": []
        }))
        .send()
        .await
        .expect("send patch with a known field type");
    assert!(
        resp.status().is_success(),
        "a recognised type must still be accepted, got {}",
        resp.status()
    );
}
