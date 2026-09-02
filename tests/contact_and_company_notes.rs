//! PMS-952: the note on a company and on a contact can be read back.
//!
//! The field has been on the write path since `migrations/004_contacts.sql`
//! created the two columns, and on no response until now, so a caller could
//! store a value the API would never return. These tests pin the round trip
//! and, just as importantly, pin the rule a client has to write against to
//! clear one: the service builds a partial UPDATE gated on
//! `request.notes.is_some()`, so a null does not mean "erase it".

mod common;

use sqlx::PgPool;

/// Create a company through the API and return its id.
async fn create_company(app: &common::TestApp, token: &str, body: serde_json::Value) -> String {
    let resp = app
        .client
        .post(app.url("/api/v1/contacts/companies"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("send create company");
    assert!(
        resp.status().is_success(),
        "create company should 2xx, got {}",
        resp.status()
    );
    let json: serde_json::Value = resp.json().await.expect("create company JSON");
    json["id"].as_str().expect("company id").to_string()
}

/// Create a contact through the API and return its id.
async fn create_contact(app: &common::TestApp, token: &str, body: serde_json::Value) -> String {
    let resp = app
        .client
        .post(app.url("/api/v1/contacts/contacts"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("send create contact");
    assert!(
        resp.status().is_success(),
        "create contact should 2xx, got {}",
        resp.status()
    );
    let json: serde_json::Value = resp.json().await.expect("create contact JSON");
    json["id"].as_str().expect("contact id").to_string()
}

async fn get_json(app: &common::TestApp, token: &str, path: &str) -> serde_json::Value {
    let resp = app
        .client
        .get(app.url(path))
        .bearer_auth(token)
        .send()
        .await
        .expect("send GET");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "GET {path} should 200"
    );
    resp.json().await.expect("GET JSON")
}

async fn put_notes(
    app: &common::TestApp,
    token: &str,
    path: &str,
    notes: serde_json::Value,
) -> serde_json::Value {
    let resp = app
        .client
        .put(app.url(path))
        .bearer_auth(token)
        .json(&serde_json::json!({ "notes": notes }))
        .send()
        .await
        .expect("send PUT");
    assert!(
        resp.status().is_success(),
        "PUT {path} should 2xx, got {}",
        resp.status()
    );
    resp.json().await.expect("PUT JSON")
}

/// The whole point: a note written on create comes back on an independent
/// read, and so does one written by an update. The list endpoint serves the
/// same DTO, so it carries the field too.
#[sqlx::test]
async fn a_company_note_can_be_read_back(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let id = create_company(
        &app,
        &token,
        serde_json::json!({ "name": "Acme", "notes": "Renews in March." }),
    )
    .await;

    let got = get_json(&app, &token, &format!("/api/v1/contacts/companies/{id}")).await;
    assert_eq!(got["notes"].as_str(), Some("Renews in March."));

    let put = put_notes(
        &app,
        &token,
        &format!("/api/v1/contacts/companies/{id}"),
        serde_json::json!("Renews in April."),
    )
    .await;
    assert_eq!(
        put["notes"].as_str(),
        Some("Renews in April."),
        "the update response carries the new value"
    );

    let got = get_json(&app, &token, &format!("/api/v1/contacts/companies/{id}")).await;
    assert_eq!(got["notes"].as_str(), Some("Renews in April."));

    let list = get_json(&app, &token, "/api/v1/contacts/companies").await;
    let row = list["data"]
        .as_array()
        .expect("companies array")
        .iter()
        .find(|c| c["id"].as_str() == Some(id.as_str()))
        .expect("the company is in the list");
    assert_eq!(row["notes"].as_str(), Some("Renews in April."));
}

#[sqlx::test]
async fn a_contact_note_can_be_read_back(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let company_id = create_company(&app, &token, serde_json::json!({ "name": "Acme" })).await;
    let id = create_contact(
        &app,
        &token,
        serde_json::json!({
            "company_id": company_id,
            "first_name": "Dana",
            "last_name": "Reed",
            "email": "dana@acme.example",
            "notes": "Prefers email before 10am.",
        }),
    )
    .await;

    let got = get_json(&app, &token, &format!("/api/v1/contacts/contacts/{id}")).await;
    assert_eq!(got["notes"].as_str(), Some("Prefers email before 10am."));

    put_notes(
        &app,
        &token,
        &format!("/api/v1/contacts/contacts/{id}"),
        serde_json::json!("Prefers a phone call."),
    )
    .await;

    let got = get_json(&app, &token, &format!("/api/v1/contacts/contacts/{id}")).await;
    assert_eq!(got["notes"].as_str(), Some("Prefers a phone call."));
}

/// A record nobody has written a note on returns the key as null. It must not
/// be omitted: a client that reads `json["notes"]` to seed an edit form needs
/// the same shape whether or not a note exists.
#[sqlx::test]
async fn a_record_with_no_note_returns_null(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let company_id = create_company(&app, &token, serde_json::json!({ "name": "Acme" })).await;
    let contact_id = create_contact(
        &app,
        &token,
        serde_json::json!({
            "company_id": company_id,
            "first_name": "Dana",
            "last_name": "Reed",
        }),
    )
    .await;

    for path in [
        format!("/api/v1/contacts/companies/{company_id}"),
        format!("/api/v1/contacts/contacts/{contact_id}"),
    ] {
        let got = get_json(&app, &token, &path).await;
        assert!(
            got.get("notes").is_some(),
            "{path} must carry the key, got {got}"
        );
        assert!(got["notes"].is_null(), "{path} must report null, got {got}");
    }
}

/// The rule a client has to write against, and the reason this test exists
/// rather than a comment: `update_company` / `update_contact` add
/// `notes = $n` to the UPDATE only when `request.notes.is_some()`, so a null
/// means "leave it alone" and NOT "erase it". A form that maps an empty field
/// to null therefore reports a save that stored nothing. An empty string is
/// what actually clears the note.
#[sqlx::test]
async fn clearing_a_note_takes_an_empty_string_and_a_null_leaves_it(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let company_id = create_company(
        &app,
        &token,
        serde_json::json!({ "name": "Acme", "notes": "Keep me." }),
    )
    .await;
    let contact_id = create_contact(
        &app,
        &token,
        serde_json::json!({
            "company_id": company_id,
            "first_name": "Dana",
            "last_name": "Reed",
            "notes": "Keep me.",
        }),
    )
    .await;

    for path in [
        format!("/api/v1/contacts/companies/{company_id}"),
        format!("/api/v1/contacts/contacts/{contact_id}"),
    ] {
        // Null is not an erase.
        put_notes(&app, &token, &path, serde_json::Value::Null).await;
        let got = get_json(&app, &token, &path).await;
        assert_eq!(
            got["notes"].as_str(),
            Some("Keep me."),
            "a null must leave the stored note alone on {path}, got {got}"
        );

        // An empty string is.
        put_notes(&app, &token, &path, serde_json::json!("")).await;
        let got = get_json(&app, &token, &path).await;
        assert_eq!(
            got["notes"].as_str(),
            Some(""),
            "an empty string must clear the note on {path}, got {got}"
        );
    }
}
