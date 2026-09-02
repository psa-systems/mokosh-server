//! PMS-924: the API must not accept or store characters that render as
//! nothing.
//!
//! `Acme\u{200B}` and `Acme` are two different rows that look identical in
//! every list, search result and picker, and a trailing U+200B on an otherwise
//! valid phone number made the SPA reject it with no visible cause
//! (MAPPS-581 / MAPPS-582). `sanitize_json_body` strips them from every JSON
//! request body before deserialization; these are the end-to-end pins.
//!
//! Pins:
//!   - A JSON write stores the sanitized value, through nested objects.
//!   - The reported phone number is accepted and stored normalized.
//!   - A password is NOT sanitized: the stored hash verifies against the exact
//!     bytes the client sent, and login with those bytes succeeds.
//!   - A non-JSON (multipart) body reaches the handler byte-identical.

mod common;

use reqwest::multipart::{Form, Part};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

/// The zero width space that started this: invisible, and `str::trim` does not
/// remove it because `char::is_whitespace('\u{200B}')` is false.
const ZWSP: &str = "\u{200B}";
/// A no-break space: reaches a validator looking exactly like a space.
const NBSP: &str = "\u{00A0}";

#[sqlx::test]
async fn a_json_write_stores_the_value_with_invisible_characters_removed(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let resp = app
        .client
        .post(app.url("/api/v1/contacts/companies"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            // Top level, and nested one object down, so the recursive walk is
            // exercised rather than just the root map.
            "name": format!("Acme{ZWSP}"),
            "notes": format!("  needs{NBSP}review\u{FEFF}  "),
            "address": {
                "city": format!("Raleigh{ZWSP}"),
                "state": "NC ",
            },
        }))
        .send()
        .await
        .expect("send create company");
    assert!(
        resp.status().is_success(),
        "create company should 2xx, got {}",
        resp.status()
    );
    let created: Value = resp.json().await.expect("create response JSON");
    let company_id = Uuid::parse_str(created["id"].as_str().expect("created id")).unwrap();

    // The response the SPA renders is clean...
    assert_eq!(created["name"], "Acme");

    // ...and so is the row, which is the guarantee this issue is about.
    let (name, notes, city): (String, Option<String>, Option<String>) =
        sqlx::query_as("SELECT name, notes, city FROM companies WHERE id = $1")
            .bind(company_id)
            .fetch_one(&pool)
            .await
            .expect("read the stored company");
    assert_eq!(name, "Acme", "stored name must not carry a U+200B");
    assert_eq!(
        notes.as_deref(),
        Some("needs review"),
        "NBSP folds to a space and the value is trimmed",
    );
    assert_eq!(
        city.as_deref(),
        Some("Raleigh"),
        "nested object values are sanitized too",
    );
}

#[sqlx::test]
async fn the_reported_phone_number_is_accepted_and_stored_normalized(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    // MAPPS-581 verbatim: this value was rejected with "must be a valid phone
    // number" and deleting the invisible trailing character fixed it.
    let resp = app
        .client
        .post(app.url("/api/v1/contacts/companies"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "name": "Phone Test Co",
            "phone": format!("919-397-4144{ZWSP}"),
        }))
        .send()
        .await
        .expect("send create company");
    assert!(
        resp.status().is_success(),
        "an invisible-suffixed phone must be accepted, got {}",
        resp.status()
    );
    let created: Value = resp.json().await.expect("create response JSON");
    let company_id = Uuid::parse_str(created["id"].as_str().expect("created id")).unwrap();

    let phone: Option<String> = sqlx::query_scalar("SELECT phone FROM companies WHERE id = $1")
        .bind(company_id)
        .fetch_one(&pool)
        .await
        .expect("read the stored phone");
    assert_eq!(
        phone.as_deref(),
        Some("9193974144"),
        "the stored phone is the normalized number, not the invisible-carrying original",
    );
}

#[sqlx::test]
async fn a_password_reaches_the_hasher_byte_identical(pool: PgPool) {
    let (admin_id, email, old_password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &old_password).await;

    // A password may legitimately contain any character. Sanitizing one turns a
    // correct credential into a failed login with nothing to diagnose it by, so
    // `SECRET_FIELD_NAMES` exempts these fields.
    let new_password = format!("Str{ZWSP}ong{NBSP}Pass1!");
    let resp = app
        .client
        .put(app.url("/api/v1/auth/me/password"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "current_password": old_password,
            "new_password": new_password,
            "confirm_password": new_password,
        }))
        .send()
        .await
        .expect("send change password");
    assert!(
        resp.status().is_success(),
        "change password should 2xx, got {}",
        resp.status()
    );

    // The stored hash verifies against the exact bytes the client sent.
    let hash: String = sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1")
        .bind(admin_id)
        .fetch_one(&pool)
        .await
        .expect("read the stored hash");
    assert!(
        mokosh_server::utils::crypto::verify_password(&new_password, &hash)
            .expect("verify original bytes"),
        "the stored hash must verify against the password as sent",
    );
    // ...and not against what the sanitizer would have made of it.
    let sanitized = mokosh_server::utils::text::sanitize_invisible(&new_password).into_owned();
    assert_ne!(
        sanitized, new_password,
        "the test value must be sanitizable"
    );
    assert!(
        !mokosh_server::utils::crypto::verify_password(&sanitized, &hash)
            .expect("verify sanitized bytes"),
        "the sanitized form must NOT be what was stored",
    );

    // End to end: the client can log back in with the password it chose.
    let login = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .json(&serde_json::json!({ "email": email, "password": new_password }))
        .send()
        .await
        .expect("send login");
    assert!(
        login.status().is_success(),
        "login with the original password bytes should 2xx, got {}",
        login.status()
    );
}

#[sqlx::test]
async fn a_multipart_body_reaches_the_handler_byte_identical(pool: PgPool) {
    // Own directory + generous cap: this suite only cares about the bytes.
    common::storage_root();
    std::env::set_var("ATTACHMENT_MAX_BYTES", "65536");

    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let (ticket_id, note_id) = common::seed_ticket_and_note(&pool, admin_id, company_id).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    // Every class the sanitizer would rewrite, inside a non-JSON body. A
    // multipart upload is opaque bytes: rewriting one would corrupt the file.
    let payload = format!("zwsp{ZWSP} nbsp{NBSP} bom\u{FEFF} trailing   ").into_bytes();
    let form = Form::new().part(
        "file",
        Part::bytes(payload.clone())
            .file_name("invisible.txt")
            .mime_str("text/plain")
            .expect("mime"),
    );
    let resp = app
        .client
        .post(app.url(&format!(
            "/api/v1/tickets/{ticket_id}/notes/{note_id}/attachments"
        )))
        .bearer_auth(&token)
        .multipart(form)
        .send()
        .await
        .expect("upload");
    assert!(
        resp.status().is_success(),
        "upload should 2xx, got {}",
        resp.status()
    );
    let row: Value = resp.json().await.expect("upload json");
    assert_eq!(
        row["file_size"].as_u64(),
        Some(payload.len() as u64),
        "the stored size must match the bytes sent",
    );
    let attachment_id = row["id"].as_str().expect("attachment id");

    let downloaded = app
        .client
        .get(app.url(&format!(
            "/api/v1/tickets/{ticket_id}/notes/{note_id}/attachments/{attachment_id}"
        )))
        .bearer_auth(&token)
        .send()
        .await
        .expect("download");
    assert!(downloaded.status().is_success());
    assert_eq!(
        downloaded.bytes().await.expect("download bytes").as_ref(),
        payload.as_slice(),
        "a multipart body must round-trip byte-identical",
    );
}
