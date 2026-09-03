//! PMS-867: a value is accepted or refused identically whether it arrives on a
//! create or on an update.
//!
//! Seven text fields carried a `#[validate(length(...))]` on their
//! `Create*Request` and nothing on the `Update*Request`, and
//! `UpdateInvoiceRequest::lines` accepted the empty set that
//! `CreateInvoiceRequest::lines` refuses. Every struct already derived
//! `Validate` and every handler already called `body.validate()?`, so the
//! asymmetry was entirely in the attribute and invisible from the update struct
//! alone.
//!
//! Two failures, and they are not the same defect:
//!
//!   * Over the max, the `VARCHAR(n)` column rejects the value itself, so the
//!     update path answered 500 with a raw Postgres `22001 value too long for
//!     type character varying(n)` where create answers a 422 naming the field.
//!     Asserting 422 here is therefore asserting that the check runs BEFORE the
//!     database, which is the whole point.
//!   * Under the min, nothing rejected anything: `""` satisfies a `NOT NULL`
//!     column, so an update could leave a nameless contract, a titleless
//!     article or an unnamed asset. Nothing 500s and nothing warns, which is
//!     why no existing test caught it.
//!
//! One file rather than a test per module because `tests/contracts.rs` drives
//! `ContractsService` directly with no HTTP layer, and `validate()` is called by
//! the route handler. The invariant is also one invariant; reading it in one
//! place is how you can see that all six paths answer alike.
//!
//! `scripts/check-create-update-validate-parity.nu` is the mechanical half: it
//! fails a PR whose new pair reintroduces the gap. These tests are the
//! behavioural half, proving the attribute produces a 422 rather than trusting
//! that it does.

mod common;

use common::{boot, login, seed_admin, seed_company, TestApp};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

/// 256 characters, one past every `max = 255` in this file.
fn over_255() -> String {
    "x".repeat(256)
}

/// Assert a write was refused with a 422 that names `field`.
///
/// The status assertion is the load-bearing one: before PMS-867 these update
/// paths answered 500 from the column's own `22001`, so a test that only
/// checked "not 2xx" would have passed against the defect.
async fn assert_422_naming(resp: reqwest::Response, field: &str, what: &str) {
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.expect("error JSON");
    assert_eq!(
        status,
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "{what} must be refused with a 422, not a database error, got {status} {body}"
    );
    let named = body["error"]["errors"]
        .as_array()
        .map(|errors| errors.iter().any(|e| e["field"].as_str() == Some(field)))
        .unwrap_or(false);
    assert!(named, "{what} must name `{field}`, got {body}");
}

async fn post(
    app: &TestApp,
    token: &str,
    path: &str,
    body: serde_json::Value,
) -> reqwest::Response {
    app.client
        .post(app.url(path))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .unwrap_or_else(|e| panic!("send POST {path}: {e}"))
}

async fn put(app: &TestApp, token: &str, path: &str, body: serde_json::Value) -> reqwest::Response {
    app.client
        .put(app.url(path))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .unwrap_or_else(|e| panic!("send PUT {path}: {e}"))
}

/// Create through `path` and return the new row's id, failing loudly rather
/// than unwrapping a 4xx body into a confusing `None`.
async fn create_id(app: &TestApp, token: &str, path: &str, body: serde_json::Value) -> String {
    let resp = post(app, token, path, body).await;
    let status = resp.status();
    let created: serde_json::Value = resp.json().await.expect("create JSON");
    assert!(
        status.is_success(),
        "fixture create on {path} must 2xx, got {status} {created}"
    );
    created["id"]
        .as_str()
        .unwrap_or_else(|| panic!("created row from {path} has no id: {created}"))
        .to_string()
}

#[sqlx::test]
async fn a_contract_name_is_bounded_on_create_and_on_update(pool: PgPool) {
    let (_admin_id, email, password) = seed_admin(&pool).await;
    let company_id = seed_company(&pool).await;
    let app = boot(pool).await;
    let token = login(&app, &email, &password).await;

    let valid = json!({
        "name": "Managed Services",
        "company_id": company_id,
        "contract_type": "managed_services",
        "start_date": "2026-01-01",
    });

    for (label, name) in [("over the max", over_255()), ("empty", String::new())] {
        let mut body = valid.clone();
        body["name"] = json!(name);
        assert_422_naming(
            post(&app, &token, "/api/v1/contracts", body).await,
            "name",
            &format!("creating a contract with a name {label}"),
        )
        .await;
    }

    let id = create_id(&app, &token, "/api/v1/contracts", valid).await;

    for (label, name) in [("over the max", over_255()), ("empty", String::new())] {
        assert_422_naming(
            put(
                &app,
                &token,
                &format!("/api/v1/contracts/{id}"),
                json!({ "name": name }),
            )
            .await,
            "name",
            &format!("updating a contract to a name {label}"),
        )
        .await;
    }

    // A name inside the bounds still writes, so the refusal is about the value
    // and not about the update path.
    let resp = put(
        &app,
        &token,
        &format!("/api/v1/contracts/{id}"),
        json!({ "name": "Managed Services (renewed)" }),
    )
    .await;
    assert!(
        resp.status().is_success(),
        "a name inside the bounds must still update, got {}",
        resp.status()
    );
}

#[sqlx::test]
async fn a_kb_article_is_bounded_on_create_and_on_update(pool: PgPool) {
    let (_admin_id, email, password) = seed_admin(&pool).await;
    let app = boot(pool).await;
    let token = login(&app, &email, &password).await;

    let valid = json!({
        "title": "Resetting a password",
        "slug": "resetting-a-password",
        "content": "Open the console.",
    });

    // `title` and `slug` are VARCHAR(255); `content` is TEXT with a `min` only,
    // so an over-length body is legitimate and only the empty case applies.
    for field in ["title", "slug"] {
        let mut body = valid.clone();
        body[field] = json!(over_255());
        assert_422_naming(
            post(&app, &token, "/api/v1/kb/articles", body).await,
            field,
            &format!("creating an article with a `{field}` over the max"),
        )
        .await;
    }
    for field in ["title", "slug", "content"] {
        let mut body = valid.clone();
        body[field] = json!("");
        assert_422_naming(
            post(&app, &token, "/api/v1/kb/articles", body).await,
            field,
            &format!("creating an article with an empty `{field}`"),
        )
        .await;
    }

    let id = create_id(&app, &token, "/api/v1/kb/articles", valid).await;
    let path = format!("/api/v1/kb/articles/{id}");

    for field in ["title", "slug"] {
        assert_422_naming(
            put(&app, &token, &path, json!({ field: over_255() })).await,
            field,
            &format!("updating an article's `{field}` past the max"),
        )
        .await;
    }
    for field in ["title", "slug", "content"] {
        assert_422_naming(
            put(&app, &token, &path, json!({ field: "" })).await,
            field,
            &format!("updating an article's `{field}` to empty"),
        )
        .await;
    }

    let resp = put(&app, &token, &path, json!({ "title": "Resetting a login" })).await;
    assert!(
        resp.status().is_success(),
        "a title inside the bounds must still update, got {}",
        resp.status()
    );
}

#[sqlx::test]
async fn an_asset_name_is_bounded_on_create_and_on_update(pool: PgPool) {
    let (_admin_id, email, password) = seed_admin(&pool).await;
    let company_id = seed_company(&pool).await;
    let app = boot(pool).await;
    let token = login(&app, &email, &password).await;

    let type_id = create_id(
        &app,
        &token,
        "/api/v1/asset-types",
        json!({ "name": "Laptop" }),
    )
    .await;

    let valid = json!({
        "name": "Reception laptop",
        "asset_type_id": type_id,
        "company_id": company_id,
    });

    for (label, name) in [("over the max", over_255()), ("empty", String::new())] {
        let mut body = valid.clone();
        body["name"] = json!(name);
        assert_422_naming(
            post(&app, &token, "/api/v1/assets", body).await,
            "name",
            &format!("creating an asset with a name {label}"),
        )
        .await;
    }

    let id = create_id(&app, &token, "/api/v1/assets", valid).await;
    let path = format!("/api/v1/assets/{id}");

    for (label, name) in [("over the max", over_255()), ("empty", String::new())] {
        assert_422_naming(
            put(&app, &token, &path, json!({ "name": name })).await,
            "name",
            &format!("updating an asset to a name {label}"),
        )
        .await;
    }

    let resp = put(
        &app,
        &token,
        &path,
        json!({ "name": "Reception laptop v2" }),
    )
    .await;
    assert!(
        resp.status().is_success(),
        "a name inside the bounds must still update, got {}",
        resp.status()
    );
}

#[sqlx::test]
async fn an_appointment_title_is_bounded_on_create_and_on_update(pool: PgPool) {
    let (admin_id, email, password) = seed_admin(&pool).await;
    let app = boot(pool).await;
    let token = login(&app, &email, &password).await;

    let valid = json!({
        "title": "Onsite visit",
        "assigned_to_id": admin_id,
        "start_time": "2026-03-02T09:00:00Z",
        "end_time": "2026-03-02T10:00:00Z",
    });

    for (label, title) in [("over the max", over_255()), ("empty", String::new())] {
        let mut body = valid.clone();
        body["title"] = json!(title);
        assert_422_naming(
            post(&app, &token, "/api/v1/appointments", body).await,
            "title",
            &format!("booking an appointment with a title {label}"),
        )
        .await;
    }

    let id = create_id(&app, &token, "/api/v1/appointments", valid).await;
    let path = format!("/api/v1/appointments/{id}");

    for (label, title) in [("over the max", over_255()), ("empty", String::new())] {
        assert_422_naming(
            put(&app, &token, &path, json!({ "title": title })).await,
            "title",
            &format!("updating an appointment to a title {label}"),
        )
        .await;
    }

    let resp = put(
        &app,
        &token,
        &path,
        json!({ "title": "Onsite visit (moved)" }),
    )
    .await;
    assert!(
        resp.status().is_success(),
        "a title inside the bounds must still update, got {}",
        resp.status()
    );
}

#[sqlx::test]
async fn a_template_default_title_is_bounded_on_create_and_on_update(pool: PgPool) {
    let (_admin_id, email, password) = seed_admin(&pool).await;
    let app = boot(pool).await;
    let token = login(&app, &email, &password).await;

    let valid = json!({
        "name": "On-site visit",
        "kind": "dispatch",
        "duration_minutes": 120,
        "default_title": "Site visit",
    });

    // `default_title` carries a `max` and no `min`, so the empty string is a
    // legitimate value on both paths: it clears the default.
    let mut body = valid.clone();
    body["default_title"] = json!(over_255());
    assert_422_naming(
        post(&app, &token, "/api/v1/scheduling-templates", body).await,
        "default_title",
        "creating a template with a default title over the max",
    )
    .await;

    let id = create_id(&app, &token, "/api/v1/scheduling-templates", valid).await;
    let path = format!("/api/v1/scheduling-templates/{id}");

    assert_422_naming(
        put(&app, &token, &path, json!({ "default_title": over_255() })).await,
        "default_title",
        "updating a template to a default title over the max",
    )
    .await;

    let resp = put(&app, &token, &path, json!({ "default_title": "" })).await;
    assert!(
        resp.status().is_success(),
        "an empty default title clears it rather than being refused, got {}",
        resp.status()
    );
}

#[sqlx::test]
async fn an_invoice_needs_a_line_on_create_and_on_update(pool: PgPool) {
    let (_admin_id, email, password) = seed_admin(&pool).await;
    let company_id: Uuid = seed_company(&pool).await;
    let app = boot(pool).await;
    let token = login(&app, &email, &password).await;

    let line = json!({
        "line_type": "service",
        "description": "Work",
        "quantity": "1",
        "unit_price": "100",
    });
    let valid = json!({
        "company_id": company_id,
        "invoice_date": "2026-06-15",
        "due_date": "2026-07-15",
        "lines": [line],
    });

    let mut body = valid.clone();
    body["lines"] = json!([]);
    assert_422_naming(
        post(&app, &token, "/api/v1/invoices", body).await,
        "lines",
        "creating an invoice with no lines",
    )
    .await;

    let id = create_id(&app, &token, "/api/v1/invoices", valid).await;
    let path = format!("/api/v1/invoices/{id}");

    // PMS-867: this replaced every line with none and left a zero-total invoice
    // that create would have refused. The same request can carry `status`, so it
    // could be sent in that state.
    assert_422_naming(
        put(&app, &token, &path, json!({ "lines": [] })).await,
        "lines",
        "replacing an invoice's lines with none",
    )
    .await;

    // Omitting the key is how a caller leaves the existing lines alone, so a
    // header-only update is untouched by the new bound.
    let resp = put(&app, &token, &path, json!({ "po_number": "PO-1" })).await;
    assert!(
        resp.status().is_success(),
        "a header-only update must not need `lines`, got {}",
        resp.status()
    );

    // And a non-empty replacement still replaces.
    let resp = put(&app, &token, &path, json!({ "lines": [line] })).await;
    assert!(
        resp.status().is_success(),
        "a non-empty line set must still replace, got {}",
        resp.status()
    );
}
