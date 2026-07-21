//! PMS-672: integration tests for the quotes module.
//!
//! Pins the guarantees the ticket calls out:
//!   - Full CRUD round-trips, with a per-tenant quote number allocated
//!     on create.
//!   - Totals are ALWAYS computed server-side from `quote_lines`; a
//!     caller-supplied total is never persisted.
//!   - Every line mutation recomputes the header `subtotal` / `total`.
//!   - A quote freezes once issued: edits to a `sent` quote are 409.
//!   - Content is frozen from `submitted` onwards, while the internal
//!     workflow can still advance the status.
//!   - A staff user cannot forge the client's decision.
//!   - Quotes are invisible across tenants on every route.
//!   - The pre-existing `/quotes/{id}/approvals` surface still works
//!     against a quote created through the new API.

mod common;

use reqwest::StatusCode;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

/// Create a quote through the API and return its JSON body.
async fn create_quote(app: &common::TestApp, token: &str, body: Value) -> Value {
    let resp = app
        .client
        .post(app.url("/api/v1/quotes"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("send create quote");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "create quote should 200, got {}",
        resp.status()
    );
    resp.json().await.expect("create quote body")
}

fn line(description: &str, qty: &str, price: &str) -> Value {
    serde_json::json!({
        "line_type": "service",
        "description": description,
        "quantity": qty,
        "unit_price": price,
    })
}

/// Log in as a user outside the default tenant.
///
/// PMS-138 binds the login lookup to `(tenant_id, email)` and falls back
/// to the default tenant when the caller supplies no hint, so
/// `common::login` can only ever reach the default tenant's users. The
/// cross-tenant test needs the second tenant's admin, so it passes the
/// hint explicitly.
async fn login_in_tenant(
    app: &common::TestApp,
    tenant_id: Uuid,
    email: &str,
    password: &str,
) -> String {
    let resp = app
        .client
        .post(app.url("/api/v1/auth/login"))
        .json(&serde_json::json!({
            "email": email,
            "password": password,
            "tenant_id": tenant_id,
        }))
        .send()
        .await
        .expect("send tenant-scoped login");
    assert!(
        resp.status().is_success(),
        "tenant-scoped login expected 2xx, got {}",
        resp.status()
    );
    let body: Value = resp.json().await.expect("login body");
    body["access_token"]
        .as_str()
        .expect("access_token")
        .to_string()
}

/// Force a status the staff API deliberately refuses to set, so the
/// frozen-state tests can reach `sent` without the PMS-673 send route.
async fn force_status(pool: &PgPool, quote_id: Uuid, status: &str) {
    sqlx::query("UPDATE quotes SET status = $2 WHERE id = $1")
        .bind(quote_id)
        .bind(status)
        .execute(pool)
        .await
        .expect("force quote status");
}

#[sqlx::test]
async fn quote_crud_round_trip(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company = common::seed_company(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    // Create with two lines: 2 * 500 + 1 * 250 = 1250 subtotal.
    let quote = create_quote(
        &app,
        &token,
        serde_json::json!({
            "company_id": company,
            "title": "Provide LLM access to Employees",
            "description": "Set up Private Network, set up a web service with SSL, configure users + LLM software.",
            "lines": [line("Network build", "2", "500"), line("LLM configuration", "1", "250")],
        }),
    )
    .await;

    let quote_id = Uuid::parse_str(quote["id"].as_str().unwrap()).unwrap();
    assert_eq!(quote["status"], "draft");
    assert_eq!(quote["subtotal"], "1250.00");
    assert_eq!(quote["total"], "1250.00");
    assert_eq!(
        quote["quote_number"].as_str().unwrap(),
        "QUO-000001",
        "the first quote in a tenant seeds the sequence"
    );
    assert_eq!(
        quote["company_name"], "Acme Co",
        "responses resolve the company name so the client never shows a UUID"
    );
    assert_eq!(quote["lines"].as_array().unwrap().len(), 2);

    // A second quote takes the next number from the same sequence.
    let second = create_quote(
        &app,
        &token,
        serde_json::json!({ "company_id": company, "title": "Second" }),
    )
    .await;
    assert_eq!(second["quote_number"], "QUO-000002");
    assert_eq!(
        second["total"], "0",
        "a quote with no lines totals zero, not null"
    );

    // Read back.
    let got: Value = app
        .client
        .get(app.url(&format!("/api/v1/quotes/{quote_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get quote")
        .json()
        .await
        .expect("get body");
    assert_eq!(got["id"], quote["id"]);
    assert_eq!(got["lines"].as_array().unwrap().len(), 2);

    // Update the header; tax flows into the recomputed total.
    let updated: Value = app
        .client
        .put(app.url(&format!("/api/v1/quotes/{quote_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "title": "Renamed", "tax_amount": "50" }))
        .send()
        .await
        .expect("update quote")
        .json()
        .await
        .expect("update body");
    assert_eq!(updated["title"], "Renamed");
    assert_eq!(updated["subtotal"], "1250.00");
    assert_eq!(
        updated["total"], "1300.00",
        "total is subtotal + tax, recomputed even though the lines did not change"
    );

    // List, filtered by status.
    let listed: Value = app
        .client
        .get(app.url("/api/v1/quotes?status=draft"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list quotes")
        .json()
        .await
        .expect("list body");
    assert_eq!(listed["meta"]["total"], 2);

    // Free-text search hits the title.
    let searched: Value = app
        .client
        .get(app.url("/api/v1/quotes?q=Renamed"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("search quotes")
        .json()
        .await
        .expect("search body");
    assert_eq!(searched["meta"]["total"], 1);
    assert_eq!(searched["data"][0]["id"], quote["id"]);

    // DELETE cancels rather than removing the row.
    let cancelled = app
        .client
        .delete(app.url(&format!("/api/v1/quotes/{quote_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("cancel quote");
    assert!(cancelled.status().is_success());
    let after: Value = app
        .client
        .get(app.url(&format!("/api/v1/quotes/{quote_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get cancelled")
        .json()
        .await
        .expect("cancelled body");
    assert_eq!(
        after["status"], "cancelled",
        "DELETE is a soft cancel; the commercial record survives"
    );
}

#[sqlx::test]
async fn line_mutations_recompute_totals(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company = common::seed_company(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let quote = create_quote(
        &app,
        &token,
        serde_json::json!({
            "company_id": company,
            "title": "Line maths",
            "lines": [line("Base", "1", "100")],
        }),
    )
    .await;
    let quote_id = Uuid::parse_str(quote["id"].as_str().unwrap()).unwrap();
    assert_eq!(quote["total"], "100.00");

    // Add a line -> total moves.
    let added: Value = app
        .client
        .post(app.url(&format!("/api/v1/quotes/{quote_id}/lines")))
        .bearer_auth(&token)
        .json(&line("Extra", "3", "50"))
        .send()
        .await
        .expect("add line")
        .json()
        .await
        .expect("add line body");
    assert_eq!(added["subtotal"], "250.00");
    assert_eq!(added["total"], "250.00");

    let line_id = added["lines"]
        .as_array()
        .unwrap()
        .iter()
        .find(|l| l["description"] == "Extra")
        .map(|l| Uuid::parse_str(l["id"].as_str().unwrap()).unwrap())
        .expect("added line present");

    // Update that line -> total moves again.
    let edited: Value = app
        .client
        .put(app.url(&format!("/api/v1/quotes/{quote_id}/lines/{line_id}")))
        .bearer_auth(&token)
        .json(&line("Extra", "1", "50"))
        .send()
        .await
        .expect("update line")
        .json()
        .await
        .expect("update line body");
    assert_eq!(edited["total"], "150.00");

    // A negative line is legitimate (a discount) and simply subtracts.
    let discounted: Value = app
        .client
        .post(app.url(&format!("/api/v1/quotes/{quote_id}/lines")))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "line_type": "discount",
            "description": "Loyalty discount",
            "quantity": "1",
            "unit_price": "-25",
        }))
        .send()
        .await
        .expect("add discount")
        .json()
        .await
        .expect("discount body");
    assert_eq!(discounted["total"], "125.00");

    // Delete the line -> total returns.
    let deleted: Value = app
        .client
        .delete(app.url(&format!("/api/v1/quotes/{quote_id}/lines/{line_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("delete line")
        .json()
        .await
        .expect("delete line body");
    assert_eq!(deleted["total"], "75.00");

    // A line belonging to another quote is not reachable through this
    // quote's path.
    let other = create_quote(
        &app,
        &token,
        serde_json::json!({ "company_id": company, "title": "Other" }),
    )
    .await;
    let other_id = other["id"].as_str().unwrap();
    let cross = app
        .client
        .delete(app.url(&format!("/api/v1/quotes/{other_id}/lines/{line_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("cross-quote line delete");
    assert_eq!(cross.status(), StatusCode::NOT_FOUND);
}

#[sqlx::test]
async fn client_supplied_total_is_never_trusted(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company = common::seed_company(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    // The caller tries to state its own totals. The DTO has no such
    // fields, so they are ignored outright and the figures come from the
    // lines. Without this a caller could show the customer one price and
    // store another.
    let quote = create_quote(
        &app,
        &token,
        serde_json::json!({
            "company_id": company,
            "title": "Total spoofing",
            "subtotal": "1",
            "total": "1",
            "lines": [line("Real work", "10", "100")],
        }),
    )
    .await;
    assert_eq!(quote["subtotal"], "1000.00");
    assert_eq!(quote["total"], "1000.00");

    // Same on update.
    let quote_id = quote["id"].as_str().unwrap();
    let updated: Value = app
        .client
        .put(app.url(&format!("/api/v1/quotes/{quote_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "total": "5", "subtotal": "5" }))
        .send()
        .await
        .expect("update with forged totals")
        .json()
        .await
        .expect("update body");
    assert_eq!(updated["total"], "1000.00");
}

#[sqlx::test]
async fn sent_quote_rejects_every_edit(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company = common::seed_company(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let quote = create_quote(
        &app,
        &token,
        serde_json::json!({
            "company_id": company,
            "title": "Issued",
            "lines": [line("Work", "1", "100")],
        }),
    )
    .await;
    let quote_id = Uuid::parse_str(quote["id"].as_str().unwrap()).unwrap();
    let line_id = quote["lines"][0]["id"].as_str().unwrap().to_string();

    // The customer has now seen this quote.
    force_status(&pool, quote_id, "sent").await;

    let put = app
        .client
        .put(app.url(&format!("/api/v1/quotes/{quote_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "title": "Sneaky rename" }))
        .send()
        .await
        .expect("edit sent quote");
    assert_eq!(
        put.status(),
        StatusCode::CONFLICT,
        "editing a sent quote must 409"
    );

    let add = app
        .client
        .post(app.url(&format!("/api/v1/quotes/{quote_id}/lines")))
        .bearer_auth(&token)
        .json(&line("Sneaky line", "1", "999"))
        .send()
        .await
        .expect("add line to sent quote");
    assert_eq!(add.status(), StatusCode::CONFLICT);

    let del_line = app
        .client
        .delete(app.url(&format!("/api/v1/quotes/{quote_id}/lines/{line_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("delete line on sent quote");
    assert_eq!(del_line.status(), StatusCode::CONFLICT);

    let cancel = app
        .client
        .delete(app.url(&format!("/api/v1/quotes/{quote_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("cancel sent quote");
    assert_eq!(cancel.status(), StatusCode::CONFLICT);
}

#[sqlx::test]
async fn content_freezes_at_submitted_but_status_still_advances(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company = common::seed_company(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let quote = create_quote(
        &app,
        &token,
        serde_json::json!({
            "company_id": company,
            "title": "For approval",
            "lines": [line("Work", "1", "100")],
        }),
    )
    .await;
    let quote_id = quote["id"].as_str().unwrap();

    // Send it for internal approval.
    let submit = app
        .client
        .put(app.url(&format!("/api/v1/quotes/{quote_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "status": "submitted" }))
        .send()
        .await
        .expect("submit");
    assert_eq!(submit.status(), StatusCode::OK);

    // The figures an approver is looking at must not move underneath them.
    let edit = app
        .client
        .put(app.url(&format!("/api/v1/quotes/{quote_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "title": "Changed after submit" }))
        .send()
        .await
        .expect("edit submitted quote");
    assert_eq!(
        edit.status(),
        StatusCode::CONFLICT,
        "content edits stop at submitted"
    );

    // But the workflow itself still advances.
    let approve = app
        .client
        .put(app.url(&format!("/api/v1/quotes/{quote_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "status": "approved" }))
        .send()
        .await
        .expect("approve");
    assert_eq!(approve.status(), StatusCode::OK);

    // Rejecting reopens the quote for editing.
    let reject = app
        .client
        .put(app.url(&format!("/api/v1/quotes/{quote_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "status": "rejected" }))
        .send()
        .await
        .expect("reject");
    assert_eq!(reject.status(), StatusCode::OK);
    let reedit = app
        .client
        .put(app.url(&format!("/api/v1/quotes/{quote_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "title": "Reworked" }))
        .send()
        .await
        .expect("edit rejected quote");
    assert_eq!(
        reedit.status(),
        StatusCode::OK,
        "a rejected quote goes back to being editable"
    );
}

#[sqlx::test]
async fn staff_cannot_forge_the_client_decision(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company = common::seed_company(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let quote = create_quote(
        &app,
        &token,
        serde_json::json!({ "company_id": company, "title": "Not yours to accept" }),
    )
    .await;
    let quote_id = quote["id"].as_str().unwrap();

    // Acceptance belongs to the client (PMS-673 portal), `sent` to the
    // send route, `converted` to the PMS-674 conversion. None of them may
    // be reached with a plain header update.
    for forged in ["accepted", "declined", "sent", "converted", "expired"] {
        let resp = app
            .client
            .put(app.url(&format!("/api/v1/quotes/{quote_id}")))
            .bearer_auth(&token)
            .json(&serde_json::json!({ "status": forged }))
            .send()
            .await
            .expect("forge status");
        assert_eq!(
            resp.status(),
            StatusCode::CONFLICT,
            "staff must not be able to set '{forged}'"
        );
    }
}

#[sqlx::test]
async fn quotes_are_invisible_across_tenants(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company = common::seed_company(&pool).await;

    // A second tenant with its own admin and its own company. The billing
    // module has to be enabled for it too, or the gate 404s before the
    // tenant check is even reached and the test would pass vacuously.
    let (other_tenant, _other_user, other_email, other_password) =
        common::seed_tenant_with_admin(&pool, "pms672-other").await;
    sqlx::query(
        "INSERT INTO module_config (tenant_id, module_name, is_enabled, config) VALUES ($1, 'billing', TRUE, '{}')",
    )
    .bind(other_tenant)
    .execute(&pool)
    .await
    .expect("enable billing for the other tenant");
    let foreign_company = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, 'Foreign Co')")
        .bind(foreign_company)
        .bind(other_tenant)
        .execute(&pool)
        .await
        .expect("seed foreign company");

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let other_token = login_in_tenant(&app, other_tenant, &other_email, &other_password).await;

    let quote = create_quote(
        &app,
        &token,
        serde_json::json!({
            "company_id": company,
            "title": "Tenant A private",
            "lines": [line("Work", "1", "100")],
        }),
    )
    .await;
    let quote_id = quote["id"].as_str().unwrap();
    let line_id = quote["lines"][0]["id"].as_str().unwrap();

    // Every per-id route must 404 for the other tenant.
    let get = app
        .client
        .get(app.url(&format!("/api/v1/quotes/{quote_id}")))
        .bearer_auth(&other_token)
        .send()
        .await
        .expect("cross-tenant get");
    assert_eq!(get.status(), StatusCode::NOT_FOUND);

    let put = app
        .client
        .put(app.url(&format!("/api/v1/quotes/{quote_id}")))
        .bearer_auth(&other_token)
        .json(&serde_json::json!({ "title": "Stolen" }))
        .send()
        .await
        .expect("cross-tenant put");
    assert_eq!(put.status(), StatusCode::NOT_FOUND);

    let del = app
        .client
        .delete(app.url(&format!("/api/v1/quotes/{quote_id}")))
        .bearer_auth(&other_token)
        .send()
        .await
        .expect("cross-tenant delete");
    assert_eq!(del.status(), StatusCode::NOT_FOUND);

    let add_line = app
        .client
        .post(app.url(&format!("/api/v1/quotes/{quote_id}/lines")))
        .bearer_auth(&other_token)
        .json(&line("Injected", "1", "1"))
        .send()
        .await
        .expect("cross-tenant add line");
    assert_eq!(add_line.status(), StatusCode::NOT_FOUND);

    let put_line = app
        .client
        .put(app.url(&format!("/api/v1/quotes/{quote_id}/lines/{line_id}")))
        .bearer_auth(&other_token)
        .json(&line("Injected", "1", "1"))
        .send()
        .await
        .expect("cross-tenant put line");
    assert_eq!(put_line.status(), StatusCode::NOT_FOUND);

    let del_line = app
        .client
        .delete(app.url(&format!("/api/v1/quotes/{quote_id}/lines/{line_id}")))
        .bearer_auth(&other_token)
        .send()
        .await
        .expect("cross-tenant delete line");
    assert_eq!(del_line.status(), StatusCode::NOT_FOUND);

    // And the list route must not leak the row either.
    let listed: Value = app
        .client
        .get(app.url("/api/v1/quotes"))
        .bearer_auth(&other_token)
        .send()
        .await
        .expect("cross-tenant list")
        .json()
        .await
        .expect("cross-tenant list body");
    assert_eq!(
        listed["meta"]["total"], 0,
        "the other tenant sees none of tenant A's quotes"
    );

    // Creating against another tenant's company is rejected: the FK alone
    // would pass, because FK checks bypass RLS.
    let foreign = app
        .client
        .post(app.url("/api/v1/quotes"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "company_id": foreign_company,
            "title": "Cross-tenant company",
        }))
        .send()
        .await
        .expect("create against foreign company");
    assert_eq!(foreign.status(), StatusCode::BAD_REQUEST);
}

#[sqlx::test]
async fn validation_rejects_malformed_quotes(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company = common::seed_company(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    // Empty title.
    let blank = app
        .client
        .post(app.url("/api/v1/quotes"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "company_id": company, "title": "" }))
        .send()
        .await
        .expect("blank title");
    assert_eq!(blank.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // Empty line description, nested inside the lines vec.
    let bad_line = app
        .client
        .post(app.url("/api/v1/quotes"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "company_id": company,
            "title": "Has a bad line",
            "lines": [{ "line_type": "service", "description": "", "quantity": "1", "unit_price": "1" }],
        }))
        .send()
        .await
        .expect("blank line description");
    assert_eq!(
        bad_line.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "nested line validation must run, not just the header fields"
    );

    // Unknown company.
    let unknown = app
        .client
        .post(app.url("/api/v1/quotes"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "company_id": Uuid::new_v4(), "title": "Ghost client" }))
        .send()
        .await
        .expect("unknown company");
    assert_eq!(unknown.status(), StatusCode::BAD_REQUEST);
}

#[sqlx::test]
async fn approvals_surface_still_works_on_an_api_created_quote(pool: PgPool) {
    // PMS-484 wired `/quotes/{id}/approvals` against the stub table. It
    // must keep working now that quotes are created through their own
    // module rather than by a raw INSERT.
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company = common::seed_company(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let quote = create_quote(
        &app,
        &token,
        serde_json::json!({
            "company_id": company,
            "title": "Needs sign-off",
            "lines": [line("Work", "1", "100")],
        }),
    )
    .await;
    let quote_id = quote["id"].as_str().unwrap();

    let created = app
        .client
        .post(app.url(&format!("/api/v1/quotes/{quote_id}/approvals")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "approver_role": "super_admin", "notes": "price ok?" }))
        .send()
        .await
        .expect("create approval");
    assert!(
        created.status().is_success(),
        "approvals on an API-created quote should 2xx, got {}",
        created.status()
    );
    let row: Value = created.json().await.expect("approval body");
    assert_eq!(row["target"], "quote");
    assert_eq!(row["entity_id"], quote["id"]);
}
