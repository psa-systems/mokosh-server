//! PMS-955: the product catalog, and what a document does with a link to it.
//!
//! The tests that matter here are the ones about time. A catalog is only safe
//! to edit if editing it cannot reach backwards into documents already written,
//! and it is only worth having if two rows cannot quietly claim to be the same
//! product at two different prices.

mod common;

use rust_decimal::Decimal;
use serde_json::Value;
use sqlx::PgPool;
use std::str::FromStr;

fn dec(v: &Value) -> Decimal {
    Decimal::from_str(v.as_str().unwrap_or("0")).expect("decimal")
}

async fn create_product(app: &common::TestApp, token: &str, body: Value) -> reqwest::Response {
    app.client
        .post(app.url("/api/v1/products"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("send create product")
}

async fn a_product(app: &common::TestApp, token: &str, name: &str, price: &str) -> String {
    let resp = create_product(
        app,
        token,
        serde_json::json!({ "name": name, "unit_price": price, "sku": name }),
    )
    .await;
    assert!(
        resp.status().is_success(),
        "create product should 2xx, got {}",
        resp.status()
    );
    let product: Value = resp.json().await.expect("product JSON");
    product["id"].as_str().expect("product id").to_string()
}

async fn invoice_with_product(
    app: &common::TestApp,
    token: &str,
    company_id: uuid::Uuid,
    product_id: &str,
    price: &str,
) -> reqwest::Response {
    app.client
        .post(app.url("/api/v1/invoices"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "company_id": company_id,
            "invoice_date": "2026-08-01",
            "due_date": "2026-08-31",
            "lines": [{
                "line_type": "product",
                "product_id": product_id,
                "description": "Licence",
                "quantity": "1",
                "unit_price": price,
            }],
        }))
        .send()
        .await
        .expect("send create invoice")
}

/// The catalog exists to stop two rows quietly being the same product at two
/// prices, so both identities are enforced and each refusal says which one was
/// hit rather than quoting an index name.
#[sqlx::test]
async fn the_catalog_refuses_a_second_row_for_the_same_product(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    a_product(&app, &token, "M365 Business Standard", "22.00").await;

    // Same name, different case, different price: the exact confusion.
    let dup_name = create_product(
        &app,
        &token,
        serde_json::json!({ "name": "m365 business standard", "unit_price": "19.00" }),
    )
    .await;
    assert_eq!(dup_name.status(), reqwest::StatusCode::CONFLICT);
    let body = dup_name.text().await.unwrap_or_default();
    assert!(
        body.contains("name"),
        "the 409 says which identity, got {body}"
    );

    let dup_sku = create_product(
        &app,
        &token,
        serde_json::json!({
            "name": "Something else entirely",
            "sku": "M365 Business Standard",
            "unit_price": "19.00",
        }),
    )
    .await;
    assert_eq!(dup_sku.status(), reqwest::StatusCode::CONFLICT);
    let body = dup_sku.text().await.unwrap_or_default();
    assert!(
        body.contains("SKU"),
        "the 409 says which identity, got {body}"
    );

    // Two products with no SKU at all are fine: the index is partial, so the
    // optional field does not become a one-row-only field.
    for name in ["Cable, cat6", "Cable, cat6a"] {
        let resp = create_product(
            &app,
            &token,
            serde_json::json!({ "name": name, "unit_price": "5.00" }),
        )
        .await;
        assert!(resp.status().is_success(), "got {}", resp.status());
    }
}

/// The load-bearing test. A catalog that reached into documents already written
/// would re-price last year's invoices the day somebody corrected a typo in a
/// price, and an issued invoice is immutable (PMS-953).
#[sqlx::test]
async fn changing_a_catalog_price_does_not_reprice_a_document(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let company_id = common::seed_company(&pool).await;
    // PMS-993: an invoice cannot be sent without a billing contact.
    common::seed_billing_contact(&pool, company_id).await;

    let product_id = a_product(&app, &token, "Licence", "100").await;
    let resp = invoice_with_product(&app, &token, company_id, &product_id, "100").await;
    assert!(resp.status().is_success(), "got {}", resp.status());
    let invoice: Value = resp.json().await.expect("invoice JSON");
    let invoice_id = invoice["id"].as_str().expect("invoice id").to_string();
    assert_eq!(dec(&invoice["total"]), Decimal::from(100));

    // Send it, so it is frozen as well as written.
    let sent = app
        .client
        .put(app.url(&format!("/api/v1/invoices/{invoice_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "status": "sent" }))
        .send()
        .await
        .expect("send invoice");
    assert!(sent.status().is_success());

    // Double the catalog price.
    let bumped = app
        .client
        .put(app.url(&format!("/api/v1/products/{product_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "name": "Licence", "sku": "Licence", "unit_price": "200" }))
        .send()
        .await
        .expect("send product update");
    assert!(bumped.status().is_success(), "got {}", bumped.status());

    let after: Value = app
        .client
        .get(app.url(&format!("/api/v1/invoices/{invoice_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get invoice")
        .json()
        .await
        .expect("invoice JSON");
    assert_eq!(
        dec(&after["total"]),
        Decimal::from(100),
        "the invoice charges what it charged"
    );
    let line = &after["lines"].as_array().expect("lines")[0];
    assert_eq!(dec(&line["unit_price"]), Decimal::from(100));
    assert_eq!(
        line["product_id"].as_str(),
        Some(product_id.as_str()),
        "and still names the product it sold"
    );
}

/// Retiring is the path for a product that has been sold, and the refusal to
/// delete says so instead of surfacing a foreign-key error.
#[sqlx::test]
async fn a_sold_product_is_retired_rather_than_deleted(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let company_id = common::seed_company(&pool).await;
    // PMS-993: an invoice cannot be sent without a billing contact.
    common::seed_billing_contact(&pool, company_id).await;

    let unsold = a_product(&app, &token, "Never sold", "10").await;
    let sold = a_product(&app, &token, "Sold once", "10").await;
    assert!(invoice_with_product(&app, &token, company_id, &sold, "10")
        .await
        .status()
        .is_success());

    // Nothing has sold this one, so it can go.
    let gone = app
        .client
        .delete(app.url(&format!("/api/v1/products/{unsold}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("delete unsold");
    assert!(gone.status().is_success(), "got {}", gone.status());

    let refused = app
        .client
        .delete(app.url(&format!("/api/v1/products/{sold}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("delete sold");
    assert_eq!(refused.status(), reqwest::StatusCode::CONFLICT);
    let body = refused.text().await.unwrap_or_default();
    assert!(
        body.contains("Retire"),
        "the refusal names the alternative, got {body}"
    );

    // Retiring works, and takes it out of a picker's list without touching the
    // invoice that sold it.
    let retired = app
        .client
        .put(app.url(&format!("/api/v1/products/{sold}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "name": "Sold once", "sku": "Sold once", "unit_price": "10", "is_active": false,
        }))
        .send()
        .await
        .expect("retire");
    assert!(retired.status().is_success());

    let active: Value = app
        .client
        .get(app.url("/api/v1/products?is_active=true"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list active")
        .json()
        .await
        .expect("products JSON");
    assert!(
        active["data"].as_array().expect("data").is_empty(),
        "the retired product is out of the picker: {active}"
    );

    // A retired product cannot go onto a NEW document, which is the point of
    // retiring it.
    let refused_line = invoice_with_product(&app, &token, company_id, &sold, "10").await;
    assert_eq!(refused_line.status(), reqwest::StatusCode::BAD_REQUEST);
}

/// An FK check bypasses RLS, so a product id from another tenant would satisfy
/// the constraint and link across tenants without a word. It is refused
/// explicitly instead, and every link on the request is checked before the
/// first line is written.
#[sqlx::test]
async fn a_foreign_product_is_refused_and_no_line_is_written(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let company_id = common::seed_company(&pool).await;
    // PMS-993: an invoice cannot be sent without a billing contact.
    common::seed_billing_contact(&pool, company_id).await;

    // A product belonging to nobody this caller can see.
    let other_tenant = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name, slug, kind) VALUES ($1, 'Other', $2, 'org')")
        .bind(other_tenant)
        .bind(format!("other-{}", &other_tenant.to_string()[..8]))
        .execute(&pool)
        .await
        .expect("seed other tenant");
    let foreign: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO products (id, tenant_id, name, unit_price) \
         VALUES ($1, $2, 'Foreign', 10) RETURNING id",
    )
    .bind(uuid::Uuid::new_v4())
    .bind(other_tenant)
    .fetch_one(&pool)
    .await
    .expect("seed foreign product");

    let resp = invoice_with_product(&app, &token, company_id, &foreign.to_string(), "10").await;
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);

    // A second line with a good link must not have survived the bad one.
    let mine = a_product(&app, &token, "Mine", "10").await;
    let mixed = app
        .client
        .post(app.url("/api/v1/invoices"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "company_id": company_id,
            "invoice_date": "2026-08-01",
            "due_date": "2026-08-31",
            "lines": [
                { "line_type": "product", "product_id": mine, "description": "Good",
                  "quantity": "1", "unit_price": "10" },
                { "line_type": "product", "product_id": foreign, "description": "Bad",
                  "quantity": "1", "unit_price": "10" },
            ],
        }))
        .send()
        .await
        .expect("send mixed invoice");
    assert_eq!(mixed.status(), reqwest::StatusCode::BAD_REQUEST);

    let lines: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM invoice_lines")
        .fetch_one(&pool)
        .await
        .expect("count lines");
    assert_eq!(lines, 0, "the good line was not left behind");
}

/// A line with no product is every line written before this existed, and it has
/// to keep working exactly as it did.
#[sqlx::test]
async fn a_line_with_no_product_is_unaffected(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let company_id = common::seed_company(&pool).await;
    // PMS-993: an invoice cannot be sent without a billing contact.
    common::seed_billing_contact(&pool, company_id).await;

    let resp = app
        .client
        .post(app.url("/api/v1/invoices"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "company_id": company_id,
            "invoice_date": "2026-08-01",
            "due_date": "2026-08-31",
            "lines": [{
                "line_type": "service",
                "description": "Consulting",
                "quantity": "2",
                "unit_price": "150",
            }],
        }))
        .send()
        .await
        .expect("send create invoice");
    assert!(resp.status().is_success(), "got {}", resp.status());
    let invoice: Value = resp.json().await.expect("invoice JSON");
    assert_eq!(dec(&invoice["total"]), Decimal::from(300));
    assert!(invoice["lines"].as_array().expect("lines")[0]["product_id"].is_null());
}

/// The update path writes its own INSERT, and this branch shipped it with one
/// placeholder missing: the column list gained `product_id` and the `VALUES`
/// list did not, so replacing an invoice's lines 500'd. Every test above went
/// through `create_invoice` and none of them noticed;
/// `create_update_validation_parity` did, which is the whole reason that suite
/// exists. This is the coverage that should have been here.
#[sqlx::test]
async fn replacing_the_lines_keeps_the_product_link(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let company_id = common::seed_company(&pool).await;
    // PMS-993: an invoice cannot be sent without a billing contact.
    common::seed_billing_contact(&pool, company_id).await;

    let first = a_product(&app, &token, "First", "10").await;
    let second = a_product(&app, &token, "Second", "20").await;
    let created = invoice_with_product(&app, &token, company_id, &first, "10").await;
    assert!(created.status().is_success(), "got {}", created.status());
    let invoice: Value = created.json().await.expect("invoice JSON");
    let invoice_id = invoice["id"].as_str().expect("invoice id").to_string();

    let replaced = app
        .client
        .put(app.url(&format!("/api/v1/invoices/{invoice_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "lines": [{
                "line_type": "product",
                "product_id": second,
                "description": "Swapped",
                "quantity": "2",
                "unit_price": "20",
            }],
        }))
        .send()
        .await
        .expect("send line replacement");
    assert!(
        replaced.status().is_success(),
        "replacing lines should 2xx, got {}",
        replaced.status()
    );

    let after: Value = app
        .client
        .get(app.url(&format!("/api/v1/invoices/{invoice_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get invoice")
        .json()
        .await
        .expect("invoice JSON");
    let lines = after["lines"].as_array().expect("lines");
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["product_id"].as_str(), Some(second.as_str()));
    assert_eq!(dec(&after["total"]), Decimal::from(40));

    // And the same tenant check applies on this path, before the DELETE, so a
    // rejected link cannot take the existing lines with it.
    let other_tenant = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name, slug, kind) VALUES ($1, 'Other', $2, 'org')")
        .bind(other_tenant)
        .bind(format!("other-{}", &other_tenant.to_string()[..8]))
        .execute(&pool)
        .await
        .expect("seed other tenant");
    let foreign: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO products (id, tenant_id, name, unit_price) \
         VALUES ($1, $2, 'Foreign', 10) RETURNING id",
    )
    .bind(uuid::Uuid::new_v4())
    .bind(other_tenant)
    .fetch_one(&pool)
    .await
    .expect("seed foreign product");

    let refused = app
        .client
        .put(app.url(&format!("/api/v1/invoices/{invoice_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "lines": [{
                "line_type": "product",
                "product_id": foreign,
                "description": "Foreign",
                "quantity": "1",
                "unit_price": "10",
            }],
        }))
        .send()
        .await
        .expect("send foreign replacement");
    assert_eq!(refused.status(), reqwest::StatusCode::BAD_REQUEST);

    let still: Value = app
        .client
        .get(app.url(&format!("/api/v1/invoices/{invoice_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get invoice")
        .json()
        .await
        .expect("invoice JSON");
    assert_eq!(
        still["lines"].as_array().map(|l| l.len()),
        Some(1),
        "the rejected replacement left the existing line alone"
    );
    assert_eq!(dec(&still["total"]), Decimal::from(40));
}
