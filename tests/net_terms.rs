//! PMS-990: net terms are a number, and the due date follows from it.
//!
//! `payment_terms` was a name-only lookup, so "Net 30" was a label the server
//! attached no meaning to: the client typed every due date, and the two paths
//! where the server mints invoices itself hardcoded thirty days. A term now
//! carries `net_days`, and `BillingService::resolve_due_date` is the one rule
//! for a due date the caller did not give.

mod common;

use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

async fn terms(app: &common::TestApp, token: &str) -> Vec<Value> {
    let body: Value = app
        .client
        .get(app.url("/api/v1/payment-terms?per_page=50"))
        .bearer_auth(token)
        .send()
        .await
        .expect("list payment terms")
        .json()
        .await
        .expect("payment terms JSON");
    body["data"].as_array().expect("data array").clone()
}

fn term_named<'a>(rows: &'a [Value], name: &str) -> &'a Value {
    rows.iter()
        .find(|t| t["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("term {name} present"))
}

async fn create_term(app: &common::TestApp, token: &str, body: Value) -> Value {
    let resp = app
        .client
        .post(app.url("/api/v1/payment-terms"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("create term");
    assert!(resp.status().is_success(), "create term: {}", resp.status());
    resp.json().await.expect("term JSON")
}

async fn create_invoice(app: &common::TestApp, token: &str, body: Value) -> reqwest::Response {
    app.client
        .post(app.url("/api/v1/invoices"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("create invoice")
}

fn one_line_invoice(company_id: Uuid, invoice_date: &str) -> Value {
    json!({
        "company_id": company_id,
        "invoice_date": invoice_date,
        "lines": [{
            "line_type": "service",
            "description": "Managed services",
            "quantity": "1",
            "unit_price": "100.00",
        }],
    })
}

/// Migration 133 gives the seeded names their counts: the readable forms
/// PMS-117 wrote, and "Due on receipt" as zero.
#[sqlx::test]
async fn the_seeded_terms_carry_their_counts(pool: PgPool) {
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;
    let rows = terms(&app, &token).await;
    assert_eq!(term_named(&rows, "Net 30")["net_days"], 30);
    assert_eq!(term_named(&rows, "Net 15")["net_days"], 15);
    assert_eq!(term_named(&rows, "Net 60")["net_days"], 60);
    assert_eq!(term_named(&rows, "Due on receipt")["net_days"], 0);
}

/// A count round-trips through create and update, blank is allowed (a term
/// like "On approval" names no count), and the cap holds.
#[sqlx::test]
async fn net_days_round_trip_and_are_capped(pool: PgPool) {
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    let created = create_term(
        &app,
        &token,
        json!({ "name": "Net 45", "net_days": 45, "sort_order": 9 }),
    )
    .await;
    assert_eq!(created["net_days"], 45);
    let id = created["id"].as_str().expect("id");

    let updated: Value = app
        .client
        .put(app.url(&format!("/api/v1/payment-terms/{id}")))
        .bearer_auth(&token)
        .json(&json!({ "name": "On approval", "sort_order": 9 }))
        .send()
        .await
        .expect("update term")
        .json()
        .await
        .expect("term JSON");
    assert!(updated["net_days"].is_null(), "blank clears the count");

    let too_long = app
        .client
        .post(app.url("/api/v1/payment-terms"))
        .bearer_auth(&token)
        .json(&json!({ "name": "Net forever", "net_days": 4000 }))
        .send()
        .await
        .expect("create term");
    assert_eq!(too_long.status().as_u16(), 422, "ten years is the cap");
    let negative = app
        .client
        .post(app.url("/api/v1/payment-terms"))
        .bearer_auth(&token)
        .json(&json!({ "name": "Net minus", "net_days": -1 }))
        .send()
        .await
        .expect("create term");
    assert_eq!(negative.status().as_u16(), 422);
}

/// No due date and a named term: the invoice date plus that term's count,
/// and the invoice records the term.
#[sqlx::test]
async fn a_named_term_derives_the_due_date(pool: PgPool) {
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;
    let rows = terms(&app, &token).await;
    let net15 = term_named(&rows, "Net 15")["id"]
        .as_str()
        .unwrap()
        .to_string();

    let mut body = one_line_invoice(company_id, "2026-03-01");
    body["payment_term_id"] = Value::String(net15.clone());
    let resp = create_invoice(&app, &token, body).await;
    assert!(resp.status().is_success(), "{}", resp.status());
    let invoice: Value = resp.json().await.expect("invoice JSON");
    assert_eq!(invoice["due_date"], "2026-03-16");
    assert_eq!(invoice["payment_term_id"], net15);
    assert_eq!(invoice["payment_term_name"], "Net 15");
}

/// No due date and no term: the tenant's default term (Net 30 as seeded)
/// supplies both the count and the link, which is what "a configurable
/// default" means.
#[sqlx::test]
async fn the_default_term_derives_the_due_date_when_none_is_named(pool: PgPool) {
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;
    let rows = terms(&app, &token).await;
    let default = term_named(&rows, "Net 30");
    assert_eq!(default["is_default"], true);

    let resp = create_invoice(&app, &token, one_line_invoice(company_id, "2026-03-01")).await;
    assert!(resp.status().is_success(), "{}", resp.status());
    let invoice: Value = resp.json().await.expect("invoice JSON");
    assert_eq!(invoice["due_date"], "2026-03-31");
    assert_eq!(invoice["payment_term_id"], default["id"]);
}

/// Changing the default changes what a new invoice gets: the setting is the
/// operator's, not the seed's.
#[sqlx::test]
async fn a_new_default_is_what_the_next_invoice_follows(pool: PgPool) {
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    let net7 = create_term(
        &app,
        &token,
        json!({ "name": "Net 7", "net_days": 7, "is_default": true }),
    )
    .await;
    let resp = create_invoice(&app, &token, one_line_invoice(company_id, "2026-03-01")).await;
    let invoice: Value = resp.json().await.expect("invoice JSON");
    assert_eq!(invoice["due_date"], "2026-03-08");
    assert_eq!(invoice["payment_term_id"], net7["id"]);
}

/// A term that names no count, or a tenant whose default is gone, falls
/// back to thirty days: what the server-minted paths always did.
#[sqlx::test]
async fn a_term_without_a_count_falls_back_to_thirty_days(pool: PgPool) {
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    let on_approval = create_term(&app, &token, json!({ "name": "On approval" })).await;
    let mut body = one_line_invoice(company_id, "2026-03-01");
    body["payment_term_id"] = on_approval["id"].clone();
    let invoice: Value = create_invoice(&app, &token, body)
        .await
        .json()
        .await
        .expect("invoice JSON");
    assert_eq!(invoice["due_date"], "2026-03-31");
    assert_eq!(invoice["payment_term_id"], on_approval["id"]);

    // No active default at all: retire the seeded one.
    sqlx::query("UPDATE payment_terms SET is_active = FALSE WHERE tenant_id = $1 AND is_default")
        .bind(common::DEFAULT_TENANT_ID)
        .execute(&app.pool)
        .await
        .expect("retire the default");
    let invoice: Value = create_invoice(&app, &token, one_line_invoice(company_id, "2026-03-01"))
        .await
        .json()
        .await
        .expect("invoice JSON");
    assert_eq!(invoice["due_date"], "2026-03-31");
    assert!(
        invoice["payment_term_id"].is_null(),
        "a retired default is not linked"
    );
}

/// A given due date is stored as given whatever the term says, and one
/// before the invoice date is still refused.
#[sqlx::test]
async fn a_given_due_date_wins_and_an_inverted_one_is_refused(pool: PgPool) {
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;
    let rows = terms(&app, &token).await;
    let net15 = term_named(&rows, "Net 15")["id"].clone();

    let mut body = one_line_invoice(company_id, "2026-03-01");
    body["payment_term_id"] = net15.clone();
    body["due_date"] = Value::String("2026-04-10".to_string());
    let invoice: Value = create_invoice(&app, &token, body)
        .await
        .json()
        .await
        .expect("invoice JSON");
    assert_eq!(invoice["due_date"], "2026-04-10");
    assert_eq!(invoice["payment_term_id"], net15);

    let mut inverted = one_line_invoice(company_id, "2026-03-01");
    inverted["due_date"] = Value::String("2026-02-01".to_string());
    let resp = create_invoice(&app, &token, inverted).await;
    assert_eq!(resp.status().as_u16(), 422);
}

/// Changing the term with no due date re-derives it; changing nothing, or
/// giving a date, leaves it as the caller says.
#[sqlx::test]
async fn changing_the_term_re_derives_the_due_date(pool: PgPool) {
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;
    let rows = terms(&app, &token).await;
    let net15 = term_named(&rows, "Net 15")["id"].clone();
    let net60 = term_named(&rows, "Net 60")["id"].clone();

    let invoice: Value = create_invoice(&app, &token, one_line_invoice(company_id, "2026-03-01"))
        .await
        .json()
        .await
        .expect("invoice JSON");
    let id = invoice["id"].as_str().unwrap().to_string();
    assert_eq!(invoice["due_date"], "2026-03-31");

    let update = |body: Value| {
        let app = &app;
        let token = &token;
        let id = id.clone();
        async move {
            let resp = app
                .client
                .put(app.url(&format!("/api/v1/invoices/{id}")))
                .bearer_auth(token)
                .json(&body)
                .send()
                .await
                .expect("update invoice");
            assert!(resp.status().is_success(), "{}", resp.status());
            resp.json::<Value>().await.expect("invoice JSON")
        }
    };

    let moved = update(json!({ "payment_term_id": net15 })).await;
    assert_eq!(
        moved["due_date"], "2026-03-16",
        "Net 15 from the invoice date"
    );

    let untouched = update(json!({ "notes": "no term change" })).await;
    assert_eq!(untouched["due_date"], "2026-03-16", "left alone");

    let explicit = update(json!({ "payment_term_id": net60, "due_date": "2026-05-05" })).await;
    assert_eq!(explicit["due_date"], "2026-05-05", "a given date wins");

    // The invoice date moving with the term re-derives from the new date.
    let redated = update(json!({ "payment_term_id": net15, "invoice_date": "2026-04-01" })).await;
    assert_eq!(redated["due_date"], "2026-04-16");
}

/// A new tenant inherits the counts along with the names, because
/// `TenantService` copies the default tenant's terms row-for-row.
#[sqlx::test]
async fn a_new_tenant_inherits_net_days(pool: PgPool) {
    let svc = mokosh_server::modules::tenants::TenantService::new(
        mokosh_server::Database::from_pool(pool.clone()),
    );
    let tenant_id = svc
        .ensure_personal_tenant(Uuid::new_v4(), None, None)
        .await
        .expect("provision a tenant");
    let rows: Vec<(String, Option<i32>)> =
        sqlx::query_as("SELECT name, net_days FROM payment_terms WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_all(&pool)
            .await
            .expect("read the new tenant's terms");
    let net30 = rows
        .iter()
        .find(|(n, _)| n == "Net 30")
        .expect("Net 30 copied to the new tenant");
    assert_eq!(net30.1, Some(30));
    let receipt = rows
        .iter()
        .find(|(n, _)| n == "Due on receipt")
        .expect("Due on receipt copied");
    assert_eq!(receipt.1, Some(0));
}
