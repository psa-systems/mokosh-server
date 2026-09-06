//! PMS-1029: tax is computed from the tenant's rate over the taxable lines,
//! and the invoice records the rate it used.
//!
//! The tenant has carried a default tax rate since migration 010 and every
//! writer ignored it: an invoice built by the server went out with zero tax,
//! and one typed in carried a figure the server never checked. And the rate
//! is a percent everywhere it is handled while the column could not hold one
//! at or above 10, so a real rate could not even be stored.

mod common;

use rust_decimal::Decimal;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

fn dec(v: &Value) -> Decimal {
    v.as_str()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("a decimal string, got {v}"))
}

async fn post(app: &common::TestApp, token: &str, path: &str, body: Value) -> Value {
    let response = app
        .client
        .post(app.url(path))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("post");
    assert!(
        response.status().is_success(),
        "POST {path}: {} {:?}",
        response.status(),
        response.text().await
    );
    response.json().await.expect("json")
}

async fn put(app: &common::TestApp, token: &str, path: &str, body: Value) -> Value {
    let response = app
        .client
        .put(app.url(path))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("put");
    assert!(
        response.status().is_success(),
        "PUT {path}: {} {:?}",
        response.status(),
        response.text().await
    );
    response.json().await.expect("json")
}

async fn get(app: &common::TestApp, token: &str, path: &str) -> Value {
    let response = app
        .client
        .get(app.url(path))
        .bearer_auth(token)
        .send()
        .await
        .expect("get");
    assert!(
        response.status().is_success(),
        "GET {path}: {}",
        response.status()
    );
    response.json().await.expect("json")
}

/// A real rate. `DECIMAL(5,4)` could not hold this before migration 189.
async fn default_rate(app: &common::TestApp, token: &str, name: &str, pct: &str) -> String {
    let rate = post(
        app,
        token,
        "/api/v1/tax-rates",
        json!({ "name": name, "rate": pct, "is_default": true }),
    )
    .await;
    assert_eq!(rate["is_default"], true);
    rate["id"].as_str().expect("rate id").to_string()
}

fn line(description: &str, price: &str, taxable: bool) -> Value {
    json!({
        "line_type": "service",
        "description": description,
        "quantity": "1",
        "unit_price": price,
        "is_taxable": taxable,
    })
}

fn invoice(company_id: Uuid, lines: Vec<Value>) -> Value {
    json!({
        "company_id": company_id,
        "invoice_date": "2026-08-01",
        "due_date": "2026-08-31",
        "lines": lines,
    })
}

/// With a 13% default, tax lands on the taxable subtotal only, rounded half
/// away from zero, and the invoice records the rate it used.
#[sqlx::test]
async fn tax_is_the_default_rate_over_the_taxable_lines(pool: PgPool) {
    let (_, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let company_id = common::seed_company(&pool).await;
    let hst = default_rate(&app, &token, "HST", "13").await;

    let created = post(
        &app,
        &token,
        "/api/v1/invoices",
        invoice(
            company_id,
            vec![
                line("Managed services", "100", true),
                line("Onboarding", "50.05", true),
                line("Exempt fee", "30", false),
            ],
        ),
    )
    .await;
    // 150.05 * 13% = 19.5065 -> 19.51
    assert_eq!(dec(&created["subtotal"]), Decimal::new(18005, 2));
    assert_eq!(dec(&created["tax_amount"]), Decimal::new(1951, 2));
    assert_eq!(dec(&created["total"]), Decimal::new(19956, 2));
    assert_eq!(dec(&created["balance_due"]), Decimal::new(19956, 2));
    assert_eq!(created["tax_rate_id"], hst);
    assert_eq!(dec(&created["tax_rate"]), Decimal::from(13));
    let taxable: Vec<bool> = created["lines"]
        .as_array()
        .expect("lines")
        .iter()
        .map(|l| l["is_taxable"].as_bool().expect("flag"))
        .collect();
    assert_eq!(taxable, [true, true, false]);
}

/// The rate is frozen on the invoice: editing the tenant's rate afterwards
/// changes nothing already written, and a new invoice picks the new rate.
#[sqlx::test]
async fn a_later_rate_change_does_not_reprice_an_invoice(pool: PgPool) {
    let (_, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let company_id = common::seed_company(&pool).await;
    let hst = default_rate(&app, &token, "HST", "13").await;

    let first = post(
        &app,
        &token,
        "/api/v1/invoices",
        invoice(company_id, vec![line("Managed services", "100", true)]),
    )
    .await;
    assert_eq!(dec(&first["tax_amount"]), Decimal::from(13));

    put(
        &app,
        &token,
        &format!("/api/v1/tax-rates/{hst}"),
        json!({ "name": "HST", "rate": "15", "is_default": true }),
    )
    .await;
    let first_id = first["id"].as_str().expect("id");
    let reread = get(&app, &token, &format!("/api/v1/invoices/{first_id}")).await;
    assert_eq!(dec(&reread["tax_amount"]), Decimal::from(13));
    assert_eq!(dec(&reread["tax_rate"]), Decimal::from(13));

    let second = post(
        &app,
        &token,
        "/api/v1/invoices",
        invoice(company_id, vec![line("Managed services", "100", true)]),
    )
    .await;
    assert_eq!(dec(&second["tax_amount"]), Decimal::from(15));
    assert_eq!(dec(&second["tax_rate"]), Decimal::from(15));
}

/// A product line takes the product's own flag, whatever the request says.
#[sqlx::test]
async fn a_product_line_copies_the_products_taxability(pool: PgPool) {
    let (_, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let company_id = common::seed_company(&pool).await;
    default_rate(&app, &token, "HST", "13").await;
    let exempt = post(
        &app,
        &token,
        "/api/v1/products",
        json!({ "name": "Exempt licence", "sku": "EX-1", "unit_price": "100", "is_taxable": false }),
    )
    .await;
    let exempt_id = exempt["id"].as_str().expect("product id");

    let created = post(
        &app,
        &token,
        "/api/v1/invoices",
        invoice(
            company_id,
            vec![
                json!({ "line_type": "product", "product_id": exempt_id, "description": "Licence", "quantity": "1", "unit_price": "100" }),
                line("Setup", "100", true),
            ],
        ),
    )
    .await;
    assert_eq!(created["lines"][0]["is_taxable"], false);
    assert_eq!(
        dec(&created["tax_amount"]),
        Decimal::from(13),
        "only the setup line is taxed"
    );
}

/// The two server-built writers, which wrote zero tax before, carry the
/// default rate's tax.
#[sqlx::test]
async fn server_built_invoices_carry_the_default_rates_tax(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let company_id = common::seed_company(&pool).await;
    let hst = default_rate(&app, &token, "HST", "13").await;

    // From time entries.
    let work_types = get(&app, &token, "/api/v1/work-types").await;
    let work_type_id = work_types["data"][0]["id"].as_str().expect("work type");
    sqlx::query(
        "INSERT INTO time_entries (id, tenant_id, user_id, date, duration_minutes, work_type_id, \
         company_id, is_billable, billing_status, hourly_rate, total_amount) \
         VALUES ($1, $2, $3, '2026-06-15', 60, $4::uuid, $5, TRUE, 'ready_to_bill', 100, 100)",
    )
    .bind(Uuid::new_v4())
    .bind(common::DEFAULT_TENANT_ID)
    .bind(admin_id)
    .bind(work_type_id)
    .bind(company_id)
    .execute(&pool)
    .await
    .expect("seed a billable entry");
    let from_time = post(
        &app,
        &token,
        "/api/v1/invoices/from-time-entries",
        json!({ "company_id": company_id }),
    )
    .await;
    assert_eq!(dec(&from_time["subtotal"]), Decimal::from(100));
    assert_eq!(dec(&from_time["tax_amount"]), Decimal::from(13));
    assert_eq!(dec(&from_time["total"]), Decimal::from(113));
    assert_eq!(from_time["tax_rate_id"], hst);

    // From a contract.
    let contract_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contracts (id, tenant_id, name, company_id, contract_type, status, \
         start_date, billing_cycle) \
         VALUES ($1, $2, 'Managed', $3, 'managed_services', 'active', '2026-06-01', 'monthly')",
    )
    .bind(contract_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .execute(&pool)
    .await
    .expect("seed contract");
    sqlx::query(
        "INSERT INTO contract_items (id, tenant_id, contract_id, name, item_type, quantity, \
         unit_price, total_price, sort_order, billing_rule) \
         VALUES ($1, $2, $3, 'Managed Services', 'recurring_service', 1, 200, 200, 0, 'every_period')",
    )
    .bind(Uuid::new_v4())
    .bind(common::DEFAULT_TENANT_ID)
    .bind(contract_id)
    .execute(&pool)
    .await
    .expect("seed recurring item");
    let svc = mokosh_server::modules::billing::BillingService::new(
        mokosh_server::Database::from_pool(pool.clone()),
    );
    let created = svc
        .generate_due_recurring_invoices(
            mokosh_server::modules::auth::TenantId::from_trusted(common::DEFAULT_TENANT_ID),
            chrono::Utc::now(),
            &mokosh_server::modules::audit::AuditCtx::system(common::DEFAULT_TENANT_ID),
        )
        .await
        .expect("generate");
    assert_eq!(created.len(), 1);
    let recurring = get(&app, &token, &format!("/api/v1/invoices/{}", created[0])).await;
    assert_eq!(dec(&recurring["tax_amount"]), Decimal::from(26));
    assert_eq!(dec(&recurring["total"]), Decimal::from(226));
    assert_eq!(recurring["tax_rate_id"], hst);
}

/// A given amount is stored as given and records no rate; a tenant still on
/// the seeded `No Tax` default gets zero, as before.
#[sqlx::test]
async fn a_given_amount_wins_and_no_tax_stays_zero(pool: PgPool) {
    let (_, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let company_id = common::seed_company(&pool).await;

    let untouched = post(
        &app,
        &token,
        "/api/v1/invoices",
        invoice(company_id, vec![line("Managed services", "100", true)]),
    )
    .await;
    assert_eq!(dec(&untouched["tax_amount"]), Decimal::ZERO);
    assert!(
        untouched["tax_rate_id"].is_string(),
        "the seeded No Tax default was applied"
    );
    assert_eq!(dec(&untouched["tax_rate"]), Decimal::ZERO);

    default_rate(&app, &token, "HST", "13").await;
    let mut body = invoice(company_id, vec![line("Managed services", "100", true)]);
    body["tax_amount"] = json!("5");
    let given = post(&app, &token, "/api/v1/invoices", body).await;
    assert_eq!(dec(&given["tax_amount"]), Decimal::from(5));
    assert!(
        given["tax_rate_id"].is_null(),
        "a supplied amount records no rate"
    );
    assert_eq!(dec(&given["total"]), Decimal::from(105));
}

/// Replacing a draft's lines re-derives the tax; an update that touches
/// neither lines nor rate nor amount leaves it alone; a foreign or retired
/// rate is refused.
#[sqlx::test]
async fn an_update_rederives_only_when_asked(pool: PgPool) {
    let (_, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let company_id = common::seed_company(&pool).await;
    default_rate(&app, &token, "HST", "13").await;

    let created = post(
        &app,
        &token,
        "/api/v1/invoices",
        invoice(company_id, vec![line("Managed services", "100", true)]),
    )
    .await;
    let id = created["id"].as_str().expect("id").to_string();

    let noted = put(
        &app,
        &token,
        &format!("/api/v1/invoices/{id}"),
        json!({ "notes": "hi" }),
    )
    .await;
    assert_eq!(dec(&noted["tax_amount"]), Decimal::from(13));

    let relined = put(
        &app,
        &token,
        &format!("/api/v1/invoices/{id}"),
        json!({ "lines": [line("Managed services", "200", true)] }),
    )
    .await;
    assert_eq!(dec(&relined["subtotal"]), Decimal::from(200));
    assert_eq!(dec(&relined["tax_amount"]), Decimal::from(26));
    assert_eq!(dec(&relined["total"]), Decimal::from(226));

    let response = app
        .client
        .put(app.url(&format!("/api/v1/invoices/{id}")))
        .bearer_auth(&token)
        .json(&json!({ "tax_rate_id": Uuid::new_v4() }))
        .send()
        .await
        .expect("put a foreign rate");
    assert_eq!(response.status(), 400, "{:?}", response.text().await);
}
