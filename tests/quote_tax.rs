//! PMS-1038: a quote's tax is derived from the tenant's rate over its
//! taxable lines, the PMS-1029 shape on quotes. The customer signs the
//! quote's total, so the figure is one they accept, and the rate is frozen on
//! the quote so a later edit to `tax_rates` cannot move a total they saw.

mod common;

use reqwest::StatusCode;
use rust_decimal::Decimal;
use serde_json::{json, Value};
use sqlx::PgPool;

fn dec(v: &Value) -> Decimal {
    v.as_str()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("a decimal string, got {v}"))
}

async fn send(app: &common::TestApp, token: &str, method: &str, path: &str, body: Value) -> Value {
    let request = match method {
        "POST" => app.client.post(app.url(path)),
        "PUT" => app.client.put(app.url(path)),
        _ => unreachable!(),
    };
    let response = request
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("send");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "{method} {path}: {:?}",
        response.text().await
    );
    response.json().await.expect("json")
}

async fn default_rate(app: &common::TestApp, token: &str, pct: &str) -> String {
    let rate = send(
        app,
        token,
        "POST",
        "/api/v1/tax-rates",
        json!({ "name": "HST", "rate": pct, "is_default": true }),
    )
    .await;
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

fn quote(company_id: uuid::Uuid, lines: Vec<Value>) -> Value {
    json!({ "company_id": company_id, "title": "Network build", "lines": lines })
}

/// Tax lands on the taxable subtotal only, the rate is recorded, and adding a
/// line re-derives it.
#[sqlx::test]
async fn tax_follows_the_rate_over_the_taxable_lines_and_every_line_change(pool: PgPool) {
    let (_, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let company_id = common::seed_company(&pool).await;
    let hst = default_rate(&app, &token, "13").await;

    let created = send(
        &app,
        &token,
        "POST",
        "/api/v1/quotes",
        quote(
            company_id,
            vec![
                line("Build", "100", true),
                line("Config", "50.05", true),
                line("Exempt", "30", false),
            ],
        ),
    )
    .await;
    // 150.05 * 13% = 19.5065 -> 19.51
    assert_eq!(dec(&created["subtotal"]), Decimal::new(18005, 2));
    assert_eq!(dec(&created["tax_amount"]), Decimal::new(1951, 2));
    assert_eq!(dec(&created["total"]), Decimal::new(19956, 2));
    assert_eq!(created["tax_rate_id"], hst);
    assert_eq!(dec(&created["tax_rate"]), Decimal::from(13));
    assert_eq!(created["lines"][2]["is_taxable"], false);

    let id = created["id"].as_str().expect("id");
    let with_line = send(
        &app,
        &token,
        "POST",
        &format!("/api/v1/quotes/{id}/lines"),
        line("Extra", "100", true),
    )
    .await;
    // 250.05 * 13% = 32.5065 -> 32.51
    assert_eq!(dec(&with_line["tax_amount"]), Decimal::new(3251, 2));
    assert_eq!(dec(&with_line["total"]), Decimal::new(28256, 2));
}

/// A given amount is kept through line changes and records no rate; naming a
/// rate on update re-derives; giving an amount on update clears the rate.
#[sqlx::test]
async fn a_given_amount_is_kept_until_a_rate_is_named(pool: PgPool) {
    let (_, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let company_id = common::seed_company(&pool).await;
    let hst = default_rate(&app, &token, "13").await;

    let mut body = quote(company_id, vec![line("Build", "100", true)]);
    body["tax_amount"] = json!("7");
    let given = send(&app, &token, "POST", "/api/v1/quotes", body).await;
    assert_eq!(dec(&given["tax_amount"]), Decimal::from(7));
    assert!(given["tax_rate_id"].is_null());
    let id = given["id"].as_str().expect("id");

    let with_line = send(
        &app,
        &token,
        "POST",
        &format!("/api/v1/quotes/{id}/lines"),
        line("Extra", "100", true),
    )
    .await;
    assert_eq!(
        dec(&with_line["tax_amount"]),
        Decimal::from(7),
        "a given amount survives a line change"
    );
    assert_eq!(dec(&with_line["total"]), Decimal::from(207));

    let rated = send(
        &app,
        &token,
        "PUT",
        &format!("/api/v1/quotes/{id}"),
        json!({ "tax_rate_id": hst }),
    )
    .await;
    assert_eq!(
        dec(&rated["tax_amount"]),
        Decimal::from(26),
        "naming a rate re-derives"
    );
    assert_eq!(rated["tax_rate_id"], hst);

    let regiven = send(
        &app,
        &token,
        "PUT",
        &format!("/api/v1/quotes/{id}"),
        json!({ "tax_amount": "9" }),
    )
    .await;
    assert_eq!(dec(&regiven["tax_amount"]), Decimal::from(9));
    assert!(
        regiven["tax_rate_id"].is_null(),
        "giving an amount clears the rate"
    );
}

/// Changing the tenant's rate afterwards does not move an existing quote.
#[sqlx::test]
async fn a_later_rate_change_does_not_move_an_existing_quote(pool: PgPool) {
    let (_, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let company_id = common::seed_company(&pool).await;
    let hst = default_rate(&app, &token, "13").await;

    let created = send(
        &app,
        &token,
        "POST",
        "/api/v1/quotes",
        quote(company_id, vec![line("Build", "100", true)]),
    )
    .await;
    let id = created["id"].as_str().expect("id");
    send(
        &app,
        &token,
        "PUT",
        &format!("/api/v1/tax-rates/{hst}"),
        json!({ "name": "HST", "rate": "15", "is_default": true }),
    )
    .await;
    // A line change re-derives from the FROZEN rate, not the edited one.
    let with_line = send(
        &app,
        &token,
        "POST",
        &format!("/api/v1/quotes/{id}/lines"),
        line("Extra", "100", true),
    )
    .await;
    assert_eq!(dec(&with_line["tax_amount"]), Decimal::from(26));
    assert_eq!(dec(&with_line["tax_rate"]), Decimal::from(13));
}
