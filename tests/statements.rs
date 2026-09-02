//! PMS-954: a client statement, derived at read time.
//!
//! The acceptance test for a statement is that it reconciles, so these tests
//! assert the arithmetic rather than the wording: opening plus charges less
//! receipts equals closing, in every case, including the ones that are easy to
//! get wrong. A draft invoice that leaks in, a voided invoice dropped along
//! with its credit note, or an opening balance read off today's `balance_due`
//! all produce a document that looks right and does not add up.

mod common;

use rust_decimal::Decimal;
use serde_json::Value;
use sqlx::PgPool;
use std::str::FromStr;

fn dec(v: &Value) -> Decimal {
    Decimal::from_str(v.as_str().unwrap_or("0")).expect("decimal")
}

async fn invoice_on(
    app: &common::TestApp,
    token: &str,
    company_id: uuid::Uuid,
    date: &str,
    amount: &str,
) -> String {
    let resp = app
        .client
        .post(app.url("/api/v1/invoices"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "company_id": company_id,
            "invoice_date": date,
            "due_date": date,
            "lines": [{
                "line_type": "service",
                "description": "Managed services",
                "quantity": "1",
                "unit_price": amount,
            }],
        }))
        .send()
        .await
        .expect("send create invoice");
    assert!(
        resp.status().is_success(),
        "create invoice should 2xx, got {}",
        resp.status()
    );
    let invoice: Value = resp.json().await.expect("invoice JSON");
    invoice["id"].as_str().expect("invoice id").to_string()
}

async fn send(app: &common::TestApp, token: &str, invoice_id: &str) {
    let resp = app
        .client
        .put(app.url(&format!("/api/v1/invoices/{invoice_id}")))
        .bearer_auth(token)
        .json(&serde_json::json!({ "status": "sent" }))
        .send()
        .await
        .expect("send invoice");
    assert!(resp.status().is_success(), "got {}", resp.status());
}

async fn pay(
    app: &common::TestApp,
    token: &str,
    company_id: uuid::Uuid,
    invoice_id: &str,
    date: &str,
    amount: &str,
) {
    let resp = app
        .client
        .post(app.url("/api/v1/payments"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "invoice_id": invoice_id,
            "company_id": company_id,
            "payment_date": date,
            "amount": amount,
            "payment_method": "check",
        }))
        .send()
        .await
        .expect("send payment");
    assert!(resp.status().is_success(), "got {}", resp.status());
}

async fn credit(app: &common::TestApp, token: &str, invoice_id: &str, date: &str, amount: &str) {
    let resp = app
        .client
        .post(app.url("/api/v1/credit-notes"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "invoice_id": invoice_id,
            "issue_date": date,
            "reason": "Corrected after the fact",
            "lines": [{
                "line_type": "adjustment",
                "description": "Credit",
                "quantity": "1",
                "unit_price": amount,
            }],
        }))
        .send()
        .await
        .expect("send credit note");
    assert!(resp.status().is_success(), "got {}", resp.status());
}

async fn statement(
    app: &common::TestApp,
    token: &str,
    company_id: uuid::Uuid,
    from: &str,
    to: &str,
) -> Value {
    let resp = app
        .client
        .get(app.url(&format!(
            "/api/v1/statements?company_id={company_id}&period_start={from}&period_end={to}"
        )))
        .bearer_auth(token)
        .send()
        .await
        .expect("send statement request");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "statement should 200"
    );
    resp.json().await.expect("statement JSON")
}

/// The invariant, asserted on every statement these tests produce. A document
/// that does not satisfy this is not a statement, whatever else is right about
/// it.
fn assert_reconciles(s: &Value) {
    let expected =
        dec(&s["opening_balance"]) + dec(&s["total_invoiced"]) + dec(&s["total_refunded"])
            - dec(&s["total_paid"])
            - dec(&s["total_credited"]);
    assert_eq!(
        dec(&s["closing_balance"]),
        expected,
        "opening plus charges less receipts must equal closing: {s}"
    );

    // And the totals must be the rows, not a separately maintained figure.
    let sum = |key: &str, field: &str| -> Decimal {
        s[key]
            .as_array()
            .map(|rows| rows.iter().map(|r| dec(&r[field])).sum())
            .unwrap_or(Decimal::ZERO)
    };
    assert_eq!(dec(&s["total_invoiced"]), sum("invoices", "total"));
    assert_eq!(dec(&s["total_paid"]), sum("payments", "amount"));
    assert_eq!(dec(&s["total_credited"]), sum("credit_notes", "total"));
    assert_eq!(dec(&s["total_refunded"]), sum("refunds", "amount"));
}

/// One period, one of everything, and the arithmetic holds.
#[sqlx::test]
async fn a_statement_reconciles_across_charges_payments_and_credits(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let company_id = common::seed_company(&pool).await;
    // PMS-993: an invoice cannot be sent without a billing contact.
    common::seed_billing_contact(&pool, company_id).await;

    let a = invoice_on(&app, &token, company_id, "2026-06-05", "1000").await;
    send(&app, &token, &a).await;
    let b = invoice_on(&app, &token, company_id, "2026-06-20", "500").await;
    send(&app, &token, &b).await;
    pay(&app, &token, company_id, &a, "2026-06-25", "400").await;
    credit(&app, &token, &b, "2026-06-28", "100").await;

    let s = statement(&app, &token, company_id, "2026-06-01", "2026-06-30").await;
    assert_reconciles(&s);

    assert_eq!(dec(&s["opening_balance"]), Decimal::ZERO);
    assert_eq!(dec(&s["total_invoiced"]), Decimal::from(1500));
    assert_eq!(dec(&s["total_paid"]), Decimal::from(400));
    assert_eq!(dec(&s["total_credited"]), Decimal::from(100));
    assert_eq!(dec(&s["closing_balance"]), Decimal::from(1000));
    assert_eq!(s["invoices"].as_array().map(|r| r.len()), Some(2));
    assert_eq!(s["company_name"].as_str(), Some("Acme Co"));
}

/// The half that a running total would get wrong. Everything before the period
/// is folded into the opening balance rather than dropped, so splitting one
/// period into two cannot change where the account ends up.
#[sqlx::test]
async fn the_opening_balance_carries_everything_before_the_period(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let company_id = common::seed_company(&pool).await;
    // PMS-993: an invoice cannot be sent without a billing contact.
    common::seed_billing_contact(&pool, company_id).await;

    let may = invoice_on(&app, &token, company_id, "2026-05-10", "800").await;
    send(&app, &token, &may).await;
    pay(&app, &token, company_id, &may, "2026-05-20", "300").await;
    let june = invoice_on(&app, &token, company_id, "2026-06-10", "200").await;
    send(&app, &token, &june).await;

    let june_statement = statement(&app, &token, company_id, "2026-06-01", "2026-06-30").await;
    assert_reconciles(&june_statement);
    assert_eq!(
        dec(&june_statement["opening_balance"]),
        Decimal::from(500),
        "800 invoiced less 300 paid, all before June"
    );
    assert_eq!(dec(&june_statement["closing_balance"]), Decimal::from(700));
    assert!(
        june_statement["invoices"]
            .as_array()
            .expect("invoices")
            .iter()
            .all(|i| i["invoice_date"].as_str() != Some("2026-05-10")),
        "May's invoice is in the opening balance, not listed again"
    );

    // The whole span reaches the same closing balance by a different route,
    // which is what makes the opening balance more than a plausible number.
    let whole = statement(&app, &token, company_id, "2026-05-01", "2026-06-30").await;
    assert_reconciles(&whole);
    assert_eq!(dec(&whole["opening_balance"]), Decimal::ZERO);
    assert_eq!(
        dec(&whole["closing_balance"]),
        dec(&june_statement["closing_balance"])
    );
}

/// A draft invoice has not been issued, so the client does not owe it. It must
/// not appear and must not reach the opening balance either, which is the part
/// a period-start check alone would miss.
#[sqlx::test]
async fn a_draft_invoice_is_on_no_statement(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let company_id = common::seed_company(&pool).await;
    // PMS-993: an invoice cannot be sent without a billing contact.
    common::seed_billing_contact(&pool, company_id).await;

    invoice_on(&app, &token, company_id, "2026-05-10", "999").await;
    invoice_on(&app, &token, company_id, "2026-06-10", "777").await;
    let issued = invoice_on(&app, &token, company_id, "2026-06-15", "100").await;
    send(&app, &token, &issued).await;

    let s = statement(&app, &token, company_id, "2026-06-01", "2026-06-30").await;
    assert_reconciles(&s);
    assert_eq!(
        dec(&s["opening_balance"]),
        Decimal::ZERO,
        "May's draft is not owed, so it is not carried in"
    );
    assert_eq!(dec(&s["total_invoiced"]), Decimal::from(100));
    assert_eq!(s["invoices"].as_array().map(|r| r.len()), Some(1));
}

/// A voided invoice stays on the statement, with the credit note that voided
/// it. Dropping both would net to the same closing balance and would take the
/// correction out of the record, which is exactly what a client reconciling
/// their own books needs to see.
#[sqlx::test]
async fn a_voided_invoice_and_its_credit_note_both_appear(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let company_id = common::seed_company(&pool).await;
    // PMS-993: an invoice cannot be sent without a billing contact.
    common::seed_billing_contact(&pool, company_id).await;

    let wrong = invoice_on(&app, &token, company_id, "2026-06-05", "600").await;
    send(&app, &token, &wrong).await;
    credit(&app, &token, &wrong, "2026-06-06", "600").await;

    let s = statement(&app, &token, company_id, "2026-06-01", "2026-06-30").await;
    assert_reconciles(&s);
    assert_eq!(dec(&s["closing_balance"]), Decimal::ZERO);

    let invoices = s["invoices"].as_array().expect("invoices");
    assert_eq!(invoices.len(), 1);
    assert_eq!(invoices[0]["status"].as_str(), Some("void"));
    assert_eq!(dec(&invoices[0]["total"]), Decimal::from(600));

    let credits = s["credit_notes"].as_array().expect("credit notes");
    assert_eq!(credits.len(), 1);
    assert_eq!(dec(&credits[0]["total"]), Decimal::from(600));
    assert_eq!(
        credits[0]["invoice_number"].as_str(),
        invoices[0]["invoice_number"].as_str(),
        "the credit names the invoice it corrected"
    );
}

/// The reason nothing reads `invoices.balance_due`. A statement for a closed
/// period must show what was outstanding THEN; the invoice's own balance has
/// moved since and would make last month's statement change under the client.
#[sqlx::test]
async fn a_closed_period_is_not_rewritten_by_later_activity(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let company_id = common::seed_company(&pool).await;
    // PMS-993: an invoice cannot be sent without a billing contact.
    common::seed_billing_contact(&pool, company_id).await;

    let june = invoice_on(&app, &token, company_id, "2026-06-10", "900").await;
    send(&app, &token, &june).await;

    let before = statement(&app, &token, company_id, "2026-06-01", "2026-06-30").await;
    assert_eq!(dec(&before["closing_balance"]), Decimal::from(900));

    // Paid in July, after the period closed.
    pay(&app, &token, company_id, &june, "2026-07-03", "900").await;

    let after = statement(&app, &token, company_id, "2026-06-01", "2026-06-30").await;
    assert_reconciles(&after);
    assert_eq!(
        dec(&after["closing_balance"]),
        Decimal::from(900),
        "June closed owing 900 and still did; the July payment belongs to July"
    );
    assert!(after["payments"].as_array().expect("payments").is_empty());

    let july = statement(&app, &token, company_id, "2026-07-01", "2026-07-31").await;
    assert_reconciles(&july);
    assert_eq!(dec(&july["opening_balance"]), Decimal::from(900));
    assert_eq!(dec(&july["total_paid"]), Decimal::from(900));
    assert_eq!(dec(&july["closing_balance"]), Decimal::ZERO);
}

/// A voided credit note stops counting, on the statement as everywhere else.
#[sqlx::test]
async fn a_voided_credit_note_leaves_the_statement(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let company_id = common::seed_company(&pool).await;
    // PMS-993: an invoice cannot be sent without a billing contact.
    common::seed_billing_contact(&pool, company_id).await;

    let inv = invoice_on(&app, &token, company_id, "2026-06-05", "400").await;
    send(&app, &token, &inv).await;
    credit(&app, &token, &inv, "2026-06-06", "400").await;

    let note: Value = app
        .client
        .get(app.url("/api/v1/credit-notes"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list credit notes")
        .json()
        .await
        .expect("credit notes JSON");
    let note_id = note["data"][0]["id"].as_str().expect("note id").to_string();

    let resp = app
        .client
        .post(app.url(&format!("/api/v1/credit-notes/{note_id}/void")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("void");
    assert!(resp.status().is_success());

    let s = statement(&app, &token, company_id, "2026-06-01", "2026-06-30").await;
    assert_reconciles(&s);
    assert!(s["credit_notes"].as_array().expect("credits").is_empty());
    assert_eq!(dec(&s["closing_balance"]), Decimal::from(400));
}

/// Two companies in one tenant do not see each other's account, and a period
/// that runs backwards is a 400 rather than an empty document that looks fine.
#[sqlx::test]
async fn a_statement_is_scoped_and_its_period_is_checked(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let company_id = common::seed_company(&pool).await;
    // PMS-993: an invoice cannot be sent without a billing contact.
    common::seed_billing_contact(&pool, company_id).await;

    let other: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, 'Other Co') RETURNING id",
    )
    .bind(uuid::Uuid::new_v4())
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("seed second company");

    let inv = invoice_on(&app, &token, company_id, "2026-06-05", "300").await;
    send(&app, &token, &inv).await;

    let theirs = statement(&app, &token, other, "2026-06-01", "2026-06-30").await;
    assert_reconciles(&theirs);
    assert_eq!(dec(&theirs["closing_balance"]), Decimal::ZERO);
    assert!(theirs["invoices"].as_array().expect("invoices").is_empty());

    let backwards = app
        .client
        .get(app.url(&format!(
            "/api/v1/statements?company_id={company_id}&period_start=2026-06-30&period_end=2026-06-01"
        )))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send backwards period");
    assert_eq!(backwards.status(), reqwest::StatusCode::BAD_REQUEST);

    let missing = app
        .client
        .get(app.url(&format!(
            "/api/v1/statements?company_id={}&period_start=2026-06-01&period_end=2026-06-30",
            uuid::Uuid::new_v4()
        )))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send unknown company");
    assert_eq!(missing.status(), reqwest::StatusCode::NOT_FOUND);
}
