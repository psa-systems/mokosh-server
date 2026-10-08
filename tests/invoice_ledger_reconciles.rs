//! PMS-1307: the invoice ledger and the invoice's balance are the same story.
//!
//! `GET /invoices/{id}/ledger` (PMS-1088) reads `payments` and `payment_refunds`
//! and sums them into `total_paid` and `total_refunded`. `balance_due`,
//! `amount_paid` and `amount_credited` on the invoice come from
//! `BillingService::recompute_invoice_balance`, which sums the same two tables
//! plus issued credit notes (PMS-953). Two readers over one set of facts, and the
//! existing coverage pins the ledger's SHAPE - ordering, currency, which columns a
//! contact may see - but never that the two agree.
//!
//! That is the disagreement a customer finds rather than a developer: the ledger
//! lists what they paid, the invoice says what they owe, and if the arithmetic
//! between them drifts, the MSP is arguing with a document the customer is
//! reading correctly. So what is asserted here is the arithmetic itself, across a
//! payment, a partial refund and a credit note, at every step rather than only at
//! the end.
//!
//! A credit note deliberately does NOT appear in the ledger. The ledger is
//! "money that moved"; a credit note is a document that reduces what was owed, it
//! has its own list and its own PDF, and folding it in as a negative payment
//! would tell the customer they paid something they did not. What must hold is
//! that the invoice's own numbers account for it, which the last case checks.

mod common;

use mokosh_test::mokosh_test;
use rust_decimal::Decimal;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

async fn draft_invoice(app: &common::TestApp, token: &str, company_id: Uuid) -> Value {
    let resp = app
        .client
        .post(app.url("/api/v1/invoices"))
        .bearer_auth(token)
        .json(&json!({
            "company_id": company_id,
            "invoice_date": "2026-09-01",
            "due_date": "2026-09-30",
            "lines": [{
                "line_type": "service",
                "description": "Managed services, September",
                "quantity": "1",
                "unit_price": "1000.00",
            }],
        }))
        .send()
        .await
        .expect("create invoice");
    assert!(resp.status().is_success(), "create invoice");
    resp.json().await.expect("json")
}

async fn send(app: &common::TestApp, token: &str, invoice_id: &str) {
    let resp = app
        .client
        .put(app.url(&format!("/api/v1/invoices/{invoice_id}")))
        .bearer_auth(token)
        .json(&json!({ "status": "sent", "delivery": { "method": "other", "note": "Test seed, delivered outside Mokosh" } }))
        .send()
        .await
        .expect("send invoice");
    assert!(
        resp.status().is_success(),
        "send invoice: {}",
        resp.status()
    );
}

async fn record_payment(
    app: &common::TestApp,
    token: &str,
    company_id: Uuid,
    invoice_id: &str,
    amount: &str,
) -> Uuid {
    let resp = app
        .client
        .post(app.url("/api/v1/payments"))
        .bearer_auth(token)
        .json(&json!({
            "invoice_id": invoice_id,
            "company_id": company_id,
            "payment_date": "2026-09-05",
            "amount": amount,
            "payment_method": "wire",
        }))
        .send()
        .await
        .expect("record payment");
    assert!(
        resp.status().is_success(),
        "record payment: {}",
        resp.status()
    );
    let body: Value = resp.json().await.expect("payment json");
    body["id"]
        .as_str()
        .and_then(|id| Uuid::parse_str(id).ok())
        .expect("the payment's id")
}

async fn ledger(app: &common::TestApp, token: &str, invoice_id: &str) -> Value {
    let resp = app
        .client
        // The route is `/payments`, not `/ledger`: PMS-1088 named the response
        // the ledger and hung it off the invoice's payments path.
        .get(app.url(&format!("/api/v1/invoices/{invoice_id}/payments")))
        .bearer_auth(token)
        .send()
        .await
        .expect("read the ledger");
    assert!(resp.status().is_success(), "ledger: {}", resp.status());
    resp.json().await.expect("ledger json")
}

async fn invoice(app: &common::TestApp, token: &str, invoice_id: &str) -> Value {
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/invoices/{invoice_id}")))
        .bearer_auth(token)
        .send()
        .await
        .expect("read the invoice");
    assert!(resp.status().is_success(), "invoice: {}", resp.status());
    resp.json().await.expect("invoice json")
}

/// Parse a money field the API serialises as a string, so the assertions below
/// compare numbers rather than spellings ("100.00" against "100.0").
fn money(value: &Value, field: &str) -> Decimal {
    let raw = value[field]
        .as_str()
        .unwrap_or_else(|| panic!("{field} is a string on {value}"));
    raw.parse()
        .unwrap_or_else(|e| panic!("{field} = {raw:?} is not a decimal: {e}"))
}

/// The whole arithmetic, step by step: a send, a partial payment, a refund of
/// part of it, and a credit note. After each, the ledger's totals and the
/// invoice's own numbers have to tell the same story.
#[mokosh_test]
async fn the_ledger_and_the_balance_agree_at_every_step(pool: PgPool) {
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    common::seed_billing_contact(&pool, company_id).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &pw).await;

    let inv = draft_invoice(&app, &token, company_id).await;
    let id = inv["id"].as_str().expect("id").to_string();
    let total = money(&inv, "total");
    send(&app, &token, &id).await;

    // Nothing has moved: an empty ledger, and the whole total outstanding.
    let led = ledger(&app, &token, &id).await;
    let read = invoice(&app, &token, &id).await;
    assert_eq!(money(&led, "total_paid"), Decimal::ZERO);
    assert_eq!(money(&led, "total_refunded"), Decimal::ZERO);
    assert_eq!(money(&read, "balance_due"), total);

    // A partial payment. The ledger's total and the invoice's `amount_paid` are
    // two readers of the same rows and must not diverge.
    let payment_id = record_payment(&app, &token, company_id, &id, "400.00").await;
    let led = ledger(&app, &token, &id).await;
    let read = invoice(&app, &token, &id).await;
    assert_eq!(money(&led, "total_paid"), Decimal::new(40000, 2));
    assert_eq!(
        money(&led, "total_paid"),
        money(&read, "amount_paid"),
        "the ledger's total and the invoice's amount_paid read the same rows"
    );
    assert_eq!(
        money(&read, "balance_due"),
        total - money(&led, "total_paid") + money(&led, "total_refunded"),
        "balance = total - paid + refunded"
    );
    assert_eq!(read["status"], "partially_paid");
    let payments = led["payments"].as_array().expect("payments");
    assert_eq!(payments.len(), 1);
    assert_eq!(payments[0]["id"], payment_id.to_string());

    // A refund of part of that payment gives money back, so the balance grows
    // again. `amount_paid` is net of refunds, which is what makes the refund
    // visible in both places rather than only in the ledger.
    sqlx::query(
        "INSERT INTO payment_refunds \
            (tenant_id, payment_id, invoice_id, amount, provider, provider_reference) \
         VALUES ($1, $2, $3, $4, 'stripe', $5)",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(payment_id)
    .bind(Uuid::parse_str(&id).expect("invoice id"))
    .bind(Decimal::new(15000, 2))
    .bind(format!("re_{}", Uuid::new_v4().simple()))
    .execute(&pool)
    .await
    .expect("seed the refund");
    // The balance is derived on a money event, so a hand-seeded refund needs one
    // to be folded in; recording a further payment is the event, and it also
    // keeps the arithmetic honest with two payments and one refund in play.
    record_payment(&app, &token, company_id, &id, "100.00").await;

    let led = ledger(&app, &token, &id).await;
    let read = invoice(&app, &token, &id).await;
    assert_eq!(money(&led, "total_paid"), Decimal::new(50000, 2));
    assert_eq!(money(&led, "total_refunded"), Decimal::new(15000, 2));
    assert_eq!(led["refunds"].as_array().expect("refunds").len(), 1);
    assert_eq!(
        money(&read, "amount_paid"),
        money(&led, "total_paid") - money(&led, "total_refunded"),
        "the invoice's amount_paid is the ledger's payments net of its refunds"
    );
    assert_eq!(
        money(&read, "balance_due"),
        total - money(&read, "amount_paid"),
        "and the balance follows from it"
    );

    // A credit note reduces what is owed without moving money, so it belongs to
    // the invoice's numbers and NOT to the ledger. Both halves are asserted,
    // because folding it in as a negative payment would tell the customer they
    // had paid something they had not.
    let credit = app
        .client
        .post(app.url("/api/v1/credit-notes"))
        .bearer_auth(&token)
        .json(&json!({
            "invoice_id": id,
            "reason": "Goodwill for the September outage",
            "lines": [{
                // `line_type` is required on a credit-note line, the way
                // tests/credit_notes.rs sends it.
                "line_type": "adjustment",
                "description": "Service credit",
                "quantity": "1",
                "unit_price": "50.00",
            }],
        }))
        .send()
        .await
        .expect("raise a credit note");
    assert!(
        credit.status().is_success(),
        "credit note: {}",
        credit.status()
    );

    let led = ledger(&app, &token, &id).await;
    let read = invoice(&app, &token, &id).await;
    assert_eq!(
        money(&led, "total_paid"),
        Decimal::new(50000, 2),
        "a credit note is not a payment"
    );
    assert_eq!(
        money(&led, "total_refunded"),
        Decimal::new(15000, 2),
        "nor a refund"
    );
    assert_eq!(money(&read, "amount_credited"), Decimal::new(5000, 2));
    assert_eq!(
        money(&read, "balance_due"),
        total - money(&read, "amount_paid") - money(&read, "amount_credited"),
        "balance = total - paid (net of refunds) - credited"
    );
}

/// An invoice nobody has paid has an empty ledger rather than no ledger, and the
/// totals are zero rather than absent: a client rendering a payment history needs
/// the same shape whether or not there is one.
#[mokosh_test]
async fn an_unpaid_invoice_has_an_empty_ledger_rather_than_a_missing_one(pool: PgPool) {
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    common::seed_billing_contact(&pool, company_id).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &pw).await;

    let inv = draft_invoice(&app, &token, company_id).await;
    let id = inv["id"].as_str().expect("id").to_string();

    let led = ledger(&app, &token, &id).await;
    assert_eq!(led["invoice_id"], id.as_str());
    assert!(led["payments"].as_array().expect("payments").is_empty());
    assert!(led["refunds"].as_array().expect("refunds").is_empty());
    assert_eq!(money(&led, "total_paid"), Decimal::ZERO);
    assert_eq!(money(&led, "total_refunded"), Decimal::ZERO);
    assert_eq!(
        led["currency"], inv["currency"],
        "the ledger reports the invoice's own currency, not a default"
    );
}
