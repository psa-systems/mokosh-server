//! PMS-1036: write off an invoice that will not be paid, distinct from
//! crediting it.
//!
//! `written_off` was a status the model knew and nothing wrote. A credit note
//! says the customer did not owe this and reduces revenue; a write-off says
//! they did and will not pay, a bad-debt expense. So the write-off freezes the
//! balance at that moment in `write_off_amount`, leaves `balance_due` alone
//! (the debt was not forgiven), and a payment recorded afterwards is a
//! recovery: kept, with the status standing. The statement shows the
//! write-off as its own line kind and takes it out of the closing balance.

mod common;

use reqwest::StatusCode;
use rust_decimal::Decimal;
use serde_json::Value;
use sqlx::PgPool;
use std::str::FromStr;
use uuid::Uuid;

fn dec(v: &Value) -> Decimal {
    Decimal::from_str(v.as_str().unwrap_or("0")).expect("decimal")
}

async fn invoice_on(
    app: &common::TestApp,
    token: &str,
    company_id: Uuid,
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
    assert_eq!(resp.status(), StatusCode::OK, "create invoice");
    let invoice: Value = resp.json().await.expect("invoice JSON");
    invoice["id"].as_str().expect("invoice id").to_string()
}

async fn send(app: &common::TestApp, token: &str, invoice_id: &str) {
    let resp = app
        .client
        .put(app.url(&format!("/api/v1/invoices/{invoice_id}")))
        .bearer_auth(token)
        .json(&serde_json::json!({ "status": "sent", "skip_email": true }))
        .send()
        .await
        .expect("send invoice");
    assert_eq!(resp.status(), StatusCode::OK, "send");
}

async fn pay(app: &common::TestApp, token: &str, company_id: Uuid, invoice_id: &str, amount: &str) {
    let resp = app
        .client
        .post(app.url("/api/v1/payments"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "invoice_id": invoice_id,
            "company_id": company_id,
            "payment_date": "2026-03-10",
            "amount": amount,
            "payment_method": "check",
        }))
        .send()
        .await
        .expect("send payment");
    assert_eq!(resp.status(), StatusCode::OK, "pay");
}

async fn credit_in_full(app: &common::TestApp, token: &str, invoice_id: &str, amount: &str) {
    let resp = app
        .client
        .post(app.url("/api/v1/credit-notes"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "invoice_id": invoice_id,
            "issue_date": "2026-03-10",
            "reason": "Should not have been issued",
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
    assert_eq!(resp.status(), StatusCode::OK, "credit");
}

async fn write_off(
    app: &common::TestApp,
    token: &str,
    invoice_id: &str,
    reason: &str,
) -> reqwest::Response {
    app.client
        .post(app.url(&format!("/api/v1/invoices/{invoice_id}/write-off")))
        .bearer_auth(token)
        .json(&serde_json::json!({ "reason": reason }))
        .send()
        .await
        .expect("send write-off")
}

async fn get_invoice(app: &common::TestApp, token: &str, invoice_id: &str) -> Value {
    app.client
        .get(app.url(&format!("/api/v1/invoices/{invoice_id}")))
        .bearer_auth(token)
        .send()
        .await
        .expect("get invoice")
        .json()
        .await
        .expect("invoice JSON")
}

/// A sent invoice with a balance is written off with a reason; the response
/// and the read carry the status, the frozen amount, who did it and why,
/// and the balance itself is left as it was.
#[sqlx::test]
async fn a_sent_invoice_with_a_balance_is_written_off_with_a_reason(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company = common::seed_company(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let invoice = invoice_on(&app, &token, company, "2026-03-01", "500").await;
    send(&app, &token, &invoice).await;
    pay(&app, &token, company, &invoice, "100").await;

    let resp = write_off(&app, &token, &invoice, "Customer ceased trading").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.expect("write-off JSON");
    assert_eq!(body["status"], "written_off");
    assert_eq!(dec(&body["write_off_amount"]), Decimal::from(400));
    assert_eq!(body["write_off_reason"], "Customer ceased trading");
    assert_eq!(body["written_off_by_id"], admin_id.to_string());
    assert!(body["written_off_at"].is_string());
    assert_eq!(
        dec(&body["balance_due"]),
        Decimal::from(400),
        "the debt stands"
    );

    let read = get_invoice(&app, &token, &invoice).await;
    assert_eq!(read["status"], "written_off");
    assert_eq!(dec(&read["write_off_amount"]), Decimal::from(400));

    let audited: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log WHERE entity_type = 'invoices' AND entity_id = $1 \
         AND action = 'update' AND new_values->>'status' = 'written_off'",
    )
    .bind(Uuid::parse_str(&invoice).unwrap())
    .fetch_one(&pool)
    .await
    .expect("audit rows");
    assert_eq!(audited, 1, "the decision lands in the audit log");

    // Twice is a refusal naming the status.
    let again = write_off(&app, &token, &invoice, "again").await;
    assert_eq!(again.status(), StatusCode::CONFLICT);
    let text = again.text().await.unwrap_or_default();
    assert!(text.contains("written_off"), "{text}");
}

/// A draft, a paid, a void and an already written-off invoice are refused
/// with a 409 that names the status; a missing reason is a 422.
#[sqlx::test]
async fn the_wrong_states_and_a_missing_reason_are_refused(pool: PgPool) {
    let (_admin, email, password) = common::seed_admin(&pool).await;
    let company = common::seed_company(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let draft = invoice_on(&app, &token, company, "2026-03-01", "100").await;
    let paid = invoice_on(&app, &token, company, "2026-03-01", "100").await;
    send(&app, &token, &paid).await;
    pay(&app, &token, company, &paid, "100").await;
    let void = invoice_on(&app, &token, company, "2026-03-01", "100").await;
    send(&app, &token, &void).await;
    credit_in_full(&app, &token, &void, "100").await;
    assert_eq!(get_invoice(&app, &token, &void).await["status"], "void");

    for (id, status) in [(&draft, "draft"), (&paid, "paid"), (&void, "void")] {
        let resp = write_off(&app, &token, id, "no").await;
        assert_eq!(resp.status(), StatusCode::CONFLICT, "{status}");
        let text = resp.text().await.unwrap_or_default();
        assert!(text.contains(status), "names the status: {text}");
    }

    let sent = invoice_on(&app, &token, company, "2026-03-01", "100").await;
    send(&app, &token, &sent).await;
    let blank = write_off(&app, &token, &sent, "   ").await;
    assert_eq!(blank.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(get_invoice(&app, &token, &sent).await["status"], "sent");
}

/// A payment after the write-off is a recovery: recorded, the balance moves,
/// and the status stays `written_off` rather than flipping back to
/// `partially_paid` on the next balance recomputation.
#[sqlx::test]
async fn a_late_payment_is_kept_and_the_status_stands(pool: PgPool) {
    let (_admin, email, password) = common::seed_admin(&pool).await;
    let company = common::seed_company(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let invoice = invoice_on(&app, &token, company, "2026-03-01", "300").await;
    send(&app, &token, &invoice).await;
    let resp = write_off(&app, &token, &invoice, "Disputed and abandoned").await;
    assert_eq!(resp.status(), StatusCode::OK);

    pay(&app, &token, company, &invoice, "50").await;
    let read = get_invoice(&app, &token, &invoice).await;
    assert_eq!(read["status"], "written_off");
    assert_eq!(dec(&read["amount_paid"]), Decimal::from(50));
    assert_eq!(dec(&read["balance_due"]), Decimal::from(250));
    assert_eq!(
        dec(&read["write_off_amount"]),
        Decimal::from(300),
        "the frozen amount does not follow the recovery"
    );

    // And the online payment path reports it as not payable, as it does void.
    let readiness: Value = app
        .client
        .get(app.url(&format!("/api/v1/invoices/{invoice}/payment-readiness")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("readiness")
        .json()
        .await
        .expect("readiness JSON");
    assert_eq!(readiness["invoice_payable"], false, "{readiness}");
}

/// The statement shows the write-off as its own line kind, dated by the
/// write-off, and takes it out of the closing balance; a write-off before
/// the period is in the opening balance.
#[sqlx::test]
async fn the_statement_shows_the_write_off_and_settles_it(pool: PgPool) {
    let (_admin, email, password) = common::seed_admin(&pool).await;
    let company = common::seed_company(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let invoice = invoice_on(&app, &token, company, "2026-02-15", "800").await;
    send(&app, &token, &invoice).await;
    pay(&app, &token, company, &invoice, "300").await;
    let resp = write_off(&app, &token, &invoice, "Went into administration").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let today = chrono::Utc::now().date_naive();

    let statement = |from: chrono::NaiveDate, to: chrono::NaiveDate| {
        let app = &app;
        let token = &token;
        async move {
            let resp = app
                .client
                .get(app.url(&format!(
                    "/api/v1/statements?company_id={company}&period_start={from}&period_end={to}"
                )))
                .bearer_auth(token)
                .send()
                .await
                .expect("statement");
            assert_eq!(resp.status(), StatusCode::OK);
            resp.json::<Value>().await.expect("statement JSON")
        }
    };

    // The period holding the invoice, the payment and today's write-off.
    let s = statement(chrono::NaiveDate::from_ymd_opt(2026, 2, 1).unwrap(), today).await;
    let write_offs = s["write_offs"].as_array().expect("write_offs");
    assert_eq!(write_offs.len(), 1, "{s}");
    assert_eq!(write_offs[0]["invoice_id"], invoice);
    assert_eq!(dec(&write_offs[0]["amount"]), Decimal::from(500));
    assert_eq!(write_offs[0]["reason"], "Went into administration");
    assert_eq!(write_offs[0]["write_off_date"], today.to_string());
    assert_eq!(dec(&s["total_written_off"]), Decimal::from(500));
    assert_eq!(dec(&s["total_invoiced"]), Decimal::from(800));
    assert_eq!(dec(&s["total_paid"]), Decimal::from(300));
    assert_eq!(dec(&s["closing_balance"]), Decimal::ZERO, "settled: {s}");
    assert_eq!(s["invoices"][0]["status"], "written_off");

    // A period after the write-off carries it in the opening balance.
    let later = statement(
        today + chrono::Duration::days(1),
        today + chrono::Duration::days(30),
    )
    .await;
    assert_eq!(dec(&later["opening_balance"]), Decimal::ZERO, "{later}");
    assert!(later["write_offs"].as_array().unwrap().is_empty());
    assert_eq!(dec(&later["closing_balance"]), Decimal::ZERO);

    // The statement document prints the table and the total.
    let pdf = app
        .client
        .get(app.url(&format!(
            "/api/v1/statements/pdf?company_id={company}&period_start=2026-02-01&period_end={today}"
        )))
        .bearer_auth(&token)
        .send()
        .await
        .expect("statement pdf");
    assert_eq!(pdf.status(), StatusCode::OK);
}
