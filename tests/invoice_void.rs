//! PMS-1333: voiding an invoice, as its own act.
//!
//! Voiding used to happen BY crediting: an invoice credited for its full total
//! was moved to `void` (PMS-953, narrowed by PMS-1226). That read a credited
//! invoice as a cancelled one, which it is not, and it left `void` with no
//! writer of its own once the arm came out - the state PMS-953 had found it
//! in. Three comments already named a `void_invoice` that did not exist, and
//! PMS-1227 had closed the one path a client used (`PUT /invoices/{id}` with
//! `{"status":"void"}`), so voiding a draft answered 422 pointing at a method
//! nobody had written.
//!
//! What it means here: a void says the document never stood. That is why it is
//! allowed only from `draft` and `pending` - past those the customer holds a
//! copy and the correction is a credit note - and why it freezes no amount the
//! way a write-off does.

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

async fn draft_invoice(
    app: &common::TestApp,
    token: &str,
    company_id: Uuid,
    amount: &str,
) -> String {
    let resp = app
        .client
        .post(app.url("/api/v1/invoices"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "company_id": company_id,
            "invoice_date": "2026-06-05",
            "due_date": "2026-07-05",
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
        .json(&serde_json::json!({ "status": "sent", "skip_email": true }))
        .send()
        .await
        .expect("send invoice");
    assert!(resp.status().is_success(), "got {}", resp.status());
}

async fn void(
    app: &common::TestApp,
    token: &str,
    invoice_id: &str,
    body: Value,
) -> reqwest::Response {
    app.client
        .post(app.url(&format!("/api/v1/invoices/{invoice_id}/void")))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("send void")
}

async fn get_invoice(app: &common::TestApp, token: &str, invoice_id: &str) -> Value {
    app.client
        .get(app.url(&format!("/api/v1/invoices/{invoice_id}")))
        .bearer_auth(token)
        .send()
        .await
        .expect("send get invoice")
        .json()
        .await
        .expect("invoice JSON")
}

/// The case the endpoint exists for: a draft raised in error is withdrawn, on
/// the record, with who and why on the row.
#[sqlx::test]
async fn a_draft_is_voided_with_who_and_why(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let company_id = common::seed_company(&pool).await;
    let invoice_id = draft_invoice(&app, &token, company_id, "900").await;

    let resp = void(
        &app,
        &token,
        &invoice_id,
        serde_json::json!({ "reason": "Raised against the wrong company" }),
    )
    .await;
    assert!(
        resp.status().is_success(),
        "void should 2xx: {}",
        resp.status()
    );
    let body: Value = resp.json().await.expect("void JSON");
    assert_eq!(body["status"].as_str(), Some("void"));

    let after = get_invoice(&app, &token, &invoice_id).await;
    assert_eq!(after["status"].as_str(), Some("void"));
    assert!(!after["voided_at"].is_null(), "{after}");
    assert_eq!(
        after["voided_by_id"].as_str(),
        Some(admin_id.to_string().as_str())
    );
    assert_eq!(
        after["void_reason"].as_str(),
        Some("Raised against the wrong company")
    );
    assert!(
        !after["voided_by_name"].as_str().unwrap_or("").is_empty(),
        "the detail read names who voided it, the way it names who wrote one off: {after}"
    );
    // A void freezes no amount: nothing was ever owed.
    assert_eq!(dec(&after["total"]), Decimal::from(900));
    assert!(after["write_off_amount"].is_null());
}

/// The reason is optional, because a draft withdrawn before anyone saw it
/// often has nothing to say. An empty one is stored as none rather than as a
/// blank string.
#[sqlx::test]
async fn the_reason_is_optional_and_blank_is_none(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let company_id = common::seed_company(&pool).await;

    for body in [
        serde_json::json!({}),
        serde_json::json!({ "reason": "   " }),
    ] {
        let invoice_id = draft_invoice(&app, &token, company_id, "100").await;
        let resp = void(&app, &token, &invoice_id, body.clone()).await;
        assert!(resp.status().is_success(), "{body}: {}", resp.status());
        let after = get_invoice(&app, &token, &invoice_id).await;
        assert_eq!(after["status"].as_str(), Some("void"));
        assert!(after["void_reason"].is_null(), "{body}: {after}");
    }
}

/// Past `pending` the customer holds a copy, so the invoice is frozen and the
/// correction is a credit note. The refusal names the status and says so,
/// because "cannot be voided" alone does not tell the operator what to do.
#[sqlx::test]
async fn a_sent_invoice_cannot_be_voided(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let company_id = common::seed_company(&pool).await;
    // PMS-993: an invoice cannot be sent without a billing contact.
    common::seed_billing_contact(&pool, company_id).await;
    let invoice_id = draft_invoice(&app, &token, company_id, "500").await;
    send(&app, &token, &invoice_id).await;

    let resp = void(&app, &token, &invoice_id, serde_json::json!({})).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let body: Value = resp.json().await.expect("refusal JSON");
    let text = body.to_string();
    assert!(
        text.contains("sent"),
        "the refusal names the status: {text}"
    );
    assert!(
        text.contains("credit note"),
        "and points at the correction that does work: {text}"
    );

    let after = get_invoice(&app, &token, &invoice_id).await;
    assert_eq!(after["status"].as_str(), Some("sent"), "unchanged: {after}");
    assert!(after["voided_at"].is_null());
}

/// Voiding twice is a conflict, not a silent second no-op: the second caller
/// is acting on a document that is already gone.
#[sqlx::test]
async fn voiding_twice_is_refused(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let company_id = common::seed_company(&pool).await;
    let invoice_id = draft_invoice(&app, &token, company_id, "300").await;

    assert!(void(&app, &token, &invoice_id, serde_json::json!({}))
        .await
        .status()
        .is_success());
    let again = void(&app, &token, &invoice_id, serde_json::json!({})).await;
    assert_eq!(again.status(), StatusCode::CONFLICT);
}

/// A payment recorded afterwards cannot derive the status back: `voided_at`
/// leads `recompute_invoice_balance`'s CASE for the reason `written_off_at`
/// does, because every payment and credit event runs that statement.
#[sqlx::test]
async fn a_later_payment_does_not_unvoid_it(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let company_id = common::seed_company(&pool).await;
    let invoice_id = draft_invoice(&app, &token, company_id, "700").await;
    assert!(void(&app, &token, &invoice_id, serde_json::json!({}))
        .await
        .status()
        .is_success());

    let payment = app
        .client
        .post(app.url("/api/v1/payments"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "invoice_id": invoice_id,
            "company_id": company_id,
            "payment_date": "2026-06-20",
            "amount": "700",
            "payment_method": "check",
        }))
        .send()
        .await
        .expect("send payment");
    // Whether the payment is accepted is not what this test pins; what it pins
    // is that the status somebody chose is still there afterwards.
    let _ = payment.status();

    let after = get_invoice(&app, &token, &invoice_id).await;
    assert_eq!(after["status"].as_str(), Some("void"), "{after}");
    assert!(!after["voided_at"].is_null());
}

/// The void is an audit row on the invoice, the way the write-off is: the
/// question "who cancelled this and when" is answered from the history.
#[sqlx::test]
async fn voiding_writes_an_audit_row(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let company_id = common::seed_company(&pool).await;
    let invoice_id = draft_invoice(&app, &token, company_id, "250").await;
    assert!(void(
        &app,
        &token,
        &invoice_id,
        serde_json::json!({ "reason": "Duplicate of INV-000100" })
    )
    .await
    .status()
    .is_success());

    let rows: Vec<(String, Option<Value>)> = sqlx::query_as(
        "SELECT action, new_values FROM audit_log \
         WHERE tenant_id = $1 AND entity_type = 'invoices' AND entity_id = $2 \
         ORDER BY \"timestamp\"",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(Uuid::from_str(&invoice_id).expect("invoice id"))
    .fetch_all(&pool)
    .await
    .expect("audit rows");
    assert!(
        rows.iter().any(|(_, new)| new
            .as_ref()
            .and_then(|v| v["status"].as_str())
            .is_some_and(|s| s == "void")),
        "the void is in the history: {rows:?}"
    );
}
