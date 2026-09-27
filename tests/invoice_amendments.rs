//! PMS-1334: a sent invoice is replaced, not edited.
//!
//! The model is Stripe's revision (docs.stripe.com/invoicing/invoice-edits),
//! and the ordering is the part worth testing: creating the amendment does
//! nothing to the invoice it amends, and SENDING the amendment is what voids it.
//! That is what lets an operator start a correction, change their mind, and
//! leave the customer holding an invoice that is still the invoice.
//!
//! The refusals are the other half. Each one has a different instrument behind
//! it - a draft is edited, a paid invoice is credited - so each is asserted with
//! the message that says which, because a 409 with no direction is how PMS-977
//! described the defect it fixed.

mod common;

use mokosh_test::mokosh_test;
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
            "invoice_date": "2026-08-01",
            "due_date": "2026-08-31",
            "lines": [
                {
                    "line_type": "service",
                    "description": "Managed services, August",
                    "quantity": "1",
                    "unit_price": "1200.00",
                },
                {
                    "line_type": "service",
                    "description": "Out of hours callout",
                    "quantity": "2",
                    "unit_price": "150.00",
                },
            ],
        }))
        .send()
        .await
        .expect("create invoice");
    assert!(resp.status().is_success(), "create invoice");
    resp.json().await.expect("json")
}

async fn send(app: &common::TestApp, token: &str, invoice_id: &str) -> reqwest::Response {
    app.client
        .put(app.url(&format!("/api/v1/invoices/{invoice_id}")))
        .bearer_auth(token)
        .json(&json!({ "status": "sent", "skip_email": true }))
        .send()
        .await
        .expect("send invoice")
}

async fn amend(app: &common::TestApp, token: &str, invoice_id: &str) -> reqwest::Response {
    app.client
        .post(app.url(&format!("/api/v1/invoices/{invoice_id}/amend")))
        .bearer_auth(token)
        .send()
        .await
        .expect("amend invoice")
}

async fn record_payment(
    app: &common::TestApp,
    token: &str,
    company_id: Uuid,
    invoice_id: &str,
    amount: &str,
) -> (reqwest::StatusCode, String) {
    let resp = app
        .client
        .post(app.url("/api/v1/payments"))
        .bearer_auth(token)
        .json(&json!({
            "invoice_id": invoice_id,
            "company_id": company_id,
            "amount": amount,
            "payment_method": "wire",
            "payment_date": "2026-08-05",
        }))
        .send()
        .await
        .expect("record payment");
    let status = resp.status();
    (status, resp.text().await.expect("body"))
}

async fn get_invoice(app: &common::TestApp, token: &str, invoice_id: &str) -> Value {
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/invoices/{invoice_id}")))
        .bearer_auth(token)
        .send()
        .await
        .expect("read invoice");
    assert!(resp.status().is_success(), "read invoice");
    resp.json().await.expect("json")
}

struct Fixture {
    app: common::TestApp,
    token: String,
    company_id: Uuid,
}

async fn setup(pool: &PgPool) -> Fixture {
    let (_id, email, pw) = common::seed_admin(pool).await;
    let company_id = common::seed_company(pool).await;
    // PMS-993: an invoice cannot be sent without somebody to send it to.
    common::seed_billing_contact(pool, company_id).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &pw).await;
    Fixture {
        app,
        token,
        company_id,
    }
}

/// The whole flow, and the ordering inside it: amend leaves the original alone,
/// sending the amendment voids it, and the two are linked in both directions.
#[mokosh_test]
async fn amending_a_sent_invoice_replaces_it_when_the_amendment_is_sent(pool: PgPool) {
    let f = setup(&pool).await;
    let original = draft_invoice(&f.app, &f.token, f.company_id).await;
    let original_id = original["id"].as_str().expect("id").to_string();
    let original_number = original["invoice_number"]
        .as_str()
        .expect("number")
        .to_string();
    assert!(send(&f.app, &f.token, &original_id)
        .await
        .status()
        .is_success());

    let resp = amend(&f.app, &f.token, &original_id).await;
    assert!(
        resp.status().is_success(),
        "amending a sent invoice should succeed, got {}",
        resp.status()
    );
    let amendment: Value = resp.json().await.expect("json");
    let amendment_id = amendment["id"].as_str().expect("id").to_string();

    // The amendment is a draft, carries the lines, and names what it replaces.
    assert_eq!(amendment["status"], "draft");
    assert_eq!(amendment["amends_invoice_id"], original_id.as_str());
    assert_ne!(
        amendment["invoice_number"], original["invoice_number"],
        "an amendment is its own document and gets its own number"
    );
    let lines = amendment["lines"].as_array().expect("lines");
    assert_eq!(lines.len(), 2, "both lines came across");
    assert_eq!(lines[0]["description"], "Managed services, August");
    assert_eq!(amendment["total"], original["total"]);
    // Nothing that belongs to the document that was SENT came with it.
    assert!(amendment["sent_at"].is_null(), "an amendment starts unsent");
    assert!(amendment["emailed_to"].is_null());
    assert_eq!(amendment["amount_paid"], "0");

    // AC: the original is not mutated by an amend.
    let still_sent = get_invoice(&f.app, &f.token, &original_id).await;
    assert_eq!(
        still_sent["status"], "sent",
        "creating the amendment must not touch the invoice the customer holds"
    );
    assert_eq!(still_sent["balance_due"], original["total"]);
    assert!(still_sent["voided_at"].is_null());
    // And it already knows what is being written to replace it.
    assert_eq!(
        still_sent["amended_by"]["id"],
        amendment_id.as_str(),
        "the original resolves its amendment without storing a second link"
    );
    assert_eq!(still_sent["amended_by"]["status"], "draft");

    // Sending the amendment is the act that replaces it.
    assert!(send(&f.app, &f.token, &amendment_id)
        .await
        .status()
        .is_success());
    let replaced = get_invoice(&f.app, &f.token, &original_id).await;
    assert_eq!(replaced["status"], "void", "the replaced invoice is voided");
    assert!(replaced["voided_at"].as_str().is_some());
    assert_eq!(
        replaced["balance_due"], "0",
        "a voided document is zero-value, so it is not owed and not overdue"
    );
    assert_eq!(
        replaced["void_reason"],
        format!(
            "Replaced by invoice {}",
            amendment["invoice_number"].as_str().expect("number")
        ),
        "the reason names the invoice the customer should be holding"
    );
    assert_eq!(replaced["amended_by"]["status"], "sent");

    let sent_amendment = get_invoice(&f.app, &f.token, &amendment_id).await;
    assert_eq!(sent_amendment["status"], "sent");
    assert_eq!(
        sent_amendment["amends_invoice_id"],
        original_id.as_str(),
        "the link survives the send, so the pair stays traceable"
    );
    assert!(
        !original_number.is_empty(),
        "the replaced number stays addressable, which is what a void keeps"
    );
}

/// A draft is edited in place, so amending one is refused and says so.
#[mokosh_test]
async fn a_draft_is_edited_rather_than_amended(pool: PgPool) {
    let f = setup(&pool).await;
    let invoice = draft_invoice(&f.app, &f.token, f.company_id).await;
    let id = invoice["id"].as_str().expect("id");

    let resp = amend(&f.app, &f.token, id).await;
    assert_eq!(resp.status(), reqwest::StatusCode::CONFLICT);
    let body = resp.text().await.expect("body");
    assert!(
        body.contains("has not been sent yet"),
        "the refusal points at editing instead: {body}"
    );
}

/// A payment against the invoice makes the void wrong, so the credit note is
/// the instrument and the refusal names it.
#[mokosh_test]
async fn an_invoice_with_a_payment_is_credited_rather_than_amended(pool: PgPool) {
    let f = setup(&pool).await;
    let invoice = draft_invoice(&f.app, &f.token, f.company_id).await;
    let id = invoice["id"].as_str().expect("id").to_string();
    assert!(send(&f.app, &f.token, &id).await.status().is_success());

    let (status, body) = record_payment(&f.app, &f.token, f.company_id, &id, "100.00").await;
    assert!(status.is_success(), "record payment: {status} {body}");

    let resp = amend(&f.app, &f.token, &id).await;
    assert_eq!(resp.status(), reqwest::StatusCode::CONFLICT);
    let body = resp.text().await.expect("body");
    assert!(
        body.contains("credit note"),
        "the refusal names the right instrument: {body}"
    );
}

/// One draft amendment at a time (Stripe's constraint), so "what replaces this
/// invoice" has one answer while the correction is being written.
#[mokosh_test]
async fn a_second_draft_amendment_is_refused(pool: PgPool) {
    let f = setup(&pool).await;
    let invoice = draft_invoice(&f.app, &f.token, f.company_id).await;
    let id = invoice["id"].as_str().expect("id").to_string();
    assert!(send(&f.app, &f.token, &id).await.status().is_success());

    let first = amend(&f.app, &f.token, &id).await;
    assert!(first.status().is_success(), "the first amendment is fine");
    let first_body: Value = first.json().await.expect("json");

    let second = amend(&f.app, &f.token, &id).await;
    assert_eq!(second.status(), reqwest::StatusCode::CONFLICT);
    let body = second.text().await.expect("body");
    assert!(
        body.contains(
            first_body["invoice_number"]
                .as_str()
                .expect("the first amendment's number")
        ),
        "the refusal names the draft already open: {body}"
    );
}

/// The preconditions are re-checked when the amendment is sent, not trusted
/// from when it was created: a payment can land against the original while the
/// draft sits, and then the void would orphan it.
#[mokosh_test]
async fn a_payment_after_the_draft_blocks_the_send(pool: PgPool) {
    let f = setup(&pool).await;
    let invoice = draft_invoice(&f.app, &f.token, f.company_id).await;
    let id = invoice["id"].as_str().expect("id").to_string();
    assert!(send(&f.app, &f.token, &id).await.status().is_success());

    let amendment: Value = amend(&f.app, &f.token, &id)
        .await
        .json()
        .await
        .expect("json");
    let amendment_id = amendment["id"].as_str().expect("id").to_string();

    let (status, body) = record_payment(&f.app, &f.token, f.company_id, &id, "50.00").await;
    assert!(status.is_success(), "record payment: {status} {body}");

    let resp = send(&f.app, &f.token, &amendment_id).await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::CONFLICT,
        "sending must refuse once the original has money against it"
    );
    let body = resp.text().await.expect("body");
    assert!(body.contains("credit note"), "{body}");

    // And the refusal left both documents as they were.
    let original = get_invoice(&f.app, &f.token, &id).await;
    assert_eq!(original["status"], "partially_paid");
    assert!(original["voided_at"].is_null(), "nothing was voided");
    let still_draft = get_invoice(&f.app, &f.token, &amendment_id).await;
    assert_eq!(still_draft["status"], "draft");
}

/// An amendment can itself be amended, and the original then points at the
/// newest one, because what a reader wants to know is where the chain ended up.
#[mokosh_test]
async fn an_amendment_can_be_amended_and_the_chain_resolves_forward(pool: PgPool) {
    let f = setup(&pool).await;
    let first = draft_invoice(&f.app, &f.token, f.company_id).await;
    let first_id = first["id"].as_str().expect("id").to_string();
    assert!(send(&f.app, &f.token, &first_id)
        .await
        .status()
        .is_success());

    let second: Value = amend(&f.app, &f.token, &first_id)
        .await
        .json()
        .await
        .expect("json");
    let second_id = second["id"].as_str().expect("id").to_string();
    assert!(send(&f.app, &f.token, &second_id)
        .await
        .status()
        .is_success());

    let third: Value = amend(&f.app, &f.token, &second_id)
        .await
        .json()
        .await
        .expect("json");
    let third_id = third["id"].as_str().expect("id").to_string();
    assert!(send(&f.app, &f.token, &third_id)
        .await
        .status()
        .is_success());

    let first_read = get_invoice(&f.app, &f.token, &first_id).await;
    assert_eq!(first_read["status"], "void");
    assert_eq!(
        first_read["amended_by"]["id"],
        second_id.as_str(),
        "each invoice names the one that replaced IT, not the end of the chain"
    );
    let second_read = get_invoice(&f.app, &f.token, &second_id).await;
    assert_eq!(second_read["status"], "void");
    assert_eq!(second_read["amended_by"]["id"], third_id.as_str());
    let third_read = get_invoice(&f.app, &f.token, &third_id).await;
    assert_eq!(third_read["status"], "sent");
    assert!(
        third_read["amended_by"].is_null(),
        "the live invoice is the one nothing has replaced"
    );
}

/// A voided invoice has nothing to replace, and the refusal says where to go.
#[mokosh_test]
async fn a_voided_invoice_cannot_be_amended(pool: PgPool) {
    let f = setup(&pool).await;
    let invoice = draft_invoice(&f.app, &f.token, f.company_id).await;
    let id = invoice["id"].as_str().expect("id").to_string();
    assert!(send(&f.app, &f.token, &id).await.status().is_success());
    let amendment: Value = amend(&f.app, &f.token, &id)
        .await
        .json()
        .await
        .expect("json");
    let amendment_id = amendment["id"].as_str().expect("id").to_string();
    assert!(send(&f.app, &f.token, &amendment_id)
        .await
        .status()
        .is_success());

    let resp = amend(&f.app, &f.token, &id).await;
    assert_eq!(resp.status(), reqwest::StatusCode::CONFLICT);
    let body = resp.text().await.expect("body");
    assert!(
        body.contains("is void"),
        "the refusal points at the invoice that replaced it: {body}"
    );
}
