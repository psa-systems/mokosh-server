//! PMS-1001: the document names the person it was sent to.
//!
//! PMS-993 routed an invoice to a billing contact and PMS-1004 gave the
//! document a "Bill to" block, but the two did not meet: `update_invoice`
//! resolved the recipient from the company's default pointer and never wrote it
//! down, so an invoice created without a contact was emailed to a person and
//! addressed to an organization. These tests read the text back out of the
//! rendered bytes, so they assert on what a customer's PDF reader shows rather
//! than on what the service passed around.

mod common;

use printpdf::PdfDocument;
use reqwest::StatusCode;
use serde_json::{json, Value};
use sqlx::PgPool;
use std::path::PathBuf;
use uuid::Uuid;

fn install_test_attachment_env() {
    common::storage_root();
}

fn document_path(id: &str) -> PathBuf {
    common::storage_root()
        .join(common::DEFAULT_TENANT_ID.to_string())
        .join("documents")
        .join(id)
}

/// Read the text back out of rendered bytes, through printpdf's own parser so
/// this reads what a PDF reader reads.
fn extracted_text(bytes: &[u8]) -> String {
    let mut warnings = Vec::new();
    PdfDocument::parse(bytes, &printpdf::PdfParseOptions::default(), &mut warnings)
        .expect("the served bytes parse as a PDF")
        .extract_text()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("\n")
}

async fn seed_contact(pool: &PgPool, company_id: Uuid, first: &str, email: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contacts (id, tenant_id, company_id, email, first_name, last_name) \
         VALUES ($1, $2, $3, $4, $5, 'Payer')",
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .bind(email)
    .bind(first)
    .execute(pool)
    .await
    .expect("seed contact");
    id
}

async fn set_company_billing_contact(pool: &PgPool, company_id: Uuid, contact_id: Uuid) {
    sqlx::query(
        "UPDATE companies SET default_billing_contact_id = $3 WHERE tenant_id = $1 AND id = $2",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .bind(contact_id)
    .execute(pool)
    .await
    .expect("set the company's billing contact");
}

async fn invoice_contact(pool: &PgPool, invoice_id: &str) -> Option<Uuid> {
    sqlx::query_scalar("SELECT billing_contact_id FROM invoices WHERE tenant_id = $1 AND id = $2")
        .bind(common::DEFAULT_TENANT_ID)
        .bind(invoice_id.parse::<Uuid>().expect("uuid"))
        .fetch_one(pool)
        .await
        .expect("read the invoice's contact")
}

async fn draft_invoice(app: &common::TestApp, token: &str, company_id: Uuid) -> String {
    let resp = app
        .client
        .post(app.url("/api/v1/invoices"))
        .bearer_auth(token)
        .json(&json!({
            "company_id": company_id,
            "invoice_date": "2026-08-01",
            "due_date": "2026-08-31",
            "lines": [{
                "line_type": "service",
                "description": "Managed services, August",
                "quantity": "1",
                "unit_price": "1200.00",
            }],
        }))
        .send()
        .await
        .expect("create invoice");
    assert!(resp.status().is_success(), "create invoice");
    let invoice: Value = resp.json().await.expect("json");
    invoice["id"].as_str().expect("id").to_string()
}

async fn send_invoice(app: &common::TestApp, token: &str, invoice_id: &str, skip_email: bool) {
    let resp = app
        .client
        .put(app.url(&format!("/api/v1/invoices/{invoice_id}")))
        .bearer_auth(token)
        .json(&json!({ "status": "sent", "skip_email": skip_email }))
        .send()
        .await
        .expect("send invoice");
    assert!(
        resp.status().is_success(),
        "sending should 2xx, got {}: {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

async fn pdf(app: &common::TestApp, token: &str, path: &str) -> (StatusCode, Vec<u8>) {
    let resp = app
        .client
        .get(app.url(path))
        .bearer_auth(token)
        .send()
        .await
        .expect("pdf request");
    let status = resp.status();
    (status, resp.bytes().await.expect("bytes").to_vec())
}

/// The defect itself: an invoice the caller named no contact for is emailed to
/// the company's default billing contact, so the document has to name that
/// person. Since PMS-1016 the create path resolves that same pointer, so the
/// draft already carries the recipient and the send keeps it rather than
/// filling it in; either way the document names whoever was emailed.
#[sqlx::test]
async fn a_sent_invoice_names_the_person_it_was_emailed_to(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let contact_id = seed_contact(&pool, company_id, "Bill", "ap@client.example").await;
    set_company_billing_contact(&pool, company_id, contact_id).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &pw).await;

    let invoice_id = draft_invoice(&app, &token, company_id).await;
    assert_eq!(
        invoice_contact(&pool, &invoice_id).await,
        Some(contact_id),
        "PMS-1016: the create resolves the company's pointer, so the draft \
         already names who it is for"
    );

    send_invoice(&app, &token, &invoice_id, false).await;

    assert_eq!(
        invoice_contact(&pool, &invoice_id).await,
        Some(contact_id),
        "and the send records the person it emailed"
    );
    let (status, bytes) = pdf(&app, &token, &format!("/api/v1/invoices/{invoice_id}/pdf")).await;
    assert_eq!(status, StatusCode::OK);
    let text = extracted_text(&bytes);
    assert!(text.contains("Bill to"), "the block is there: {text:?}");
    assert!(
        text.contains("Attn: Bill Payer"),
        "and it names the recipient: {text:?}"
    );
    assert!(
        text.contains("ap@client.example"),
        "and their email address: {text:?}"
    );
}

/// The block is sourced from the invoice's own column, not from the company's
/// current pointer. Proven by deleting the stored document so the route has to
/// render live, then moving the company's pointer to somebody else: a render
/// that read the pointer would name the new person.
#[sqlx::test]
async fn reassigning_the_billing_role_does_not_change_an_issued_invoice(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let first = seed_contact(&pool, company_id, "Bill", "ap@client.example").await;
    set_company_billing_contact(&pool, company_id, first).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &pw).await;

    let invoice_id = draft_invoice(&app, &token, company_id).await;
    send_invoice(&app, &token, &invoice_id, false).await;
    let (_, stored) = pdf(&app, &token, &format!("/api/v1/invoices/{invoice_id}/pdf")).await;

    let second = seed_contact(&pool, company_id, "Nora", "nora@client.example").await;
    set_company_billing_contact(&pool, company_id, second).await;

    // Stored bytes first: the document a customer holds does not move.
    let (_, after) = pdf(&app, &token, &format!("/api/v1/invoices/{invoice_id}/pdf")).await;
    assert_eq!(after, stored, "the stored document is served unchanged");

    // Then force a live render, which is what a document issued before PMS-959
    // gets, and prove the source of the name is the invoice and not the pointer.
    std::fs::remove_file(document_path(&invoice_id)).expect("drop the stored document");
    let (status, rendered) = pdf(&app, &token, &format!("/api/v1/invoices/{invoice_id}/pdf")).await;
    assert_eq!(status, StatusCode::OK);
    let text = extracted_text(&rendered);
    assert!(
        text.contains("Attn: Bill Payer"),
        "a live re-render still names who it was sent to: {text:?}"
    );
    assert!(
        !text.contains("Nora"),
        "and never the person who holds the role today: {text:?}"
    );
}

/// An invoice sent with no contact anywhere prints the company and nothing
/// else: an empty labelled attention line is worse than none.
#[sqlx::test]
async fn an_invoice_with_no_contact_prints_no_attention_line(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &pw).await;

    let invoice_id = draft_invoice(&app, &token, company_id).await;
    send_invoice(&app, &token, &invoice_id, true).await;

    assert_eq!(
        invoice_contact(&pool, &invoice_id).await,
        None,
        "a hand-delivered invoice resolves nobody, so nobody is recorded"
    );
    let (status, bytes) = pdf(&app, &token, &format!("/api/v1/invoices/{invoice_id}/pdf")).await;
    assert_eq!(status, StatusCode::OK);
    let text = extracted_text(&bytes);
    assert!(
        text.contains("Acme Co"),
        "the bill is still owed by the company: {text:?}"
    );
    assert!(
        !text.contains("Attn:"),
        "and no empty attention line is printed: {text:?}"
    );
}

/// A credit note is addressed to whoever received the invoice it corrects, so
/// the two documents in one correction name the same person.
#[sqlx::test]
async fn a_credit_note_names_the_contact_of_the_invoice_it_corrects(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let contact_id = seed_contact(&pool, company_id, "Bill", "ap@client.example").await;
    set_company_billing_contact(&pool, company_id, contact_id).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &pw).await;

    let invoice_id = draft_invoice(&app, &token, company_id).await;
    send_invoice(&app, &token, &invoice_id, false).await;

    let resp = app
        .client
        .post(app.url("/api/v1/credit-notes"))
        .bearer_auth(&token)
        .json(&json!({
            "invoice_id": invoice_id,
            "reason": "Billed twice for August",
            "lines": [{
                "line_type": "service",
                "description": "Managed services, August",
                "quantity": "1",
                "unit_price": "200.00",
            }],
        }))
        .send()
        .await
        .expect("create credit note");
    assert!(resp.status().is_success(), "create credit note");
    let note: Value = resp.json().await.expect("json");
    let note_id = note["id"].as_str().expect("id").to_string();

    let (status, bytes) = pdf(&app, &token, &format!("/api/v1/credit-notes/{note_id}/pdf")).await;
    assert_eq!(status, StatusCode::OK);
    let text = extracted_text(&bytes);
    assert!(
        text.contains("Credit to"),
        "the credit note has the block too: {text:?}"
    );
    assert!(
        text.contains("Attn: Bill Payer") && text.contains("ap@client.example"),
        "naming the invoice's recipient: {text:?}"
    );
}

/// A statement names the company's CURRENT billing contact, because it stores
/// nothing and renders from today (PMS-954), exactly as its branding does.
#[sqlx::test]
async fn a_statement_names_the_companys_current_billing_contact(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let contact_id = seed_contact(&pool, company_id, "Bill", "ap@client.example").await;
    set_company_billing_contact(&pool, company_id, contact_id).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &pw).await;

    let invoice_id = draft_invoice(&app, &token, company_id).await;
    send_invoice(&app, &token, &invoice_id, false).await;

    let path = format!(
        "/api/v1/statements/pdf?company_id={company_id}&period_start=2026-08-01&period_end=2026-08-31"
    );
    let (status, bytes) = pdf(&app, &token, &path).await;
    assert_eq!(status, StatusCode::OK, "statement pdf");
    assert!(
        extracted_text(&bytes).contains("Attn: Bill Payer"),
        "the statement names the account's billing contact"
    );

    let second = seed_contact(&pool, company_id, "Nora", "nora@client.example").await;
    set_company_billing_contact(&pool, company_id, second).await;
    let (status, bytes) = pdf(&app, &token, &path).await;
    assert_eq!(status, StatusCode::OK);
    let text = extracted_text(&bytes);
    assert!(
        text.contains("Attn: Nora Payer"),
        "and follows the role when it is reassigned, because it stores nothing: {text:?}"
    );
}
