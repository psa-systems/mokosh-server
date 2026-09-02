//! PMS-911: an invoice carries the MSP's identity, and a rebrand cannot change
//! a document a client already holds.
//!
//! The interesting assertions are all comparisons between two renders of the
//! same invoice with something changed in between. They rest on rendering being
//! deterministic, which `pdf::tests::rendering_is_deterministic` pins
//! separately: without it every test here would pass or fail for reasons having
//! nothing to do with branding.

mod common;

use reqwest::StatusCode;
use serde_json::{json, Value};
use sqlx::PgPool;

/// Set before `common::boot`: the logo store reads `ATTACHMENT_DIR` when it is
/// constructed.
fn install_test_attachment_env() {
    common::storage_root();
}

/// A one-pixel PNG.
const PNG: &[u8] = &[
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4,
    0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00,
    0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE,
    0x42, 0x60, 0x82,
];

/// A two-pixel PNG, so "the logo changed" is a real change of bytes rather than
/// a re-upload of the same file.
const PNG_WIDER: &[u8] = &[
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x72, 0xB6, 0x0D,
    0x24, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x60, 0x00, 0x02, 0x00,
    0x00, 0x05, 0x00, 0x01, 0xE9, 0xFA, 0xDC, 0xD8, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44,
    0xAE, 0x42, 0x60, 0x82,
];

async fn set_branding(app: &common::TestApp, token: &str, branding: Value) {
    let resp = app
        .client
        .put(app.url("/api/v1/tenants/current"))
        .bearer_auth(token)
        .json(&json!({ "branding": branding }))
        .send()
        .await
        .expect("set branding");
    assert!(
        resp.status().is_success(),
        "setting branding should 2xx, got {}: {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

async fn upload_logo(app: &common::TestApp, token: &str, bytes: &[u8]) {
    let part = reqwest::multipart::Part::bytes(bytes.to_vec())
        .file_name("logo.png")
        .mime_str("image/png")
        .expect("mime");
    let resp = app
        .client
        .put(app.url("/api/v1/tenants/current/logo"))
        .bearer_auth(token)
        .multipart(reqwest::multipart::Form::new().part("file", part))
        .send()
        .await
        .expect("upload logo");
    assert_eq!(resp.status(), StatusCode::OK, "logo upload");
}

async fn draft_invoice(app: &common::TestApp, token: &str, company_id: uuid::Uuid) -> String {
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
    let invoice: Value = resp.json().await.expect("invoice JSON");
    invoice["id"].as_str().expect("id").to_string()
}

async fn send_invoice(app: &common::TestApp, token: &str, invoice_id: &str) {
    let resp = app
        .client
        .put(app.url(&format!("/api/v1/invoices/{invoice_id}")))
        .bearer_auth(token)
        .json(&json!({ "status": "sent" }))
        .send()
        .await
        .expect("send invoice");
    assert!(resp.status().is_success(), "sending should 2xx");
}

async fn invoice_pdf(
    app: &common::TestApp,
    token: &str,
    invoice_id: &str,
) -> (StatusCode, Vec<u8>) {
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/invoices/{invoice_id}/pdf")))
        .bearer_auth(token)
        .send()
        .await
        .expect("invoice pdf");
    let status = resp.status();
    (status, resp.bytes().await.expect("bytes").to_vec())
}

fn acme() -> Value {
    json!({
        "company_name": "Acme IT",
        "legal_name": "Acme IT Services Pty Ltd",
        "postal_address": "12 Example Street\nSydney NSW 2000",
        "tax_id": "ABN 12 345 678 901",
        "support_email": "billing@acme.example",
        "support_phone": "555-0100",
    })
}

/// The whole point: an invoice renders as a document carrying the MSP.
#[sqlx::test]
async fn an_invoice_renders_with_the_issuing_msp(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;
    set_branding(&app, &token, acme()).await;
    upload_logo(&app, &token, PNG).await;

    let invoice_id = draft_invoice(&app, &token, company_id).await;
    send_invoice(&app, &token, &invoice_id).await;

    let resp = app
        .client
        .get(app.url(&format!("/api/v1/invoices/{invoice_id}/pdf")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("pdf");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/pdf")
    );
    assert!(resp
        .headers()
        .get("content-disposition")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("attachment; filename=")));
    let bytes = resp.bytes().await.expect("bytes").to_vec();
    assert!(
        bytes.starts_with(b"%PDF-"),
        "a reader has to be able to open it"
    );
    assert!(
        bytes.windows(5).any(|w| w == b"%%EOF"),
        "and it is complete"
    );
}

/// The no-branding acceptance criterion: an MSP that filled nothing in still
/// gets a valid invoice, with its own name on it.
#[sqlx::test]
async fn an_msp_with_no_branding_still_gets_a_valid_invoice(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    let invoice_id = draft_invoice(&app, &token, company_id).await;
    send_invoice(&app, &token, &invoice_id).await;

    let (status, bytes) = invoice_pdf(&app, &token, &invoice_id).await;
    assert_eq!(status, StatusCode::OK, "no logo is not an error");
    assert!(bytes.starts_with(b"%PDF-"));
    assert!(bytes.windows(5).any(|w| w == b"%%EOF"));
}

/// Rebranding after sending leaves the sent invoice exactly as it was. This is
/// the criterion the whole snapshot exists for.
#[sqlx::test]
async fn a_rebrand_after_sending_leaves_the_invoice_byte_identical(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;
    set_branding(&app, &token, acme()).await;

    let invoice_id = draft_invoice(&app, &token, company_id).await;
    send_invoice(&app, &token, &invoice_id).await;
    let (_, before) = invoice_pdf(&app, &token, &invoice_id).await;

    set_branding(
        &app,
        &token,
        json!({
            "company_name": "Zenith Managed IT",
            "legal_name": "Zenith Managed IT Ltd",
            "postal_address": "99 Other Road\nMelbourne VIC 3000",
            "tax_id": "ABN 99 999 999 999",
            "support_email": "hello@zenith.example",
        }),
    )
    .await;

    let (status, after) = invoice_pdf(&app, &token, &invoice_id).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        before, after,
        "a document the client already holds cannot change because a setting did"
    );
}

/// And replacing the logo FILE leaves it byte-identical too, which is the case
/// a snapshot holding a logo URL would fail: the live logo is written to one
/// key per tenant and overwritten in place.
#[sqlx::test]
async fn replacing_the_logo_after_sending_leaves_the_invoice_byte_identical(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;
    set_branding(&app, &token, acme()).await;
    upload_logo(&app, &token, PNG).await;

    let invoice_id = draft_invoice(&app, &token, company_id).await;
    send_invoice(&app, &token, &invoice_id).await;
    let (_, before) = invoice_pdf(&app, &token, &invoice_id).await;

    upload_logo(&app, &token, PNG_WIDER).await;

    let (_, after) = invoice_pdf(&app, &token, &invoice_id).await;
    assert_eq!(
        before, after,
        "the snapshot holds the logo's BYTES; a stored URL would have re-rendered \
         with the new mark"
    );
}

/// A draft has not been sent, so there is nothing to preserve and it follows
/// current branding. Without this the previous two tests could pass for the
/// wrong reason: a renderer that ignored branding entirely.
#[sqlx::test]
async fn a_draft_follows_current_branding(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;
    set_branding(&app, &token, acme()).await;

    let invoice_id = draft_invoice(&app, &token, company_id).await;
    let (_, before) = invoice_pdf(&app, &token, &invoice_id).await;

    set_branding(
        &app,
        &token,
        json!({ "legal_name": "Zenith Managed IT Ltd" }),
    )
    .await;

    let (status, after) = invoice_pdf(&app, &token, &invoice_id).await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(
        before, after,
        "a draft is not frozen, so branding reaches it - and branding reaching \
         the document at all is what makes the immutability tests meaningful"
    );
}

/// A statement renders live, because PMS-954 made it a read model that stores
/// nothing: there is no statement row for a snapshot to hang off.
#[sqlx::test]
async fn a_statement_renders_from_current_branding(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;
    set_branding(&app, &token, acme()).await;
    let invoice_id = draft_invoice(&app, &token, company_id).await;
    send_invoice(&app, &token, &invoice_id).await;

    let url = format!(
        "/api/v1/statements/pdf?company_id={company_id}&period_start=2026-08-01&period_end=2026-08-31"
    );
    let first = app
        .client
        .get(app.url(&url))
        .bearer_auth(&token)
        .send()
        .await
        .expect("statement pdf");
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(
        first
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/pdf")
    );
    let before = first.bytes().await.expect("bytes").to_vec();
    assert!(before.starts_with(b"%PDF-"));

    set_branding(
        &app,
        &token,
        json!({ "legal_name": "Zenith Managed IT Ltd" }),
    )
    .await;

    let after = app
        .client
        .get(app.url(&url))
        .bearer_auth(&token)
        .send()
        .await
        .expect("statement pdf")
        .bytes()
        .await
        .expect("bytes")
        .to_vec();
    assert_ne!(
        before, after,
        "a statement is reproducible rather than immutable, so it follows today"
    );
}

/// A rendered invoice is the same financial data in another format, so it sits
/// behind the same gate. A new output format must not become a side door around
/// a permission (PMS-350), and the first draft of `get_invoice_pdf` was exactly
/// that: it carried the module gate and not the finance one, which this test
/// caught.
///
/// The statement PDF is finance-gated too. PMS-911 left the JSON route beside
/// it ungated on purpose, and PMS-962 closed that gap along with five others in
/// the same file, so the two now answer a given role identically.
#[sqlx::test]
async fn the_pdf_routes_are_behind_the_billing_gate(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let (_tid, tech_email, tech_pw) = common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "pms911-tech@example.com",
        "technician",
    )
    .await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;
    let invoice_id = draft_invoice(&app, &token, company_id).await;
    send_invoice(&app, &token, &invoice_id).await;

    let tech = common::login(&app, &tech_email, &tech_pw).await;
    let (status, _) = invoice_pdf(&app, &tech, &invoice_id).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "invoice PDF");

    let statement = app
        .client
        .get(app.url(&format!(
            "/api/v1/statements/pdf?company_id={company_id}&period_start=2026-08-01&period_end=2026-08-31"
        )))
        .bearer_auth(&tech)
        .send()
        .await
        .expect("statement pdf");
    assert_eq!(statement.status(), StatusCode::FORBIDDEN, "statement PDF");
}
