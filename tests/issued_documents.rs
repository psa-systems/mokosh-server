//! PMS-959: the document that was sent is kept, not re-rendered.
//!
//! The case that matters is the one a re-render cannot survive. Branding is
//! frozen (PMS-911) and `pdf::render` is deterministic, so regenerating an
//! invoice from its snapshot agrees with what was sent - right up until
//! somebody edits the renderer, at which point every past invoice quietly
//! reprints differently. A test cannot edit the renderer, so it does the thing
//! that stands in for it: it corrupts the stored bytes and proves the route
//! serves them anyway. If the route were re-rendering, the tampered bytes would
//! be ignored and the test would fail.

mod common;

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

async fn send_invoice(app: &common::TestApp, token: &str, invoice_id: &str) {
    let resp = app
        .client
        .put(app.url(&format!("/api/v1/invoices/{invoice_id}")))
        .bearer_auth(token)
        .json(&json!({ "status": "sent" }))
        .send()
        .await
        .expect("send invoice");
    assert!(
        resp.status().is_success(),
        "sending should 2xx, got {}",
        resp.status()
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

async fn ledger_row(pool: &PgPool, entity_id: Uuid) -> Option<(String, i64)> {
    sqlx::query_as(
        "SELECT entity_type, file_size FROM files WHERE tenant_id = $1 AND entity_id = $2",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(entity_id)
    .fetch_optional(pool)
    .await
    .expect("read ledger")
}

/// Sending an invoice writes its document. Not on the first request for it:
/// on the send.
#[sqlx::test]
async fn sending_an_invoice_stores_its_document(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    // PMS-993: an invoice cannot be sent without a billing contact.
    common::seed_billing_contact(&pool, company_id).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &pw).await;

    let invoice_id = draft_invoice(&app, &token, company_id).await;
    assert!(
        !document_path(&invoice_id).exists(),
        "a draft has been sent to nobody, so there is nothing to preserve"
    );

    send_invoice(&app, &token, &invoice_id).await;

    let path = document_path(&invoice_id);
    assert!(path.exists(), "the send is what writes the document");
    let stored = std::fs::read(&path).expect("stored bytes");
    assert!(stored.starts_with(b"%PDF-"));

    // PMS-957: every stored object gets a ledger row, this one included.
    let row = ledger_row(&pool, invoice_id.parse().expect("uuid")).await;
    assert_eq!(
        row.as_ref().map(|(kind, _)| kind.as_str()),
        Some("invoice_document")
    );
    assert_eq!(
        row.expect("a row").1,
        stored.len() as i64,
        "the ledger records the size of what was actually written"
    );
}

/// The route serves the stored bytes rather than rendering again.
///
/// Proven by tampering: the stored file is overwritten with different bytes,
/// and the route hands those back. A route that re-rendered would return a
/// valid PDF and ignore the tampering, so this is the assertion that separates
/// "stored" from "reproducible".
#[sqlx::test]
async fn the_route_serves_the_stored_bytes_not_a_fresh_render(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    // PMS-993: an invoice cannot be sent without a billing contact.
    common::seed_billing_contact(&pool, company_id).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;
    let invoice_id = draft_invoice(&app, &token, company_id).await;
    send_invoice(&app, &token, &invoice_id).await;

    let (status, first) = pdf(&app, &token, &format!("/api/v1/invoices/{invoice_id}/pdf")).await;
    assert_eq!(status, StatusCode::OK);

    // Stand-in for an edit to the renderer, which a test cannot make.
    let marker = b"%PDF-1.3\n% not what render() would produce\n%%EOF".to_vec();
    std::fs::write(document_path(&invoice_id), &marker).expect("tamper");

    let (status, second) = pdf(&app, &token, &format!("/api/v1/invoices/{invoice_id}/pdf")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        second, marker,
        "the route re-rendered instead of serving what was kept"
    );
    assert_ne!(first, second, "the tamper has to have changed something");
}

/// A rebrand after sending leaves the stored document alone, which is the
/// PMS-911 guarantee now backed by bytes on disk rather than by re-derivation.
#[sqlx::test]
async fn a_rebrand_cannot_reach_a_stored_document(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    // PMS-993: an invoice cannot be sent without a billing contact.
    common::seed_billing_contact(&pool, company_id).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;
    let invoice_id = draft_invoice(&app, &token, company_id).await;
    send_invoice(&app, &token, &invoice_id).await;
    let (_, before) = pdf(&app, &token, &format!("/api/v1/invoices/{invoice_id}/pdf")).await;

    let resp = app
        .client
        .put(app.url("/api/v1/tenants/current"))
        .bearer_auth(&token)
        .json(&json!({ "branding": { "legal_name": "Zenith Managed IT Ltd" } }))
        .send()
        .await
        .expect("rebrand");
    assert!(resp.status().is_success());

    let (_, after) = pdf(&app, &token, &format!("/api/v1/invoices/{invoice_id}/pdf")).await;
    assert_eq!(before, after);
}

/// A draft has no document and renders live, so the fallback is exercised
/// rather than merely present.
#[sqlx::test]
async fn a_draft_renders_live_and_stores_nothing(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    // PMS-993: an invoice cannot be sent without a billing contact.
    common::seed_billing_contact(&pool, company_id).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &pw).await;
    let invoice_id = draft_invoice(&app, &token, company_id).await;

    let (status, bytes) = pdf(&app, &token, &format!("/api/v1/invoices/{invoice_id}/pdf")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(bytes.starts_with(b"%PDF-"));
    assert!(
        !document_path(&invoice_id).exists(),
        "rendering a draft must not store anything: the document is not issued"
    );
    assert_eq!(
        ledger_row(&pool, invoice_id.parse().expect("uuid")).await,
        None
    );
}

/// A credit note gets its document at creation, because it is issued the
/// instant it exists (PMS-953) and has no separate send transition.
#[sqlx::test]
async fn a_credit_note_gets_its_document_at_creation(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    // PMS-993: an invoice cannot be sent without a billing contact.
    common::seed_billing_contact(&pool, company_id).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &pw).await;
    let invoice_id = draft_invoice(&app, &token, company_id).await;
    send_invoice(&app, &token, &invoice_id).await;

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
    assert!(
        resp.status().is_success(),
        "create credit note, got {}",
        resp.status()
    );
    let note: Value = resp.json().await.expect("json");
    let note_id = note["id"].as_str().expect("id").to_string();

    assert!(
        document_path(&note_id).exists(),
        "a credit note is issued at creation, so its document is written there"
    );
    let (status, served) = pdf(&app, &token, &format!("/api/v1/credit-notes/{note_id}/pdf")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        served,
        std::fs::read(document_path(&note_id)).expect("stored"),
        "the route serves what was kept"
    );
    assert_eq!(
        ledger_row(&pool, note_id.parse().expect("uuid"))
            .await
            .map(|(kind, _)| kind),
        Some("credit_note_document".to_string())
    );
}

/// Voiding a credit note does not replace its document: the customer holds
/// what was issued, and a void is a status the note carries.
#[sqlx::test]
async fn voiding_a_credit_note_leaves_its_document_alone(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    // PMS-993: an invoice cannot be sent without a billing contact.
    common::seed_billing_contact(&pool, company_id).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;
    let invoice_id = draft_invoice(&app, &token, company_id).await;
    send_invoice(&app, &token, &invoice_id).await;

    let note: Value = app
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
        .expect("create credit note")
        .json()
        .await
        .expect("json");
    let note_id = note["id"].as_str().expect("id").to_string();
    let before = std::fs::read(document_path(&note_id)).expect("stored");

    let resp = app
        .client
        .post(app.url(&format!("/api/v1/credit-notes/{note_id}/void")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("void");
    assert!(resp.status().is_success(), "void should 2xx");

    assert_eq!(
        std::fs::read(document_path(&note_id)).expect("stored"),
        before,
        "voiding changes a status, not the document that went out"
    );
}

/// The credit-note PDF is behind the finance gate like every other financial
/// read in that file (PMS-962).
#[sqlx::test]
async fn the_credit_note_pdf_is_finance_gated(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let (_tid, tech_email, tech_pw) = common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "pms959-tech@example.com",
        "technician",
    )
    .await;
    let app = common::boot(pool).await;
    let _admin = common::login(&app, &email, &pw).await;
    let tech = common::login(&app, &tech_email, &tech_pw).await;

    let (status, _) = pdf(
        &app,
        &tech,
        &format!("/api/v1/credit-notes/{}/pdf", Uuid::new_v4()),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the gate answers before the lookup, so an unknown id is still 403"
    );
}
