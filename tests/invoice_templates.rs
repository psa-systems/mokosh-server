//! PMS-1006: three document templates, chosen once per tenant.
//!
//! The choice lives in `tenants.branding.invoice_template` and reaches the
//! invoice, the credit note and the statement. Two things it must NOT reach:
//! a document already issued, whose bytes are kept (PMS-959), and the report
//! export, which is not a commercial document and stays Classic.
//!
//! Every assertion here is a comparison between two renders with one thing
//! changed, which rests on rendering being deterministic per template;
//! `pdf::tests::every_template_renders_deterministically_and_differs_from_the_others`
//! pins that separately.

mod common;

use reqwest::StatusCode;
use serde_json::{json, Value};
use sqlx::PgPool;
use std::path::PathBuf;

/// Set before `common::boot`: the logo store reads `ATTACHMENT_DIR` when it is
/// constructed.
fn install_test_attachment_env() {
    common::storage_root();
}

const TEMPLATES: [&str; 3] = ["classic", "modern", "compact"];

fn document_path(id: &str) -> PathBuf {
    common::storage_root()
        .join(common::DEFAULT_TENANT_ID.to_string())
        .join("documents")
        .join(id)
}

async fn set_branding(app: &common::TestApp, token: &str, branding: Value) -> StatusCode {
    let resp = app
        .client
        .put(app.url("/api/v1/tenants/current"))
        .bearer_auth(token)
        .json(&json!({ "branding": branding }))
        .send()
        .await
        .expect("set branding");
    resp.status()
}

async fn set_template(app: &common::TestApp, token: &str, template: &str) {
    let status = set_branding(app, token, json!({ "invoice_template": template })).await;
    assert!(
        status.is_success(),
        "setting `{template}` returned {status}"
    );
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
        .json(&json!({ "status": "sent", "skip_email": true }))
        .send()
        .await
        .expect("send invoice");
    assert!(resp.status().is_success(), "sending should 2xx");
}

async fn get_bytes(app: &common::TestApp, token: &str, path: &str) -> (StatusCode, Vec<u8>) {
    let resp = app
        .client
        .get(app.url(path))
        .bearer_auth(token)
        .send()
        .await
        .expect("request");
    let status = resp.status();
    (status, resp.bytes().await.expect("bytes").to_vec())
}

async fn invoice_pdf(
    app: &common::TestApp,
    token: &str,
    invoice_id: &str,
) -> (StatusCode, Vec<u8>) {
    get_bytes(app, token, &format!("/api/v1/invoices/{invoice_id}/pdf")).await
}

/// The setting takes the three keys and nothing else, and the refusal names
/// them: a typo that fell through would silently leave every document on
/// Classic with nobody the wiser.
#[sqlx::test]
async fn the_template_setting_takes_exactly_three_keys(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    for template in TEMPLATES {
        set_template(&app, &token, template).await;
    }

    let resp = app
        .client
        .put(app.url("/api/v1/tenants/current"))
        .bearer_auth(&token)
        .json(&json!({ "branding": { "invoice_template": "fancy" } }))
        .send()
        .await
        .expect("set branding");
    assert!(
        !resp.status().is_success(),
        "an unknown key must be refused"
    );
    let body = resp.text().await.unwrap_or_default();
    for template in TEMPLATES {
        assert!(
            body.contains(template),
            "the refusal must name `{template}`: {body}"
        );
    }

    assert!(
        set_branding(&app, &token, json!({ "invoice_template": null }))
            .await
            .is_success(),
        "an explicit null clears the choice back to Classic"
    );
    let (_, cleared) = get_bytes(&app, &token, "/api/v1/tenants/current").await;
    let tenant: Value = serde_json::from_slice(&cleared).expect("tenant JSON");
    assert!(
        tenant["branding"]["invoice_template"].is_null(),
        "the cleared value reads back as unset: {}",
        tenant["branding"]
    );
}

/// Each template produces its own document, and the one a tenant gets with no
/// setting at all is the same document Classic renders.
#[sqlx::test]
async fn each_template_renders_its_own_invoice_and_no_setting_means_classic(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;
    let invoice_id = draft_invoice(&app, &token, company_id).await;

    let (status, unset) = invoice_pdf(&app, &token, &invoice_id).await;
    assert_eq!(status, StatusCode::OK);
    assert!(unset.starts_with(b"%PDF-"));

    let mut rendered = Vec::new();
    for template in TEMPLATES {
        set_template(&app, &token, template).await;
        let (status, bytes) = invoice_pdf(&app, &token, &invoice_id).await;
        assert_eq!(status, StatusCode::OK, "{template}");
        assert!(bytes.starts_with(b"%PDF-"), "{template} is a PDF");
        rendered.push((template, bytes));
    }
    assert_eq!(
        rendered[0].1, unset,
        "a tenant that never chose one gets exactly the Classic document"
    );
    for (i, (a, first)) in rendered.iter().enumerate() {
        for (b, second) in rendered.iter().skip(i + 1) {
            assert_ne!(first, second, "`{a}` and `{b}` render the same document");
        }
    }

    // The tenant's own colour reaches the one template that draws in it.
    set_template(&app, &token, "modern").await;
    let (_, default_accent) = invoice_pdf(&app, &token, &invoice_id).await;
    assert!(
        set_branding(&app, &token, json!({ "primary_color": "#7A1F3D" }))
            .await
            .is_success()
    );
    let (_, own_accent) = invoice_pdf(&app, &token, &invoice_id).await;
    assert_ne!(
        default_accent, own_accent,
        "a Modern band must be drawn in the tenant's primary_color"
    );
}

/// PMS-990's guarantee, per template: previewing a draft shows the bytes the
/// send will keep. The send must therefore use the tenant's stored choice and
/// nothing else.
#[sqlx::test]
async fn a_draft_preview_matches_the_document_stored_at_send_for_every_template(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    for template in TEMPLATES {
        set_template(&app, &token, template).await;
        let invoice_id = draft_invoice(&app, &token, company_id).await;
        let (status, preview) = invoice_pdf(&app, &token, &invoice_id).await;
        assert_eq!(status, StatusCode::OK, "{template}");
        assert!(
            !document_path(&invoice_id).exists(),
            "{template}: a draft preview stores nothing"
        );

        send_invoice(&app, &token, &invoice_id).await;
        let stored = std::fs::read(document_path(&invoice_id))
            .unwrap_or_else(|e| panic!("{template}: the document stored at send: {e}"));
        assert_eq!(
            preview, stored,
            "{template}: the previewed draft and the stored document differ"
        );
        let (_, served) = invoice_pdf(&app, &token, &invoice_id).await;
        assert_eq!(
            served, stored,
            "{template}: the route serves the stored bytes"
        );
    }
}

/// PMS-911's rule, extended to the template: changing anything about the
/// tenant's presentation after a send leaves the document the customer holds
/// exactly as it was.
#[sqlx::test]
async fn changing_the_template_after_sending_leaves_the_invoice_byte_identical(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    set_template(&app, &token, "modern").await;
    let invoice_id = draft_invoice(&app, &token, company_id).await;
    send_invoice(&app, &token, &invoice_id).await;
    let (status, before) = invoice_pdf(&app, &token, &invoice_id).await;
    assert_eq!(status, StatusCode::OK);

    set_template(&app, &token, "compact").await;
    assert!(set_branding(
        &app,
        &token,
        json!({ "primary_color": "#123456", "legal_name": "Zenith Managed IT Ltd" })
    )
    .await
    .is_success());

    let (_, after) = invoice_pdf(&app, &token, &invoice_id).await;
    assert_eq!(
        before, after,
        "a sent invoice keeps the document that was sent, template and all"
    );
}

/// `?template=` is how an MSP tries a layout on its own data. It answers only
/// where an answer is honest: a draft is rendered live, and an issued invoice
/// serves the bytes that were sent, so an override there would hand back a
/// document that is not the one the customer holds.
#[sqlx::test]
async fn the_template_parameter_previews_a_draft_and_is_refused_on_an_issued_invoice(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;
    let invoice_id = draft_invoice(&app, &token, company_id).await;

    let (status, overridden) = get_bytes(
        &app,
        &token,
        &format!("/api/v1/invoices/{invoice_id}/pdf?template=modern"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "an editable invoice honours it");

    set_template(&app, &token, "modern").await;
    let (_, as_the_setting) = invoice_pdf(&app, &token, &invoice_id).await;
    assert_eq!(
        overridden, as_the_setting,
        "the preview is the same document the setting would produce"
    );
    set_template(&app, &token, "classic").await;
    let (_, without) = invoice_pdf(&app, &token, &invoice_id).await;
    assert_ne!(overridden, without, "and it overrode the stored choice");

    let (status, _) = get_bytes(
        &app,
        &token,
        &format!("/api/v1/invoices/{invoice_id}/pdf?template=fancy"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an unknown key is refused rather than falling back to Classic"
    );

    send_invoice(&app, &token, &invoice_id).await;
    let (status, body) = get_bytes(
        &app,
        &token,
        &format!("/api/v1/invoices/{invoice_id}/pdf?template=compact"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an issued invoice has one document and it is the one that was sent"
    );
    assert!(
        !body.starts_with(b"%PDF-"),
        "the refusal is a refusal, not a document"
    );
    let (status, _) = invoice_pdf(&app, &token, &invoice_id).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "and the invoice itself is still served"
    );
}

/// A statement stores nothing (PMS-954), so it follows the tenant's template
/// as it stands now.
#[sqlx::test]
async fn a_statement_follows_the_current_template(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;
    let invoice_id = draft_invoice(&app, &token, company_id).await;
    send_invoice(&app, &token, &invoice_id).await;

    let url = format!(
        "/api/v1/statements/pdf?company_id={company_id}&period_start=2026-08-01&period_end=2026-08-31"
    );
    let mut rendered = Vec::new();
    for template in TEMPLATES {
        set_template(&app, &token, template).await;
        let (status, bytes) = get_bytes(&app, &token, &url).await;
        assert_eq!(status, StatusCode::OK, "{template}");
        assert!(bytes.starts_with(b"%PDF-"));
        rendered.push((template, bytes));
    }
    for (i, (a, first)) in rendered.iter().enumerate() {
        for (b, second) in rendered.iter().skip(i + 1) {
            assert_ne!(first, second, "a statement renders `{a}` and `{b}` alike");
        }
    }
}

/// A credit note is issued the instant it exists, so its template is the one
/// current at creation and it keeps that document afterwards.
#[sqlx::test]
async fn a_credit_note_is_issued_in_the_template_that_was_current(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    let mut rendered = Vec::new();
    for template in ["classic", "modern"] {
        let invoice_id = draft_invoice(&app, &token, company_id).await;
        send_invoice(&app, &token, &invoice_id).await;
        set_template(&app, &token, template).await;
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
        let (status, bytes) =
            get_bytes(&app, &token, &format!("/api/v1/credit-notes/{note_id}/pdf")).await;
        assert_eq!(status, StatusCode::OK);
        rendered.push((note_id, bytes));
    }
    assert_ne!(
        rendered[0].1, rendered[1].1,
        "a credit note issued under Modern is not the Classic one"
    );

    // And the first one does not change when the template moves on.
    set_template(&app, &token, "compact").await;
    let (_, again) = get_bytes(
        &app,
        &token,
        &format!("/api/v1/credit-notes/{}/pdf", rendered[0].0),
    )
    .await;
    assert_eq!(
        again, rendered[0].1,
        "a credit note is never re-rendered: it was issued the instant it existed"
    );
}

/// The report export is not a document a client receives, and PMS-876 never
/// gave it branding. It stays Classic whatever the tenant picked.
#[sqlx::test]
async fn the_report_export_is_unaffected_by_the_template(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &pw).await;

    let url = "/api/v1/reports/tickets/export?format=pdf";
    let (status, classic) = get_bytes(&app, &token, url).await;
    assert_eq!(status, StatusCode::OK);
    assert!(classic.starts_with(b"%PDF-"));

    set_template(&app, &token, "modern").await;
    assert!(
        set_branding(&app, &token, json!({ "primary_color": "#7A1F3D" }))
            .await
            .is_success()
    );
    let (status, after) = get_bytes(&app, &token, url).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        classic, after,
        "an internal report is not a commercial document and takes no template"
    );
}
