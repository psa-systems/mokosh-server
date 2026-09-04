//! PMS-1016: an invoice knows who it is for from the moment it exists.
//!
//! `resolve_invoice_recipient` (PMS-992) falls back to the company's
//! `default_billing_contact_id` at send time, but no create path did, so a
//! draft carried `billing_contact_id: null` for an invoice that would in fact
//! be emailed to that contact. `GET /invoices/{id}` named nobody and the live
//! draft preview printed no `Attn:` line while the document stored at the send
//! printed one, so an operator could not check who an invoice was going to
//! until after it had gone.
//!
//! All three create paths now resolve it: the API path, the time-entry path,
//! and the unattended recurring generator. What is deliberately unchanged is
//! the send-time guard: a company with no pointer still produces a draft
//! naming nobody, and sending it is still refused with the 409 that names the
//! company.

mod common;

use chrono::{NaiveDate, TimeZone, Utc};
use mokosh_server::modules::audit::AuditCtx;
use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::billing::BillingService;
use mokosh_server::Database;
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

async fn seed_contact(pool: &PgPool, company_id: Uuid, first: &str, last: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contacts (id, tenant_id, company_id, email, first_name, last_name) \
         VALUES ($1, $2, $3, 'ap@client.example', $4, $5)",
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .bind(first)
    .bind(last)
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

/// Read the column back from the database rather than only from the response,
/// so the assertion is about what was stored.
async fn stored_contact(pool: &PgPool, invoice_id: Uuid) -> Option<Uuid> {
    sqlx::query_scalar("SELECT billing_contact_id FROM invoices WHERE id = $1")
        .bind(invoice_id)
        .fetch_one(pool)
        .await
        .expect("read the invoice's billing contact")
}

async fn create_invoice(
    app: &common::TestApp,
    token: &str,
    company_id: Uuid,
    contact_id: Option<Uuid>,
) -> Value {
    let resp = app
        .client
        .post(app.url("/api/v1/invoices"))
        .bearer_auth(token)
        .json(&json!({
            "company_id": company_id,
            "billing_contact_id": contact_id,
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
    assert!(resp.status().is_success(), "create: {}", resp.status());
    resp.json().await.expect("invoice JSON")
}

/// Read the text back out of rendered bytes, through printpdf's own parser,
/// so this reads what a PDF reader reads.
fn extracted_text(bytes: &[u8]) -> String {
    let mut warnings = Vec::new();
    let parsed =
        printpdf::PdfDocument::parse(bytes, &printpdf::PdfParseOptions::default(), &mut warnings)
            .expect("the rendered bytes parse as a PDF");
    parsed
        .extract_text()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("\n")
}

/// The API path: no contact on the request, so the company's pointer decides.
#[sqlx::test]
async fn the_api_path_stores_the_companys_default_billing_contact(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let contact = seed_contact(&pool, company_id, "Bill", "Payer").await;
    set_company_billing_contact(&pool, company_id, contact).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &pw).await;

    let invoice = create_invoice(&app, &token, company_id, None).await;
    assert_eq!(
        invoice["billing_contact_id"].as_str(),
        Some(contact.to_string().as_str()),
        "the draft names the contact it will be emailed to: {invoice}"
    );
    let id = Uuid::parse_str(invoice["id"].as_str().unwrap()).unwrap();
    assert_eq!(stored_contact(&pool, id).await, Some(contact));
}

/// The time-entry path resolves it the same way.
#[sqlx::test]
async fn the_time_entry_path_stores_the_companys_default_billing_contact(pool: PgPool) {
    install_test_attachment_env();
    let (admin_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let contact = seed_contact(&pool, company_id, "Bill", "Payer").await;
    set_company_billing_contact(&pool, company_id, contact).await;

    let work_type_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO work_types (id, tenant_id, name, default_billable, default_rate) \
         VALUES ($1, $2, 'Billing Contact Work', TRUE, 150.00)",
    )
    .bind(work_type_id)
    .bind(common::DEFAULT_TENANT_ID)
    .execute(&pool)
    .await
    .expect("seed work type");
    sqlx::query(
        "INSERT INTO time_entries \
         (id, tenant_id, user_id, date, duration_minutes, work_type_id, company_id, \
          is_billable, billing_status, hourly_rate, total_amount) \
         VALUES ($1, $2, $3, CURRENT_DATE, 60, $4, $5, TRUE, 'ready_to_bill', $6, $7)",
    )
    .bind(Uuid::new_v4())
    .bind(common::DEFAULT_TENANT_ID)
    .bind(admin_id)
    .bind(work_type_id)
    .bind(company_id)
    .bind(common::dec("150.00"))
    .bind(common::dec("150.00"))
    .execute(&pool)
    .await
    .expect("seed time entry");

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &pw).await;
    let resp = app
        .client
        .post(app.url("/api/v1/invoices/from-time-entries"))
        .bearer_auth(&token)
        .json(&json!({ "company_id": company_id }))
        .send()
        .await
        .expect("generate invoice");
    assert!(resp.status().is_success(), "{}", resp.status());
    let invoice: Value = resp.json().await.expect("invoice JSON");
    assert_eq!(
        invoice["billing_contact_id"].as_str(),
        Some(contact.to_string().as_str()),
        "{invoice}"
    );
    let id = Uuid::parse_str(invoice["id"].as_str().unwrap()).unwrap();
    assert_eq!(stored_contact(&pool, id).await, Some(contact));
}

/// The recurring generator has no caller to name a contact, so the company's
/// pointer is the only answer it can give - and it now gives it.
#[sqlx::test]
async fn the_recurring_generator_stores_the_companys_default_billing_contact(pool: PgPool) {
    let tenant = common::DEFAULT_TENANT_ID;
    let company = common::seed_company(&pool).await;
    let contact = seed_contact(&pool, company, "Bill", "Payer").await;
    set_company_billing_contact(&pool, company, contact).await;

    let contract = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contracts \
         (id, tenant_id, name, company_id, contract_type, status, start_date, billing_cycle) \
         VALUES ($1, $2, 'Managed', $3, 'managed_services', 'active', $4, 'monthly')",
    )
    .bind(contract)
    .bind(tenant)
    .bind(company)
    .bind(NaiveDate::from_ymd_opt(2026, 1, 1).unwrap())
    .execute(&pool)
    .await
    .expect("seed contract");
    sqlx::query(
        "INSERT INTO contract_items \
         (id, tenant_id, contract_id, name, item_type, quantity, unit_price, total_price, \
          sort_order, billing_rule) \
         VALUES ($1, $2, $3, 'Managed Services', 'recurring_service', $4, $5, $6, 0, \
                 'every_period')",
    )
    .bind(Uuid::new_v4())
    .bind(tenant)
    .bind(contract)
    .bind(common::dec("1"))
    .bind(common::dec("100"))
    .bind(common::dec("100"))
    .execute(&pool)
    .await
    .expect("seed recurring item");

    let svc = BillingService::new(Database::from_pool(pool.clone()));
    let ctx = AuditCtx::system(tenant);
    let now = Utc.with_ymd_and_hms(2026, 1, 15, 12, 0, 0).unwrap();
    let created = svc
        .generate_due_recurring_invoices(TenantId::from_trusted(tenant), now, &ctx)
        .await
        .expect("generate recurring invoices");
    assert_eq!(created.len(), 1, "one invoice for the due period");
    assert_eq!(stored_contact(&pool, created[0]).await, Some(contact));
}

/// A company with no pointer is unchanged: the draft names nobody, and the
/// send is still refused with the 409 that names the company.
#[sqlx::test]
async fn a_company_with_no_default_creates_an_invoice_naming_nobody(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    // A contact exists, but the company points at nobody: no guessing.
    seed_contact(&pool, company_id, "Bill", "Payer").await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &pw).await;

    let invoice = create_invoice(&app, &token, company_id, None).await;
    assert!(
        invoice["billing_contact_id"].is_null(),
        "no pointer, so no contact: {invoice}"
    );
    let id = invoice["id"].as_str().unwrap().to_string();
    assert_eq!(
        stored_contact(&pool, Uuid::parse_str(&id).unwrap()).await,
        None
    );

    let company_name: String = sqlx::query_scalar("SELECT name FROM companies WHERE id = $1")
        .bind(company_id)
        .fetch_one(&pool)
        .await
        .expect("company name");
    let resp = app
        .client
        .put(app.url(&format!("/api/v1/invoices/{id}")))
        .bearer_auth(&token)
        .json(&json!({ "status": "sent" }))
        .send()
        .await
        .expect("send invoice");
    assert_eq!(resp.status().as_u16(), 409, "refused, not recorded");
    let body: Value = resp.json().await.expect("error JSON");
    let message = body["error"]["message"].as_str().unwrap_or_default();
    assert!(message.contains(&company_name), "{message}");
    assert!(message.contains("no billing contact"), "{message}");
}

/// The request always wins: a caller naming a contact is not second-guessed
/// by the company's pointer.
#[sqlx::test]
async fn an_explicit_contact_wins_over_the_companys_default(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let default_contact = seed_contact(&pool, company_id, "Bill", "Payer").await;
    let chosen = seed_contact(&pool, company_id, "Ada", "Chooser").await;
    set_company_billing_contact(&pool, company_id, default_contact).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &pw).await;

    let invoice = create_invoice(&app, &token, company_id, Some(chosen)).await;
    assert_eq!(
        invoice["billing_contact_id"].as_str(),
        Some(chosen.to_string().as_str()),
        "{invoice}"
    );
    let id = Uuid::parse_str(invoice["id"].as_str().unwrap()).unwrap();
    assert_eq!(stored_contact(&pool, id).await, Some(chosen));
    assert_ne!(stored_contact(&pool, id).await, Some(default_contact));
}

/// The point of resolving at create: the preview an operator sees before the
/// send is addressed to the same person as the document the customer gets.
#[sqlx::test]
async fn the_draft_preview_prints_the_same_attn_line_as_the_stored_document(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let contact = seed_contact(&pool, company_id, "Bill", "Payer").await;
    set_company_billing_contact(&pool, company_id, contact).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &pw).await;

    let invoice = create_invoice(&app, &token, company_id, None).await;
    let id = invoice["id"].as_str().unwrap().to_string();

    let resp = app
        .client
        .get(app.url(&format!("/api/v1/invoices/{id}/pdf")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("preview the draft");
    assert_eq!(resp.status(), StatusCode::OK);
    let preview = resp.bytes().await.expect("preview bytes").to_vec();

    let sent = app
        .client
        .put(app.url(&format!("/api/v1/invoices/{id}")))
        .bearer_auth(&token)
        .json(&json!({ "status": "sent", "skip_email": true }))
        .send()
        .await
        .expect("send invoice");
    assert!(sent.status().is_success(), "{}", sent.status());
    let stored = std::fs::read(document_path(&id)).expect("the document stored at send");

    let preview_text = extracted_text(&preview);
    let stored_text = extracted_text(&stored);
    assert!(
        preview_text.contains("Attn: Bill Payer"),
        "the draft preview is addressed to the billing contact: {preview_text}"
    );
    assert!(
        stored_text.contains("Attn: Bill Payer"),
        "the stored document is addressed to the billing contact: {stored_text}"
    );
}
