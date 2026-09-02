//! PMS-991: sending an invoice emails it.
//!
//! The 2026-09-01 standup sent a fresh invoice and nothing arrived. The
//! "no email rule matches this action" it reported was the client's preview
//! modal (MAPPS-642); the server's part was that the pay-now mail was gated on
//! a connected payment gateway, so a fresh install with none mailed nobody on
//! Send and nothing said so. The invoice is the message: it goes whenever
//! there is a billing contact with an address, carries the document stored at
//! send (PMS-959), and adds the pay link only when a gateway can take the
//! payment.

mod common;

use async_trait::async_trait;
use mokosh_server::utils::email::{EmailAttachment, Mailer};
use mokosh_server::utils::error::AppResult;
use serde_json::{json, Value};
use sqlx::PgPool;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

#[derive(Clone, Debug)]
struct Sent {
    to: String,
    subject: String,
    text: String,
    attachments: Vec<(String, String, Vec<u8>)>,
}

#[derive(Default)]
struct CapturingMailer {
    sent: Mutex<Vec<Sent>>,
}

#[async_trait]
impl Mailer for CapturingMailer {
    async fn send_multipart(
        &self,
        to: &str,
        subject: &str,
        text: &str,
        _html: Option<&str>,
    ) -> AppResult<()> {
        self.sent.lock().unwrap().push(Sent {
            to: to.to_string(),
            subject: subject.to_string(),
            text: text.to_string(),
            attachments: Vec::new(),
        });
        Ok(())
    }

    async fn send_with_attachments(
        &self,
        to: &str,
        subject: &str,
        text: &str,
        attachments: &[EmailAttachment<'_>],
    ) -> AppResult<()> {
        self.sent.lock().unwrap().push(Sent {
            to: to.to_string(),
            subject: subject.to_string(),
            text: text.to_string(),
            attachments: attachments
                .iter()
                .map(|a| (a.filename.to_string(), a.mime.to_string(), a.bytes.to_vec()))
                .collect(),
        });
        Ok(())
    }
}

fn install_test_attachment_env() {
    common::storage_root();
}

async fn seed_contact(pool: &PgPool, company_id: Uuid, email: Option<&str>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contacts (id, tenant_id, company_id, email, first_name, last_name) \
         VALUES ($1, $2, $3, $4, 'Bill', 'Payer')",
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .bind(email)
    .execute(pool)
    .await
    .expect("seed contact");
    id
}

async fn seed_active_gateway(pool: &PgPool) {
    sqlx::query(
        "INSERT INTO payment_gateway_configs (tenant_id, provider, is_active, is_test_mode, config_encrypted) \
         VALUES ($1, 'stripe', TRUE, TRUE, NULL)",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .execute(pool)
    .await
    .expect("seed gateway");
}

async fn create_and_send(
    app: &common::TestApp,
    token: &str,
    company_id: Uuid,
    contact_id: Option<Uuid>,
) -> Value {
    let created = app
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
    assert!(
        created.status().is_success(),
        "create: {}",
        created.status()
    );
    let invoice: Value = created.json().await.expect("invoice JSON");
    let id = invoice["id"].as_str().expect("id");
    let sent = app
        .client
        .put(app.url(&format!("/api/v1/invoices/{id}")))
        .bearer_auth(token)
        .json(&json!({ "status": "sent" }))
        .send()
        .await
        .expect("send invoice");
    assert!(sent.status().is_success(), "send: {}", sent.status());
    sent.json().await.expect("sent invoice JSON")
}

async fn boot_capturing(pool: PgPool) -> (common::TestApp, Arc<CapturingMailer>) {
    let app = common::boot(pool).await;
    let mailer = Arc::new(CapturingMailer::default());
    app.mailer.swap(mailer.clone());
    (app, mailer)
}

/// The default configuration: a billing contact with an address, no
/// payment gateway. The invoice goes, with the stored document attached and
/// no pay link, because nothing could take the payment.
#[sqlx::test]
async fn a_send_with_no_gateway_still_emails_the_invoice_with_its_pdf(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let contact = seed_contact(&pool, company_id, Some("ap@client.example")).await;
    let (app, mailer) = boot_capturing(pool.clone()).await;
    let token = common::login(&app, &email, &pw).await;

    let invoice = create_and_send(&app, &token, company_id, Some(contact)).await;
    assert_eq!(invoice["status"], "sent");
    let number = invoice["invoice_number"].as_str().unwrap().to_string();
    let invoice_id = Uuid::parse_str(invoice["id"].as_str().unwrap()).unwrap();

    let sent = mailer.sent.lock().unwrap().clone();
    assert_eq!(sent.len(), 1, "exactly one email on send: {sent:?}");
    let mail = &sent[0];
    assert_eq!(mail.to, "ap@client.example");
    assert!(mail.subject.contains(&number), "{}", mail.subject);
    assert!(
        mail.text.contains("Amount due: 1200.00 USD"),
        "{}",
        mail.text
    );
    assert!(
        !mail.text.contains("pay online"),
        "no gateway, so no pay link: {}",
        mail.text
    );
    assert_eq!(mail.attachments.len(), 1);
    let (name, mime, bytes) = &mail.attachments[0];
    assert_eq!(name, &format!("{number}.pdf"));
    assert_eq!(mime, "application/pdf");
    assert!(bytes.starts_with(b"%PDF"), "the attachment is a PDF");
    // The same bytes the route serves: the document as issued.
    let stored = mokosh_server::modules::billing::documents::read_issued(
        common::DEFAULT_TENANT_ID,
        invoice_id,
    )
    .await
    .expect("stored document");
    assert_eq!(bytes, &stored, "the attachment is the stored document");
}

/// With a gateway connected the same message also carries the pay link.
#[sqlx::test]
async fn a_send_with_a_gateway_adds_the_pay_link(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let contact = seed_contact(&pool, company_id, Some("ap@client.example")).await;
    seed_active_gateway(&pool).await;
    let (app, mailer) = boot_capturing(pool.clone()).await;
    let token = common::login(&app, &email, &pw).await;

    let invoice = create_and_send(&app, &token, company_id, Some(contact)).await;
    let id = invoice["id"].as_str().unwrap();
    let sent = mailer.sent.lock().unwrap().clone();
    assert_eq!(sent.len(), 1);
    assert!(
        sent[0].subject.contains("ready to pay"),
        "{}",
        sent[0].subject
    );
    assert!(
        sent[0].text.contains(&format!("/portal/invoices/{id}")),
        "{}",
        sent[0].text
    );
    assert_eq!(sent[0].attachments.len(), 1);
}

/// No billing contact, or a contact with no address: the invoice still moves
/// to sent and nothing is mailed. The reason is logged; it is not an error,
/// because the status change is the operator's and has already landed.
#[sqlx::test]
async fn a_send_with_nobody_to_email_still_sends_the_invoice(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let no_address = seed_contact(&pool, company_id, None).await;
    let (app, mailer) = boot_capturing(pool.clone()).await;
    let token = common::login(&app, &email, &pw).await;

    let without_contact = create_and_send(&app, &token, company_id, None).await;
    assert_eq!(without_contact["status"], "sent");
    let without_address = create_and_send(&app, &token, company_id, Some(no_address)).await;
    assert_eq!(without_address["status"], "sent");
    assert!(
        mailer.sent.lock().unwrap().is_empty(),
        "nobody to email, so nothing sent"
    );
}

/// A second update of a sent invoice does not mail again: the hook fires on
/// the first transition only.
#[sqlx::test]
async fn only_the_first_send_emails(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let contact = seed_contact(&pool, company_id, Some("ap@client.example")).await;
    let (app, mailer) = boot_capturing(pool.clone()).await;
    let token = common::login(&app, &email, &pw).await;

    let invoice = create_and_send(&app, &token, company_id, Some(contact)).await;
    let id = invoice["id"].as_str().unwrap();
    let again = app
        .client
        .put(app.url(&format!("/api/v1/invoices/{id}")))
        .bearer_auth(&token)
        .json(&json!({ "status": "sent" }))
        .send()
        .await
        .expect("second send");
    // Whatever the server says about a second send of a frozen invoice, it
    // is not another email.
    let _ = again.status();
    assert_eq!(mailer.sent.lock().unwrap().len(), 1);
}
