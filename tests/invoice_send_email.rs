//! PMS-991 and PMS-992: what "sent" means.
//!
//! The 2026-09-01 standup sent a fresh invoice and nothing arrived, and the
//! invoice said `sent` anyway. Two things were wrong. The pay-now mail was
//! gated on a connected payment gateway, so a fresh install mailed nobody
//! (PMS-991); and the status moved whether or not anyone could be emailed, so
//! the record claimed a delivery that never happened (PMS-992).
//!
//! Now the recipient is resolved before the transition, the mail goes inside
//! the transaction that freezes the invoice, and `sent` means one of two
//! things the record can show: emailed to `emailed_to` at `emailed_at`, or
//! marked sent without emailing on purpose (`skip_email`).

mod common;

use async_trait::async_trait;
use mokosh_server::utils::email::{EmailAttachment, Mailer};
use mokosh_server::utils::error::{AppError, AppResult};
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
    /// When set, every send is refused with this message: the relay is down.
    refuse: Option<String>,
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
        self.send_with_attachments(to, subject, text, &[]).await
    }

    async fn send_with_attachments(
        &self,
        to: &str,
        subject: &str,
        text: &str,
        attachments: &[EmailAttachment<'_>],
    ) -> AppResult<()> {
        if let Some(reason) = &self.refuse {
            return Err(AppError::external_service("smtp", reason.clone()));
        }
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

async fn create_draft(
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
    created.json().await.expect("invoice JSON")
}

async fn send(app: &common::TestApp, token: &str, id: &str, body: Value) -> reqwest::Response {
    app.client
        .put(app.url(&format!("/api/v1/invoices/{id}")))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("send invoice")
}

async fn invoice(app: &common::TestApp, token: &str, id: &str) -> Value {
    app.client
        .get(app.url(&format!("/api/v1/invoices/{id}")))
        .bearer_auth(token)
        .send()
        .await
        .expect("get invoice")
        .json()
        .await
        .expect("invoice JSON")
}

async fn boot_capturing(
    pool: PgPool,
    mailer: CapturingMailer,
) -> (common::TestApp, Arc<CapturingMailer>) {
    let app = common::boot(pool).await;
    let mailer = Arc::new(mailer);
    app.mailer.swap(mailer.clone());
    (app, mailer)
}

/// The default configuration: a billing contact with an address, no
/// payment gateway. The invoice goes, with the stored document attached and
/// no pay link, and the record says who it went to.
#[sqlx::test]
async fn a_send_with_no_gateway_emails_the_invoice_with_its_pdf_and_records_it(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let contact = seed_contact(&pool, company_id, Some("ap@client.example")).await;
    let (app, mailer) = boot_capturing(pool.clone(), CapturingMailer::default()).await;
    let token = common::login(&app, &email, &pw).await;

    let draft = create_draft(&app, &token, company_id, Some(contact)).await;
    let id = draft["id"].as_str().unwrap().to_string();
    let resp = send(&app, &token, &id, json!({ "status": "sent" })).await;
    assert!(resp.status().is_success(), "{}", resp.status());
    let sent: Value = resp.json().await.unwrap();
    assert_eq!(sent["status"], "sent");
    assert_eq!(sent["emailed_to"], "ap@client.example");
    assert!(sent["emailed_at"].is_string(), "{sent}");
    let number = sent["invoice_number"].as_str().unwrap().to_string();

    let mails = mailer.sent.lock().unwrap().clone();
    assert_eq!(mails.len(), 1, "exactly one email on send: {mails:?}");
    let mail = &mails[0];
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
    let stored = mokosh_server::modules::billing::documents::read_issued(
        common::DEFAULT_TENANT_ID,
        Uuid::parse_str(&id).unwrap(),
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
    let (app, mailer) = boot_capturing(pool.clone(), CapturingMailer::default()).await;
    let token = common::login(&app, &email, &pw).await;

    let draft = create_draft(&app, &token, company_id, Some(contact)).await;
    let id = draft["id"].as_str().unwrap();
    let resp = send(&app, &token, id, json!({ "status": "sent" })).await;
    assert!(resp.status().is_success());
    let mails = mailer.sent.lock().unwrap().clone();
    assert_eq!(mails.len(), 1);
    assert!(
        mails[0].subject.contains("ready to pay"),
        "{}",
        mails[0].subject
    );
    assert!(
        mails[0].text.contains(&format!("/portal/invoices/{id}")),
        "{}",
        mails[0].text
    );
}

/// The invoice names no contact, but the company does: the company's default
/// billing contact is the recipient.
#[sqlx::test]
async fn the_companys_billing_contact_is_the_fallback_recipient(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let contact = seed_contact(&pool, company_id, Some("billing@client.example")).await;
    set_company_billing_contact(&pool, company_id, contact).await;
    let (app, mailer) = boot_capturing(pool.clone(), CapturingMailer::default()).await;
    let token = common::login(&app, &email, &pw).await;

    let draft = create_draft(&app, &token, company_id, None).await;
    let id = draft["id"].as_str().unwrap();
    let resp = send(&app, &token, id, json!({ "status": "sent" })).await;
    assert!(resp.status().is_success(), "{}", resp.status());
    let sent: Value = resp.json().await.unwrap();
    assert_eq!(sent["emailed_to"], "billing@client.example");
    assert_eq!(mailer.sent.lock().unwrap().len(), 1);
}

/// No contact anywhere: the send is refused, the error names the company and
/// what is missing, the invoice stays a draft, and nothing is mailed.
#[sqlx::test]
async fn a_send_with_no_billing_contact_is_refused_and_names_the_company(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let (app, mailer) = boot_capturing(pool.clone(), CapturingMailer::default()).await;
    let token = common::login(&app, &email, &pw).await;
    let company_name: String = sqlx::query_scalar("SELECT name FROM companies WHERE id = $1")
        .bind(company_id)
        .fetch_one(&pool)
        .await
        .unwrap();

    let draft = create_draft(&app, &token, company_id, None).await;
    let id = draft["id"].as_str().unwrap();
    let resp = send(&app, &token, id, json!({ "status": "sent" })).await;
    assert_eq!(resp.status().as_u16(), 409, "refused, not recorded");
    let body: Value = resp.json().await.unwrap();
    let message = body["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        message.contains(&company_name),
        "names the company: {message}"
    );
    assert!(message.contains("no billing contact"), "{message}");
    assert!(
        message.contains("sent without emailing"),
        "points at the alternative: {message}"
    );

    let after = invoice(&app, &token, id).await;
    assert_eq!(after["status"], "draft", "the transition was blocked");
    assert!(after["sent_at"].is_null());
    assert!(mailer.sent.lock().unwrap().is_empty());
}

/// A contact without an address is the same refusal, naming the contact.
#[sqlx::test]
async fn a_send_to_a_contact_without_an_address_is_refused(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let no_address = seed_contact(&pool, company_id, None).await;
    let (app, mailer) = boot_capturing(pool.clone(), CapturingMailer::default()).await;
    let token = common::login(&app, &email, &pw).await;

    let draft = create_draft(&app, &token, company_id, Some(no_address)).await;
    let id = draft["id"].as_str().unwrap();
    let resp = send(&app, &token, id, json!({ "status": "sent" })).await;
    assert_eq!(resp.status().as_u16(), 409);
    let body: Value = resp.json().await.unwrap();
    let message = body["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        message.contains("Bill Payer"),
        "names the contact: {message}"
    );
    assert!(message.contains("no email address"), "{message}");
    assert_eq!(invoice(&app, &token, id).await["status"], "draft");
    assert!(mailer.sent.lock().unwrap().is_empty());
}

/// `skip_email` is the explicit path for an invoice delivered by hand: it
/// freezes and records nobody as emailed, and the record says so.
#[sqlx::test]
async fn skip_email_marks_sent_without_emailing_and_records_nobody(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let (app, mailer) = boot_capturing(pool.clone(), CapturingMailer::default()).await;
    let token = common::login(&app, &email, &pw).await;

    let draft = create_draft(&app, &token, company_id, None).await;
    let id = draft["id"].as_str().unwrap();
    let resp = send(
        &app,
        &token,
        id,
        json!({ "status": "sent", "skip_email": true }),
    )
    .await;
    assert!(resp.status().is_success(), "{}", resp.status());
    let sent: Value = resp.json().await.unwrap();
    assert_eq!(sent["status"], "sent");
    assert!(sent["sent_at"].is_string());
    assert!(sent["emailed_to"].is_null(), "{sent}");
    assert!(sent["emailed_at"].is_null(), "{sent}");
    assert!(mailer.sent.lock().unwrap().is_empty());
    // The document is still stored: hand-delivered is still issued.
    assert!(mokosh_server::modules::billing::documents::read_issued(
        common::DEFAULT_TENANT_ID,
        Uuid::parse_str(id).unwrap(),
    )
    .await
    .is_some());
}

/// A relay that refuses the message rolls the transition back: the invoice
/// stays a draft with no snapshot, no stored document and no `sent_at`,
/// because "sent" means the send was accepted.
#[sqlx::test]
async fn a_refused_send_leaves_the_invoice_a_draft(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let contact = seed_contact(&pool, company_id, Some("ap@client.example")).await;
    let (app, _mailer) = boot_capturing(
        pool.clone(),
        CapturingMailer {
            sent: Mutex::new(Vec::new()),
            refuse: Some("relay unreachable".to_string()),
        },
    )
    .await;
    let token = common::login(&app, &email, &pw).await;

    let draft = create_draft(&app, &token, company_id, Some(contact)).await;
    let id = draft["id"].as_str().unwrap();
    let resp = send(&app, &token, id, json!({ "status": "sent" })).await;
    assert_eq!(resp.status().as_u16(), 502, "{}", resp.status());
    let body: Value = resp.json().await.unwrap();
    let message = body["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(message.contains("ap@client.example"), "{message}");
    assert!(message.contains("has not been sent"), "{message}");

    let after = invoice(&app, &token, id).await;
    assert_eq!(after["status"], "draft");
    assert!(after["sent_at"].is_null());
    assert!(after["emailed_at"].is_null());
    // The ledger row went with the rollback. The bytes may still sit in
    // storage, which is not transactional, and the PDF route must not serve
    // them for a draft: it renders live, as for any draft.
    let ledger: Option<(String,)> =
        sqlx::query_as("SELECT entity_type FROM files WHERE tenant_id = $1 AND entity_id = $2")
            .bind(common::DEFAULT_TENANT_ID)
            .bind(Uuid::parse_str(id).unwrap())
            .fetch_optional(&pool)
            .await
            .unwrap();
    assert!(ledger.is_none(), "nothing was issued: {ledger:?}");
    let preview = app
        .client
        .get(app.url(&format!("/api/v1/invoices/{id}/pdf")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("preview");
    assert_eq!(
        preview.status().as_u16(),
        200,
        "a draft still previews live"
    );
}
