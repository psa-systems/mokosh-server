//! PMS-1037: overdue is derived on every invoice read, and a reminder worker
//! mails the customer on a schedule.
//!
//! Overdue is not a status: `is_overdue` and `days_overdue` are computed in
//! the tenant's day from `status`, `balance_due` and `due_date` on the list
//! and the detail, and `?overdue=true` filters on the same predicate. The
//! reminder sweep reads `billing_reminders/{enabled,schedule,send_hour}`,
//! runs at the tenant's local hour, mails each overdue invoice once per
//! schedule step (`invoice_reminders` is the guard), to whoever the invoice
//! was emailed to else the billing contact, with the stored document.

mod common;

use async_trait::async_trait;
use chrono::{Duration, Timelike, Utc};
use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::billing::BillingService;
use mokosh_server::secrets::DatabaseSecretProvider;
use mokosh_server::utils::email::{EmailAttachment, Mailer};
use mokosh_server::utils::error::AppResult;
use mokosh_server::Database;
use reqwest::StatusCode;
use serde_json::Value;
use sqlx::PgPool;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

#[derive(Clone, Debug)]
struct Sent {
    to: String,
    subject: String,
    text: String,
    attachments: Vec<(String, String, usize)>,
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
        self.send_with_attachments(to, subject, text, &[]).await
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
                .map(|a| (a.filename.to_string(), a.mime.to_string(), a.bytes.len()))
                .collect(),
        });
        Ok(())
    }
}

fn install_test_attachment_env() {
    common::storage_root();
}

async fn tenant_on_utc(pool: &PgPool) {
    sqlx::query("UPDATE business_hours SET timezone = 'UTC' WHERE tenant_id = $1 AND is_default")
        .bind(common::DEFAULT_TENANT_ID)
        .execute(pool)
        .await
        .expect("set the default business-hours zone");
}

async fn seed_billing_contact(pool: &PgPool, company_id: Uuid, email: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contacts (id, tenant_id, company_id, first_name, last_name, email) \
         VALUES ($1, $2, $3, 'Accounts', 'Payable', $4)",
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .bind(email)
    .execute(pool)
    .await
    .expect("seed contact");
    sqlx::query("UPDATE companies SET default_billing_contact_id = $1 WHERE id = $2")
        .bind(id)
        .bind(company_id)
        .execute(pool)
        .await
        .expect("point the company at its billing contact");
    id
}

/// An invoice dated `invoice_days_ago` days back and due `due_days_ago`
/// days back (negative means in the future), for `amount`.
async fn invoice(
    app: &common::TestApp,
    token: &str,
    company_id: Uuid,
    due_days_ago: i64,
    amount: &str,
) -> String {
    let today = Utc::now().date_naive();
    let due = today - Duration::days(due_days_ago);
    let dated = due - Duration::days(14);
    let resp = app
        .client
        .post(app.url("/api/v1/invoices"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "company_id": company_id,
            "invoice_date": dated.to_string(),
            "due_date": due.to_string(),
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
            "payment_date": Utc::now().date_naive().to_string(),
            "amount": amount,
            "payment_method": "check",
        }))
        .send()
        .await
        .expect("send payment");
    assert_eq!(resp.status(), StatusCode::OK, "pay");
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

async fn list_ids(app: &common::TestApp, token: &str, query: &str) -> Vec<String> {
    let body: Value = app
        .client
        .get(app.url(&format!("/api/v1/invoices?per_page=50{query}")))
        .bearer_auth(token)
        .send()
        .await
        .expect("list invoices")
        .json()
        .await
        .expect("list JSON");
    body["data"]
        .as_array()
        .expect("data")
        .iter()
        .filter_map(|i| i["id"].as_str().map(str::to_string))
        .collect()
}

async fn put_setting(app: &common::TestApp, token: &str, key: &str, value: Value) {
    let resp = app
        .client
        .put(app.url("/api/v1/settings"))
        .bearer_auth(token)
        .json(&serde_json::json!({ "category": "billing_reminders", "key": key, "value": value }))
        .send()
        .await
        .expect("put setting");
    assert_eq!(resp.status(), StatusCode::OK, "setting {key}");
}

fn reminder_service(pool: &PgPool, mailer: Arc<CapturingMailer>) -> BillingService {
    let key = [0u8; 32];
    BillingService::with_delivery(
        Database::from_pool(pool.clone()),
        key,
        mailer,
        "https://portal.example".to_string(),
        Arc::new(DatabaseSecretProvider::new(
            Database::from_pool(pool.clone()),
            key,
        )),
    )
}

/// Overdue is derived: a sent invoice past due says so with the day count,
/// one due today or in the future does not, and a paid, draft or
/// written-off one never does. The list filter applies the same rule.
#[sqlx::test]
async fn overdue_is_derived_on_every_read_and_filters_the_list(pool: PgPool) {
    tenant_on_utc(&pool).await;
    let (_admin, email, password) = common::seed_admin(&pool).await;
    let company = common::seed_company(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let overdue = invoice(&app, &token, company, 5, "100").await;
    send(&app, &token, &overdue).await;
    let partly = invoice(&app, &token, company, 12, "200").await;
    send(&app, &token, &partly).await;
    pay(&app, &token, company, &partly, "50").await;
    let due_today = invoice(&app, &token, company, 0, "100").await;
    send(&app, &token, &due_today).await;
    let future = invoice(&app, &token, company, -3, "100").await;
    send(&app, &token, &future).await;
    let paid = invoice(&app, &token, company, 9, "100").await;
    send(&app, &token, &paid).await;
    pay(&app, &token, company, &paid, "100").await;
    let draft = invoice(&app, &token, company, 9, "100").await;
    let written_off = invoice(&app, &token, company, 9, "100").await;
    send(&app, &token, &written_off).await;
    sqlx::query("UPDATE invoices SET status = 'written_off' WHERE id = $1")
        .bind(Uuid::parse_str(&written_off).unwrap())
        .execute(&pool)
        .await
        .expect("write off by hand");

    let read = get_invoice(&app, &token, &overdue).await;
    assert_eq!(read["is_overdue"], true, "{read}");
    assert_eq!(read["days_overdue"], 5, "{read}");
    let read = get_invoice(&app, &token, &partly).await;
    assert_eq!(read["status"], "partially_paid");
    assert_eq!(read["is_overdue"], true);
    assert_eq!(read["days_overdue"], 12);
    for (id, why) in [
        (&due_today, "due today"),
        (&future, "due in the future"),
        (&paid, "paid"),
        (&draft, "draft"),
        (&written_off, "written off"),
    ] {
        let read = get_invoice(&app, &token, id).await;
        assert_eq!(read["is_overdue"], false, "{why}: {read}");
        assert_eq!(read["days_overdue"], 0, "{why}: {read}");
    }

    let only_overdue = list_ids(&app, &token, "&overdue=true").await;
    assert_eq!(only_overdue.len(), 2, "{only_overdue:?}");
    assert!(only_overdue.contains(&overdue) && only_overdue.contains(&partly));
    let not_overdue = list_ids(&app, &token, "&overdue=false").await;
    assert_eq!(not_overdue.len(), 5, "{not_overdue:?}");
    assert!(!not_overdue.contains(&overdue));
    let all = list_ids(&app, &token, "").await;
    assert_eq!(all.len(), 7);
}

/// With reminders on and a `[3, 7]` schedule at the tenant's current hour, an
/// invoice 3 days past due gets one mail, a second run the same hour sends
/// nothing, day 7 sends the second, and reminders off send nothing. The mail
/// goes to the billing contact and carries the stored document.
#[sqlx::test]
async fn reminders_follow_the_schedule_once_per_step(pool: PgPool) {
    install_test_attachment_env();
    tenant_on_utc(&pool).await;
    let (_admin, email, password) = common::seed_admin(&pool).await;
    let company = common::seed_company(&pool).await;
    seed_billing_contact(&pool, company, "ap@client.example").await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let now = Utc::now();
    put_setting(&app, &token, "enabled", Value::Bool(true)).await;
    put_setting(&app, &token, "schedule", serde_json::json!([3, 7])).await;
    put_setting(&app, &token, "send_hour", Value::from(now.hour())).await;

    let three = invoice(&app, &token, company, 3, "150").await;
    send(&app, &token, &three).await;
    let one = invoice(&app, &token, company, 1, "150").await;
    send(&app, &token, &one).await;
    let current = invoice(&app, &token, company, -2, "150").await;
    send(&app, &token, &current).await;

    let mailer = Arc::new(CapturingMailer::default());
    let svc = reminder_service(&pool, mailer.clone());
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);

    let sent = svc
        .send_due_reminders(tenant, now)
        .await
        .expect("first run");
    assert_eq!(sent, vec![Uuid::parse_str(&three).unwrap()], "day 3 only");
    let mails = mailer.sent.lock().unwrap().clone();
    assert_eq!(mails.len(), 1, "{mails:?}");
    let mail = &mails[0];
    assert_eq!(mail.to, "ap@client.example");
    assert!(mail.subject.contains("3 days overdue"), "{}", mail.subject);
    assert!(mail.text.contains("Amount due: 150"), "{}", mail.text);
    assert!(mail.text.contains("(3 days ago)"), "{}", mail.text);
    assert!(!mail.text.contains("pay online"), "no gateway, no pay link");
    assert_eq!(mail.attachments.len(), 1, "the stored document travels");
    assert_eq!(mail.attachments[0].1, "application/pdf");
    assert!(mail.attachments[0].2 > 0);

    // The same hour again: nothing.
    let again = svc
        .send_due_reminders(tenant, now)
        .await
        .expect("second run");
    assert!(again.is_empty());
    assert_eq!(mailer.sent.lock().unwrap().len(), 1);

    // Another hour: nothing either, whatever is due.
    let off_hour = now + Duration::hours(1);
    let none = svc
        .send_due_reminders(tenant, off_hour)
        .await
        .expect("off hour");
    assert!(none.is_empty());

    // Day 7 for the first invoice: the second step fires once.
    sqlx::query("UPDATE invoices SET due_date = $2 WHERE id = $1")
        .bind(Uuid::parse_str(&three).unwrap())
        .bind(now.date_naive() - Duration::days(7))
        .execute(&pool)
        .await
        .expect("age the invoice");
    let day7 = svc.send_due_reminders(tenant, now).await.expect("day 7");
    assert_eq!(day7.len(), 1);
    let mails = mailer.sent.lock().unwrap().clone();
    assert_eq!(mails.len(), 2);
    assert!(
        mails[1].subject.contains("7 days overdue"),
        "{}",
        mails[1].subject
    );
    let rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM invoice_reminders WHERE invoice_id = $1")
            .bind(Uuid::parse_str(&three).unwrap())
            .fetch_one(&pool)
            .await
            .expect("reminder rows");
    assert_eq!(rows, 2, "one row per step");

    // Off: nothing, even with a step due.
    put_setting(&app, &token, "enabled", Value::Bool(false)).await;
    sqlx::query("UPDATE invoices SET due_date = $2 WHERE id = $1")
        .bind(Uuid::parse_str(&one).unwrap())
        .bind(now.date_naive() - Duration::days(3))
        .execute(&pool)
        .await
        .expect("age the other invoice");
    let off = svc.send_due_reminders(tenant, now).await.expect("off");
    assert!(off.is_empty());
    assert_eq!(mailer.sent.lock().unwrap().len(), 2);
}

/// The schedule setting refuses shapes the sweep could not follow.
#[sqlx::test]
async fn the_schedule_setting_is_validated(pool: PgPool) {
    let (_admin, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    for bad in [
        serde_json::json!([]),
        serde_json::json!([7, 3]),
        serde_json::json!([3, 3]),
        serde_json::json!([0]),
        serde_json::json!([400]),
        serde_json::json!("3,7"),
    ] {
        let resp = app
            .client
            .put(app.url("/api/v1/settings"))
            .bearer_auth(&token)
            .json(&serde_json::json!({ "category": "billing_reminders", "key": "schedule", "value": bad }))
            .send()
            .await
            .expect("put setting");
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY, "{bad}");
    }
    let resp = app
        .client
        .put(app.url("/api/v1/settings"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "category": "billing_reminders", "key": "send_hour", "value": 24 }))
        .send()
        .await
        .expect("put setting");
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}
