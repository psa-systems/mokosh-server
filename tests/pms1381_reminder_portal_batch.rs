//! PMS-1381 (F4): `BillingService::send_due_reminders` looks up each claimed
//! invoice's company portal id in ONE batched query for the whole sweep,
//! rather than opening a fresh `company_portal_id` transaction per claim.
//!
//! Two companies, two overdue invoices each (four claims total), proves both
//! halves at once: the statement log (an in-process `log_statement=all`, the
//! same technique `tests/notification_worker_transactions.rs` uses for the
//! same "count what actually ran" problem) shows exactly one `SELECT ...
//! FROM companies ... = ANY(...)` for the whole run, not four; and each
//! mailed reminder still links its OWN company's portal id, not a shared or
//! swapped one.
//!
//! This file holds exactly ONE test on purpose: the tracing subscriber
//! installed below is process-global, so a second test running concurrently
//! in this binary would count its statements too.

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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use uuid::Uuid;

const TEST_KEY: [u8; 32] = [0u8; 32];

#[derive(Default)]
struct Recorder {
    armed: AtomicBool,
    statements: Mutex<Vec<String>>,
}

impl Recorder {
    fn push(&self, entry: String) {
        self.statements.lock().expect("statement log").push(entry);
    }

    fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.statements.lock().expect("statement log"))
    }
}

#[derive(Default)]
struct SqlVisitor {
    statement: Option<String>,
    summary: Option<String>,
}

impl Visit for SqlVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        match field.name() {
            "db.statement" => self.statement = Some(format!("{value:?}")),
            "summary" => self.summary = Some(format!("{value:?}")),
            _ => {}
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        match field.name() {
            "db.statement" => self.statement = Some(value.to_string()),
            "summary" => self.summary = Some(value.to_string()),
            _ => {}
        }
    }
}

struct RecordingLayer(Arc<Recorder>);

impl<S: tracing::Subscriber> Layer<S> for RecordingLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        if event.metadata().target() != "sqlx::query" || !self.0.armed.load(Ordering::SeqCst) {
            return;
        }
        let mut visitor = SqlVisitor::default();
        event.record(&mut visitor);
        let sql = visitor
            .statement
            .filter(|s| !s.trim().is_empty())
            .or(visitor.summary)
            .unwrap_or_else(|| "<no sql field>".to_string());
        self.0
            .push(sql.split_whitespace().collect::<Vec<_>>().join(" "));
    }
}

#[derive(Clone, Debug)]
struct Sent {
    to: String,
    text: String,
}

#[derive(Default)]
struct CapturingMailer {
    sent: Mutex<Vec<Sent>>,
}

#[async_trait]
impl Mailer for CapturingMailer {
    async fn send_multipart(
        &self,
        _to: &str,
        _subject: &str,
        _text: &str,
        _html: Option<&str>,
    ) -> AppResult<()> {
        unreachable!("reminders send with attachments")
    }

    async fn send_with_attachments(
        &self,
        to: &str,
        _subject: &str,
        text: &str,
        _attachments: &[EmailAttachment<'_>],
    ) -> AppResult<()> {
        self.sent.lock().unwrap().push(Sent {
            to: to.to_string(),
            text: text.to_string(),
        });
        Ok(())
    }
}

fn reminder_service(pool: &PgPool, mailer: Arc<CapturingMailer>) -> BillingService {
    BillingService::with_delivery(
        Database::from_pool(pool.clone()),
        TEST_KEY,
        mailer,
        "https://portal.example".to_string(),
        Arc::new(DatabaseSecretProvider::new(
            Database::from_pool(pool.clone()),
            TEST_KEY,
        )),
    )
}

async fn tenant_on_utc(pool: &PgPool) {
    sqlx::query("UPDATE business_hours SET timezone = 'UTC' WHERE tenant_id = $1 AND is_default")
        .bind(common::DEFAULT_TENANT_ID)
        .execute(pool)
        .await
        .expect("set the default business-hours zone");
}

async fn seed_stripe_gateway(pool: &PgPool) {
    let plaintext = serde_json::json!({
        "secret_key": "sk_test_1", "webhook_secret": "whsec_1",
    })
    .to_string();
    let encrypted = mokosh_server::utils::crypto::encrypt(&plaintext, &TEST_KEY).unwrap();
    sqlx::query(
        "INSERT INTO payment_gateway_configs \
         (tenant_id, provider, is_active, is_test_mode, config_encrypted) \
         VALUES ($1, 'stripe', TRUE, TRUE, $2)",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(encrypted)
    .execute(pool)
    .await
    .expect("seed stripe gateway");
}

async fn seed_company_with_portal(pool: &PgPool, name: &str, portal_id: i64, email: &str) -> Uuid {
    let company_id = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name, portal_id) VALUES ($1, $2, $3, $4)")
        .bind(company_id)
        .bind(common::DEFAULT_TENANT_ID)
        .bind(name)
        .bind(portal_id)
        .execute(pool)
        .await
        .expect("seed company");
    let contact_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contacts (id, tenant_id, company_id, first_name, last_name, email) \
         VALUES ($1, $2, $3, 'Accounts', 'Payable', $4)",
    )
    .bind(contact_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .bind(email)
    .execute(pool)
    .await
    .expect("seed billing contact");
    sqlx::query("UPDATE companies SET default_billing_contact_id = $1 WHERE id = $2")
        .bind(contact_id)
        .bind(company_id)
        .execute(pool)
        .await
        .expect("point company at its billing contact");
    company_id
}

/// An overdue invoice (3 days past due), sent, for `company_id`.
async fn overdue_invoice(app: &common::TestApp, token: &str, company_id: Uuid) -> Uuid {
    let today = Utc::now().date_naive();
    let due = today - Duration::days(3);
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
                "unit_price": "150",
            }],
        }))
        .send()
        .await
        .expect("send create invoice");
    assert_eq!(resp.status(), StatusCode::OK, "create invoice");
    let invoice: Value = resp.json().await.expect("invoice JSON");
    let invoice_id = Uuid::parse_str(invoice["id"].as_str().expect("invoice id")).unwrap();

    let resp = app
        .client
        .put(app.url(&format!("/api/v1/invoices/{invoice_id}")))
        .bearer_auth(token)
        .json(&serde_json::json!({ "status": "sent", "skip_email": true }))
        .send()
        .await
        .expect("send invoice");
    assert_eq!(resp.status(), StatusCode::OK, "mark sent");
    invoice_id
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

#[sqlx::test]
async fn a_reminder_sweep_looks_up_portal_ids_in_one_batched_query(pool: PgPool) {
    let recorder = Arc::new(Recorder::default());
    tracing::subscriber::set_global_default(
        tracing_subscriber::registry().with(RecordingLayer(recorder.clone())),
    )
    .expect("install the recording subscriber");

    tenant_on_utc(&pool).await;
    seed_stripe_gateway(&pool).await;
    let (_admin, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let now = Utc::now();
    put_setting(&app, &token, "enabled", Value::Bool(true)).await;
    put_setting(&app, &token, "schedule", serde_json::json!([3])).await;
    put_setting(&app, &token, "send_hour", Value::from(now.hour())).await;

    // Two companies, each with its own portal id, two overdue invoices apiece
    // (four claims total): the batch must resolve two portal ids, not four.
    let company_a = seed_company_with_portal(&pool, "Acme Co", 111111111, "ap@acme.example").await;
    let company_b =
        seed_company_with_portal(&pool, "Widget Co", 222222222, "ap@widget.example").await;
    overdue_invoice(&app, &token, company_a).await;
    overdue_invoice(&app, &token, company_a).await;
    overdue_invoice(&app, &token, company_b).await;
    overdue_invoice(&app, &token, company_b).await;

    let mailer = Arc::new(CapturingMailer::default());
    let svc = reminder_service(&pool, mailer.clone());
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);

    recorder.armed.store(true, Ordering::SeqCst);
    let sent = svc
        .send_due_reminders(tenant, now)
        .await
        .expect("reminder sweep");
    recorder.armed.store(false, Ordering::SeqCst);

    assert_eq!(sent.len(), 4, "all four overdue invoices are reminded");

    // AC: one query for portal ids across N claims / M companies, not one
    // transaction per claim.
    let log = recorder.take();
    let portal_lookups: Vec<&String> = log
        .iter()
        .filter(|s| s.contains("FROM companies") && s.contains("portal_id"))
        .collect();
    assert_eq!(
        portal_lookups.len(),
        1,
        "expected exactly one batched portal id lookup for the whole sweep, got: {log:#?}"
    );
    assert!(
        portal_lookups[0].contains("ANY"),
        "the one lookup must be the batched ANY($1) form: {portal_lookups:?}"
    );

    // AC: each mail still links its OWN company's portal, not a shared or
    // swapped one.
    let mails = mailer.sent.lock().unwrap().clone();
    assert_eq!(mails.len(), 4, "{mails:#?}");
    for mail in &mails {
        if mail.to == "ap@acme.example" {
            assert!(
                mail.text.contains("/portal/111111111/login"),
                "Acme's reminder must link Acme's own portal id: {}",
                mail.text
            );
            assert!(!mail.text.contains("222222222"), "{}", mail.text);
        } else if mail.to == "ap@widget.example" {
            assert!(
                mail.text.contains("/portal/222222222/login"),
                "Widget's reminder must link Widget's own portal id: {}",
                mail.text
            );
            assert!(!mail.text.contains("111111111"), "{}", mail.text);
        } else {
            panic!("unexpected recipient: {}", mail.to);
        }
    }
}
