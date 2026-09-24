//! PMS-1381 (F6): `invoice_lines` / `credit_note_lines` inserts are one
//! batched multi-row `INSERT ... FROM UNNEST(...)` per request, not one
//! `INSERT` per line, at all four sites the issue names: `create_invoice`,
//! `generate_one_recurring_invoice`, `update_invoice` (delete-then-reinsert),
//! and `create_credit_note`.
//!
//! Uses the same in-process statement log as
//! `tests/notification_worker_transactions.rs` and
//! `tests/pms1381_reminder_portal_batch.rs` (a `tracing` subscriber capturing
//! `target: "sqlx::query"` events, the in-process equivalent of
//! `log_statement=all`) to count what actually ran, since Postgres has no
//! reliable, immediately-visible statement counter for a `#[sqlx::test]`
//! throwaway database.
//!
//! Also proves the recurring generator's per-"once"-item idempotency claim
//! (PMS-64) still runs row-by-row: it is a per-row `UPDATE ... WHERE
//! billed_at IS NULL` claim, not a batchable insert, and must stay that way
//! even though the `invoice_lines` insert that follows it now batches.
//!
//! This file holds exactly ONE test on purpose: the tracing subscriber
//! installed below is process-global, so a second test running concurrently
//! in this binary would count its statements too.

mod common;

use chrono::{NaiveDate, TimeZone, Utc};
use mokosh_server::modules::audit::AuditCtx;
use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::billing::BillingService;
use mokosh_server::Database;
use reqwest::StatusCode;
use rust_decimal::Decimal;
use serde_json::Value;
use sqlx::PgPool;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use uuid::Uuid;

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

fn count_matching<'a>(log: &'a [String], needles: &[&str]) -> Vec<&'a String> {
    log.iter()
        .filter(|s| needles.iter().all(|n| s.contains(n)))
        .collect()
}

async fn create_invoice_with_lines(
    app: &common::TestApp,
    token: &str,
    company_id: Uuid,
    line_count: usize,
) -> Uuid {
    let lines: Vec<Value> = (0..line_count)
        .map(|i| {
            serde_json::json!({
                "line_type": "service",
                "description": format!("Line {i}"),
                "quantity": "1",
                "unit_price": "100",
            })
        })
        .collect();
    let resp = app
        .client
        .post(app.url("/api/v1/invoices"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "company_id": company_id,
            "invoice_date": "2026-06-01",
            "due_date": "2026-07-01",
            "lines": lines,
        }))
        .send()
        .await
        .expect("send create invoice");
    assert_eq!(resp.status(), StatusCode::OK, "create invoice");
    let invoice: Value = resp.json().await.expect("invoice JSON");
    Uuid::parse_str(invoice["id"].as_str().expect("invoice id")).unwrap()
}

async fn replace_invoice_lines(
    app: &common::TestApp,
    token: &str,
    invoice_id: Uuid,
    line_count: usize,
) {
    let lines: Vec<Value> = (0..line_count)
        .map(|i| {
            serde_json::json!({
                "line_type": "service",
                "description": format!("Replaced line {i}"),
                "quantity": "1",
                "unit_price": "50",
            })
        })
        .collect();
    let resp = app
        .client
        .put(app.url(&format!("/api/v1/invoices/{invoice_id}")))
        .bearer_auth(token)
        .json(&serde_json::json!({ "lines": lines }))
        .send()
        .await
        .expect("send update invoice");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "update invoice: {invoice_id}"
    );
}

async fn create_credit_note_with_lines(
    app: &common::TestApp,
    token: &str,
    invoice_id: Uuid,
    line_count: usize,
) {
    let lines: Vec<Value> = (0..line_count)
        .map(|i| {
            serde_json::json!({
                "line_type": "adjustment",
                "description": format!("Credit line {i}"),
                "quantity": "1",
                "unit_price": "10",
            })
        })
        .collect();
    let resp = app
        .client
        .post(app.url("/api/v1/credit-notes"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "invoice_id": invoice_id,
            "reason": "Test credit",
            "lines": lines,
        }))
        .send()
        .await
        .expect("send create credit note");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "create credit note: {}",
        resp.status()
    );
}

async fn seed_contract(pool: &PgPool, company_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO contracts
           (id, tenant_id, name, company_id, contract_type, status,
            start_date, end_date, billing_cycle)
           VALUES ($1, $2, 'Managed', $3, 'managed_services', 'active',
                   $4, NULL, 'monthly')"#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .bind(NaiveDate::from_ymd_opt(2026, 1, 1).unwrap())
    .execute(pool)
    .await
    .expect("seed contract");
    id
}

async fn seed_item(
    pool: &PgPool,
    contract_id: Uuid,
    name: &str,
    item_type: &str,
    billing_rule: &str,
    unit_price: Decimal,
) {
    sqlx::query(
        r#"INSERT INTO contract_items
           (id, tenant_id, contract_id, name, item_type, quantity, unit_price,
            total_price, sort_order, billing_rule)
           VALUES ($1, $2, $3, $4, $5, 1, $6, $6, 0, $7)"#,
    )
    .bind(Uuid::new_v4())
    .bind(common::DEFAULT_TENANT_ID)
    .bind(contract_id)
    .bind(name)
    .bind(item_type)
    .bind(unit_price)
    .bind(billing_rule)
    .execute(pool)
    .await
    .expect("seed contract item");
}

#[sqlx::test]
async fn line_inserts_are_batched_at_all_four_sites(pool: PgPool) {
    let recorder = Arc::new(Recorder::default());
    tracing::subscriber::set_global_default(
        tracing_subscriber::registry().with(RecordingLayer(recorder.clone())),
    )
    .expect("install the recording subscriber");

    let (_admin, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    // --- Site 1: create_invoice --------------------------------------
    recorder.armed.store(true, Ordering::SeqCst);
    let invoice_id = create_invoice_with_lines(&app, &token, company_id, 5).await;
    recorder.armed.store(false, Ordering::SeqCst);
    let log = recorder.take();
    let inserts = count_matching(&log, &["INSERT INTO invoice_lines"]);
    assert_eq!(
        inserts.len(),
        1,
        "create_invoice must issue exactly one INSERT for 5 lines, got: {log:#?}"
    );
    assert!(
        inserts[0].contains("UNNEST"),
        "the one insert must be the batched UNNEST form: {inserts:?}"
    );
    let line_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM invoice_lines WHERE invoice_id = $1")
            .bind(invoice_id)
            .fetch_one(&pool)
            .await
            .expect("count lines");
    assert_eq!(line_count, 5, "all 5 lines were actually written");

    // --- Site 3: update_invoice (delete-then-reinsert) ----------------
    recorder.armed.store(true, Ordering::SeqCst);
    replace_invoice_lines(&app, &token, invoice_id, 4).await;
    recorder.armed.store(false, Ordering::SeqCst);
    let log = recorder.take();
    let deletes = count_matching(&log, &["DELETE FROM invoice_lines"]);
    let inserts = count_matching(&log, &["INSERT INTO invoice_lines"]);
    assert_eq!(
        deletes.len(),
        1,
        "update_invoice must issue exactly one DELETE, got: {log:#?}"
    );
    assert_eq!(
        inserts.len(),
        1,
        "update_invoice must issue exactly one INSERT for the replacement lines, got: {log:#?}"
    );
    assert!(
        inserts[0].contains("UNNEST"),
        "the replacement insert must be the batched UNNEST form: {inserts:?}"
    );
    let line_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM invoice_lines WHERE invoice_id = $1")
            .bind(invoice_id)
            .fetch_one(&pool)
            .await
            .expect("count lines after update");
    assert_eq!(
        line_count, 4,
        "the invoice now has exactly the 4 replacement lines"
    );

    // Send the invoice so a credit note can be raised against it.
    let resp = app
        .client
        .put(app.url(&format!("/api/v1/invoices/{invoice_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "status": "sent", "skip_email": true }))
        .send()
        .await
        .expect("send invoice");
    assert_eq!(resp.status(), StatusCode::OK, "mark sent");

    // --- Site 4: create_credit_note ------------------------------------
    recorder.armed.store(true, Ordering::SeqCst);
    create_credit_note_with_lines(&app, &token, invoice_id, 3).await;
    recorder.armed.store(false, Ordering::SeqCst);
    let log = recorder.take();
    let inserts = count_matching(&log, &["INSERT INTO credit_note_lines"]);
    assert_eq!(
        inserts.len(),
        1,
        "create_credit_note must issue exactly one INSERT for 3 lines, got: {log:#?}"
    );
    assert!(
        inserts[0].contains("UNNEST"),
        "the one insert must be the batched UNNEST form: {inserts:?}"
    );
    let credit_line_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM credit_note_lines cnl JOIN credit_notes cn ON cn.id = cnl.credit_note_id WHERE cn.invoice_id = $1")
            .bind(invoice_id)
            .fetch_one(&pool)
            .await
            .expect("count credit note lines");
    assert_eq!(
        credit_line_count, 3,
        "all 3 credit lines were actually written"
    );

    // --- Site 2: generate_one_recurring_invoice -------------------------
    // Two `once` items (the per-row idempotency claim must stay row-by-row)
    // plus one `every_period` item, so the invoice ends up with 3 lines from
    // one batched insert.
    let contract_id = seed_contract(&pool, company_id).await;
    seed_item(
        &pool,
        contract_id,
        "Onboarding A",
        "one_time",
        "once",
        Decimal::from(200),
    )
    .await;
    seed_item(
        &pool,
        contract_id,
        "Onboarding B",
        "one_time",
        "once",
        Decimal::from(300),
    )
    .await;
    seed_item(
        &pool,
        contract_id,
        "Managed services",
        "recurring_service",
        "every_period",
        Decimal::from(500),
    )
    .await;

    let svc = BillingService::new(Database::from_pool(pool.clone()));
    let ctx = AuditCtx::system(common::DEFAULT_TENANT_ID);
    let now = Utc.with_ymd_and_hms(2026, 1, 15, 12, 0, 0).unwrap();

    recorder.armed.store(true, Ordering::SeqCst);
    let created = svc
        .generate_due_recurring_invoices(
            TenantId::from_trusted(common::DEFAULT_TENANT_ID),
            now,
            &ctx,
        )
        .await
        .expect("generate recurring invoices");
    recorder.armed.store(false, Ordering::SeqCst);
    assert_eq!(created.len(), 1, "one recurring invoice generated");
    let recurring_invoice_id = created[0];

    let log = recorder.take();
    let claims = count_matching(&log, &["UPDATE contract_items", "billed_at"]);
    assert_eq!(
        claims.len(),
        2,
        "the two `once` items must each claim with their own row-by-row UPDATE, got: {log:#?}"
    );
    let inserts = count_matching(&log, &["INSERT INTO invoice_lines"]);
    assert_eq!(
        inserts.len(),
        1,
        "generate_one_recurring_invoice must issue exactly one batched INSERT for all 3 items, got: {log:#?}"
    );
    assert!(
        inserts[0].contains("UNNEST"),
        "the recurring insert must be the batched UNNEST form: {inserts:?}"
    );
    let recurring_line_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM invoice_lines WHERE invoice_id = $1")
            .bind(recurring_invoice_id)
            .fetch_one(&pool)
            .await
            .expect("count recurring lines");
    assert_eq!(recurring_line_count, 3, "all 3 items became lines");

    // Idempotency is unaffected by the batching: a second run bills nothing
    // more (the `once` items are claimed, and the period is already billed).
    let second = svc
        .generate_due_recurring_invoices(
            TenantId::from_trusted(common::DEFAULT_TENANT_ID),
            now,
            &ctx,
        )
        .await
        .expect("second run");
    assert!(second.is_empty(), "second run creates nothing");
}
