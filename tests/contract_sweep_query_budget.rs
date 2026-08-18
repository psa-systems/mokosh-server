//! PMS-779: the statement budget of the contract lifecycle sweep
//! (`ContractsService::expire_due_contracts`), pinned as a regression test.
//!
//! The sweep drains each tenant's due contracts a batch at a time under
//! `FOR UPDATE`. It used to snapshot each row for the audit log with two extra
//! scalar reads per contract - `SELECT to_jsonb(t) FROM contracts t WHERE
//! id = $1` before the update and again after it - so a batch of N contracts
//! cost `1 + N` reads of `contracts` (plus N more after the writes), all with
//! the row locks held.
//!
//! The `before` snapshot now rides on the batch read as `to_jsonb(contracts)`
//! and the `after` snapshot on `UPDATE ... RETURNING to_jsonb(contracts)`, so
//! the read count per batch is 1 regardless of N.
//!
//! The count comes from a `tracing` subscriber that records `sqlx::query`
//! events, the in-process equivalent of Postgres `log_statement=all` (the
//! `tests/bunyip_query_budget.rs` pattern). This file holds exactly ONE test
//! on purpose: the subscriber is process-global, so a second test running
//! concurrently would count its statements as well.

mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use chrono::{TimeZone, Utc};
use sqlx::PgPool;
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use uuid::Uuid;

use mokosh_server::modules::contracts::ContractsService;
use mokosh_server::Database;

/// Statements observed while [`Recorder::armed`] is set.
#[derive(Default)]
struct Recorder {
    armed: AtomicBool,
    statements: Mutex<Vec<String>>,
}

impl Recorder {
    fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.statements.lock().expect("statement log"))
    }
}

/// Pulls the SQL text off an `sqlx::query` event. sqlx records the full text as
/// `db.statement` and a one-line version as `summary`; either identifies the
/// statement, so prefer the full text and fall back to the summary.
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
            .or(visitor.summary)
            .unwrap_or_else(|| "<no sql field>".to_string());
        self.0
            .statements
            .lock()
            .expect("statement log")
            .push(sql.split_whitespace().collect::<Vec<_>>().join(" "));
    }
}

/// Due contracts seeded for the sweep: enough that a per-contract read shows up
/// clearly against the fixed per-batch cost.
const DUE_CONTRACTS: usize = 4;

/// Reads of `contracts` one sweep of a single tenant may cost: the tenant
/// discovery query, the batch that returns the due rows, and the empty batch
/// that terminates the drain. Independent of [`DUE_CONTRACTS`]; raising this is
/// a throughput regression, not a test failure to paper over.
const CONTRACT_READ_BUDGET: usize = 3;

#[sqlx::test]
async fn a_sweep_batch_reads_contracts_once(pool: PgPool) {
    let recorder = Arc::new(Recorder::default());
    tracing::subscriber::set_global_default(
        tracing_subscriber::registry().with(RecordingLayer(recorder.clone())),
    )
    .expect("install the recording subscriber");

    let tenant = common::DEFAULT_TENANT_ID;
    let company = common::seed_company(&pool).await;

    // Half renew, half expire, so both branches of the loop run in one batch.
    for i in 0..DUE_CONTRACTS {
        sqlx::query(
            r#"INSERT INTO contracts
               (id, tenant_id, name, company_id, contract_type, status,
                start_date, end_date, auto_renew, renewal_terms)
               VALUES ($1, $2, $3, $4, 'managed_services', 'active',
                       '2025-01-01', '2025-12-31', $5, '{"term_months": 12}'::jsonb)"#,
        )
        .bind(Uuid::new_v4())
        .bind(tenant)
        .bind(format!("Due {i}"))
        .bind(company)
        .bind(i % 2 == 0)
        .execute(&pool)
        .await
        .expect("seed due contract");
    }

    let svc = ContractsService::new(Database::from_pool(pool.clone()));
    let now = Utc.with_ymd_and_hms(2026, 1, 15, 0, 0, 0).unwrap();

    recorder.armed.store(true, Ordering::SeqCst);
    let (renewed, expired) = svc.expire_due_contracts(now).await.expect("sweep");
    recorder.armed.store(false, Ordering::SeqCst);

    assert_eq!(
        renewed as usize + expired as usize,
        DUE_CONTRACTS,
        "the measured sweep must still process every due contract"
    );

    let statements = recorder.take();

    // AC: the read count per sweep is fixed, not `1 + N` per batch.
    let contract_reads: Vec<&String> = statements
        .iter()
        .filter(|s| s.starts_with("SELECT") && s.contains("contracts"))
        .collect();
    assert_eq!(
        contract_reads.len(),
        CONTRACT_READ_BUDGET,
        "a sweep of {DUE_CONTRACTS} due contracts must read `contracts` \
         {CONTRACT_READ_BUDGET} times, got: {contract_reads:#?}"
    );

    // Exactly one of those reads is the locking batch that returns rows; the
    // other locking read is the empty batch that ends the drain.
    let batch_reads = contract_reads
        .iter()
        .filter(|s| s.contains("FOR UPDATE"))
        .count();
    assert_eq!(
        batch_reads, 2,
        "one loaded batch plus the empty terminating batch: {contract_reads:#?}"
    );

    // AC: neither audit snapshot is a standalone read any more.
    assert!(
        !statements.iter().any(|s| s.starts_with("SELECT to_jsonb")),
        "the sweep must not snapshot a row with its own SELECT: {statements:#?}"
    );

    // Both snapshots still reach the audit log: one row per contract, each
    // carrying `old_values` and `new_values`.
    let snapshotted: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM audit_log
           WHERE entity_type = 'contracts' AND action = 'update'
             AND old_values IS NOT NULL AND new_values IS NOT NULL"#,
    )
    .fetch_one(&pool)
    .await
    .expect("count sweep audit rows");
    assert_eq!(
        snapshotted, DUE_CONTRACTS as i64,
        "every swept contract keeps a before/after audit snapshot"
    );
}
