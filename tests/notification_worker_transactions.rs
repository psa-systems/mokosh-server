//! PMS-782 (finding F9): the dispatcher worker must not hold a database
//! transaction across an SMTP round trip.
//!
//! `run_tick` used to open one migrator-pool transaction, select the batch
//! `FOR UPDATE SKIP LOCKED`, and deliver every row inside it, so the
//! transaction lived for the sum of the batch's relay latencies: a 25-row
//! batch against a 500 ms relay pinned a connection and 25 row locks for ~12 s
//! every 5 s tick, blocked vacuum on `notifications`, and overlapped itself.
//!
//! The tick is now claim (one statement, own transaction), send (nothing
//! open), settle (one transaction, at most two statements). This test proves
//! it two ways at once:
//!
//!   * the mailer samples `pg_stat_activity` on every send and asserts that no
//!     other backend of this database has a transaction open, which is the
//!     issue's own `max(now() - xact_start)` validation reduced to a
//!     deterministic assertion;
//!   * a `tracing` subscriber records every statement (the in-process
//!     equivalent of `log_statement=all`, per `tests/contract_sweep_query_budget.rs`)
//!     so the settle budget can be counted.
//!
//! This file holds exactly ONE test on purpose: the subscriber is
//! process-global, so a second test running concurrently would count its
//! statements as well. The crash-recovery half of F9 lives in
//! `tests/notifications.rs`, which installs no subscriber.

mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use sqlx::PgPool;
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};

use mokosh_server::modules::notifications::DispatcherWorker;
use mokosh_server::utils::email::Mailer;
use mokosh_server::utils::error::AppResult;
use mokosh_server::Database;

/// How long the fake relay takes to answer, matching the issue's 500 ms
/// scenario. A transaction held across the batch would show up as an age well
/// past [`MAX_XACT_AGE_MS`] on the second send.
const RELAY_LATENCY: Duration = Duration::from_millis(500);

/// The issue's threshold: no transaction in this database may be older than
/// this while a send is in flight.
const MAX_XACT_AGE_MS: f64 = 100.0;

/// Statements observed while [`Recorder::armed`] is set, interleaved with a
/// marker for each send so the ordering is checkable.
const SEND_MARKER: &str = "<<SEND>>";

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
        // sqlx leaves `db.statement` empty for a single-line statement and puts
        // the text in `summary`; a multi-line one populates both.
        let sql = visitor
            .statement
            .filter(|s| !s.trim().is_empty())
            .or(visitor.summary)
            .unwrap_or_else(|| "<no sql field>".to_string());
        self.0
            .push(sql.split_whitespace().collect::<Vec<_>>().join(" "));
    }
}

/// A relay that takes [`RELAY_LATENCY`] to answer and, while it is answering,
/// looks at what the rest of the database is doing.
struct SlowProbingMailer {
    pool: PgPool,
    recorder: Arc<Recorder>,
    /// Oldest open transaction (milliseconds) seen by any send, and how many
    /// other backends were in a transaction at that moment.
    observations: Mutex<Vec<(f64, i64)>>,
}

#[async_trait]
impl Mailer for SlowProbingMailer {
    async fn send_multipart(
        &self,
        _to: &str,
        _subject: &str,
        _text: &str,
        _html: Option<&str>,
    ) -> AppResult<()> {
        self.recorder.push(SEND_MARKER.to_string());
        tokio::time::sleep(RELAY_LATENCY).await;

        // Every backend with an open transaction has a non-null `xact_start`,
        // whether it is `active` or parked `idle in transaction`. Our own
        // backend is excluded: this probe is itself a statement.
        let (oldest_ms, open): (Option<f64>, i64) = sqlx::query_as(
            r#"SELECT MAX(EXTRACT(EPOCH FROM (clock_timestamp() - xact_start)) * 1000)::float8,
                      COUNT(*)
               FROM pg_stat_activity
               WHERE datname = current_database()
                 AND pid <> pg_backend_pid()
                 AND xact_start IS NOT NULL"#,
        )
        .fetch_one(&self.pool)
        .await
        .expect("probe pg_stat_activity");
        self.observations
            .lock()
            .expect("observations")
            .push((oldest_ms.unwrap_or(0.0), open));
        Ok(())
    }
}

/// Rows delivered over SMTP in the measured tick.
const EMAIL_ROWS: usize = 3;

#[sqlx::test]
async fn a_tick_sends_with_no_transaction_open(pool: PgPool) {
    let recorder = Arc::new(Recorder::default());
    tracing::subscriber::set_global_default(
        tracing_subscriber::registry().with(RecordingLayer(recorder.clone())),
    )
    .expect("install the recording subscriber");

    let tenant_id = common::DEFAULT_TENANT_ID;
    let (admin_id, _email, _password) = common::seed_admin(&pool).await;

    for i in 0..EMAIL_ROWS {
        sqlx::query(
            r#"INSERT INTO notifications (tenant_id, user_id, channel_type, subject, body, status)
               VALUES ($1, $2, 'email', $3, 'body', 'pending')"#,
        )
        .bind(tenant_id)
        .bind(admin_id)
        .bind(format!("Subject {i}"))
        .execute(&pool)
        .await
        .expect("seed pending email row");
    }
    // One row on a channel with no transport, so the tick settles a failure
    // alongside the successes and both write-back statements run.
    sqlx::query(
        r#"INSERT INTO notifications (tenant_id, user_id, channel_type, subject, body, status)
           VALUES ($1, $2, 'slack', 'No transport', 'body', 'pending')"#,
    )
    .bind(tenant_id)
    .bind(admin_id)
    .execute(&pool)
    .await
    .expect("seed transport-less row");

    let mailer = Arc::new(SlowProbingMailer {
        pool: pool.clone(),
        recorder: recorder.clone(),
        observations: Mutex::new(Vec::new()),
    });
    let worker = DispatcherWorker::new(Database::from_pool(pool.clone()), mailer.clone());

    recorder.armed.store(true, Ordering::SeqCst);
    let stats = worker.run_tick(10).await.expect("worker tick");
    recorder.armed.store(false, Ordering::SeqCst);

    assert_eq!(stats.examined, EMAIL_ROWS as u64 + 1);
    assert_eq!(
        stats.sent, EMAIL_ROWS as u64,
        "every email row must be sent"
    );
    assert_eq!(stats.failed, 1, "the transport-less row fails permanently");
    assert_eq!(stats.retried, 0);

    // AC: `max(now() - xact_start)` stays under 100 ms while a 500 ms relay is
    // answering. Nothing may be open at all: the claim committed before the
    // first send and the settle has not started.
    let observations = mailer.observations.lock().expect("observations").clone();
    assert_eq!(
        observations.len(),
        EMAIL_ROWS,
        "the probe must have run once per send",
    );
    for (age_ms, open) in &observations {
        assert_eq!(
            *open, 0,
            "a transaction was open during an SMTP send (oldest {age_ms} ms)",
        );
        assert!(
            *age_ms < MAX_XACT_AGE_MS,
            "oldest open transaction during a send was {age_ms} ms",
        );
    }

    let log = recorder.take();
    let last_send = log
        .iter()
        .rposition(|e| e == SEND_MARKER)
        .expect("the tick must have sent something");

    // AC: the status updates for one tick are written in at most two
    // statements - one for the sent rows, one for everything else - however
    // many rows the batch held.
    let settle: Vec<&String> = log[last_send + 1..]
        .iter()
        .filter(|s| s.starts_with("UPDATE notifications"))
        .collect();
    assert_eq!(
        settle.len(),
        2,
        "one tick settles in two statements, got: {settle:#?}"
    );
    assert!(
        settle[1].contains("UNNEST"),
        "the non-sent outcomes must be written in one batched statement: {settle:#?}"
    );

    // The claim is one statement too, and it runs before any send.
    let claims = log[..last_send]
        .iter()
        .filter(|s| s.contains("FOR UPDATE SKIP LOCKED"))
        .count();
    assert_eq!(claims, 1, "the batch is claimed once per tick: {log:#?}");
    assert!(
        !log[last_send + 1..]
            .iter()
            .any(|s| s.contains("FOR UPDATE SKIP LOCKED")),
        "nothing may re-claim after the sends: {log:#?}"
    );

    // Outcomes actually landed.
    let sent: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM notifications WHERE status = 'sent' AND sent_at IS NOT NULL",
    )
    .fetch_one(&pool)
    .await
    .expect("count sent");
    assert_eq!(sent, EMAIL_ROWS as i64);
    let failed: (i64, Option<String>) = sqlx::query_as(
        "SELECT COUNT(*), MAX(error_message) FROM notifications WHERE status = 'failed'",
    )
    .fetch_one(&pool)
    .await
    .expect("count failed");
    assert_eq!(failed.0, 1);
    assert!(
        failed.1.unwrap_or_default().contains("no transport"),
        "the permanent failure must carry its reason",
    );
    let left_sending: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM notifications WHERE status = 'sending'")
            .fetch_one(&pool)
            .await
            .expect("count sending");
    assert_eq!(left_sending, 0, "a finished tick leaves no claimed rows");
}
