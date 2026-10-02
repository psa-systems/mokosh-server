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
//!   * the mailer samples `pg_stat_activity` on every send and asserts that
//!     nothing has been in a transaction longer than the issue's own
//!     `max(now() - xact_start)` threshold. PMS-932: the AGE is the verdict and
//!     the COUNT is only context. Asserting the count was zero failed CI on a
//!     transaction 8 ms old belonging to a backend this test does not own, and
//!     failed it before the criterion the issue specifies was evaluated. The
//!     probe sees every backend on `current_database()`, and the test controls
//!     none of them beyond its own pool, so a count of zero is not something it
//!     can require. Do not re-add it as a tightening;
//!   * a `tracing` subscriber records every statement (the in-process
//!     equivalent of `log_statement=all`, per `tests/contract_sweep_query_budget.rs`)
//!     so the settle budget can be counted, and so that NOTHING but the probe
//!     itself runs between two sends. That second assertion is the flake-free
//!     half of the proof and catches strictly more than the count ever did: a
//!     brief statement mid-send is a database round trip across an SMTP one,
//!     and it is over long before the probe would sample it.
//!
//! This file holds exactly ONE test on purpose: the subscriber is
//! process-global, so a second test running concurrently would count its
//! statements as well. The crash-recovery half of F9 lives in
//! `tests/notifications.rs`, which installs no subscriber.

mod common;

use mokosh_test::mokosh_test;
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

/// No transaction held by the WORKER may be older than this while a send is in
/// flight. The issue's own number (PMS-932), restored by PMS-1436.
///
/// It went to 400ms under PMS-1426, which was the wrong fix and is worth
/// recording as such. That change tolerated the noise instead of excluding it:
/// the probe measured every backend on the database, the test shares its pool
/// with the worker, and a 188ms transaction belonging to something other than
/// the worker failed a pull request that only touched PDF export. Widening the
/// threshold made that stop happening and also made the test blind to a worker
/// holding a transaction for a third of a second, which is the regression it
/// exists to catch (PMS-782, PMS-1122).
///
/// PMS-1436 scopes the probe to [`WORKER_APP_NAME`] instead, so the number can
/// go back to meaning what it says. A transaction held across the relay shows up
/// at [`RELAY_LATENCY`] or more, five times this bound, so the discrimination is
/// wide while the tolerance for noise is zero, which is the right way round.
const MAX_XACT_AGE_MS: f64 = 100.0;

/// `application_name` on the pool the worker is given, so the probe can tell the
/// worker's backends from every other connection to the same database.
///
/// This is the fix. The test and the worker shared one pool, so no `pid` filter
/// could separate them, and `datname = current_database()` was the closest the
/// probe could get: it caught the harness's own connections, sqlx's, and
/// anything else that happened to be mid-transaction. Tagging the worker's pool
/// turns "some backend on this database" into "the worker", which is what the
/// test's contract was always about.
const WORKER_APP_NAME: &str = "mokosh-notification-worker";

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
    observations: Mutex<Vec<Observation>>,
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
        // whether it is `active` or parked `idle in transaction`.
        //
        // PMS-1436: scoped to the WORKER's connections by `application_name`.
        // The old predicate was `datname = current_database()`, which is every
        // connection to this database including the harness's own, and that is
        // what made a 188ms transaction nobody owned fail a pull request about
        // PDF export. `pid <> pg_backend_pid()` stays as belt and braces; the
        // probe itself runs on the UNTAGGED test pool, so the tag already
        // excludes it.
        //
        // The offender's pid, state and statement travel with the row, because
        // the previous failure message said only "1 backend(s) in a transaction"
        // and left nobody able to say which one. Truncated, since a statement is
        // unbounded and this ends up in a panic message.
        let offender: Option<(f64, i32, String, String)> = sqlx::query_as(
            r#"SELECT EXTRACT(EPOCH FROM (clock_timestamp() - xact_start))::float8 * 1000,
                      pid,
                      COALESCE(state, '(none)'),
                      COALESCE(left(query, 200), '(none)')
               FROM pg_stat_activity
               WHERE datname = current_database()
                 AND application_name = $1
                 AND pid <> pg_backend_pid()
                 AND xact_start IS NOT NULL
               ORDER BY xact_start
               LIMIT 1"#,
        )
        .bind(WORKER_APP_NAME)
        .fetch_optional(&self.pool)
        .await
        .expect("probe pg_stat_activity");
        self.observations
            .lock()
            .expect("observations")
            .push(match offender {
                Some((age_ms, pid, state, query)) => Observation {
                    age_ms,
                    detail: format!("pid {pid}, state {state}, running: {query}"),
                },
                // Nothing of the worker's is in a transaction, which is the
                // answer this test wants. Zero rather than `None` keeps the
                // assertion one comparison.
                None => Observation {
                    age_ms: 0.0,
                    detail: "no worker backend was in a transaction".to_string(),
                },
            });
        Ok(())
    }
}

/// What one probe saw: how long the worker's oldest transaction had been open,
/// and enough about the backend holding it to act on a failure.
///
/// PMS-1436: the detail exists because the previous message was "188.552 ms (1
/// backend(s) in a transaction)", which says a transaction existed and nothing
/// about whose it was, so the first thing anyone had to do was reproduce it.
#[derive(Debug, Clone)]
struct Observation {
    age_ms: f64,
    detail: String,
}

/// Rows delivered over SMTP in the measured tick.
const EMAIL_ROWS: usize = 3;

/// A pool on the same per-test database whose connections announce themselves as
/// the notification worker.
///
/// `max_connections(2)` on purpose: the worker's own claim-and-settle path needs
/// one, and holding a second is what the injected-violation test below does, so a
/// larger pool would let a leaked connection hide between runs instead of being
/// the thing the probe sees.
async fn worker_tagged_pool(pool: &PgPool) -> PgPool {
    let opts = pool
        .connect_options()
        .as_ref()
        .clone()
        .application_name(WORKER_APP_NAME);
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect_with(opts)
        .await
        .expect("connect the worker-tagged pool")
}

#[mokosh_test]
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
    // PMS-1436: the worker gets its OWN pool, tagged, so the probe can name it.
    // Derived from the test pool's options so it is the same per-test database
    // with nothing but `application_name` changed, the shape
    // `common::build_app_role_pool` already uses to swap a login role.
    let worker_pool = worker_tagged_pool(&pool).await;
    let worker = DispatcherWorker::new(Database::from_pool(worker_pool), mailer.clone());

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
    for observed in &observations {
        // PMS-932: the AGE is the verdict. PMS-1436: and it is now the worker's
        // age, not the database's, so the number can be the issue's own again.
        //
        // The probe fires 500ms into a send, and a transaction genuinely held
        // across that round trip is observed at `RELAY_LATENCY` or more, which is
        // five times this bound. Nothing of the worker's being open reads as 0.0,
        // which is the answer this test wants. The deterministic half of the
        // proof is the statement log below, which catches a SHORT transaction
        // opened mid-send and depends on no clock at all.
        assert!(
            observed.age_ms < MAX_XACT_AGE_MS,
            "the worker held a transaction for {} ms during a send ({})",
            observed.age_ms,
            observed.detail,
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

    // PMS-932: the flake-free half. Sampling `pg_stat_activity` is inherently
    // racy; the statement log is not. If this process issues no statement
    // between the first send and the last, it cannot have had a transaction
    // open across one, and no timing is involved.
    //
    // The probe's own `pg_stat_activity` query is the one statement that
    // legitimately lands there: the mailer pushes its marker, sleeps, then
    // probes. Anything else is the worker talking to the database mid-send,
    // which is the defect whether or not it lives long enough to trip the age
    // threshold above.
    let first_send = log
        .iter()
        .position(|e| e == SEND_MARKER)
        .expect("the tick must have sent something");
    let between: Vec<&String> = log[first_send..last_send]
        .iter()
        .filter(|s| *s != SEND_MARKER && !s.contains("pg_stat_activity"))
        .collect();
    assert!(
        between.is_empty(),
        "no statement may run between two sends, got: {between:#?}"
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
