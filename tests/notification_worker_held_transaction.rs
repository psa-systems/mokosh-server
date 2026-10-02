//! PMS-1436: the scoped probe still catches a worker that really holds a
//! transaction across a send.
//!
//! This is the half that makes the narrowing safe. `notification_worker_transactions`
//! used to measure every backend on the database, which failed a pull request
//! about PDF export on a 188ms transaction nobody owned; PMS-1436 scopes it to
//! the worker's `application_name`. The obvious risk in narrowing a predicate is
//! narrowing it to nothing: a filter that matched no rows would pass forever and
//! look exactly like a fix.
//!
//! So this holds a transaction open on a worker-tagged connection for a whole
//! tick and requires the probe to see it. That is the shape of the regression
//! PMS-782 and PMS-1122 guard against, a worker keeping a transaction open
//! across an SMTP round trip so every send holds row locks for the relay's
//! latency.
//!
//! ## Why this is its own binary
//!
//! Not tidiness. The sibling suite installs a `tracing` subscriber with
//! `set_global_default` to record every statement in the PROCESS, and asserts
//! that nothing ran between two sends. Put both tests in one file and `cargo
//! test` runs them as threads in one process, so this test's statements land in
//! that assertion's log and fail it with `ROLLBACK` and the harness's own `DROP
//! DATABASE`. One suite per process is what keeps a global subscriber honest.
//! The small amount of duplication below is the price, and it is cheaper than
//! either suite learning to filter the other's statements out.
//!
//! Injected on a tagged connection rather than by making the worker wrong,
//! because what is under test is the PROBE's reach. Driving the real regression
//! would mean editing `DispatcherWorker` to hold a transaction, which is a change
//! nobody wants merged even temporarily.

mod common;

use async_trait::async_trait;
use mokosh_server::modules::notifications::DispatcherWorker;
use mokosh_server::utils::email::Mailer;
use mokosh_server::utils::error::AppResult;
use mokosh_server::Database;
use mokosh_test::mokosh_test;
use sqlx::PgPool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Matches the sibling suite: the probe fires this far into a send.
const RELAY_LATENCY: Duration = Duration::from_millis(500);

/// Matches the sibling suite's bound, which is the issue's own number.
const MAX_XACT_AGE_MS: f64 = 100.0;

/// Matches the sibling suite's tag. The two have to agree or this test proves
/// nothing about that one, so a mismatch is a silent false pass; the assertion
/// at the end spells out that failure mode.
const WORKER_APP_NAME: &str = "mokosh-notification-worker";

/// The probe, reduced to what this test needs: how old the worker's oldest
/// transaction is, and what the backend holding it was doing.
#[derive(Debug, Clone)]
struct Observation {
    age_ms: f64,
    detail: String,
}

struct ProbingMailer {
    pool: PgPool,
    observations: Mutex<Vec<Observation>>,
}

#[async_trait]
impl Mailer for ProbingMailer {
    async fn send_multipart(
        &self,
        _to: &str,
        _subject: &str,
        _text: &str,
        _html: Option<&str>,
    ) -> AppResult<()> {
        tokio::time::sleep(RELAY_LATENCY).await;
        let offender: Option<(f64, i32, String)> = sqlx::query_as(
            r#"SELECT EXTRACT(EPOCH FROM (clock_timestamp() - xact_start))::float8 * 1000,
                      pid,
                      COALESCE(state, '(none)')
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
                Some((age_ms, pid, state)) => Observation {
                    age_ms,
                    detail: format!("pid {pid}, state {state}"),
                },
                None => Observation {
                    age_ms: 0.0,
                    detail: "no worker backend was in a transaction".to_string(),
                },
            });
        Ok(())
    }
}

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
async fn a_transaction_held_across_a_send_is_still_caught(pool: PgPool) {
    let tenant_id = common::DEFAULT_TENANT_ID;
    let (admin_id, _email, _password) = common::seed_admin(&pool).await;

    sqlx::query(
        r#"INSERT INTO notifications (tenant_id, user_id, channel_type, subject, body, status)
           VALUES ($1, $2, 'email', 'Held', 'body', 'pending')"#,
    )
    .bind(tenant_id)
    .bind(admin_id)
    .execute(&pool)
    .await
    .expect("seed one pending email row");

    let worker_pool = worker_tagged_pool(&pool).await;

    // Opened before the tick and still open while the probe fires. Left IDLE
    // rather than running `pg_sleep`: the transaction only has to exist, and
    // `idle in transaction` is the harder case for a probe that might otherwise
    // have keyed on `state = 'active'`.
    let mut held = worker_pool
        .begin()
        .await
        .expect("open a transaction on a worker-tagged connection");
    sqlx::query("SELECT 1")
        .execute(&mut *held)
        .await
        .expect("make the transaction real, so xact_start is set");

    let mailer = Arc::new(ProbingMailer {
        pool: pool.clone(),
        observations: Mutex::new(Vec::new()),
    });
    let worker = DispatcherWorker::new(Database::from_pool(worker_pool.clone()), mailer.clone());
    let _ = worker.run_tick(10).await;

    let observations = mailer.observations.lock().expect("observations").clone();
    assert!(
        !observations.is_empty(),
        "the tick has to have sent something, or the probe never ran and this test is vacuous"
    );
    let worst = observations
        .iter()
        .max_by(|a, b| a.age_ms.total_cmp(&b.age_ms))
        .expect("at least one observation")
        .clone();
    assert!(
        worst.age_ms >= MAX_XACT_AGE_MS,
        "a transaction held across a send has to breach the bound. If it does not, the \
         application_name filter is matching nothing and the sibling suite now passes for \
         that reason rather than because the worker is clean. Worst observed: {} ms ({})",
        worst.age_ms,
        worst.detail,
    );
    assert!(
        worst.detail.contains("pid ") && worst.detail.contains("idle in transaction"),
        "the observation has to name the backend and its state, which is the other half of \
         PMS-1436: {}",
        worst.detail,
    );

    held.rollback().await.expect("release the held transaction");
}
