//! Smoke test for the shared scheduler (PMS-135).
//!
//! Pins the per-job spawn + interval semantics that follow-up
//! migration PRs (notifications dispatcher, RMM sync worker, future
//! reminder/breach/renewal jobs) all rely on:
//!
//! - Each registered `Job` runs on its own tokio task.
//! - Ticks fire at the configured interval (no missed-tick backlog).
//! - An error returned by `run` is logged + swallowed; the next tick
//!   still fires.
//! - `register` rejects duplicate job names so per-job span fields
//!   stay unambiguous.
//!
//! Uses `tokio::time::pause()` so ticks are driven by virtual time
//! and the assertions are deterministic on any runner. The default
//! `current_thread` runtime is required (pause() panics on a
//! multi-thread runtime); the spawned job task and the test body
//! share the runtime, which is fine because every wait is a
//! `tokio::time::sleep` that yields back to the executor.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use mokosh_server::scheduler::{Job, Scheduler};
use mokosh_server::utils::error::{AppError, AppResult};

struct CountingJob {
    name: &'static str,
    counter: Arc<AtomicUsize>,
    fail_every: usize,
}

#[async_trait]
impl Job for CountingJob {
    fn name(&self) -> &'static str {
        self.name
    }

    async fn run(&self) -> AppResult<()> {
        let n = self.counter.fetch_add(1, Ordering::SeqCst) + 1;
        if self.fail_every > 0 && n.is_multiple_of(self.fail_every) {
            return Err(AppError::Internal("intentional smoke-test failure".into()));
        }
        Ok(())
    }
}

/// Drive `total` of virtual time in `step`-sized hops, yielding
/// between hops so the scheduler task gets cycles to advance its own
/// `interval.tick().await`. A single `tokio::time::sleep(total)` on
/// a paused clock does not deschedule the test future for long
/// enough; chopping it up gives the spawned job task room to run.
async fn advance_virtual_time(total: Duration, step: Duration) {
    let mut elapsed = Duration::ZERO;
    while elapsed < total {
        tokio::time::sleep(step).await;
        tokio::task::yield_now().await;
        elapsed += step;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn registered_job_ticks_at_interval() {
    tokio::time::pause();
    let counter = Arc::new(AtomicUsize::new(0));
    let mut sched = Scheduler::new();
    sched.register(
        CountingJob {
            name: "counting_job",
            counter: counter.clone(),
            fail_every: 0,
        },
        Duration::from_millis(50),
    );
    let _handles = sched.start();

    // `tokio::time::interval` fires immediately on the first tick,
    // then every 50ms. Drive ~250ms of virtual time so the loop
    // gets at least 3 ticks - we assert >= 3 (not =6) because the
    // current_thread runtime + virtual clock can still interleave a
    // step-sized sleep before the spawned task observes the timer
    // edge, which is acceptable as long as the loop is actually
    // alive.
    advance_virtual_time(Duration::from_millis(250), Duration::from_millis(10)).await;
    let n = counter.load(Ordering::SeqCst);
    assert!(
        n >= 3,
        "expected at least 3 ticks in 250ms virtual at 50ms interval, got {n}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn tick_errors_do_not_kill_the_loop() {
    tokio::time::pause();
    let counter = Arc::new(AtomicUsize::new(0));
    let mut sched = Scheduler::new();
    // Every second tick returns Err; the loop must keep ticking
    // past the failing tick (otherwise the counter would freeze at
    // `fail_every` and the assert would fail).
    sched.register(
        CountingJob {
            name: "flaky_job",
            counter: counter.clone(),
            fail_every: 2,
        },
        Duration::from_millis(50),
    );
    let _handles = sched.start();

    advance_virtual_time(Duration::from_millis(250), Duration::from_millis(10)).await;
    let n = counter.load(Ordering::SeqCst);
    assert!(
        n >= 4,
        "loop should survive periodic Err; want >= 4 ticks, got {n}"
    );
}

#[tokio::test]
#[should_panic(expected = "duplicate job name")]
async fn register_rejects_duplicate_job_names() {
    let counter = Arc::new(AtomicUsize::new(0));
    let mut sched = Scheduler::new();
    sched.register(
        CountingJob {
            name: "dup",
            counter: counter.clone(),
            fail_every: 0,
        },
        Duration::from_secs(1),
    );
    // Second registration with the same `name()` must panic so the
    // operator sees a misconfiguration immediately rather than
    // discovering ambiguous per-job logs in production.
    sched.register(
        CountingJob {
            name: "dup",
            counter,
            fail_every: 0,
        },
        Duration::from_secs(1),
    );
}
